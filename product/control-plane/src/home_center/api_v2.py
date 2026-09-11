from __future__ import annotations

import json
import os
import ssl
import stat
import subprocess
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlsplit

from .api import RuntimeRequestHandler
from .device_management_provider_runtime import DeviceManagementProviderRuntimeError
from .device_management_provider_selection_runtime import DeviceManagementProviderSelectionRuntimeError
from .household_device_enrollment_runtime import HouseholdDeviceEnrollmentRuntimeError
from .household_device_management_runtime import HouseholdDeviceManagementRuntimeError
from .household_device_runtime import HouseholdDeviceRuntimeError
from .household_runtime import HouseholdRuntimeError
from .release_identity import ReleaseIdentityError, current_release_identity
from .tls_status import _certificate_profile, _chain_valid, status as tls_status


def _read_public_certificate(path: Path) -> tuple[bytes, bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_size < 128
            or info.st_size > 64 * 1024
        ):
            raise ValueError("public_certificate_metadata_rejected")
        data = bytearray()
        while len(data) <= 64 * 1024:
            block = os.read(descriptor, 8192)
            if not block:
                break
            data.extend(block)
        if len(data) > 64 * 1024:
            raise ValueError("public_certificate_size_rejected")
    finally:
        os.close(descriptor)
    payload = bytes(data)
    der = ssl.PEM_cert_to_DER_cert(payload.decode("ascii"))
    return payload, der


def _validated_web_ca(config: object) -> bytes:
    web_ca = getattr(config, "web_ca")
    cluster_ca = getattr(config, "cluster_ca")
    data, web_der = _read_public_certificate(web_ca)
    _, peer_der = _read_public_certificate(cluster_ca)
    if web_der == peer_der:
        raise ValueError("web_ca_must_differ_from_peer_ca")
    if not _chain_valid(web_ca, web_ca):
        raise ValueError("web_ca_self_chain_rejected")
    profile = _certificate_profile(web_ca, scope="browser-web-ca")
    if not profile.get("profile_valid"):
        raise ValueError("web_ca_profile_rejected")
    return data


class RuntimeRequestHandlerV2(RuntimeRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(path, context):
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return
        if path == "/api/v1/meta":
            try:
                release = current_release_identity()
            except ReleaseIdentityError:
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "release_identity_unavailable",
                    "Идентичность установленного релиза не подтверждена",
                    correlation_id,
                )
                return
            self._json(
                HTTPStatus.OK,
                {
                    "schema": "home-center.meta.v2",
                    "product": "Home Center",
                    "version": release["version"],
                    "revision": release["revision"],
                    "build": release["build"],
                    "release_source": release["source"],
                    "node_name": self.runtime.config.node_name,
                    "role": self.runtime.config.role,
                },
            )
            return
        if path == "/api/v1/tls/ca.crt":
            try:
                data = _validated_web_ca(self.runtime.config)
            except (OSError, UnicodeDecodeError, ValueError, ssl.SSLError, subprocess.SubprocessError):
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "tls_trust_anchor_unavailable",
                    "Корневой сертификат Web TLS временно недоступен",
                    self._correlation_id(),
                )
                return
            self.send_response(HTTPStatus.OK)
            self._base_headers("application/x-pem-file", len(data), cache="public, max-age=300")
            self.send_header("Content-Disposition", 'attachment; filename="home-center-web-ca.crt"')
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/api/v1/tls":
            if not self._require_actor(correlation_id):
                return
            try:
                value = tls_status(self.runtime.config)
            except Exception:
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "tls_status_unavailable",
                    "Статус TLS временно недоступен",
                    correlation_id,
                )
                return
            self._json(HTTPStatus.OK, value)
            return
        if path == "/api/v1/household":
            if not self._require_actor(correlation_id):
                return
            try:
                value = self.runtime.household.status()
            except HouseholdRuntimeError as exc:
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    exc.code,
                    "Состояние семьи не прошло проверку целостности",
                    correlation_id,
                )
                return
            self._json(HTTPStatus.OK, value)
            return
        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        household_posts = {
            "/api/v1/household/bootstrap",
            "/api/v1/household/intents/plan",
            "/api/v1/household/members/plan",
            "/api/v1/household/members/confirm",
            "/api/v1/household/devices/plan",
            "/api/v1/household/devices/confirm",
            "/api/v1/household/devices/management/plan",
            "/api/v1/household/devices/enrollment/plan",
            "/api/v1/household/devices/enrollment/confirm",
            "/api/v1/household/devices/enrollment/provider-resolution/plan",
            "/api/v1/household/devices/enrollment/provider-selection/plan",
            "/api/v1/household/devices/enrollment/provider-selection/confirm",
        }
        if path not in household_posts:
            super().do_POST()
            return

        self._request_body_complete = False
        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(path, context):
            self.close_connection = True
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return
        if not self._same_origin_post_allowed(context):
            self.close_connection = True
            self.runtime.store.audit(
                actor=f"network:{context.client_address}",
                action="request.origin",
                target=self.runtime.config.node_id,
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "cross_origin_request", **self._origin_details(context)},
            )
            self._error(
                HTTPStatus.FORBIDDEN,
                "cross_origin_request_rejected",
                "Запрос из другого источника запрещён",
                correlation_id,
            )
            return
        actor = self._require_actor(correlation_id)
        if not actor:
            return
        try:
            body = self._read_json(max_bytes=8192)
            if path == "/api/v1/household/bootstrap":
                value = self.runtime.household.bootstrap(actor=actor, request=body, correlation_id=correlation_id)
                self._json(HTTPStatus.CREATED, value)
                return
            if path == "/api/v1/household/intents/plan":
                value = self.runtime.household.plan_intent(actor=actor, request=body, correlation_id=correlation_id)
                self._json(HTTPStatus.OK, value)
                return
            if path == "/api/v1/household/members/plan":
                value = self.runtime.household.plan_member_add(actor=actor, request=body, correlation_id=correlation_id)
                self._json(HTTPStatus.OK, value)
                return
            if path == "/api/v1/household/members/confirm":
                value = self.runtime.household.confirm_member_add(actor=actor, request=body, correlation_id=correlation_id)
                self._json(HTTPStatus.OK, value)
                return
            if path == "/api/v1/household/devices/plan":
                value = self.runtime.household_devices.plan_device_add(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
                self._json(HTTPStatus.OK, value)
                return
            if path == "/api/v1/household/devices/confirm":
                value = self.runtime.household_devices.confirm_device_add(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
                self._json(HTTPStatus.OK, value)
                return
            if path == "/api/v1/household/devices/management/plan":
                value = self.runtime.household_device_management.plan(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
                self._json(HTTPStatus.OK, value)
                return
            if path == "/api/v1/household/devices/enrollment/plan":
                value = self.runtime.household_device_enrollment.plan(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
                self._json(HTTPStatus.OK, value)
                return
            if path == "/api/v1/household/devices/enrollment/confirm":
                value = self.runtime.household_device_enrollment.confirm(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
                self._json(HTTPStatus.OK, value)
                return
            if path == "/api/v1/household/devices/enrollment/provider-resolution/plan":
                value = self.runtime.device_management_providers.plan(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
                self._json(HTTPStatus.OK, value)
                return
            if path == "/api/v1/household/devices/enrollment/provider-selection/plan":
                value = self.runtime.device_management_provider_selection.plan(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
                self._json(HTTPStatus.OK, value)
                return
            value = self.runtime.device_management_provider_selection.confirm(
                actor=actor,
                request=body,
                correlation_id=correlation_id,
            )
            self._json(HTTPStatus.OK, value)
            return
        except (
            HouseholdRuntimeError,
            HouseholdDeviceRuntimeError,
            HouseholdDeviceManagementRuntimeError,
            HouseholdDeviceEnrollmentRuntimeError,
            DeviceManagementProviderRuntimeError,
            DeviceManagementProviderSelectionRuntimeError,
        ) as exc:
            conflict_codes = {
                "household_already_configured",
                "household_intent_target_exists",
                "household_member_already_exists",
                "household_member_change_stale",
                "household_device_already_exists",
                "household_device_change_stale",
                "household_device_enrollment_stale",
                "household_device_enrollment_not_confirmed",
                "device_management_provider_resolution_stale",
                "device_management_provider_selection_stale",
                "device_management_provider_not_available",
                "device_management_provider_already_selected",
            }
            forbidden_codes = {
                "household_actor_not_bound",
                "household_intent_not_authorized",
                "household_member_change_not_authorized",
                "household_member_change_actor_mismatch",
                "household_device_change_not_authorized",
                "household_device_change_actor_mismatch",
                "household_device_management_not_authorized",
                "household_device_enrollment_actor_mismatch",
                "device_management_provider_selection_actor_mismatch",
            }
            not_found_codes = {
                "household_not_configured",
                "household_member_not_found",
                "household_member_proposal_not_found",
                "household_device_proposal_not_found",
                "household_device_not_found",
                "household_device_enrollment_proposal_not_found",
                "device_management_provider_selection_proposal_not_found",
            }
            unavailable_codes = {
                "household_state_invalid",
                "household_device_enrollment_state_invalid",
                "household_device_enrollment_receipt_invalid",
                "invalid_device_management_provider_catalog",
                "unsupported_device_management_provider_catalog",
                "invalid_device_management_provider_profile",
                "duplicate_device_management_provider_id",
                "invalid_device_management_provider_name",
                "invalid_device_management_provider_platforms",
                "duplicate_device_management_provider_platform",
                "invalid_device_management_enrollment_modes",
                "duplicate_device_management_enrollment_mode",
                "invalid_device_management_provider_readiness",
                "device_management_provider_selection_state_invalid",
                "device_management_provider_selection_binding_invalid",
                "device_management_provider_selection_receipt_invalid",
                "device_management_provider_selection_evidence_rejected",
            }
            if exc.code in conflict_codes:
                status = HTTPStatus.CONFLICT
            elif exc.code in forbidden_codes:
                status = HTTPStatus.FORBIDDEN
            elif exc.code in not_found_codes:
                status = HTTPStatus.NOT_FOUND
            elif exc.code in unavailable_codes:
                status = HTTPStatus.SERVICE_UNAVAILABLE
            else:
                status = HTTPStatus.BAD_REQUEST
            self.runtime.store.audit(
                actor=actor,
                action="household.request",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code, "path": path},
            )
            self._error(status, exc.code, "Запрос семьи не прошёл безопасную проверку", correlation_id)
        except (ValueError, TypeError, json.JSONDecodeError):
            self.runtime.store.audit(
                actor=actor,
                action="household.request",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "invalid_household_request", "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_household_request",
                "Некорректный запрос семьи",
                correlation_id,
            )
