"""0.58 web boundary for post-condition verification and scoped re-auth."""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .ad_auth import AdAuthError
from .api_v3 import RuntimeRequestHandlerV3
from .device_management_enrollment_post_condition_runtime import (
    DeviceManagementEnrollmentPostConditionRuntimeError,
)
from .local_admin_auth import LocalAdminAuthError
from .step_up import StepUpError


class RuntimeRequestHandlerV4(RuntimeRequestHandlerV3):
    """Add 0.58 verification plan/confirm without weakening V3 request fences."""

    REAUTH_PATH = "/api/v1/session/reauth"
    VERIFICATION_POSTS = {
        "/api/v1/household/devices/enrollment/verification/plan",
        "/api/v1/household/devices/enrollment/verification/confirm",
    }

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == self.REAUTH_PATH:
            self._reauth()
            return
        if path not in self.VERIFICATION_POSTS:
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
            service = self.runtime.device_management_enrollment_post_condition
            if path.endswith("/plan"):
                value = service.plan(actor=actor, request=body, correlation_id=correlation_id)
            else:
                value = service.confirm(
                    actor=actor,
                    request=body,
                    step_up_token=self.headers.get("X-Home-Center-Step-Up"),
                    correlation_id=correlation_id,
                )
            self._json(HTTPStatus.OK, value)
            return
        except DeviceManagementEnrollmentPostConditionRuntimeError as exc:
            forbidden = {
                "household_actor_not_bound",
                "household_member_disabled",
                "device_management_enrollment_verification_not_authorized",
                "device_management_enrollment_verification_actor_mismatch",
                "step_up_required",
                "step_up_expired",
                "step_up_binding_mismatch",
                "step_up_actor_invalid",
                "step_up_scope_invalid",
            }
            not_found = {
                "household_not_configured",
                "household_device_not_found",
                "device_management_enrollment_execution_plan_not_found",
                "device_management_enrollment_verification_plan_not_found",
            }
            conflict = {
                "device_management_enrollment_execution_not_verifiable",
                "device_management_enrollment_execution_receipt_invalid",
                "device_management_enrollment_verification_binding_mismatch",
                "device_management_enrollment_verification_stale",
                "device_management_enrollment_device_already_managed",
                "device_management_enrollment_verification_state_invalid",
                "device_management_enrollment_verification_idempotency_conflict",
                "device_management_enrollment_verification_in_progress",
                "device_management_enrollment_verification_previous_attempt_failed",
            }
            unavailable = {
                "household_state_invalid",
                "device_management_enrollment_verification_adapter_unavailable",
                "device_management_enrollment_verification_provider_error",
                "device_management_post_condition_request_rejected",
                "device_management_post_condition_result_rejected",
                "device_management_post_condition_now_invalid",
                "device_management_enrollment_managed_state_readback_failed",
            }
            if exc.code in forbidden:
                status = HTTPStatus.FORBIDDEN
            elif exc.code in not_found:
                status = HTTPStatus.NOT_FOUND
            elif exc.code in conflict:
                status = HTTPStatus.CONFLICT
            elif exc.code in unavailable:
                status = HTTPStatus.SERVICE_UNAVAILABLE
            else:
                status = HTTPStatus.BAD_REQUEST
            self.runtime.store.audit(
                actor=actor,
                action="household.device.management.enrollment.post-condition.request",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code, "path": path},
            )
            self._error(
                status,
                exc.code,
                "Проверка подключения устройства не прошла безопасную проверку",
                correlation_id,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            self.runtime.store.audit(
                actor=actor,
                action="household.device.management.enrollment.post-condition.request",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={
                    "reason": "invalid_device_management_enrollment_verification_request",
                    "path": path,
                },
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_device_management_enrollment_verification_request",
                "Некорректный запрос проверки подключения устройства",
                correlation_id,
            )

    def _reauth(self) -> None:
        self._request_body_complete = False
        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(self.REAUTH_PATH, context):
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
        limiter_key = context.limiter_key + ":reauth"
        if not self.runtime.login_limiter.allow(limiter_key):
            self._error(
                HTTPStatus.TOO_MANY_REQUESTS,
                "rate_limited",
                "Слишком много попыток повторной аутентификации",
                correlation_id,
                headers={"Retry-After": "60"},
            )
            return
        try:
            body = self._read_json(max_bytes=4096)
            if set(body) != {"schema", "provider", "username", "password", "scope"}:
                raise ValueError("invalid reauth shape")
            if body.get("schema") != "home-center.session-reauth-request.v1":
                raise ValueError("invalid reauth schema")
            provider = body.get("provider")
            username = body.get("username")
            password = body.get("password")
            scope = body.get("scope")
            if (
                provider not in {"local", "ad"}
                or not isinstance(username, str)
                or not isinstance(password, str)
                or not isinstance(scope, str)
            ):
                raise ValueError("invalid reauth values")
            if not scope.startswith("household.device.management.enrollment.verify:dmpverify-"):
                raise ValueError("invalid reauth scope")
        except (ValueError, TypeError, json.JSONDecodeError):
            self.runtime.store.audit(
                actor=actor,
                action="session.reauth",
                target=self.runtime.config.node_id,
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "invalid_reauth_request"},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_reauth_request",
                "Некорректный запрос повторной аутентификации",
                correlation_id,
            )
            return

        expected_provider = "local" if actor.startswith("local-admin:") else "ad" if actor.startswith("ad-admin:") else None
        expected_username = actor.split(":", 1)[1] if expected_provider is not None else None
        if provider != expected_provider:
            canonical_username = None
        else:
            try:
                canonical_username = (
                    self.runtime.local_admin.authenticate(username, password)
                    if provider == "local"
                    else self.runtime.ad_auth.authenticate(username, password)
                )
            except (LocalAdminAuthError, AdAuthError):
                self.runtime.store.audit(
                    actor=actor,
                    action="session.reauth",
                    target=self.runtime.config.node_id,
                    outcome="failed",
                    correlation_id=correlation_id,
                    details={"reason": "authentication_unavailable"},
                )
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "authentication_unavailable",
                    "Служба аутентификации недоступна",
                    correlation_id,
                )
                return

        if canonical_username is None or canonical_username != expected_username:
            self.runtime.store.audit(
                actor=actor,
                action="session.reauth",
                target=self.runtime.config.node_id,
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "invalid_credentials"},
            )
            self._error(
                HTTPStatus.FORBIDDEN,
                "reauthentication_failed",
                "Повторная аутентификация не пройдена",
                correlation_id,
            )
            return

        try:
            token, expires_in = self.runtime.step_up.issue(actor=actor, scope=scope)
        except StepUpError as exc:
            self._error(
                HTTPStatus.BAD_REQUEST,
                exc.code,
                "Некорректная область повторной аутентификации",
                correlation_id,
            )
            return
        self.runtime.login_limiter.clear(limiter_key)
        self.runtime.store.audit(
            actor=actor,
            action="session.reauth",
            target=self.runtime.config.node_id,
            outcome="accepted",
            correlation_id=correlation_id,
            details={"scope": scope, **self._origin_details(context)},
        )
        self._json(
            HTTPStatus.OK,
            {
                "schema": "home-center.session-reauth-result.v1",
                "state": "verified",
                "scope": scope,
                "step_up_token": token,
                "expires_in_seconds": expires_in,
                "single_use": True,
            },
        )
