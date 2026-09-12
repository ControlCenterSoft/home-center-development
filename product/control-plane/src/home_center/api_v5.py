"""0.58 post-cleanup read-back HTTP boundary."""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v4 import RuntimeRequestHandlerV4
from .device_management_enrollment_cleanup_verification_runtime import (
    DeviceManagementEnrollmentCleanupVerificationRuntimeError,
)


class RuntimeRequestHandlerV5(RuntimeRequestHandlerV4):
    """Add authenticated same-origin post-cleanup assessment to the 0.58 API."""

    CLEANUP_VERIFY_POST = "/api/v1/household/devices/enrollment/cleanup/verify"

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path != self.CLEANUP_VERIFY_POST:
            super().do_POST()
            return

        self._request_body_complete = False
        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(path, context):
            self.close_connection = True
            self._error(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "Ресурс не найден",
                correlation_id,
            )
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
            body = self._read_json(max_bytes=4096)
            value = self.runtime.device_management_enrollment_cleanup_verification.verify_cleanup(
                actor=actor,
                request=body,
                correlation_id=correlation_id,
            )
            self._json(HTTPStatus.OK, value)
            return
        except DeviceManagementEnrollmentCleanupVerificationRuntimeError as exc:
            self._cleanup_verification_error(
                actor=actor,
                path=path,
                correlation_id=correlation_id,
                code=exc.code,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            code = "invalid_device_management_enrollment_cleanup_verification_request"
            self.runtime.store.audit(
                actor=actor,
                action="household.device.management.enrollment.cleanup.verify.request",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                code,
                "Некорректный запрос проверки очистки устройства",
                correlation_id,
            )

    def _cleanup_verification_error(
        self,
        *,
        actor: str,
        path: str,
        correlation_id: str,
        code: str,
    ) -> None:
        forbidden = {
            "device_management_enrollment_cleanup_verification_actor_mismatch",
            "device_management_enrollment_deenrollment_forbidden",
            "household_actor_not_bound",
        }
        not_found = {
            "household_not_configured",
            "device_management_enrollment_deenrollment_receipt_not_found",
            "device_management_enrollment_verification_evidence_not_found",
        }
        conflict = {
            "device_management_enrollment_cleanup_verification_idempotency_conflict",
            "device_management_enrollment_cleanup_verification_retry_required",
            "device_management_enrollment_cleanup_verification_state_invalid",
            "device_management_enrollment_cleanup_verification_stale",
            "device_management_enrollment_cleanup_readback_not_after_deenrollment",
            "device_management_enrollment_cleanup_readback_not_fresh",
            "device_management_enrollment_cleanup_binding_mismatch",
            "device_management_enrollment_deenrollment_receipt_invalid",
            "device_management_enrollment_deenrollment_stale",
            "device_management_enrollment_deenrollment_device_binding_mismatch",
        }
        unavailable = {
            "household_state_invalid",
            "device_management_enrollment_verification_evidence_invalid",
            "device_management_enrollment_cleanup_verification_adapter_unavailable",
            "device_management_enrollment_cleanup_verification_provider_timeout",
            "device_management_enrollment_cleanup_verification_provider_error",
            "device_management_enrollment_verification_result_rejected",
        }
        if code in forbidden:
            status = HTTPStatus.FORBIDDEN
        elif code in not_found:
            status = HTTPStatus.NOT_FOUND
        elif code in conflict:
            status = HTTPStatus.CONFLICT
        elif code in unavailable:
            status = HTTPStatus.SERVICE_UNAVAILABLE
        else:
            status = HTTPStatus.BAD_REQUEST
        self.runtime.store.audit(
            actor=actor,
            action="household.device.management.enrollment.cleanup.verify.request",
            target="household",
            outcome="denied",
            correlation_id=correlation_id,
            details={
                "reason": code,
                "path": path,
                "provider_mutation_authorized": False,
                "retry_execution_authorized": False,
            },
        )
        self._error(
            status,
            code,
            "Проверка очистки устройства не прошла безопасную проверку",
            correlation_id,
        )
