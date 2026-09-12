"""0.58 web boundary for fail-closed enrollment post-condition verification."""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v3 import RuntimeRequestHandlerV3
from .device_management_enrollment_verification_runtime import (
    DeviceManagementEnrollmentVerificationRuntimeError,
)


class RuntimeRequestHandlerV4(RuntimeRequestHandlerV3):
    """Add 0.58 verification plan/confirm endpoints without weakening V3 fences."""

    VERIFICATION_POSTS = {
        "/api/v1/household/devices/enrollment/verification/plan",
        "/api/v1/household/devices/enrollment/verification/confirm",
    }

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
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
            service = self.runtime.device_management_enrollment_verification
            if path.endswith("/plan"):
                value = service.plan(actor=actor, request=body, correlation_id=correlation_id)
            else:
                value = service.confirm(actor=actor, request=body, correlation_id=correlation_id)
            self._json(HTTPStatus.OK, value)
            return
        except DeviceManagementEnrollmentVerificationRuntimeError as exc:
            forbidden = {
                "household_actor_not_bound",
                "device_management_enrollment_verification_actor_mismatch",
            }
            not_found = {
                "household_not_configured",
                "device_management_enrollment_execution_plan_not_found",
                "device_management_enrollment_verification_plan_not_found",
                "household_device_not_found",
            }
            conflict = {
                "device_management_enrollment_execution_not_verifiable",
                "device_management_enrollment_verification_binding_mismatch",
                "device_management_enrollment_verification_stale",
                "device_management_enrollment_verification_state_mismatch",
                "device_management_enrollment_device_already_managed",
                "device_management_enrollment_verification_in_progress",
                "device_management_enrollment_verification_idempotency_conflict",
                "device_management_enrollment_verification_previous_attempt_failed",
            }
            unavailable = {
                "household_state_invalid",
                "device_management_enrollment_execution_receipt_invalid",
                "device_management_enrollment_execution_plan_rejected",
                "device_management_enrollment_verification_state_invalid",
                "device_management_enrollment_verification_adapter_unavailable",
                "device_management_enrollment_adapter_verification_rejected",
                "device_management_enrollment_verification_provider_error",
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
                action="household.device.management.enrollment-verification.request",
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
                action="household.device.management.enrollment-verification.request",
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
