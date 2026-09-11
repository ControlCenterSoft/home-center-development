"""0.57 web boundary for explicit provider-backed device enrollment execution."""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v2 import RuntimeRequestHandlerV2
from .device_management_enrollment_execution_runtime import DeviceManagementEnrollmentExecutionRuntimeError


class RuntimeRequestHandlerV3(RuntimeRequestHandlerV2):
    """Add 0.57 plan/start/cancel/retry endpoints without weakening V2 request fences."""

    EXECUTION_POSTS = {
        "/api/v1/household/devices/enrollment/execution/plan",
        "/api/v1/household/devices/enrollment/execution/start",
        "/api/v1/household/devices/enrollment/execution/cancel",
        "/api/v1/household/devices/enrollment/execution/retry",
    }

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in self.EXECUTION_POSTS:
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
            self._error(HTTPStatus.FORBIDDEN, "cross_origin_request_rejected", "Запрос из другого источника запрещён", correlation_id)
            return
        actor = self._require_actor(correlation_id)
        if not actor:
            return
        try:
            body = self._read_json(max_bytes=8192)
            service = self.runtime.device_management_enrollment_execution
            if path.endswith("/plan"):
                value = service.plan(actor=actor, request=body, correlation_id=correlation_id)
            elif path.endswith("/start"):
                value = service.start(actor=actor, request=body, correlation_id=correlation_id)
            elif path.endswith("/cancel"):
                value = service.cancel(actor=actor, request=body, correlation_id=correlation_id)
            else:
                value = service.retry(actor=actor, request=body, correlation_id=correlation_id)
            self._json(HTTPStatus.OK, value)
            return
        except DeviceManagementEnrollmentExecutionRuntimeError as exc:
            forbidden = {
                "household_actor_not_bound",
                "device_management_enrollment_execution_actor_mismatch",
            }
            not_found = {
                "household_not_configured",
                "device_management_provider_selection_not_confirmed",
                "device_management_enrollment_execution_plan_not_found",
            }
            conflict = {
                "device_management_provider_resolution_stale",
                "device_management_provider_selection_stale",
                "device_management_provider_not_available",
                "device_management_enrollment_execution_stale",
                "device_management_enrollment_execution_in_progress",
                "device_management_enrollment_execution_already_started",
                "device_management_enrollment_execution_retry_required",
                "device_management_enrollment_execution_retry_not_allowed",
                "device_management_enrollment_execution_retry_not_safe",
                "device_management_enrollment_execution_cancel_not_allowed",
                "device_management_enrollment_execution_cancel_in_progress",
                "device_management_enrollment_execution_cancel_already_requested",
                "device_management_enrollment_execution_cancel_retry_not_safe",
            }
            unavailable = {
                "household_state_invalid",
                "household_device_enrollment_state_invalid",
                "household_device_enrollment_receipt_invalid",
                "device_management_provider_selection_receipt_invalid",
                "device_management_enrollment_execution_state_invalid",
                "device_management_enrollment_execution_plan_rejected",
                "device_management_enrollment_adapter_unavailable",
                "device_management_enrollment_provider_timeout",
                "device_management_enrollment_provider_error",
                "device_management_enrollment_cancel_provider_error",
                "trusted_time_invalid",
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
                action="household.device.management.enrollment-execution.request",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code, "path": path},
            )
            self._error(status, exc.code, "Запрос подключения устройства не прошёл безопасную проверку", correlation_id)
        except (ValueError, TypeError, json.JSONDecodeError):
            self.runtime.store.audit(
                actor=actor,
                action="household.device.management.enrollment-execution.request",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "invalid_device_management_enrollment_execution_request", "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_device_management_enrollment_execution_request",
                "Некорректный запрос подключения устройства",
                correlation_id,
            )
