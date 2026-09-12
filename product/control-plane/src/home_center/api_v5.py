"""0.58 de-enrollment execution/reconciliation web boundary."""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v4 import RuntimeRequestHandlerV4
from .device_management_deenrollment_execution_runtime import (
    DeviceManagementDeenrollmentExecutionRuntimeError,
)


class RuntimeRequestHandlerV5(RuntimeRequestHandlerV4):
    """Expose confirmed provider mutation and read-only reconciliation behind V4 fences."""

    DEENROLLMENT_EXECUTION_POSTS = {
        "/api/v1/household/devices/deenrollment/execute",
        "/api/v1/household/devices/deenrollment/reconcile",
    }

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in self.DEENROLLMENT_EXECUTION_POSTS:
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
            service = self.runtime.device_management_deenrollment_execution
            if path.endswith("/execute"):
                value = service.execute(actor=actor, request=body, correlation_id=correlation_id)
            else:
                value = service.reconcile(actor=actor, request=body, correlation_id=correlation_id)
            self._json(HTTPStatus.OK, value)
            return
        except DeviceManagementDeenrollmentExecutionRuntimeError as exc:
            forbidden = {
                "household_actor_not_bound",
                "household_member_disabled",
                "device_management_deenrollment_not_authorized",
                "device_management_deenrollment_actor_mismatch",
            }
            not_found = {
                "household_not_configured",
                "household_device_not_found",
                "device_management_deenrollment_plan_not_found",
                "device_management_deenrollment_verification_not_found",
            }
            conflict = {
                "device_management_deenrollment_confirmation_required",
                "device_management_deenrollment_confirmation_invalid",
                "device_management_deenrollment_stale",
                "device_management_deenrollment_binding_mismatch",
                "device_management_deenrollment_device_not_managed",
                "device_management_deenrollment_state_invalid",
                "device_management_deenrollment_idempotency_conflict",
                "device_management_deenrollment_provider_rejected",
                "device_management_deenrollment_verification_rejected",
                "device_management_deenrollment_reconciliation_required",
                "device_management_deenrollment_reconciliation_not_required",
                "device_management_deenrollment_reconciliation_in_progress",
            }
            unavailable = {
                "household_state_invalid",
                "device_management_deenrollment_execution_adapter_unavailable",
                "device_management_deenrollment_provider_outcome_ambiguous",
                "device_management_deenrollment_readback_unavailable",
                "device_management_deenrollment_readback_rejected",
                "device_management_deenrollment_managed_state_readback_failed",
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
                action="household.device.management.deenrollment.execution.request",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code, "path": path},
            )
            self._error(
                status,
                exc.code,
                "Отключение управления устройством не прошло безопасную проверку",
                correlation_id,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            self.runtime.store.audit(
                actor=actor,
                action="household.device.management.deenrollment.execution.request",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "invalid_device_management_deenrollment_execution_request", "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_device_management_deenrollment_execution_request",
                "Некорректный запрос отключения управления устройством",
                correlation_id,
            )
