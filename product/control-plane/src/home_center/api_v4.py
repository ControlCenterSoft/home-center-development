"""0.58 web boundaries for enrollment verification and exact managed-state commit."""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v3 import RuntimeRequestHandlerV3
from .device_management_enrollment_managed_state_runtime import (
    DeviceManagementEnrollmentManagedStateRuntimeError,
)
from .device_management_enrollment_verification_runtime import (
    DeviceManagementEnrollmentVerificationRuntimeError,
)


class RuntimeRequestHandlerV4(RuntimeRequestHandlerV3):
    """Expose authenticated, same-origin 0.58 enrollment completion boundaries."""

    VERIFICATION_POST = "/api/v1/household/devices/enrollment/verification/verify"
    MANAGED_STATE_COMMIT_POST = (
        "/api/v1/household/devices/enrollment/verification/commit-managed-state"
    )

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in {self.VERIFICATION_POST, self.MANAGED_STATE_COMMIT_POST}:
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
            if path == self.VERIFICATION_POST:
                value = self.runtime.device_management_enrollment_verification.verify(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
            else:
                value = self.runtime.device_management_enrollment_managed_state.commit(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
            self._json(HTTPStatus.OK, value)
            return
        except DeviceManagementEnrollmentVerificationRuntimeError as exc:
            self._verification_error(
                actor=actor,
                path=path,
                correlation_id=correlation_id,
                code=exc.code,
            )
        except DeviceManagementEnrollmentManagedStateRuntimeError as exc:
            self._managed_state_error(
                actor=actor,
                path=path,
                correlation_id=correlation_id,
                code=exc.code,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            action = (
                "household.device.management.enrollment.verify.request"
                if path == self.VERIFICATION_POST
                else "household.device.management.enrollment.commit-managed-state.request"
            )
            code = (
                "invalid_device_management_enrollment_verification_request"
                if path == self.VERIFICATION_POST
                else "invalid_device_management_enrollment_managed_state_commit_request"
            )
            message = (
                "Некорректный запрос проверки подключения устройства"
                if path == self.VERIFICATION_POST
                else "Некорректный запрос фиксации управляемого состояния устройства"
            )
            self.runtime.store.audit(
                actor=actor,
                action=action,
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(HTTPStatus.BAD_REQUEST, code, message, correlation_id)

    def _verification_error(
        self,
        *,
        actor: str,
        path: str,
        correlation_id: str,
        code: str,
    ) -> None:
        forbidden = {
            "device_management_enrollment_verification_actor_or_execution_mismatch",
        }
        not_found = {
            "household_not_configured",
            "device_management_enrollment_verification_execution_not_accepted",
            "device_management_enrollment_verification_execution_receipt_invalid",
        }
        conflict = {
            "device_management_enrollment_verification_idempotency_conflict",
            "device_management_enrollment_verification_in_progress",
            "device_management_enrollment_verification_retry_required",
            "device_management_enrollment_verification_stale",
            "device_management_enrollment_verification_already_managed",
            "device_management_enrollment_verification_device_binding_mismatch",
        }
        unavailable = {
            "household_state_invalid",
            "device_management_enrollment_verification_adapter_unavailable",
            "device_management_enrollment_verification_provider_timeout",
            "device_management_enrollment_verification_provider_error",
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
            action="household.device.management.enrollment.verify.request",
            target="household",
            outcome="denied",
            correlation_id=correlation_id,
            details={"reason": code, "path": path},
        )
        self._error(
            status,
            code,
            "Проверка результата подключения устройства не прошла безопасную проверку",
            correlation_id,
        )

    def _managed_state_error(
        self,
        *,
        actor: str,
        path: str,
        correlation_id: str,
        code: str,
    ) -> None:
        forbidden = {
            "device_management_enrollment_managed_state_actor_or_verification_mismatch",
        }
        not_found = {
            "household_not_configured",
            "device_management_enrollment_verification_evidence_not_found",
        }
        conflict = {
            "device_management_enrollment_managed_state_idempotency_conflict",
            "device_management_enrollment_managed_state_commit_retry_required",
            "device_management_enrollment_managed_state_commit_state_invalid",
            "device_management_enrollment_post_condition_not_verified",
            "device_management_enrollment_verification_evidence_mismatch",
            "device_management_enrollment_verification_stale",
            "device_management_enrollment_verification_already_managed",
            "device_management_enrollment_verification_device_binding_mismatch",
        }
        unavailable = {
            "household_state_invalid",
            "device_management_enrollment_verification_evidence_invalid",
            "device_management_enrollment_managed_state_commit_evidence_invalid",
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
            action="household.device.management.enrollment.commit-managed-state.request",
            target="household",
            outcome="denied",
            correlation_id=correlation_id,
            details={"reason": code, "path": path},
        )
        self._error(
            status,
            code,
            "Фиксация управляемого состояния устройства не прошла безопасную проверку",
            correlation_id,
        )
