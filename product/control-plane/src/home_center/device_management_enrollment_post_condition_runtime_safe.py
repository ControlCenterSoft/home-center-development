"""Safety wrapper for the 0.58 post-condition runtime."""
from __future__ import annotations

from typing import Any

from .device_management_enrollment_post_condition_runtime import (
    DeviceManagementEnrollmentPostConditionRuntimeService,
)


class SafeDeviceManagementEnrollmentPostConditionRuntimeService(
    DeviceManagementEnrollmentPostConditionRuntimeService
):
    """Fail before any durable Job is created when authorization/read-back is unavailable.

    The base runtime already revalidates before mutation. This wrapper also forces
    actor/RBAC revalidation for idempotent completed reads and resolves the
    observational provider adapter before the one-time step-up grant is consumed.
    """

    def confirm(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        step_up_token: object,
        correlation_id: str,
    ) -> dict[str, object]:
        with self._lock:
            _key, envelope, plan = self._load(request.get("verification_id"))
            self._revalidate(actor=actor, envelope=envelope, plan=plan)
            if envelope.get("status") != "applied":
                self._adapter(plan.get("provider_id"))
        return super().confirm(
            actor=actor,
            request=request,
            step_up_token=step_up_token,
            correlation_id=correlation_id,
        )
