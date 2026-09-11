"""Safety guard for the 0.57 provider-enrollment execution runtime.

The core runtime owns execution mechanics. This guard closes replay ambiguity:
a second command must never be emitted with a fresh idempotency key after a
successful or ambiguous prior attempt. Only the explicit retry path may retry a
failure that the adapter classified retry-safe.
"""
from __future__ import annotations

from typing import Any

from .device_management_enrollment_execution_runtime import (
    CANCEL_ACTION,
    RETRY_ACTION,
    START_ACTION,
    DeviceManagementEnrollmentExecutionRuntimeError,
    DeviceManagementEnrollmentExecutionRuntimeService,
)


class SafeDeviceManagementEnrollmentExecutionRuntimeService(DeviceManagementEnrollmentExecutionRuntimeService):
    def _jobs_for_plan(self, plan_id: object, action_ids: set[str]) -> list[dict[str, Any]]:
        if not isinstance(plan_id, str):
            return []
        return [
            job for job in self.store.jobs(500)
            if job.get("job_type") in action_ids
            and isinstance(job.get("preflight"), dict)
            and job["preflight"].get("plan_id") == plan_id
        ]

    def _receipt_replay(self, receipt: object, *, action: str, idempotency_key: object) -> dict[str, object] | None:
        if not isinstance(receipt, dict) or not isinstance(receipt.get("job_id"), str) or not isinstance(idempotency_key, str):
            return None
        job = self.store.job(receipt["job_id"])
        if (
            isinstance(job, dict)
            and job.get("job_type") == action
            and job.get("idempotency_key") == idempotency_key
            and job.get("state") == "succeeded"
        ):
            return dict(receipt)
        return None

    def start(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        plan_id = request.get("plan_id")
        _, envelope, _ = self._load(plan_id)
        replay = self._receipt_replay(
            envelope.get("receipt"), action=START_ACTION, idempotency_key=request.get("idempotency_key")
        )
        if replay is not None:
            return replay
        if isinstance(envelope.get("receipt"), dict):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_already_started")
        previous = self._jobs_for_plan(plan_id, {START_ACTION, RETRY_ACTION})
        if any(job.get("state") in {"running", "verifying"} for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_in_progress")
        if any(job.get("state") == "failed" for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_retry_required")
        return super().start(actor=actor, request=request, correlation_id=correlation_id)

    def retry(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        plan_id = request.get("plan_id")
        _, envelope, _ = self._load(plan_id)
        replay = self._receipt_replay(
            envelope.get("receipt"), action=RETRY_ACTION, idempotency_key=request.get("idempotency_key")
        )
        if replay is not None:
            return replay
        if isinstance(envelope.get("receipt"), dict):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_already_started")
        return super().retry(actor=actor, request=request, correlation_id=correlation_id)

    def cancel(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        plan_id = request.get("plan_id")
        _, envelope, _ = self._load(plan_id)
        replay = self._receipt_replay(
            envelope.get("cancel_receipt"), action=CANCEL_ACTION, idempotency_key=request.get("idempotency_key")
        )
        if replay is not None:
            return replay
        if isinstance(envelope.get("cancel_receipt"), dict):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_cancel_already_requested")
        previous = self._jobs_for_plan(plan_id, {CANCEL_ACTION})
        if any(job.get("state") in {"running", "verifying"} for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_cancel_in_progress")
        if any(job.get("state") == "failed" for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_cancel_retry_not_safe")
        return super().cancel(actor=actor, request=request, correlation_id=correlation_id)
