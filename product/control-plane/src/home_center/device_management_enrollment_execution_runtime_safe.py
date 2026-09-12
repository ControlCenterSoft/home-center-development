"""Safety guard for the 0.57 provider-enrollment execution runtime.

The core runtime owns execution mechanics. This guard closes replay ambiguity,
validates complete upstream evidence, validates adapter cancellation acceptance and
avoids a bounded job-history window when deciding whether another provider command
may be emitted.
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
from .household_device_enrollment_runtime import DEVICE_ENROLLMENT_STATE_SCHEMA, _proposal_key


CANCEL_ADAPTER_RESULT_SCHEMA = "home-center.device-management-enrollment-adapter-cancel-result.v1"


class _ValidatedProviderAdapter:
    """Require a closed, non-authorizing acknowledgement for provider cancellation."""

    def __init__(self, inner: object) -> None:
        self._inner = inner

    def start(self, request: object) -> object:
        return self._inner.start(request)

    def cancel(self, *, provider_operation_id: str, job_id: str) -> object:
        value = self._inner.cancel(provider_operation_id=provider_operation_id, job_id=job_id)
        expected = {
            "schema",
            "state",
            "provider_operation_id",
            "post_condition_verified",
            "managed_state_change_authorized",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or value.get("schema") != CANCEL_ADAPTER_RESULT_SCHEMA
            or value.get("state") != "cancel-accepted"
            or value.get("provider_operation_id") != provider_operation_id
            or value.get("post_condition_verified") is not False
            or value.get("managed_state_change_authorized") is not False
        ):
            raise ValueError("device_management_enrollment_adapter_cancel_result_rejected")
        return value


class SafeDeviceManagementEnrollmentExecutionRuntimeService(DeviceManagementEnrollmentExecutionRuntimeService):
    def register_adapter(self, provider_id: str, adapter: object) -> None:
        super().register_adapter(provider_id, _ValidatedProviderAdapter(adapter))

    def _enrollment(self, proposal_id: object):
        """Require the complete confirmation evidence before execution planning."""
        proposal = super()._enrollment(proposal_id)
        envelope = self.store.get_meta(_proposal_key(proposal_id))
        if not isinstance(envelope, dict) or envelope.get("schema") != DEVICE_ENROLLMENT_STATE_SCHEMA:
            raise DeviceManagementEnrollmentExecutionRuntimeError("household_device_enrollment_state_invalid")
        receipt = envelope.get("receipt")
        if (
            not isinstance(receipt, dict)
            or receipt.get("schema") != "home-center.household-device-enrollment-confirmation.v1"
            or receipt.get("proposal_id") != proposal.proposal_id
            or receipt.get("management_plan_id") != proposal.management_plan_id
            or receipt.get("device_id") != proposal.device_id
            or receipt.get("member_id") != proposal.member_id
            or receipt.get("snapshot_id") != proposal.snapshot_id
            or receipt.get("resource_version") != proposal.resource_version
            or receipt.get("generation") != proposal.generation
            or not isinstance(receipt.get("audit_event_id"), str)
            or not receipt["audit_event_id"]
            or receipt.get("outcome") not in {"confirmed-for-provider-resolution", "already-confirmed"}
            or receipt.get("provider_resolution_required") is not True
            or receipt.get("provider_selected") is not False
            or receipt.get("provider_execution_authorized") is not False
            or receipt.get("policy_application_authorized") is not False
            or receipt.get("managed_state_change_authorized") is not False
            or receipt.get("infrastructure_mutation_authorized") is not False
            or receipt.get("external_publication_authorized") is not False
        ):
            raise DeviceManagementEnrollmentExecutionRuntimeError("household_device_enrollment_receipt_invalid")
        return proposal

    def _jobs_for_plan(self, plan_id: object, action_ids: set[str]) -> list[dict[str, Any]]:
        """Read every relevant durable job, newest-first with a deterministic tie-breaker."""
        if not isinstance(plan_id, str) or not action_ids:
            return []
        connection = getattr(self.store, "_connection", None)
        lock = getattr(self.store, "_lock", None)
        decoder = getattr(self.store, "_decode_job", None)
        if connection is not None and lock is not None and callable(decoder):
            placeholders = ",".join("?" for _ in action_ids)
            query = f"""SELECT j.*,m.idempotency_key,m.request_hash,m.steps_json
                FROM jobs AS j LEFT JOIN action_job_metadata AS m ON m.job_id=j.job_id
                WHERE j.job_type IN ({placeholders}) ORDER BY j.created_at DESC, j.rowid DESC"""
            with lock:
                rows = connection.execute(query, tuple(sorted(action_ids))).fetchall()
            jobs = [decoder(row) for row in rows]
        else:
            # Test doubles may not expose StateStore internals; production StateStore always does.
            jobs = self.store.jobs(500)
        return [
            job for job in jobs
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
        if any(job.get("state") in {"preflight", "running", "verifying"} for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_in_progress")
        if any(job.get("state") == "failed" for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_retry_required")
        if any(job.get("state") == "succeeded" for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_state_invalid")
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
        previous = self._jobs_for_plan(plan_id, {START_ACTION, RETRY_ACTION})
        if any(job.get("state") in {"preflight", "running", "verifying"} for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_in_progress")
        if any(job.get("state") == "succeeded" for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_state_invalid")
        failed_job_id = request.get("failed_job_id")
        if not previous or previous[0].get("state") != "failed" or previous[0].get("job_id") != failed_job_id:
            # Retry is only allowed for the latest durable attempt. Selecting an older
            # retry-safe failure must never bypass a newer ambiguous failure.
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_retry_not_allowed")
        result = previous[0].get("result")
        if not isinstance(result, dict) or result.get("retry_safe") is not True:
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_retry_not_safe")
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
        if any(job.get("state") in {"preflight", "running", "verifying"} for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_cancel_in_progress")
        if any(job.get("state") == "failed" for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_cancel_retry_not_safe")
        if any(job.get("state") == "succeeded" for job in previous):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_state_invalid")
        return super().cancel(actor=actor, request=request, correlation_id=correlation_id)
