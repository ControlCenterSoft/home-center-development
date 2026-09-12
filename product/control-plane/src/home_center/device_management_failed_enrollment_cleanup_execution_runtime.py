"""Durable bounded execution for authorized failed-enrollment cleanup.

This 0.58 boundary is deliberately narrower than enrollment/de-enrollment execution.
It never calls a provider and never changes Household/ManagedDevice/policy/device records.
After the existing read-only cleanup verifier has authorized cleanup, this service may
remove only the persisted single-use artifact reference from the exact 0.57 enrollment
execution receipt. Credential references in the immutable execution plan are retained as
audit inputs; Home Center stores references, not credential values.
"""

from __future__ import annotations

import copy
import hashlib
import re
import threading
from typing import Any

from .device_management_deenrollment import DeviceManagementFailedEnrollmentCleanupPlan
from .device_management_enrollment_execution import (
    RFC3339_UTC_SECONDS,
    SECRET_REFERENCE,
    execution_plan_from_dict,
)
from .device_management_enrollment_execution_runtime import (
    STATE_SCHEMA as EXECUTION_STATE_SCHEMA,
    _key as execution_key,
)
from .device_management_failed_enrollment_cleanup_runtime import (
    STATE_SCHEMA as CLEANUP_STATE_SCHEMA,
    DeviceManagementFailedEnrollmentCleanupRuntimeError,
    DeviceManagementFailedEnrollmentCleanupRuntimeService,
)
from .store import IdempotencyConflict, StateStore
from .util import canonical_json

EXECUTE_REQUEST_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-execute-request.v1"
EXECUTION_RECEIPT_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-execution-receipt.v1"
ACTION = "household.device.management.enrollment.cleanup.execute"
IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _reference_digest(reference: str) -> str:
    return hashlib.sha256(reference.encode("utf-8")).hexdigest()


class DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService:
    """Execute only the locally bounded cleanup previously authorized by read-back."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._verification = DeviceManagementFailedEnrollmentCleanupRuntimeService(store)
        self._lock = threading.RLock()

    @staticmethod
    def _authorized_receipt(envelope: dict[str, Any], plan: DeviceManagementFailedEnrollmentCleanupPlan) -> dict[str, object]:
        receipt = envelope.get("receipt")
        if (
            envelope.get("schema") != CLEANUP_STATE_SCHEMA
            or envelope.get("status") not in {"authorized", "cleaned"}
            or not isinstance(receipt, dict)
            or receipt.get("schema") != "home-center.device-management-failed-enrollment-cleanup-receipt.v1"
            or receipt.get("state") != "authorized"
            or receipt.get("plan_id") != plan.plan_id
            or receipt.get("transient_cleanup_authorized") is not True
            or receipt.get("escalation_to_deenrollment_required") is not False
            or receipt.get("managed_state_change_authorized") is not False
            or receipt.get("provider_mutation_authorized") is not False
            or receipt.get("policy_mutation_authorized") is not False
            or receipt.get("device_record_removal_authorized") is not False
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_not_authorized"
            )
        return dict(receipt)

    def _authorized(
        self,
        *,
        actor: str,
        plan_id: object,
    ) -> tuple[str, dict[str, Any], DeviceManagementFailedEnrollmentCleanupPlan]:
        try:
            key, envelope, plan = self._verification._load(plan_id)  # internal same-package boundary
            self._authorized_receipt(envelope, plan)
            self._verification._revalidate(actor=actor, envelope=envelope, plan=plan)
        except DeviceManagementFailedEnrollmentCleanupRuntimeError as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(exc.code) from exc
        return key, envelope, plan

    @staticmethod
    def _artifact(
        *,
        requested_kind: str,
        value: object,
        allow_missing_after_intent: bool = False,
    ) -> tuple[bool, str | None]:
        if requested_kind == "none":
            if value is not None:
                raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                    "device_management_cleanup_execution_artifact_invalid"
                )
            return False, None
        if value is None and allow_missing_after_intent:
            return False, None
        if not isinstance(value, dict) or set(value) != {"kind", "reference", "expires_at", "single_use"}:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_artifact_invalid"
            )
        reference = value.get("reference")
        expires_at = value.get("expires_at")
        if (
            value.get("kind") != requested_kind
            or requested_kind not in {"token", "qr"}
            or not isinstance(reference, str)
            or SECRET_REFERENCE.fullmatch(reference) is None
            or not isinstance(expires_at, str)
            or RFC3339_UTC_SECONDS.fullmatch(expires_at) is None
            or value.get("single_use") is not True
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_artifact_invalid"
            )
        return True, _reference_digest(reference)

    def _execution(
        self,
        plan: DeviceManagementFailedEnrollmentCleanupPlan,
        *,
        allow_missing_after_intent: bool = False,
    ) -> tuple[str, dict[str, Any], dict[str, Any], bool, str | None]:
        try:
            key = execution_key(plan.enrollment_plan_id)
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_state_not_found"
            ) from exc
        envelope = self.store.get_meta(key)
        if not isinstance(envelope, dict) or envelope.get("schema") != EXECUTION_STATE_SCHEMA:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_state_not_found"
            )
        try:
            execution_plan = execution_plan_from_dict(envelope.get("plan"))
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_state_invalid"
            ) from exc
        receipt = envelope.get("receipt")
        if (
            execution_plan.plan_id != plan.enrollment_plan_id
            or execution_plan.provider_id != plan.provider_id
            or execution_plan.device_id != plan.device_id
            or execution_plan.member_id != plan.member_id
            or envelope.get("status") not in {"provider-accepted", "cancel-requested"}
            or not isinstance(receipt, dict)
            or receipt.get("state") != "provider-accepted"
            or receipt.get("plan_id") != plan.enrollment_plan_id
            or receipt.get("provider_id") != plan.provider_id
            or receipt.get("provider_operation_id") != plan.provider_operation_id
            or receipt.get("device_id") != plan.device_id
            or receipt.get("member_id") != plan.member_id
            or receipt.get("enrollment_completed") is not False
            or receipt.get("post_condition_verified") is not False
            or receipt.get("managed_state_change_authorized") is not False
            or receipt.get("policy_application_authorized") is not False
            or receipt.get("infrastructure_mutation_authorized") is not False
            or receipt.get("external_publication_authorized") is not False
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_binding_mismatch"
            )
        present, reference_sha256 = self._artifact(
            requested_kind=execution_plan.one_time_artifact,
            value=receipt.get("one_time_artifact"),
            allow_missing_after_intent=allow_missing_after_intent,
        )
        return key, envelope, receipt, present, reference_sha256

    @staticmethod
    def _request_hash(plan_id: str, idempotency_key: str) -> str:
        return _digest(
            {
                "schema": EXECUTE_REQUEST_SCHEMA,
                "plan_id": plan_id,
                "confirmed": True,
                "idempotency_key": idempotency_key,
            }
        )

    @staticmethod
    def _receipt(
        *,
        job_id: str,
        plan: DeviceManagementFailedEnrollmentCleanupPlan,
        execution_state_sha256: str,
        reference_present: bool,
        reference_sha256: str | None,
    ) -> dict[str, object]:
        return {
            "schema": EXECUTION_RECEIPT_SCHEMA,
            "state": "cleaned",
            "job_id": job_id,
            "plan_id": plan.plan_id,
            "enrollment_plan_id": plan.enrollment_plan_id,
            "provider_id": plan.provider_id,
            "provider_operation_id": plan.provider_operation_id,
            "device_id": plan.device_id,
            "member_id": plan.member_id,
            "cleanup_generation": plan.cleanup_generation,
            "execution_state_sha256": execution_state_sha256,
            "one_time_reference_removed": reference_present,
            "removed_reference_sha256": reference_sha256 if reference_present else None,
            "provider_mutation_performed": False,
            "managed_state_changed": False,
            "policy_mutation_performed": False,
            "device_record_removed": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
        }

    def _finish_succeeded_replay(
        self,
        *,
        cleanup_key: str,
        cleanup_envelope: dict[str, Any],
        plan: DeviceManagementFailedEnrollmentCleanupPlan,
        job: dict[str, Any],
    ) -> dict[str, object]:
        evidence = job.get("evidence")
        receipt = evidence.get("cleanup_receipt") if isinstance(evidence, dict) else None
        if not isinstance(receipt, dict) or receipt.get("schema") != EXECUTION_RECEIPT_SCHEMA:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_state_invalid"
            )
        _key, execution, _provider_receipt, present, _digest_value = self._execution(
            plan, allow_missing_after_intent=True
        )
        if present or _digest(execution) != receipt.get("execution_state_sha256"):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_state_changed"
            )
        if cleanup_envelope.get("status") != "cleaned" or cleanup_envelope.get("execution_receipt") != receipt:
            completed = dict(cleanup_envelope)
            completed.update(status="cleaned", execution_receipt=receipt)
            self.store.set_meta(cleanup_key, completed)
        return dict(receipt)

    def execute(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        required = {"schema", "plan_id", "confirmed", "idempotency_key"}
        if (
            set(request) != required
            or request.get("schema") != EXECUTE_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "invalid_device_management_cleanup_execute_request"
            )
        idempotency_key = request.get("idempotency_key")
        if not isinstance(idempotency_key, str) or IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "invalid_device_management_cleanup_idempotency_key"
            )

        with self._lock:
            cleanup_key, cleanup_envelope, plan = self._authorized(
                actor=actor, plan_id=request.get("plan_id")
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=ACTION,
                    actor=actor,
                    reason="explicit bounded failed-enrollment cleanup",
                    idempotency_key=idempotency_key,
                    request_hash=self._request_hash(plan.plan_id, idempotency_key),
                    preflight={
                        "schema": "home-center.device-management-failed-enrollment-cleanup-execution-preflight.v1",
                        "plan_id": plan.plan_id,
                        "enrollment_plan_id": plan.enrollment_plan_id,
                        "provider_id": plan.provider_id,
                        "device_id": plan.device_id,
                        "cleanup_generation": plan.cleanup_generation,
                        "transient_cleanup_authorized": True,
                        "provider_mutation_authorized": False,
                        "managed_state_change_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate-authorized-cleanup", "state": "succeeded"},
                        {"step": "remove-one-time-reference", "state": "pending"},
                        {"step": "local-read-back", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                    "device_management_cleanup_idempotency_conflict"
                ) from exc

            if not created and job.get("state") == "succeeded":
                return self._finish_succeeded_replay(
                    cleanup_key=cleanup_key,
                    cleanup_envelope=cleanup_envelope,
                    plan=plan,
                    job=job,
                )
            if not created and job.get("state") == "failed":
                raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                    "device_management_cleanup_previous_attempt_failed"
                )

            if job.get("state") == "preflight":
                job = self.store.transition_action_job(
                    job["job_id"], expected_state="preflight", new_state="running"
                )

            if job.get("state") == "running":
                _execution_key, _execution_envelope, _provider_receipt, present, reference_sha256 = self._execution(plan)
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="running",
                    new_state="verifying",
                    result={
                        "schema": "home-center.device-management-failed-enrollment-cleanup-mutation-intent.v1",
                        "plan_id": plan.plan_id,
                        "one_time_reference_present": present,
                        "removed_reference_sha256": reference_sha256 if present else None,
                        "provider_mutation_performed": False,
                        "managed_state_changed": False,
                    },
                    steps=[
                        {"step": "revalidate-authorized-cleanup", "state": "succeeded"},
                        {"step": "remove-one-time-reference", "state": "running"},
                        {"step": "local-read-back", "state": "pending"},
                    ],
                )

            if job.get("state") != "verifying" or not isinstance(job.get("result"), dict):
                raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                    "device_management_cleanup_execution_in_progress"
                )

            intent = job["result"]
            expected_present = intent.get("one_time_reference_present")
            expected_reference_sha256 = intent.get("removed_reference_sha256")
            if not isinstance(expected_present, bool) or (
                expected_present and not isinstance(expected_reference_sha256, str)
            ) or (not expected_present and expected_reference_sha256 is not None):
                raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                    "device_management_cleanup_execution_state_invalid"
                )

            execution_key_value, execution_envelope, provider_receipt, present, reference_sha256 = self._execution(
                plan, allow_missing_after_intent=True
            )
            if present:
                if not expected_present or reference_sha256 != expected_reference_sha256:
                    raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                        "device_management_cleanup_execution_state_changed"
                    )
                sanitized = copy.deepcopy(execution_envelope)
                sanitized_receipt = copy.deepcopy(provider_receipt)
                sanitized_receipt["one_time_artifact"] = None
                sanitized["receipt"] = sanitized_receipt
                self.store.set_meta(execution_key_value, sanitized)
            elif not expected_present:
                sanitized = execution_envelope
            else:
                # A previous attempt may already have applied the deletion after the durable intent.
                sanitized = execution_envelope

            read_back = self.store.get_meta(execution_key_value)
            if not isinstance(read_back, dict):
                self.store.transition_action_job(
                    job["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-failed-enrollment-cleanup-execution-failure.v1",
                        "state": "failed",
                        "code": "device_management_cleanup_execution_readback_failed",
                        "provider_mutation_performed": False,
                        "managed_state_changed": False,
                    },
                )
                raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                    "device_management_cleanup_execution_readback_failed"
                )
            try:
                _key_check, exact_read_back, _receipt_check, still_present, _sha_check = self._execution(
                    plan, allow_missing_after_intent=True
                )
            except DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError:
                raise
            if still_present or exact_read_back != read_back:
                self.store.transition_action_job(
                    job["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-failed-enrollment-cleanup-execution-failure.v1",
                        "state": "failed",
                        "code": "device_management_cleanup_execution_readback_failed",
                        "provider_mutation_performed": False,
                        "managed_state_changed": False,
                    },
                )
                raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                    "device_management_cleanup_execution_readback_failed"
                )

            receipt = self._receipt(
                job_id=job["job_id"],
                plan=plan,
                execution_state_sha256=_digest(read_back),
                reference_present=expected_present,
                reference_sha256=expected_reference_sha256,
            )
            done = self.store.transition_action_job(
                job["job_id"],
                expected_state="verifying",
                new_state="succeeded",
                evidence={
                    "schema": "home-center.device-management-failed-enrollment-cleanup-execution-evidence.v1",
                    "scope": "single-use-reference-only",
                    "cleanup_receipt": receipt,
                    "provider_mutation_performed": False,
                    "managed_state_changed": False,
                },
                steps=[
                    {"step": "revalidate-authorized-cleanup", "state": "succeeded"},
                    {"step": "remove-one-time-reference", "state": "succeeded"},
                    {"step": "local-read-back", "state": "succeeded"},
                ],
            )
            completed = dict(cleanup_envelope)
            completed.update(status="cleaned", execution_receipt=receipt)
            self.store.set_meta(cleanup_key, completed)
            self.store.audit(
                actor=actor,
                action=ACTION,
                target=plan.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "job_id": done["job_id"],
                    "plan_id": plan.plan_id,
                    "enrollment_plan_id": plan.enrollment_plan_id,
                    "one_time_reference_removed": expected_present,
                    "provider_mutation_performed": False,
                    "managed_state_changed": False,
                    "policy_mutation_performed": False,
                    "device_record_removed": False,
                    "infrastructure_mutation_performed": False,
                    "external_publication_performed": False,
                },
            )
            return receipt
