"""Bounded execution of authorized failed-enrollment transient cleanup.

This 0.58 boundary deliberately executes only local transient one-time reference
cleanup after the read-only NR2 verification runtime has authorized cleanup.
It never invokes provider mutation, never changes ManagedDevice state, and never
persists or audits the raw one-time reference.
"""
from __future__ import annotations

import hashlib
import re
import threading
from typing import Any, Protocol

from .device_management_deenrollment import CLEANUP_RECEIPT_SCHEMA
from .device_management_enrollment_execution import RFC3339_UTC_SECONDS, SECRET_REFERENCE
from .device_management_enrollment_execution_runtime import (
    STATE_SCHEMA as ENROLLMENT_EXECUTION_STATE_SCHEMA,
    _key as enrollment_execution_key,
)
from .device_management_failed_enrollment_cleanup_runtime import (
    STATE_SCHEMA as CLEANUP_STATE_SCHEMA,
    DeviceManagementFailedEnrollmentCleanupRuntimeError,
    DeviceManagementFailedEnrollmentCleanupRuntimeService,
)
from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now

EXECUTE_REQUEST_SCHEMA = (
    "home-center.device-management-failed-enrollment-cleanup-execute-request.v1"
)
EXECUTOR_RESULT_SCHEMA = (
    "home-center.device-management-failed-enrollment-cleanup-executor-result.v1"
)
EXECUTION_RECEIPT_SCHEMA = (
    "home-center.device-management-failed-enrollment-cleanup-execution-receipt.v1"
)
EXECUTION_STATE_SCHEMA = (
    "home-center.device-management-failed-enrollment-cleanup-execution-state.v1"
)
ACTION = "household.device.management.enrollment.cleanup.execute"
KEY_PREFIX = "cozy.household.device-enrollment-cleanup-execution."
LOCAL_TRANSIENT_SCOPE = "local-transient-reference-only"
PLAN_ID = re.compile(r"^dmclean-[0-9a-f]{24}$")
IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class DeviceManagementFailedEnrollmentCleanupExecutionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FailedEnrollmentTransientReferenceExecutor(Protocol):
    """Provider-scoped local reference eraser; provider mutation is forbidden."""

    mutation_scope: str
    provider_mutation: bool
    idempotent: bool

    def delete_reference(
        self,
        *,
        reference: str,
        reference_sha256: str,
        artifact_kind: str,
        provider_id: str,
        enrollment_plan_id: str,
        cleanup_plan_id: str,
        device_id: str,
        member_id: str,
    ) -> object: ...


def _execution_key(plan_id: object) -> str:
    if not isinstance(plan_id, str) or PLAN_ID.fullmatch(plan_id) is None:
        raise DeviceManagementFailedEnrollmentCleanupExecutionError(
            "invalid_device_management_cleanup_plan_id"
        )
    return KEY_PREFIX + plan_id


def _digest(value: object) -> str:
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    else:
        encoded = canonical_json(value).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class DeviceManagementFailedEnrollmentCleanupExecutionService:
    """Execute only the transient-reference portion of an authorized cleanup."""

    def __init__(self, store: StateStore, *, now=utc_now) -> None:
        self.store = store
        self._now = now
        self._lock = threading.RLock()
        self._executors: dict[str, FailedEnrollmentTransientReferenceExecutor] = {}

    def register_executor(self, provider_id: str, executor: object) -> None:
        if (
            not isinstance(provider_id, str)
            or not provider_id
            or provider_id in self._executors
            or getattr(executor, "mutation_scope", None) != LOCAL_TRANSIENT_SCOPE
            or getattr(executor, "provider_mutation", None) is not False
            or getattr(executor, "idempotent", None) is not True
            or not callable(getattr(executor, "delete_reference", None))
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                "invalid_device_management_cleanup_executor_registration"
            )
        self._executors[provider_id] = executor  # type: ignore[assignment]

    def _authorized_cleanup(
        self, *, actor: str, plan_id: object
    ) -> tuple[dict[str, Any], object]:
        checker = DeviceManagementFailedEnrollmentCleanupRuntimeService(
            self.store, now=self._now
        )
        try:
            _key, envelope, plan = checker._load(plan_id)
            checker._revalidate(actor=actor, envelope=envelope, plan=plan)
        except DeviceManagementFailedEnrollmentCleanupRuntimeError as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionError(exc.code) from exc

        receipt = envelope.get("receipt")
        if (
            envelope.get("schema") != CLEANUP_STATE_SCHEMA
            or envelope.get("status") != "authorized"
            or not isinstance(receipt, dict)
            or receipt.get("schema") != CLEANUP_RECEIPT_SCHEMA
            or receipt.get("state") != "authorized"
            or receipt.get("plan_id") != plan.plan_id
            or receipt.get("transient_cleanup_authorized") is not True
            or receipt.get("escalation_to_deenrollment_required") is not False
            or receipt.get("provider_mutation_authorized") is not False
            or receipt.get("managed_state_change_authorized") is not False
            or receipt.get("policy_mutation_authorized") is not False
            or receipt.get("device_record_removal_authorized") is not False
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                "device_management_cleanup_execution_not_authorized"
            )
        return envelope, plan

    @staticmethod
    def _validate_artifact(
        artifact: object, *, requested_kind: object
    ) -> tuple[str | None, str]:
        if requested_kind == "none":
            if artifact is not None:
                raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                    "device_management_cleanup_execution_binding_mismatch"
                )
            return None, "none"

        if (
            requested_kind not in {"token", "qr"}
            or not isinstance(artifact, dict)
            or set(artifact) != {"kind", "reference", "expires_at", "single_use"}
            or artifact.get("kind") != requested_kind
            or artifact.get("single_use") is not True
            or not isinstance(artifact.get("reference"), str)
            or SECRET_REFERENCE.fullmatch(artifact["reference"]) is None
            or not isinstance(artifact.get("expires_at"), str)
            or RFC3339_UTC_SECONDS.fullmatch(artifact["expires_at"]) is None
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                "device_management_cleanup_execution_artifact_invalid"
            )
        return artifact["reference"], requested_kind

    def _transient_reference(self, plan: object) -> tuple[str | None, str]:
        envelope = self.store.get_meta(enrollment_execution_key(plan.enrollment_plan_id))
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != ENROLLMENT_EXECUTION_STATE_SCHEMA
            or envelope.get("status") not in {"provider-accepted", "cancel-requested"}
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                "device_management_cleanup_execution_source_not_found"
            )

        raw_plan = envelope.get("plan")
        receipt = envelope.get("receipt")
        if (
            not isinstance(raw_plan, dict)
            or raw_plan.get("plan_id") != plan.enrollment_plan_id
            or raw_plan.get("provider_id") != plan.provider_id
            or raw_plan.get("device_id") != plan.device_id
            or raw_plan.get("member_id") != plan.member_id
            or not isinstance(receipt, dict)
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                "device_management_cleanup_execution_binding_mismatch"
            )

        expected_receipt_fields = {
            "schema",
            "state",
            "job_id",
            "retry_of_job_id",
            "plan_id",
            "selection_proposal_id",
            "provider_id",
            "provider_operation_id",
            "device_id",
            "member_id",
            "one_time_artifact",
            "enrollment_completed",
            "post_condition_verified",
            "managed_state_change_authorized",
            "policy_application_authorized",
            "infrastructure_mutation_authorized",
            "external_publication_authorized",
        }
        if (
            set(receipt) != expected_receipt_fields
            or receipt.get("schema")
            != "home-center.device-management-enrollment-execution-receipt.v1"
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
            raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                "device_management_cleanup_execution_binding_mismatch"
            )
        return self._validate_artifact(
            receipt.get("one_time_artifact"),
            requested_kind=raw_plan.get("one_time_artifact"),
        )

    @staticmethod
    def _validate_executor_result(
        value: object, *, reference_sha256: str
    ) -> dict[str, object]:
        expected = {
            "schema",
            "state",
            "reference_sha256",
            "provider_mutation_performed",
            "managed_state_changed",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or value.get("schema") != EXECUTOR_RESULT_SCHEMA
            or value.get("state") not in {"deleted", "absent"}
            or value.get("reference_sha256") != reference_sha256
            or value.get("provider_mutation_performed") is not False
            or value.get("managed_state_changed") is not False
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                "device_management_cleanup_executor_result_rejected"
            )
        return dict(value)

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
            raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                "invalid_device_management_cleanup_execute_request"
            )
        idempotency_key = request.get("idempotency_key")
        if (
            not isinstance(idempotency_key, str)
            or IDEMPOTENCY.fullmatch(idempotency_key) is None
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                "invalid_device_management_cleanup_idempotency_key"
            )

        with self._lock:
            cleanup_envelope, plan = self._authorized_cleanup(
                actor=actor, plan_id=request.get("plan_id")
            )
            reference, artifact_kind = self._transient_reference(plan)
            reference_sha256 = _digest(reference) if reference is not None else None
            state_key = _execution_key(plan.plan_id)
            existing_state = self.store.get_meta(state_key)
            if isinstance(existing_state, dict):
                if (
                    existing_state.get("schema") == EXECUTION_STATE_SCHEMA
                    and existing_state.get("status") == "succeeded"
                    and isinstance(existing_state.get("receipt"), dict)
                ):
                    return dict(existing_state["receipt"])
                raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                    "device_management_cleanup_execution_state_invalid"
                )

            executor = None
            if reference is not None:
                executor = self._executors.get(plan.provider_id)
                if executor is None:
                    raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                        "device_management_cleanup_executor_unavailable"
                    )

            request_hash = _digest(
                {
                    "plan_id": plan.plan_id,
                    "verification_job_id": cleanup_envelope.get("job_id"),
                    "reference_sha256": reference_sha256,
                    "artifact_kind": artifact_kind,
                    "idempotency_key": idempotency_key,
                }
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=ACTION,
                    actor=actor,
                    reason="explicit bounded failed-enrollment transient cleanup",
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    preflight={
                        "schema": (
                            "home-center.device-management-failed-enrollment-cleanup-"
                            "execution-preflight.v1"
                        ),
                        "plan_id": plan.plan_id,
                        "enrollment_plan_id": plan.enrollment_plan_id,
                        "provider_id": plan.provider_id,
                        "device_id": plan.device_id,
                        "member_id": plan.member_id,
                        "artifact_kind": artifact_kind,
                        "reference_sha256": reference_sha256,
                        "transient_cleanup_authorized": True,
                        "provider_mutation_authorized": False,
                        "managed_state_change_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate-authorization", "state": "succeeded"},
                        {"step": "delete-transient-reference", "state": "pending"},
                        {"step": "persist-sanitized-receipt", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                    "device_management_cleanup_idempotency_conflict"
                ) from exc

            if not created:
                saved = self.store.get_meta(state_key)
                if (
                    job.get("state") == "succeeded"
                    and isinstance(saved, dict)
                    and saved.get("schema") == EXECUTION_STATE_SCHEMA
                    and isinstance(saved.get("receipt"), dict)
                ):
                    return dict(saved["receipt"])
                if job.get("state") in {"preflight", "running", "verifying"}:
                    raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                        "device_management_cleanup_execution_in_progress"
                    )
                raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                    "device_management_cleanup_previous_attempt_failed"
                )

            running = self.store.transition_action_job(
                job["job_id"], expected_state="preflight", new_state="running"
            )
            if reference is None:
                executor_result = {
                    "schema": EXECUTOR_RESULT_SCHEMA,
                    "state": "absent",
                    "reference_sha256": None,
                    "provider_mutation_performed": False,
                    "managed_state_changed": False,
                }
            else:
                try:
                    raw_result = executor.delete_reference(  # type: ignore[union-attr]
                        reference=reference,
                        reference_sha256=reference_sha256,
                        artifact_kind=artifact_kind,
                        provider_id=plan.provider_id,
                        enrollment_plan_id=plan.enrollment_plan_id,
                        cleanup_plan_id=plan.plan_id,
                        device_id=plan.device_id,
                        member_id=plan.member_id,
                    )
                    executor_result = self._validate_executor_result(
                        raw_result, reference_sha256=reference_sha256
                    )
                except DeviceManagementFailedEnrollmentCleanupExecutionError as exc:
                    self.store.transition_action_job(
                        running["job_id"],
                        expected_state="running",
                        new_state="failed",
                        result={
                            "schema": (
                                "home-center.device-management-failed-enrollment-cleanup-"
                                "execution-failure.v1"
                            ),
                            "state": "failed",
                            "code": exc.code,
                            "reference_sha256": reference_sha256,
                            "provider_mutation_performed": False,
                            "managed_state_changed": False,
                        },
                    )
                    raise
                except Exception as exc:
                    self.store.transition_action_job(
                        running["job_id"],
                        expected_state="running",
                        new_state="failed",
                        result={
                            "schema": (
                                "home-center.device-management-failed-enrollment-cleanup-"
                                "execution-failure.v1"
                            ),
                            "state": "failed",
                            "code": "device_management_cleanup_executor_error",
                            "reference_sha256": reference_sha256,
                            "provider_mutation_performed": False,
                            "managed_state_changed": False,
                        },
                    )
                    raise DeviceManagementFailedEnrollmentCleanupExecutionError(
                        "device_management_cleanup_executor_error"
                    ) from exc

            verifying = self.store.transition_action_job(
                running["job_id"],
                expected_state="running",
                new_state="verifying",
                result=dict(executor_result),
                steps=[
                    {"step": "revalidate-authorization", "state": "succeeded"},
                    {"step": "delete-transient-reference", "state": "succeeded"},
                    {"step": "persist-sanitized-receipt", "state": "running"},
                ],
            )
            receipt = {
                "schema": EXECUTION_RECEIPT_SCHEMA,
                "state": "succeeded",
                "job_id": verifying["job_id"],
                "plan_id": plan.plan_id,
                "enrollment_plan_id": plan.enrollment_plan_id,
                "provider_id": plan.provider_id,
                "device_id": plan.device_id,
                "member_id": plan.member_id,
                "artifact_kind": artifact_kind,
                "reference_sha256": reference_sha256,
                "transient_reference_state": executor_result["state"],
                "provider_mutation_performed": False,
                "managed_state_changed": False,
                "credential_value_persisted": False,
                "policy_mutation_performed": False,
                "device_record_removed": False,
                "infrastructure_mutation_performed": False,
                "external_publication_performed": False,
            }
            done = self.store.transition_action_job(
                verifying["job_id"],
                expected_state="verifying",
                new_state="succeeded",
                evidence={
                    "schema": (
                        "home-center.device-management-failed-enrollment-cleanup-"
                        "execution-evidence.v1"
                    ),
                    "plan_id": plan.plan_id,
                    "verification_job_id": cleanup_envelope.get("job_id"),
                    "artifact_kind": artifact_kind,
                    "reference_sha256": reference_sha256,
                    "transient_reference_state": executor_result["state"],
                    "provider_mutation_performed": False,
                    "managed_state_changed": False,
                },
                steps=[
                    {"step": "revalidate-authorization", "state": "succeeded"},
                    {"step": "delete-transient-reference", "state": "succeeded"},
                    {"step": "persist-sanitized-receipt", "state": "succeeded"},
                ],
            )
            receipt["job_id"] = done["job_id"]
            self.store.set_meta(
                state_key,
                {
                    "schema": EXECUTION_STATE_SCHEMA,
                    "status": "succeeded",
                    "cleanup_plan_id": plan.plan_id,
                    "receipt": receipt,
                },
            )
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
                    "provider_id": plan.provider_id,
                    "artifact_kind": artifact_kind,
                    "reference_sha256": reference_sha256,
                    "transient_reference_state": executor_result["state"],
                    "provider_mutation_performed": False,
                    "managed_state_changed": False,
                    "credential_value_persisted": False,
                },
            )
            return receipt
