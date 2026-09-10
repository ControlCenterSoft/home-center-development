"""Fail-closed admission for one explicit retry after failed rollback verification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_commands import AUTHORIZATION_ID, OperationJobState
from .operation_rollback_execution_receipt import OperationRollbackExecutionReceipt
from .operation_rollback_verification_receipt import (
    OperationRollbackVerificationReceipt,
    revalidate_operation_rollback_verification_receipt,
)
from .util import canonical_json


SCHEMA = "home-center.operation-recovery-retry-admission.v1"


class OperationRecoveryRetryAdmissionError(RuntimeError):
    """A failed recovery retry could not be admitted safely."""


class OperationRecoveryRetryStore(Protocol):
    def operation_job(self, job_id: str) -> dict[str, Any] | None: ...


@dataclass(frozen=True, slots=True)
class OperationRecoveryRetryRequest:
    authorization_id: str
    correlation_id: str
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.authorization_id, str) or not AUTHORIZATION_ID.fullmatch(
            self.authorization_id
        ):
            raise OperationRecoveryRetryAdmissionError("invalid_retry_authorization")
        if (
            not isinstance(self.correlation_id, str)
            or not 8 <= len(self.correlation_id) <= 128
        ):
            raise OperationRecoveryRetryAdmissionError("invalid_retry_correlation_id")
        if not isinstance(self.reason, str) or not 3 <= len(self.reason) <= 500:
            raise OperationRecoveryRetryAdmissionError("invalid_retry_reason")


@dataclass(frozen=True, slots=True)
class OperationRecoveryRetryAdmission:
    admission_id: str
    rollback_verification_receipt_id: str
    rollback_execution_receipt_id: str
    job_id: str
    action_id: str
    plan_id: str
    plan_sha256: str
    target_node_id: str
    recovery_sha256: str
    failed_state_version: int
    failed_audit_event_id: str
    retry_authorization_id: str
    retry_correlation_id: str
    retry_reason_sha256: str
    schema: str = field(default=SCHEMA, init=False)
    retry_eligible: bool = field(default=True, init=False)
    requires_new_worker_claim: bool = field(default=True, init=False)
    state_transition_authorized: bool = field(default=False, init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "admission_id": self.admission_id,
            "rollback_verification_receipt_id": self.rollback_verification_receipt_id,
            "rollback_execution_receipt_id": self.rollback_execution_receipt_id,
            "job_id": self.job_id,
            "action_id": self.action_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "target_node_id": self.target_node_id,
            "recovery_sha256": self.recovery_sha256,
            "failed_state": OperationJobState.FAILED.value,
            "failed_state_version": self.failed_state_version,
            "failed_audit_event_id": self.failed_audit_event_id,
            "retry_authorization_id": self.retry_authorization_id,
            "retry_correlation_id": self.retry_correlation_id,
            "retry_reason_sha256": self.retry_reason_sha256,
            "retry_eligible": True,
            "requires_new_worker_claim": True,
            "state_transition_authorized": False,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }


class OperationRecoveryRetryAdmissionCoordinator:
    """Seal retry eligibility without granting execution or state-transition authority."""

    def __init__(self, store: OperationRecoveryRetryStore) -> None:
        if not hasattr(store, "operation_job"):
            raise TypeError("store does not provide operation job reads")
        self._store = store

    def prepare(
        self,
        receipt: OperationRollbackVerificationReceipt,
        execution: OperationRollbackExecutionReceipt,
        request: OperationRecoveryRetryRequest,
    ) -> OperationRecoveryRetryAdmission:
        if not isinstance(receipt, OperationRollbackVerificationReceipt):
            raise TypeError("receipt must be OperationRollbackVerificationReceipt")
        if not isinstance(execution, OperationRollbackExecutionReceipt):
            raise TypeError("execution must be OperationRollbackExecutionReceipt")
        if not isinstance(request, OperationRecoveryRetryRequest):
            raise TypeError("request must be OperationRecoveryRetryRequest")

        revalidate_operation_rollback_verification_receipt(
            self._store, receipt, execution
        )
        _validate_failed_receipt(receipt)

        job = self._store.operation_job(receipt.job_id)
        if job is None:
            raise OperationRecoveryRetryAdmissionError("operation_job_not_found")
        _validate_failed_job(job, receipt, execution, request)

        reason_sha256 = hashlib.sha256(request.reason.encode("utf-8")).hexdigest()
        identity = {
            "rollback_verification_receipt_id": receipt.receipt_id,
            "rollback_execution_receipt_id": execution.receipt_id,
            "job_id": receipt.job_id,
            "action_id": receipt.action_id,
            "plan_id": receipt.plan_id,
            "plan_sha256": receipt.plan_sha256,
            "target_node_id": receipt.target_node_id,
            "recovery_sha256": receipt.recovery_sha256,
            "failed_state_version": receipt.to_state_version,
            "failed_audit_event_id": job["last_audit_event_id"],
            "retry_authorization_id": request.authorization_id,
            "retry_correlation_id": request.correlation_id,
            "retry_reason_sha256": reason_sha256,
        }
        digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
        return OperationRecoveryRetryAdmission(
            admission_id=f"oprecoveryretry-{digest[:24]}",
            rollback_verification_receipt_id=receipt.receipt_id,
            rollback_execution_receipt_id=execution.receipt_id,
            job_id=receipt.job_id,
            action_id=receipt.action_id,
            plan_id=receipt.plan_id,
            plan_sha256=receipt.plan_sha256,
            target_node_id=receipt.target_node_id,
            recovery_sha256=receipt.recovery_sha256,
            failed_state_version=receipt.to_state_version,
            failed_audit_event_id=job["last_audit_event_id"],
            retry_authorization_id=request.authorization_id,
            retry_correlation_id=request.correlation_id,
            retry_reason_sha256=reason_sha256,
        )


def revalidate_operation_recovery_retry_admission(
    store: OperationRecoveryRetryStore,
    admission: OperationRecoveryRetryAdmission,
    receipt: OperationRollbackVerificationReceipt,
    execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
) -> None:
    """Fail closed if failed-job or authorization lineage changed after admission."""

    if not isinstance(admission, OperationRecoveryRetryAdmission):
        raise TypeError("admission must be OperationRecoveryRetryAdmission")
    candidate = OperationRecoveryRetryAdmissionCoordinator(store).prepare(
        receipt, execution, request
    )
    if admission != candidate:
        raise OperationRecoveryRetryAdmissionError("recovery_retry_admission_stale")


def _validate_failed_receipt(receipt: OperationRollbackVerificationReceipt) -> None:
    if (
        receipt.recovery_verified
        or not receipt.recovery_required
        or receipt.next_state != OperationJobState.FAILED.value
    ):
        raise OperationRecoveryRetryAdmissionError(
            "recovery_retry_requires_failed_verification"
        )
    value = receipt.to_dict()
    for name in (
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "grants_execution_authority",
        "production_mutation_enabled",
    ):
        if value.get(name) is not False:
            raise OperationRecoveryRetryAdmissionError("unsafe_retry_source_evidence")


def _validate_failed_job(
    job: dict[str, Any],
    receipt: OperationRollbackVerificationReceipt,
    execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
) -> None:
    if job.get("state") != OperationJobState.FAILED.value:
        raise OperationRecoveryRetryAdmissionError("operation_job_not_failed")
    if job.get("state_version") != receipt.to_state_version:
        raise OperationRecoveryRetryAdmissionError("operation_job_state_stale")
    if job.get("mutation_may_have_occurred") is not True:
        raise OperationRecoveryRetryAdmissionError("mutation_evidence_missing")
    if job.get("recovery_required") is not True:
        raise OperationRecoveryRetryAdmissionError("recovery_not_required")

    expected = {
        "job_id": receipt.job_id,
        "action_id": receipt.action_id,
        "plan_id": receipt.plan_id,
        "plan_sha256": receipt.plan_sha256,
        "target_node_id": receipt.target_node_id,
    }
    for name, value in expected.items():
        if job.get(name) != value:
            raise OperationRecoveryRetryAdmissionError(
                f"operation_job_{name}_mismatch"
            )

    if execution.receipt_id != receipt.rollback_execution_receipt_id:
        raise OperationRecoveryRetryAdmissionError(
            "rollback_execution_receipt_mismatch"
        )
    if execution.recovery_sha256 != receipt.recovery_sha256:
        raise OperationRecoveryRetryAdmissionError("recovery_contract_mismatch")

    audit_event_id = job.get("last_audit_event_id")
    if not isinstance(audit_event_id, str) or not audit_event_id:
        raise OperationRecoveryRetryAdmissionError("failed_audit_event_missing")

    original_authorization_id = job.get("authorization_id")
    if not isinstance(original_authorization_id, str) or not AUTHORIZATION_ID.fullmatch(
        original_authorization_id
    ):
        raise OperationRecoveryRetryAdmissionError("original_authorization_invalid")
    if request.authorization_id == original_authorization_id:
        raise OperationRecoveryRetryAdmissionError(
            "fresh_retry_authorization_required"
        )
