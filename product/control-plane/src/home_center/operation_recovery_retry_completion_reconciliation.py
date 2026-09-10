"""Restart-safe, fail-closed reconciliation for recovery retry completion."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_recovery_retry_admission import OperationRecoveryRetryAdmission
from .operation_recovery_retry_execution_receipt import (
    OperationRecoveryRetryExecutionReceipt,
)
from .operation_recovery_retry_verification_receipt import (
    OperationRecoveryRetryVerificationReceipt,
    OperationRecoveryRetryVerificationReceiptError,
    revalidate_operation_recovery_retry_verification_receipt,
)
from .operation_rollback_execution_receipt import OperationRollbackExecutionReceipt
from .operation_rollback_verification_receipt import OperationRollbackVerificationReceipt
from .util import canonical_json


SCHEMA = "home-center.operation-recovery-retry-completion-reconciliation.v1"
COMPLETION_JOURNAL_SCHEMA = "home-center.operation-recovery-retry-completion-journal.v1"


class OperationRecoveryRetryCompletionReconciliationError(RuntimeError):
    """Recovery retry completion evidence could not be reconciled safely."""


class OperationRecoveryRetryCompletionReconciliationStore(Protocol):
    def operation_job(self, job_id: str) -> dict[str, Any] | None: ...

    def operation_recovery_retry_completion_journal(
        self, receipt_id: str
    ) -> dict[str, Any] | None: ...

    def verify_audit_chain(self) -> str: ...


@dataclass(frozen=True, slots=True)
class OperationRecoveryRetryCompletionReconciliation:
    checkpoint_id: str
    receipt_id: str
    receipt_sha256: str
    recovery_retry_execution_receipt_id: str
    job_id: str
    plan_id: str
    plan_sha256: str
    target_node_id: str
    audit_event_id: str | None
    audit_event_sha256: str | None
    observed_state: str | None
    observed_state_version: int | None
    claimed_recovery_verified: bool
    claimed_recovery_required: bool
    completion_status: str
    reason: str
    exact_completion_confirmed: bool
    reconciliation_required: bool
    schema: str = field(default=SCHEMA, init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    grants_execution_authority: bool = field(default=False, init=False)
    retry_authorized: bool = field(default=False, init=False)
    rollback_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "checkpoint_id": self.checkpoint_id,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "recovery_retry_execution_receipt_id": (
                self.recovery_retry_execution_receipt_id
            ),
            "job_id": self.job_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "target_node_id": self.target_node_id,
            "audit_event_id": self.audit_event_id,
            "audit_event_sha256": self.audit_event_sha256,
            "observed_state": self.observed_state,
            "observed_state_version": self.observed_state_version,
            "claimed_recovery_verified": self.claimed_recovery_verified,
            "claimed_recovery_required": self.claimed_recovery_required,
            "completion_status": self.completion_status,
            "reason": self.reason,
            "exact_completion_confirmed": self.exact_completion_confirmed,
            "reconciliation_required": self.reconciliation_required,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "retry_authorized": False,
            "rollback_authorized": False,
            "production_mutation_enabled": False,
        }


def assess_operation_recovery_retry_verification_completion(
    store: OperationRecoveryRetryCompletionReconciliationStore,
    receipt: OperationRecoveryRetryVerificationReceipt,
    execution: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
) -> OperationRecoveryRetryCompletionReconciliation:
    """Confirm one durable completion or require reconciliation without retry authority."""

    _validate_inputs(store, receipt)
    receipt_sha256 = _sha256(receipt.to_dict())
    job = store.operation_job(receipt.job_id)
    if job is None:
        return _build_checkpoint(
            receipt,
            receipt_sha256,
            None,
            reason="operation_job_missing",
        )

    initial_fingerprint = _job_completion_sha256(job)
    if (
        job.get("state") != receipt.next_state
        or job.get("state_version") != receipt.to_state_version
    ):
        return _build_checkpoint(
            receipt,
            receipt_sha256,
            job,
            reason="completion_state_not_current",
        )

    try:
        store.verify_audit_chain()
    except (RuntimeError, ValueError, KeyError):
        return _build_checkpoint(
            receipt,
            receipt_sha256,
            job,
            reason="audit_chain_invalid",
        )

    try:
        revalidate_operation_recovery_retry_verification_receipt(
            store,
            receipt,
            execution,
            admission,
            prior_verification,
            prior_execution,
        )
    except OperationRecoveryRetryVerificationReceiptError:
        return _build_checkpoint(
            receipt,
            receipt_sha256,
            job,
            reason="verification_evidence_not_current",
        )

    try:
        journal = store.operation_recovery_retry_completion_journal(receipt.receipt_id)
    except (RuntimeError, ValueError, KeyError, TypeError):
        return _build_checkpoint(
            receipt,
            receipt_sha256,
            job,
            reason="transition_audit_not_current",
        )
    if journal is None:
        return _build_checkpoint(
            receipt,
            receipt_sha256,
            job,
            reason="transition_audit_missing",
        )

    audit_event_sha256 = _validate_completion_journal(
        job,
        receipt,
        receipt_sha256,
        journal,
    )
    if audit_event_sha256 is None:
        return _build_checkpoint(
            receipt,
            receipt_sha256,
            job,
            reason="transition_audit_not_current",
        )

    current = store.operation_job(receipt.job_id)
    if current is None or _job_completion_sha256(current) != initial_fingerprint:
        return _build_checkpoint(
            receipt,
            receipt_sha256,
            current,
            reason="completion_changed_during_reconciliation",
        )

    return _build_checkpoint(
        receipt,
        receipt_sha256,
        current,
        reason="confirmed",
        audit_event_sha256=audit_event_sha256,
    )


def _validate_inputs(
    store: OperationRecoveryRetryCompletionReconciliationStore,
    receipt: OperationRecoveryRetryVerificationReceipt,
) -> None:
    if not isinstance(receipt, OperationRecoveryRetryVerificationReceipt):
        raise TypeError(
            "receipt must be OperationRecoveryRetryVerificationReceipt"
        )
    for name in (
        "operation_job",
        "operation_recovery_retry_completion_journal",
        "verify_audit_chain",
    ):
        if not hasattr(store, name):
            raise TypeError(f"store does not provide {name}")
    value = receipt.to_dict()
    for name in (
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "grants_execution_authority",
        "production_mutation_enabled",
    ):
        if value.get(name) is not False:
            raise OperationRecoveryRetryCompletionReconciliationError(
                "unsafe_recovery_retry_verification_receipt"
            )
    if receipt.next_state not in {"rolled_back", "failed"}:
        raise OperationRecoveryRetryCompletionReconciliationError(
            "invalid_recovery_retry_completion_state"
        )
    if receipt.to_state_version != receipt.from_state_version + 1:
        raise OperationRecoveryRetryCompletionReconciliationError(
            "invalid_recovery_retry_completion_version"
        )
    if receipt.recovery_required == receipt.recovery_verified:
        raise OperationRecoveryRetryCompletionReconciliationError(
            "invalid_recovery_retry_completion_result"
        )
    expected_state = "rolled_back" if receipt.recovery_verified else "failed"
    if receipt.next_state != expected_state:
        raise OperationRecoveryRetryCompletionReconciliationError(
            "invalid_recovery_retry_completion_result"
        )


def _validate_completion_journal(
    job: dict[str, Any],
    receipt: OperationRecoveryRetryVerificationReceipt,
    receipt_sha256: str,
    journal: dict[str, Any],
) -> str | None:
    if not isinstance(journal, dict):
        return None
    expected = {
        "schema": COMPLETION_JOURNAL_SCHEMA,
        "journal_id": f"oprecoveryjournal-{receipt_sha256[:24]}",
        "receipt_id": receipt.receipt_id,
        "receipt_sha256": receipt_sha256,
        "job_id": receipt.job_id,
        "plan_id": receipt.plan_id,
        "plan_sha256": receipt.plan_sha256,
        "from_state": receipt.from_state,
        "to_state": receipt.next_state,
        "from_state_version": receipt.from_state_version,
        "to_state_version": receipt.to_state_version,
        "audit_event_id": job.get("last_audit_event_id"),
        "atomic_with_job_transition": True,
        "single_use": True,
        "contains_command_material": False,
        "accepts_caller_argv": False,
        "accepts_shell": False,
        "grants_execution_authority": False,
        "retry_authorized": False,
        "rollback_authorized": False,
        "production_mutation_enabled": False,
    }
    for name, value in expected.items():
        if journal.get(name) != value:
            return None

    audit_entry_hash = journal.get("audit_entry_hash")
    if not _is_sha256(audit_entry_hash):
        return None
    event = journal.get("audit_event")
    if not isinstance(event, dict):
        return None
    if (
        event.get("event_id") != journal.get("audit_event_id")
        or event.get("entry_hash") != audit_entry_hash
    ):
        return None
    return _validate_transition_audit(job, receipt, event)


def _validate_transition_audit(
    job: dict[str, Any],
    receipt: OperationRecoveryRetryVerificationReceipt,
    event: dict[str, Any],
) -> str | None:
    details = event.get("details")
    expected_details = {
        "job_id": receipt.job_id,
        "plan_id": receipt.plan_id,
        "request_sha256": job.get("request_sha256"),
        "plan_sha256": receipt.plan_sha256,
        "from_state": receipt.from_state,
        "to_state": receipt.next_state,
        "from_state_version": receipt.from_state_version,
        "to_state_version": receipt.to_state_version,
        "mutation_may_have_occurred": True,
        "recovery_required": receipt.recovery_required,
    }
    if details != expected_details:
        return None
    if (
        event.get("event_id") != job.get("last_audit_event_id")
        or event.get("action") != "operation.job.transition"
        or event.get("target")
        != f"{receipt.target_node_id}:{job.get('service')}"
        or event.get("outcome") != receipt.next_state
        or event.get("correlation_id") != job.get("correlation_id")
    ):
        return None
    for name in ("previous_hash", "entry_hash"):
        if not _is_sha256(event.get(name)):
            return None
    return _sha256(event)


def _job_completion_sha256(job: dict[str, Any]) -> str:
    material = {
        "job_id": job.get("job_id"),
        "action_id": job.get("action_id"),
        "state": job.get("state"),
        "state_version": job.get("state_version"),
        "plan_id": job.get("plan_id"),
        "request_sha256": job.get("request_sha256"),
        "plan_sha256": job.get("plan_sha256"),
        "target_node_id": job.get("target_node_id"),
        "service": job.get("service"),
        "correlation_id": job.get("correlation_id"),
        "result": job.get("result"),
        "evidence": job.get("evidence"),
        "recovery": job.get("recovery"),
        "mutation_may_have_occurred": job.get("mutation_may_have_occurred"),
        "recovery_required": job.get("recovery_required"),
        "last_audit_event_id": job.get("last_audit_event_id"),
    }
    return _sha256(material)


def _build_checkpoint(
    receipt: OperationRecoveryRetryVerificationReceipt,
    receipt_sha256: str,
    job: dict[str, Any] | None,
    *,
    reason: str,
    audit_event_sha256: str | None = None,
) -> OperationRecoveryRetryCompletionReconciliation:
    confirmed = reason == "confirmed"
    audit_event_id = (
        job.get("last_audit_event_id")
        if isinstance(job, dict)
        and isinstance(job.get("last_audit_event_id"), str)
        else None
    )
    observed_state = (
        job.get("state")
        if isinstance(job, dict) and isinstance(job.get("state"), str)
        else None
    )
    observed_state_version = (
        job.get("state_version")
        if isinstance(job, dict)
        and isinstance(job.get("state_version"), int)
        and not isinstance(job.get("state_version"), bool)
        else None
    )
    if not confirmed:
        audit_event_sha256 = None
    material = {
        "receipt_id": receipt.receipt_id,
        "receipt_sha256": receipt_sha256,
        "recovery_retry_execution_receipt_id": (
            receipt.recovery_retry_execution_receipt_id
        ),
        "job_id": receipt.job_id,
        "plan_id": receipt.plan_id,
        "plan_sha256": receipt.plan_sha256,
        "target_node_id": receipt.target_node_id,
        "audit_event_id": audit_event_id,
        "audit_event_sha256": audit_event_sha256,
        "observed_state": observed_state,
        "observed_state_version": observed_state_version,
        "claimed_recovery_verified": receipt.recovery_verified,
        "claimed_recovery_required": receipt.recovery_required,
        "completion_status": "confirmed" if confirmed else "reconcile",
        "reason": reason,
        "exact_completion_confirmed": confirmed,
        "reconciliation_required": not confirmed,
        "contains_command_material": False,
        "accepts_caller_argv": False,
        "accepts_shell": False,
        "grants_execution_authority": False,
        "retry_authorized": False,
        "rollback_authorized": False,
        "production_mutation_enabled": False,
    }
    digest = _sha256(material)
    return OperationRecoveryRetryCompletionReconciliation(
        checkpoint_id=f"oprecoveryreconcile-{digest[:24]}",
        receipt_id=receipt.receipt_id,
        receipt_sha256=receipt_sha256,
        recovery_retry_execution_receipt_id=(
            receipt.recovery_retry_execution_receipt_id
        ),
        job_id=receipt.job_id,
        plan_id=receipt.plan_id,
        plan_sha256=receipt.plan_sha256,
        target_node_id=receipt.target_node_id,
        audit_event_id=audit_event_id,
        audit_event_sha256=audit_event_sha256,
        observed_state=observed_state,
        observed_state_version=observed_state_version,
        claimed_recovery_verified=receipt.recovery_verified,
        claimed_recovery_required=receipt.recovery_required,
        completion_status="confirmed" if confirmed else "reconcile",
        reason=reason,
        exact_completion_confirmed=confirmed,
        reconciliation_required=not confirmed,
    )


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
