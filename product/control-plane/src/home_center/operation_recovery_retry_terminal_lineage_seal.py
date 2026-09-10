"""Immutable integrity seal for a confirmed terminal recovery-retry lineage."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_recovery_retry_completion_reconciliation import (
    OperationRecoveryRetryCompletionReconciliation,
)
from .util import canonical_json


SCHEMA = "home-center.operation-recovery-retry-terminal-lineage-seal.v1"
_CHECKPOINT_SCHEMA = (
    "home-center.operation-recovery-retry-completion-reconciliation.v1"
)
_JOURNAL_SCHEMA = "home-center.operation-recovery-retry-completion-journal.v1"
_RECEIPT_SCHEMA = "home-center.operation-recovery-retry-verification-receipt.v1"
_REQUIRED_EVIDENCE_KEYS = frozenset(
    {
        "worker_claim",
        "execution_receipt",
        "verification_receipt",
        "rollback_claim",
        "rollback_execution_receipt",
        "rollback_verification_receipt",
        "recovery_retry_admission",
        "recovery_retry_claim",
        "recovery_retry_execution_receipt",
        "recovery_retry_verification_receipt",
    }
)
_UNSAFE_AUTHORITY_FIELDS = (
    "contains_command_material",
    "accepts_caller_argv",
    "accepts_shell",
    "grants_execution_authority",
    "retry_authorized",
    "rollback_authorized",
    "production_mutation_enabled",
)


class OperationRecoveryRetryTerminalLineageSealError(RuntimeError):
    """Terminal lineage could not be sealed safely."""


class OperationRecoveryRetryTerminalLineageSealStore(Protocol):
    def operation_job(self, job_id: str) -> dict[str, Any] | None: ...

    def operation_recovery_retry_completion_journal(
        self, receipt_id: str
    ) -> dict[str, Any] | None: ...


@dataclass(frozen=True, slots=True)
class OperationRecoveryRetryTerminalLineageSeal:
    seal_id: str
    checkpoint_id: str
    checkpoint_sha256: str
    receipt_id: str
    receipt_sha256: str
    job_id: str
    job_state: str
    job_state_version: int
    plan_id: str
    plan_sha256: str
    target_node_id: str
    terminal_evidence_sha256: str
    job_completion_sha256: str
    completion_journal_id: str
    completion_journal_sha256: str
    audit_event_id: str
    audit_event_sha256: str
    lineage_sha256: str
    schema: str = field(default=SCHEMA, init=False)
    immutable_evidence_only: bool = field(default=True, init=False)
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
            "seal_id": self.seal_id,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_sha256": self.checkpoint_sha256,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "job_id": self.job_id,
            "job_state": self.job_state,
            "job_state_version": self.job_state_version,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "target_node_id": self.target_node_id,
            "terminal_evidence_sha256": self.terminal_evidence_sha256,
            "job_completion_sha256": self.job_completion_sha256,
            "completion_journal_id": self.completion_journal_id,
            "completion_journal_sha256": self.completion_journal_sha256,
            "audit_event_id": self.audit_event_id,
            "audit_event_sha256": self.audit_event_sha256,
            "lineage_sha256": self.lineage_sha256,
            "immutable_evidence_only": True,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "retry_authorized": False,
            "rollback_authorized": False,
            "production_mutation_enabled": False,
        }


def seal_operation_recovery_retry_terminal_lineage(
    store: OperationRecoveryRetryTerminalLineageSealStore,
    checkpoint: OperationRecoveryRetryCompletionReconciliation,
) -> OperationRecoveryRetryTerminalLineageSeal:
    """Seal a confirmed durable terminal job/journal lineage without new authority."""

    _validate_checkpoint(store, checkpoint)
    checkpoint_value = checkpoint.to_dict()
    checkpoint_sha256 = _sha256(checkpoint_value)

    job = _read_job(store, checkpoint.job_id)
    journal = _read_journal(store, checkpoint.receipt_id)
    evidence = _validate_terminal_material(job, journal, checkpoint)

    terminal_evidence_sha256 = _sha256(evidence)
    job_completion_sha256 = _sha256(_job_material(job))
    completion_journal_sha256 = _sha256(_journal_material(journal))
    audit_event_sha256 = _sha256(journal["audit_event"])
    if audit_event_sha256 != checkpoint.audit_event_sha256:
        raise OperationRecoveryRetryTerminalLineageSealError(
            "completion_audit_digest_mismatch"
        )

    _confirm_stable_read(
        store,
        checkpoint,
        job_completion_sha256,
        completion_journal_sha256,
    )

    material = {
        "checkpoint_id": checkpoint.checkpoint_id,
        "checkpoint_sha256": checkpoint_sha256,
        "receipt_id": checkpoint.receipt_id,
        "receipt_sha256": checkpoint.receipt_sha256,
        "job_id": checkpoint.job_id,
        "job_state": job["state"],
        "job_state_version": job["state_version"],
        "plan_id": checkpoint.plan_id,
        "plan_sha256": checkpoint.plan_sha256,
        "target_node_id": checkpoint.target_node_id,
        "terminal_evidence_sha256": terminal_evidence_sha256,
        "job_completion_sha256": job_completion_sha256,
        "completion_journal_id": journal["journal_id"],
        "completion_journal_sha256": completion_journal_sha256,
        "audit_event_id": checkpoint.audit_event_id,
        "audit_event_sha256": audit_event_sha256,
        "immutable_evidence_only": True,
        "contains_command_material": False,
        "accepts_caller_argv": False,
        "accepts_shell": False,
        "grants_execution_authority": False,
        "retry_authorized": False,
        "rollback_authorized": False,
        "production_mutation_enabled": False,
    }
    lineage_sha256 = _sha256(material)
    return OperationRecoveryRetryTerminalLineageSeal(
        seal_id=f"oprecoveryseal-{lineage_sha256[:24]}",
        checkpoint_id=checkpoint.checkpoint_id,
        checkpoint_sha256=checkpoint_sha256,
        receipt_id=checkpoint.receipt_id,
        receipt_sha256=checkpoint.receipt_sha256,
        job_id=checkpoint.job_id,
        job_state=job["state"],
        job_state_version=job["state_version"],
        plan_id=checkpoint.plan_id,
        plan_sha256=checkpoint.plan_sha256,
        target_node_id=checkpoint.target_node_id,
        terminal_evidence_sha256=terminal_evidence_sha256,
        job_completion_sha256=job_completion_sha256,
        completion_journal_id=journal["journal_id"],
        completion_journal_sha256=completion_journal_sha256,
        audit_event_id=checkpoint.audit_event_id,
        audit_event_sha256=audit_event_sha256,
        lineage_sha256=lineage_sha256,
    )


def _validate_checkpoint(
    store: OperationRecoveryRetryTerminalLineageSealStore,
    checkpoint: OperationRecoveryRetryCompletionReconciliation,
) -> None:
    if not isinstance(checkpoint, OperationRecoveryRetryCompletionReconciliation):
        raise TypeError(
            "checkpoint must be OperationRecoveryRetryCompletionReconciliation"
        )
    for name in (
        "operation_job",
        "operation_recovery_retry_completion_journal",
    ):
        if not hasattr(store, name):
            raise TypeError(f"store does not provide {name}")
    value = checkpoint.to_dict()
    if value.get("schema") != _CHECKPOINT_SCHEMA:
        raise OperationRecoveryRetryTerminalLineageSealError("checkpoint_schema_mismatch")
    if (
        checkpoint.completion_status != "confirmed"
        or checkpoint.reason != "confirmed"
        or checkpoint.exact_completion_confirmed is not True
        or checkpoint.reconciliation_required is not False
    ):
        raise OperationRecoveryRetryTerminalLineageSealError(
            "terminal_completion_not_confirmed"
        )
    if not _is_sha256(checkpoint.receipt_sha256):
        raise OperationRecoveryRetryTerminalLineageSealError("invalid_receipt_digest")
    if not isinstance(checkpoint.audit_event_id, str) or not checkpoint.audit_event_id:
        raise OperationRecoveryRetryTerminalLineageSealError("missing_audit_event")
    if not _is_sha256(checkpoint.audit_event_sha256):
        raise OperationRecoveryRetryTerminalLineageSealError("invalid_audit_digest")
    for name in _UNSAFE_AUTHORITY_FIELDS:
        if value.get(name) is not False:
            raise OperationRecoveryRetryTerminalLineageSealError(
                "unsafe_completion_checkpoint"
            )


def _read_job(
    store: OperationRecoveryRetryTerminalLineageSealStore,
    job_id: str,
) -> dict[str, Any]:
    try:
        job = store.operation_job(job_id)
    except (RuntimeError, ValueError, KeyError, TypeError) as exc:
        raise OperationRecoveryRetryTerminalLineageSealError(
            "terminal_job_unavailable"
        ) from exc
    if not isinstance(job, dict):
        raise OperationRecoveryRetryTerminalLineageSealError("terminal_job_missing")
    return job


def _read_journal(
    store: OperationRecoveryRetryTerminalLineageSealStore,
    receipt_id: str,
) -> dict[str, Any]:
    try:
        journal = store.operation_recovery_retry_completion_journal(receipt_id)
    except (RuntimeError, ValueError, KeyError, TypeError) as exc:
        raise OperationRecoveryRetryTerminalLineageSealError(
            "completion_journal_unavailable"
        ) from exc
    if not isinstance(journal, dict):
        raise OperationRecoveryRetryTerminalLineageSealError(
            "completion_journal_missing"
        )
    return journal


def _validate_terminal_material(
    job: dict[str, Any],
    journal: dict[str, Any],
    checkpoint: OperationRecoveryRetryCompletionReconciliation,
) -> dict[str, Any]:
    if (
        job.get("job_id") != checkpoint.job_id
        or job.get("state") != checkpoint.observed_state
        or job.get("state") not in {"rolled_back", "failed"}
        or job.get("state_version") != checkpoint.observed_state_version
        or not isinstance(job.get("state_version"), int)
        or isinstance(job.get("state_version"), bool)
        or job.get("plan_id") != checkpoint.plan_id
        or job.get("plan_sha256") != checkpoint.plan_sha256
        or job.get("target_node_id") != checkpoint.target_node_id
        or job.get("last_audit_event_id") != checkpoint.audit_event_id
    ):
        raise OperationRecoveryRetryTerminalLineageSealError(
            "terminal_job_lineage_mismatch"
        )

    evidence = job.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != _REQUIRED_EVIDENCE_KEYS:
        raise OperationRecoveryRetryTerminalLineageSealError(
            "terminal_evidence_shape_mismatch"
        )
    receipt = evidence.get("recovery_retry_verification_receipt")
    if not isinstance(receipt, dict):
        raise OperationRecoveryRetryTerminalLineageSealError(
            "terminal_receipt_missing"
        )
    if (
        receipt.get("schema") != _RECEIPT_SCHEMA
        or receipt.get("receipt_id") != checkpoint.receipt_id
        or _sha256(receipt) != checkpoint.receipt_sha256
    ):
        raise OperationRecoveryRetryTerminalLineageSealError(
            "terminal_receipt_digest_mismatch"
        )
    for name in (
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "grants_execution_authority",
        "production_mutation_enabled",
    ):
        if receipt.get(name) is not False:
            raise OperationRecoveryRetryTerminalLineageSealError(
                "unsafe_terminal_receipt"
            )

    expected_journal = {
        "schema": _JOURNAL_SCHEMA,
        "receipt_id": checkpoint.receipt_id,
        "receipt_sha256": checkpoint.receipt_sha256,
        "job_id": checkpoint.job_id,
        "plan_id": checkpoint.plan_id,
        "plan_sha256": checkpoint.plan_sha256,
        "to_state": job["state"],
        "to_state_version": job["state_version"],
        "audit_event_id": checkpoint.audit_event_id,
        "atomic_with_job_transition": True,
        "single_use": True,
    }
    for name, expected in expected_journal.items():
        if journal.get(name) != expected:
            raise OperationRecoveryRetryTerminalLineageSealError(
                "completion_journal_lineage_mismatch"
            )
    for name in _UNSAFE_AUTHORITY_FIELDS:
        if journal.get(name) is not False:
            raise OperationRecoveryRetryTerminalLineageSealError(
                "unsafe_completion_journal"
            )
    if not isinstance(journal.get("journal_id"), str) or not journal["journal_id"]:
        raise OperationRecoveryRetryTerminalLineageSealError("invalid_journal_id")
    event = journal.get("audit_event")
    if not isinstance(event, dict):
        raise OperationRecoveryRetryTerminalLineageSealError("missing_audit_event")
    if (
        event.get("event_id") != checkpoint.audit_event_id
        or event.get("entry_hash") != journal.get("audit_entry_hash")
    ):
        raise OperationRecoveryRetryTerminalLineageSealError(
            "completion_audit_binding_mismatch"
        )
    return evidence


def _confirm_stable_read(
    store: OperationRecoveryRetryTerminalLineageSealStore,
    checkpoint: OperationRecoveryRetryCompletionReconciliation,
    job_sha256: str,
    journal_sha256: str,
) -> None:
    current_job = _read_job(store, checkpoint.job_id)
    current_journal = _read_journal(store, checkpoint.receipt_id)
    if (
        _sha256(_job_material(current_job)) != job_sha256
        or _sha256(_journal_material(current_journal)) != journal_sha256
    ):
        raise OperationRecoveryRetryTerminalLineageSealError(
            "terminal_lineage_changed_during_seal"
        )


def _job_material(job: dict[str, Any]) -> dict[str, Any]:
    return {
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


def _journal_material(journal: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in journal.items()
        if key != "created_at"
    }


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
