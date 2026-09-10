"""Restart-safe revalidation for immutable operation recovery terminal seals."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_recovery_retry_terminal_lineage_seal import (
    SCHEMA as TERMINAL_LINEAGE_SEAL_SCHEMA,
    OperationRecoveryRetryTerminalLineageSeal,
)
from .util import canonical_json


SCHEMA = "home-center.operation-recovery-retry-terminal-lineage-revalidation.v1"
_JOURNAL_SCHEMA = "home-center.operation-recovery-retry-completion-journal.v1"
_RECEIPT_SCHEMA = "home-center.operation-recovery-retry-verification-receipt.v1"
_UNSAFE_AUTHORITY_FIELDS = (
    "contains_command_material",
    "accepts_caller_argv",
    "accepts_shell",
    "grants_execution_authority",
    "retry_authorized",
    "rollback_authorized",
    "production_mutation_enabled",
)


class OperationRecoveryRetryTerminalLineageRevalidationError(RuntimeError):
    """A supplied terminal lineage seal is invalid or unsafe."""


class OperationRecoveryRetryTerminalLineageRevalidationStore(Protocol):
    def operation_job(self, job_id: str) -> dict[str, Any] | None: ...

    def operation_recovery_retry_completion_journal(
        self, receipt_id: str
    ) -> dict[str, Any] | None: ...


@dataclass(frozen=True, slots=True)
class OperationRecoveryRetryTerminalLineageRevalidation:
    revalidation_id: str
    seal_id: str
    seal_sha256: str
    job_id: str
    receipt_id: str
    plan_id: str
    target_node_id: str
    sealed_job_state: str
    sealed_job_state_version: int
    observed_job_state: str | None
    observed_job_state_version: int | None
    observed_job_completion_sha256: str | None
    observed_terminal_evidence_sha256: str | None
    observed_completion_journal_sha256: str | None
    observed_audit_event_sha256: str | None
    status: str
    reason: str
    exact_seal_current: bool
    fresh_decision_required: bool
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
            "revalidation_id": self.revalidation_id,
            "seal_id": self.seal_id,
            "seal_sha256": self.seal_sha256,
            "job_id": self.job_id,
            "receipt_id": self.receipt_id,
            "plan_id": self.plan_id,
            "target_node_id": self.target_node_id,
            "sealed_job_state": self.sealed_job_state,
            "sealed_job_state_version": self.sealed_job_state_version,
            "observed_job_state": self.observed_job_state,
            "observed_job_state_version": self.observed_job_state_version,
            "observed_job_completion_sha256": self.observed_job_completion_sha256,
            "observed_terminal_evidence_sha256": (
                self.observed_terminal_evidence_sha256
            ),
            "observed_completion_journal_sha256": (
                self.observed_completion_journal_sha256
            ),
            "observed_audit_event_sha256": self.observed_audit_event_sha256,
            "status": self.status,
            "reason": self.reason,
            "exact_seal_current": self.exact_seal_current,
            "fresh_decision_required": self.fresh_decision_required,
            "immutable_evidence_only": True,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "retry_authorized": False,
            "rollback_authorized": False,
            "production_mutation_enabled": False,
        }


def revalidate_operation_recovery_retry_terminal_lineage(
    store: OperationRecoveryRetryTerminalLineageRevalidationStore,
    seal: OperationRecoveryRetryTerminalLineageSeal,
) -> OperationRecoveryRetryTerminalLineageRevalidation:
    """Re-read durable terminal evidence and classify one sealed snapshot."""

    _validate_store(store)
    seal_sha256 = _validate_seal(seal)

    first_job = _safe_job_read(store, seal.job_id)
    first_journal = _safe_journal_read(store, seal.receipt_id)
    if first_job is None or first_journal is None:
        return _result(
            seal,
            seal_sha256,
            first_job,
            first_journal,
            status="ambiguous",
            reason="durable_terminal_material_unavailable",
        )

    second_job = _safe_job_read(store, seal.job_id)
    second_journal = _safe_journal_read(store, seal.receipt_id)
    if second_job is None or second_journal is None:
        return _result(
            seal,
            seal_sha256,
            first_job,
            first_journal,
            status="ambiguous",
            reason="durable_terminal_material_unavailable",
        )
    if (
        canonical_json(first_job) != canonical_json(second_job)
        or canonical_json(first_journal) != canonical_json(second_journal)
    ):
        return _result(
            seal,
            seal_sha256,
            second_job,
            second_journal,
            status="ambiguous",
            reason="durable_lineage_changed_during_revalidation",
        )

    if not _same_core_lineage(first_job, first_journal, seal):
        return _result(
            seal,
            seal_sha256,
            first_job,
            first_journal,
            status="ambiguous",
            reason="durable_lineage_identity_mismatch",
        )

    if not _journal_is_safe(first_journal):
        return _result(
            seal,
            seal_sha256,
            first_job,
            first_journal,
            status="ambiguous",
            reason="durable_terminal_material_unsafe",
        )

    job_version = first_job.get("state_version")
    if not _valid_state_version(job_version):
        return _result(
            seal,
            seal_sha256,
            first_job,
            first_journal,
            status="ambiguous",
            reason="durable_job_revision_invalid",
        )

    journal_sha256 = _sha256(_journal_material(first_journal))
    audit_event = first_journal.get("audit_event")
    audit_sha256 = _sha256(audit_event) if isinstance(audit_event, dict) else None
    old_journal_intact = (
        first_journal.get("journal_id") == seal.completion_journal_id
        and journal_sha256 == seal.completion_journal_sha256
        and first_journal.get("audit_event_id") == seal.audit_event_id
        and audit_sha256 == seal.audit_event_sha256
    )

    if job_version > seal.job_state_version:
        if old_journal_intact:
            return _result(
                seal,
                seal_sha256,
                first_job,
                first_journal,
                status="superseded",
                reason="durable_job_revision_advanced_after_seal",
            )
        return _result(
            seal,
            seal_sha256,
            first_job,
            first_journal,
            status="ambiguous",
            reason="advanced_revision_without_intact_sealed_journal",
        )

    if job_version != seal.job_state_version:
        return _result(
            seal,
            seal_sha256,
            first_job,
            first_journal,
            status="ambiguous",
            reason="durable_job_revision_regressed",
        )

    evidence = first_job.get("evidence")
    receipt = evidence.get("recovery_retry_verification_receipt") if isinstance(
        evidence, dict
    ) else None
    current = (
        first_job.get("state") == seal.job_state
        and _sha256(_job_material(first_job)) == seal.job_completion_sha256
        and isinstance(evidence, dict)
        and _sha256(evidence) == seal.terminal_evidence_sha256
        and isinstance(receipt, dict)
        and receipt.get("schema") == _RECEIPT_SCHEMA
        and receipt.get("receipt_id") == seal.receipt_id
        and _sha256(receipt) == seal.receipt_sha256
        and old_journal_intact
    )
    if current:
        return _result(
            seal,
            seal_sha256,
            first_job,
            first_journal,
            status="current",
            reason="exact_terminal_lineage_current",
        )
    return _result(
        seal,
        seal_sha256,
        first_job,
        first_journal,
        status="ambiguous",
        reason="sealed_terminal_digest_mismatch",
    )


def _validate_store(store: OperationRecoveryRetryTerminalLineageRevalidationStore) -> None:
    for name in ("operation_job", "operation_recovery_retry_completion_journal"):
        if not hasattr(store, name):
            raise TypeError(f"store does not provide {name}")


def _validate_seal(seal: OperationRecoveryRetryTerminalLineageSeal) -> str:
    if not isinstance(seal, OperationRecoveryRetryTerminalLineageSeal):
        raise TypeError("seal must be OperationRecoveryRetryTerminalLineageSeal")
    value = seal.to_dict()
    if value.get("schema") != TERMINAL_LINEAGE_SEAL_SCHEMA:
        raise OperationRecoveryRetryTerminalLineageRevalidationError(
            "terminal_seal_schema_mismatch"
        )
    for name in _UNSAFE_AUTHORITY_FIELDS:
        if getattr(seal, name, None) is not False:
            raise OperationRecoveryRetryTerminalLineageRevalidationError(
                "unsafe_terminal_seal"
            )
    if getattr(seal, "immutable_evidence_only", None) is not True:
        raise OperationRecoveryRetryTerminalLineageRevalidationError(
            "terminal_seal_not_immutable_evidence"
        )
    if not _valid_state_version(seal.job_state_version):
        raise OperationRecoveryRetryTerminalLineageRevalidationError(
            "invalid_terminal_seal_job_revision"
        )
    for digest in (
        seal.checkpoint_sha256,
        seal.receipt_sha256,
        seal.terminal_evidence_sha256,
        seal.job_completion_sha256,
        seal.completion_journal_sha256,
        seal.audit_event_sha256,
        seal.lineage_sha256,
    ):
        if not _is_sha256(digest):
            raise OperationRecoveryRetryTerminalLineageRevalidationError(
                "invalid_terminal_seal_digest"
            )

    material = _seal_lineage_material(seal)
    expected_lineage = _sha256(material)
    if (
        expected_lineage != seal.lineage_sha256
        or seal.seal_id != f"oprecoveryseal-{expected_lineage[:24]}"
    ):
        raise OperationRecoveryRetryTerminalLineageRevalidationError(
            "terminal_seal_identity_mismatch"
        )
    return _sha256(value)


def _same_core_lineage(
    job: dict[str, Any],
    journal: dict[str, Any],
    seal: OperationRecoveryRetryTerminalLineageSeal,
) -> bool:
    return (
        job.get("job_id") == seal.job_id
        and job.get("plan_id") == seal.plan_id
        and job.get("plan_sha256") == seal.plan_sha256
        and job.get("target_node_id") == seal.target_node_id
        and journal.get("schema") == _JOURNAL_SCHEMA
        and journal.get("receipt_id") == seal.receipt_id
        and journal.get("receipt_sha256") == seal.receipt_sha256
        and journal.get("job_id") == seal.job_id
        and journal.get("plan_id") == seal.plan_id
        and journal.get("plan_sha256") == seal.plan_sha256
        and journal.get("atomic_with_job_transition") is True
        and journal.get("single_use") is True
    )


def _journal_is_safe(journal: dict[str, Any]) -> bool:
    return all(journal.get(name) is False for name in _UNSAFE_AUTHORITY_FIELDS)


def _safe_job_read(
    store: OperationRecoveryRetryTerminalLineageRevalidationStore,
    job_id: str,
) -> dict[str, Any] | None:
    try:
        value = store.operation_job(job_id)
    except (RuntimeError, ValueError, KeyError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _safe_journal_read(
    store: OperationRecoveryRetryTerminalLineageRevalidationStore,
    receipt_id: str,
) -> dict[str, Any] | None:
    try:
        value = store.operation_recovery_retry_completion_journal(receipt_id)
    except (RuntimeError, ValueError, KeyError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _result(
    seal: OperationRecoveryRetryTerminalLineageSeal,
    seal_sha256: str,
    job: dict[str, Any] | None,
    journal: dict[str, Any] | None,
    *,
    status: str,
    reason: str,
) -> OperationRecoveryRetryTerminalLineageRevalidation:
    if status not in {"current", "superseded", "ambiguous"}:
        raise ValueError("invalid terminal lineage revalidation status")
    job_state = job.get("state") if isinstance(job, dict) else None
    job_version = job.get("state_version") if isinstance(job, dict) else None
    observed_job_version = job_version if _valid_state_version(job_version) else None
    evidence = job.get("evidence") if isinstance(job, dict) else None
    job_sha256 = _sha256(_job_material(job)) if isinstance(job, dict) else None
    evidence_sha256 = _sha256(evidence) if isinstance(evidence, dict) else None
    journal_sha256 = (
        _sha256(_journal_material(journal)) if isinstance(journal, dict) else None
    )
    event = journal.get("audit_event") if isinstance(journal, dict) else None
    audit_sha256 = _sha256(event) if isinstance(event, dict) else None
    material = {
        "seal_id": seal.seal_id,
        "seal_sha256": seal_sha256,
        "job_id": seal.job_id,
        "receipt_id": seal.receipt_id,
        "plan_id": seal.plan_id,
        "target_node_id": seal.target_node_id,
        "sealed_job_state": seal.job_state,
        "sealed_job_state_version": seal.job_state_version,
        "observed_job_state": job_state if isinstance(job_state, str) else None,
        "observed_job_state_version": observed_job_version,
        "observed_job_completion_sha256": job_sha256,
        "observed_terminal_evidence_sha256": evidence_sha256,
        "observed_completion_journal_sha256": journal_sha256,
        "observed_audit_event_sha256": audit_sha256,
        "status": status,
        "reason": reason,
        "exact_seal_current": status == "current",
        "fresh_decision_required": status != "current",
        "immutable_evidence_only": True,
        "contains_command_material": False,
        "accepts_caller_argv": False,
        "accepts_shell": False,
        "grants_execution_authority": False,
        "retry_authorized": False,
        "rollback_authorized": False,
        "production_mutation_enabled": False,
    }
    digest = _sha256(material)
    return OperationRecoveryRetryTerminalLineageRevalidation(
        revalidation_id=f"oprecoveryrevalidate-{digest[:24]}",
        seal_id=seal.seal_id,
        seal_sha256=seal_sha256,
        job_id=seal.job_id,
        receipt_id=seal.receipt_id,
        plan_id=seal.plan_id,
        target_node_id=seal.target_node_id,
        sealed_job_state=seal.job_state,
        sealed_job_state_version=seal.job_state_version,
        observed_job_state=material["observed_job_state"],
        observed_job_state_version=observed_job_version,
        observed_job_completion_sha256=job_sha256,
        observed_terminal_evidence_sha256=evidence_sha256,
        observed_completion_journal_sha256=journal_sha256,
        observed_audit_event_sha256=audit_sha256,
        status=status,
        reason=reason,
        exact_seal_current=status == "current",
        fresh_decision_required=status != "current",
    )


def _seal_lineage_material(
    seal: OperationRecoveryRetryTerminalLineageSeal,
) -> dict[str, Any]:
    return {
        "checkpoint_id": seal.checkpoint_id,
        "checkpoint_sha256": seal.checkpoint_sha256,
        "receipt_id": seal.receipt_id,
        "receipt_sha256": seal.receipt_sha256,
        "job_id": seal.job_id,
        "job_state": seal.job_state,
        "job_state_version": seal.job_state_version,
        "plan_id": seal.plan_id,
        "plan_sha256": seal.plan_sha256,
        "target_node_id": seal.target_node_id,
        "terminal_evidence_sha256": seal.terminal_evidence_sha256,
        "job_completion_sha256": seal.job_completion_sha256,
        "completion_journal_id": seal.completion_journal_id,
        "completion_journal_sha256": seal.completion_journal_sha256,
        "audit_event_id": seal.audit_event_id,
        "audit_event_sha256": seal.audit_event_sha256,
        "immutable_evidence_only": True,
        "contains_command_material": False,
        "accepts_caller_argv": False,
        "accepts_shell": False,
        "grants_execution_authority": False,
        "retry_authorized": False,
        "rollback_authorized": False,
        "production_mutation_enabled": False,
    }


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
    return {key: value for key, value in journal.items() if key != "created_at"}


def _valid_state_version(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


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
