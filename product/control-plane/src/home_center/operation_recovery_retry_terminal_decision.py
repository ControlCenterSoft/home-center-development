"""Typed decision boundary for revalidated terminal operation recovery evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .operation_recovery_retry_terminal_lineage_revalidation import (
    SCHEMA as TERMINAL_REVALIDATION_SCHEMA,
    OperationRecoveryRetryTerminalLineageRevalidation,
)
from .util import canonical_json


SCHEMA = "home-center.operation-recovery-retry-terminal-decision.v1"
_UNSAFE_AUTHORITY_FIELDS = (
    "contains_command_material",
    "accepts_caller_argv",
    "accepts_shell",
    "grants_execution_authority",
    "retry_authorized",
    "rollback_authorized",
    "production_mutation_enabled",
)
_AMBIGUOUS_REASONS = frozenset(
    {
        "durable_terminal_material_unavailable",
        "durable_lineage_changed_during_revalidation",
        "durable_lineage_identity_mismatch",
        "durable_terminal_material_unsafe",
        "durable_job_revision_invalid",
        "advanced_revision_without_intact_sealed_journal",
        "durable_job_revision_regressed",
        "sealed_terminal_digest_mismatch",
    }
)


class OperationRecoveryRetryTerminalDecisionError(RuntimeError):
    """A terminal revalidation cannot safely cross the decision boundary."""


@dataclass(frozen=True, slots=True)
class OperationRecoveryRetryTerminalDecision:
    decision_id: str
    revalidation_id: str
    revalidation_sha256: str
    seal_id: str
    job_id: str
    receipt_id: str
    plan_id: str
    target_node_id: str
    revalidation_status: str
    operator_action: str
    reason: str
    terminal_closure_eligible: bool
    fresh_reconciliation_required: bool
    new_lineage_required: bool
    schema: str = field(default=SCHEMA, init=False)
    immutable_evidence_only: bool = field(default=True, init=False)
    previous_lineage_reusable: bool = field(default=False, init=False)
    fresh_admission_authorized: bool = field(default=False, init=False)
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
            "decision_id": self.decision_id,
            "revalidation_id": self.revalidation_id,
            "revalidation_sha256": self.revalidation_sha256,
            "seal_id": self.seal_id,
            "job_id": self.job_id,
            "receipt_id": self.receipt_id,
            "plan_id": self.plan_id,
            "target_node_id": self.target_node_id,
            "revalidation_status": self.revalidation_status,
            "operator_action": self.operator_action,
            "reason": self.reason,
            "terminal_closure_eligible": self.terminal_closure_eligible,
            "fresh_reconciliation_required": self.fresh_reconciliation_required,
            "new_lineage_required": self.new_lineage_required,
            "immutable_evidence_only": True,
            "previous_lineage_reusable": False,
            "fresh_admission_authorized": False,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "retry_authorized": False,
            "rollback_authorized": False,
            "production_mutation_enabled": False,
        }


def decide_operation_recovery_retry_terminal_boundary(
    revalidation: OperationRecoveryRetryTerminalLineageRevalidation,
) -> OperationRecoveryRetryTerminalDecision:
    """Translate exact revalidation evidence into one non-executable operator decision."""

    revalidation_sha256 = _validate_revalidation(revalidation)

    if revalidation.status == "current":
        operator_action = "acknowledge_terminal_closure"
        reason = "current_terminal_lineage_may_be_acknowledged"
        terminal_closure_eligible = True
        fresh_reconciliation_required = False
        new_lineage_required = False
    else:
        operator_action = "start_fresh_operator_reconciliation"
        reason = (
            f"{revalidation.status}_terminal_lineage_requires_fresh_reconciliation"
        )
        terminal_closure_eligible = False
        fresh_reconciliation_required = True
        new_lineage_required = True

    material = {
        "revalidation_id": revalidation.revalidation_id,
        "revalidation_sha256": revalidation_sha256,
        "seal_id": revalidation.seal_id,
        "job_id": revalidation.job_id,
        "receipt_id": revalidation.receipt_id,
        "plan_id": revalidation.plan_id,
        "target_node_id": revalidation.target_node_id,
        "revalidation_status": revalidation.status,
        "operator_action": operator_action,
        "reason": reason,
        "terminal_closure_eligible": terminal_closure_eligible,
        "fresh_reconciliation_required": fresh_reconciliation_required,
        "new_lineage_required": new_lineage_required,
        "immutable_evidence_only": True,
        "previous_lineage_reusable": False,
        "fresh_admission_authorized": False,
        "contains_command_material": False,
        "accepts_caller_argv": False,
        "accepts_shell": False,
        "grants_execution_authority": False,
        "retry_authorized": False,
        "rollback_authorized": False,
        "production_mutation_enabled": False,
    }
    digest = _sha256(material)
    return OperationRecoveryRetryTerminalDecision(
        decision_id=f"oprecoverydecision-{digest[:24]}",
        revalidation_id=revalidation.revalidation_id,
        revalidation_sha256=revalidation_sha256,
        seal_id=revalidation.seal_id,
        job_id=revalidation.job_id,
        receipt_id=revalidation.receipt_id,
        plan_id=revalidation.plan_id,
        target_node_id=revalidation.target_node_id,
        revalidation_status=revalidation.status,
        operator_action=operator_action,
        reason=reason,
        terminal_closure_eligible=terminal_closure_eligible,
        fresh_reconciliation_required=fresh_reconciliation_required,
        new_lineage_required=new_lineage_required,
    )


def _validate_revalidation(
    revalidation: OperationRecoveryRetryTerminalLineageRevalidation,
) -> str:
    if not isinstance(
        revalidation,
        OperationRecoveryRetryTerminalLineageRevalidation,
    ):
        raise TypeError(
            "revalidation must be OperationRecoveryRetryTerminalLineageRevalidation"
        )
    if getattr(revalidation, "schema", None) != TERMINAL_REVALIDATION_SCHEMA:
        raise OperationRecoveryRetryTerminalDecisionError(
            "terminal_revalidation_schema_mismatch"
        )
    if getattr(revalidation, "immutable_evidence_only", None) is not True:
        raise OperationRecoveryRetryTerminalDecisionError(
            "terminal_revalidation_not_immutable_evidence"
        )
    for name in _UNSAFE_AUTHORITY_FIELDS:
        if getattr(revalidation, name, None) is not False:
            raise OperationRecoveryRetryTerminalDecisionError(
                "unsafe_terminal_revalidation"
            )

    if revalidation.status == "current":
        if (
            revalidation.reason != "exact_terminal_lineage_current"
            or revalidation.exact_seal_current is not True
            or revalidation.fresh_decision_required is not False
        ):
            raise OperationRecoveryRetryTerminalDecisionError(
                "current_terminal_revalidation_inconsistent"
            )
    elif revalidation.status == "superseded":
        if (
            revalidation.reason != "durable_job_revision_advanced_after_seal"
            or revalidation.exact_seal_current is not False
            or revalidation.fresh_decision_required is not True
        ):
            raise OperationRecoveryRetryTerminalDecisionError(
                "superseded_terminal_revalidation_inconsistent"
            )
    elif revalidation.status == "ambiguous":
        if (
            revalidation.reason not in _AMBIGUOUS_REASONS
            or revalidation.exact_seal_current is not False
            or revalidation.fresh_decision_required is not True
        ):
            raise OperationRecoveryRetryTerminalDecisionError(
                "ambiguous_terminal_revalidation_inconsistent"
            )
    else:
        raise OperationRecoveryRetryTerminalDecisionError(
            "unsupported_terminal_revalidation_status"
        )

    if not _valid_state_version(revalidation.sealed_job_state_version):
        raise OperationRecoveryRetryTerminalDecisionError(
            "invalid_terminal_revalidation_revision"
        )
    observed_version = revalidation.observed_job_state_version
    if observed_version is not None and not _valid_state_version(observed_version):
        raise OperationRecoveryRetryTerminalDecisionError(
            "invalid_observed_terminal_revision"
        )
    _validate_observed_revision_semantics(revalidation, observed_version)
    for digest in (
        revalidation.seal_sha256,
        revalidation.observed_job_completion_sha256,
        revalidation.observed_terminal_evidence_sha256,
        revalidation.observed_completion_journal_sha256,
        revalidation.observed_audit_event_sha256,
    ):
        if digest is not None and not _is_sha256(digest):
            raise OperationRecoveryRetryTerminalDecisionError(
                "invalid_terminal_revalidation_digest"
            )

    material = _revalidation_identity_material(revalidation)
    expected_digest = _sha256(material)
    expected_id = f"oprecoveryrevalidate-{expected_digest[:24]}"
    if revalidation.revalidation_id != expected_id:
        raise OperationRecoveryRetryTerminalDecisionError(
            "terminal_revalidation_identity_mismatch"
        )
    return _sha256(revalidation.to_dict())


def _validate_observed_revision_semantics(
    revalidation: OperationRecoveryRetryTerminalLineageRevalidation,
    observed_version: int | None,
) -> None:
    sealed_version = revalidation.sealed_job_state_version
    if revalidation.status == "current":
        if (
            observed_version != sealed_version
            or revalidation.observed_job_state != revalidation.sealed_job_state
        ):
            raise OperationRecoveryRetryTerminalDecisionError(
                "current_terminal_revalidation_observation_mismatch"
            )
        observed_digests = (
            revalidation.observed_job_completion_sha256,
            revalidation.observed_terminal_evidence_sha256,
            revalidation.observed_completion_journal_sha256,
            revalidation.observed_audit_event_sha256,
        )
        if any(digest is None for digest in observed_digests):
            raise OperationRecoveryRetryTerminalDecisionError(
                "current_terminal_revalidation_evidence_incomplete"
            )
        return

    if revalidation.status == "superseded":
        if observed_version is None or observed_version <= sealed_version:
            raise OperationRecoveryRetryTerminalDecisionError(
                "superseded_terminal_revalidation_observation_mismatch"
            )
        return

    reason = revalidation.reason
    if (
        reason == "sealed_terminal_digest_mismatch"
        and observed_version != sealed_version
    ):
        raise OperationRecoveryRetryTerminalDecisionError(
            "ambiguous_terminal_revalidation_observation_mismatch"
        )
    if (
        reason == "advanced_revision_without_intact_sealed_journal"
        and (observed_version is None or observed_version <= sealed_version)
    ):
        raise OperationRecoveryRetryTerminalDecisionError(
            "ambiguous_terminal_revalidation_observation_mismatch"
        )
    if reason == "durable_job_revision_regressed" and (
        observed_version is None or observed_version >= sealed_version
    ):
        raise OperationRecoveryRetryTerminalDecisionError(
            "ambiguous_terminal_revalidation_observation_mismatch"
        )
    if reason == "durable_job_revision_invalid" and observed_version is not None:
        raise OperationRecoveryRetryTerminalDecisionError(
            "ambiguous_terminal_revalidation_observation_mismatch"
        )


def _revalidation_identity_material(
    revalidation: OperationRecoveryRetryTerminalLineageRevalidation,
) -> dict[str, Any]:
    return {
        "seal_id": revalidation.seal_id,
        "seal_sha256": revalidation.seal_sha256,
        "job_id": revalidation.job_id,
        "receipt_id": revalidation.receipt_id,
        "plan_id": revalidation.plan_id,
        "target_node_id": revalidation.target_node_id,
        "sealed_job_state": revalidation.sealed_job_state,
        "sealed_job_state_version": revalidation.sealed_job_state_version,
        "observed_job_state": revalidation.observed_job_state,
        "observed_job_state_version": revalidation.observed_job_state_version,
        "observed_job_completion_sha256": (
            revalidation.observed_job_completion_sha256
        ),
        "observed_terminal_evidence_sha256": (
            revalidation.observed_terminal_evidence_sha256
        ),
        "observed_completion_journal_sha256": (
            revalidation.observed_completion_journal_sha256
        ),
        "observed_audit_event_sha256": revalidation.observed_audit_event_sha256,
        "status": revalidation.status,
        "reason": revalidation.reason,
        "exact_seal_current": revalidation.exact_seal_current,
        "fresh_decision_required": revalidation.fresh_decision_required,
        "immutable_evidence_only": True,
        "contains_command_material": False,
        "accepts_caller_argv": False,
        "accepts_shell": False,
        "grants_execution_authority": False,
        "retry_authorized": False,
        "rollback_authorized": False,
        "production_mutation_enabled": False,
    }


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value)


def _valid_state_version(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1
