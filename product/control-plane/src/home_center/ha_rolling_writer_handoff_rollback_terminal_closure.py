"""Seal terminal rollback-readmission reconciliation for operator-controlled closure."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace

from .ha_rolling_writer_handoff_rollback_readmission_reconciliation import (
    RollingWriterHandoffRollbackReadmissionReconciliationReceipt,
    revalidate_writer_handoff_rollback_readmission_reconciliation_receipt,
)
from .ha_rolling_writer_handoff_rollback_reconciliation import RollbackCommitOutcome


class HARollingWriterHandoffRollbackTerminalClosureError(ValueError):
    """Stable fail-closed error for terminal recovery closure evidence."""


_OPERATOR_DECISION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffRollbackTerminalClosureReceipt:
    cluster_id: str
    closure_id: str
    closure_replay_key: str
    closure_journal_entry_id: str
    source_terminal_reconciliation_receipt_id: str
    readmission_id: str
    prior_admission_id: str
    candidate_admission_id: str
    observed_reconciliation_receipt_id: str
    outcome: RollbackCommitOutcome
    reason: str
    operator_decision_id: str
    recovery_generation: int = 1
    maximum_recovery_generation: int = 1
    terminal_generation: bool = True
    operator_recovery_closed: bool = True
    single_use_by_source_receipt: bool = True
    requires_new_recovery_lineage: bool = True
    new_peer_snapshot_required: bool = True
    new_fencing_evidence_required: bool = True
    new_recovery_assessment_required: bool = True
    previous_readmission_reusable: bool = False
    previous_admission_reusable: bool = False
    current_lineage_recovery_authorized: bool = False
    fresh_admission_authorized: bool = False
    further_readmission_authorized: bool = False
    automatic_retry_authorized: bool = False
    execution_authorized: bool = False
    failover_authorized: bool = False
    writer_service_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-writer-handoff-rollback-terminal-closure.v1"

    def to_dict(self) -> dict[str, object]:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["outcome"] = self.outcome.value
        return result


def _stable_id(prefix: str, material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(
            material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return f"{prefix}-{digest}"


def _material(
    value: RollingWriterHandoffRollbackTerminalClosureReceipt,
) -> dict[str, object]:
    material = value.to_dict()
    material.pop("closure_id")
    return material


def _verify_operator_decision_id(operator_decision_id: str) -> None:
    if not _OPERATOR_DECISION_ID.fullmatch(operator_decision_id):
        raise HARollingWriterHandoffRollbackTerminalClosureError(
            "rollback_terminal_closure_operator_decision_id_invalid"
        )


def _verify_closure(
    value: RollingWriterHandoffRollbackTerminalClosureReceipt,
) -> None:
    if (
        value.schema
        != "home-center.ha-rolling-writer-handoff-rollback-terminal-closure.v1"
        or value.recovery_generation != 1
        or value.maximum_recovery_generation != 1
        or not value.terminal_generation
        or not value.operator_recovery_closed
        or not value.single_use_by_source_receipt
        or not value.requires_new_recovery_lineage
        or not value.new_peer_snapshot_required
        or not value.new_fencing_evidence_required
        or not value.new_recovery_assessment_required
        or value.previous_readmission_reusable
        or value.previous_admission_reusable
        or value.current_lineage_recovery_authorized
        or value.fresh_admission_authorized
        or value.further_readmission_authorized
        or value.automatic_retry_authorized
        or value.execution_authorized
        or value.failover_authorized
        or value.writer_service_authorized
        or value.host_mutation_authorized
        or value.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackTerminalClosureError(
            "rollback_terminal_closure_authority_invalid"
        )
    if value.outcome is RollbackCommitOutcome.COMMITTED:
        raise HARollingWriterHandoffRollbackTerminalClosureError(
            "rollback_terminal_closure_outcome_invalid"
        )
    _verify_operator_decision_id(value.operator_decision_id)
    replay_key = _stable_id(
        "ha-roll-writer-handoff-rollback-terminal-closure-replay",
        {
            "schema": value.schema,
            "cluster_id": value.cluster_id,
            "source_terminal_reconciliation_receipt_id": (
                value.source_terminal_reconciliation_receipt_id
            ),
        },
    )
    if value.closure_replay_key != replay_key:
        raise HARollingWriterHandoffRollbackTerminalClosureError(
            "rollback_terminal_closure_replay_key_invalid"
        )
    expected_journal_entry_id = _stable_id(
        "ha-roll-writer-handoff-rollback-terminal-closure-journal",
        {
            "schema": value.schema,
            "cluster_id": value.cluster_id,
            "closure_replay_key": value.closure_replay_key,
            "source_terminal_reconciliation_receipt_id": (
                value.source_terminal_reconciliation_receipt_id
            ),
            "operator_decision_id": value.operator_decision_id,
            "outcome": value.outcome.value,
            "reason": value.reason,
        },
    )
    if value.closure_journal_entry_id != expected_journal_entry_id:
        raise HARollingWriterHandoffRollbackTerminalClosureError(
            "rollback_terminal_closure_journal_identity_invalid"
        )
    expected_closure_id = _stable_id(
        "ha-roll-writer-handoff-rollback-terminal-closure",
        _material(value),
    )
    if value.closure_id != expected_closure_id:
        raise HARollingWriterHandoffRollbackTerminalClosureError(
            "rollback_terminal_closure_identity_invalid"
        )


def close_terminal_rollback_readmission_reconciliation(
    *,
    receipt: RollingWriterHandoffRollbackReadmissionReconciliationReceipt,
    operator_decision_id: str,
) -> RollingWriterHandoffRollbackTerminalClosureReceipt:
    """Close a terminal non-committed lineage without minting recovery authority."""

    _verify_operator_decision_id(operator_decision_id)
    try:
        source = revalidate_writer_handoff_rollback_readmission_reconciliation_receipt(
            receipt=receipt
        )
    except ValueError as exc:
        raise HARollingWriterHandoffRollbackTerminalClosureError(
            "rollback_terminal_closure_source_invalid"
        ) from exc
    if (
        source.outcome is RollbackCommitOutcome.COMMITTED
        or not source.operator_recovery_closure_required
        or source.terminal_consumption_recovered
    ):
        raise HARollingWriterHandoffRollbackTerminalClosureError(
            "rollback_terminal_closure_source_not_closable"
        )

    replay_key = _stable_id(
        "ha-roll-writer-handoff-rollback-terminal-closure-replay",
        {
            "schema": "home-center.ha-rolling-writer-handoff-rollback-terminal-closure.v1",
            "cluster_id": source.cluster_id,
            "source_terminal_reconciliation_receipt_id": source.receipt_id,
        },
    )
    journal_entry_id = _stable_id(
        "ha-roll-writer-handoff-rollback-terminal-closure-journal",
        {
            "schema": "home-center.ha-rolling-writer-handoff-rollback-terminal-closure.v1",
            "cluster_id": source.cluster_id,
            "closure_replay_key": replay_key,
            "source_terminal_reconciliation_receipt_id": source.receipt_id,
            "operator_decision_id": operator_decision_id,
            "outcome": source.outcome.value,
            "reason": source.reason,
        },
    )
    provisional = RollingWriterHandoffRollbackTerminalClosureReceipt(
        cluster_id=source.cluster_id,
        closure_id="pending",
        closure_replay_key=replay_key,
        closure_journal_entry_id=journal_entry_id,
        source_terminal_reconciliation_receipt_id=source.receipt_id,
        readmission_id=source.readmission_id,
        prior_admission_id=source.prior_admission_id,
        candidate_admission_id=source.candidate_admission_id,
        observed_reconciliation_receipt_id=(
            source.observed_reconciliation_receipt_id
        ),
        outcome=source.outcome,
        reason=source.reason,
        operator_decision_id=operator_decision_id,
    )
    result = replace(
        provisional,
        closure_id=_stable_id(
            "ha-roll-writer-handoff-rollback-terminal-closure",
            _material(provisional),
        ),
    )
    _verify_closure(result)
    return result


def revalidate_writer_handoff_rollback_terminal_closure_receipt(
    *,
    receipt: RollingWriterHandoffRollbackTerminalClosureReceipt,
) -> RollingWriterHandoffRollbackTerminalClosureReceipt:
    """Validate durable closure evidence without re-opening its recovery lineage."""

    _verify_closure(receipt)
    return receipt
