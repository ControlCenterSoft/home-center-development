"""Reconcile uncertain rolling-writer rollback commits from authoritative HA evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol

from .ha_role_journal import HARoleAuthorityState, HARoleJournalEntry, HARoleJournalError
from .ha_rolling_authority import (
    HARoleAssignment,
    HARoleCoordinationError,
    build_role_assignment_snapshot,
)
from .ha_rolling_safety import NodeRole
from .ha_rolling_writer_handoff_rollback_admission import (
    RollingWriterHandoffRollbackAdmission,
)


class HARollingWriterHandoffRollbackReconciliationError(ValueError):
    """Stable fail-closed error for rollback commit reconciliation."""


class RollbackCommitOutcome(StrEnum):
    COMMITTED = "committed"
    DEFINITELY_NOT_APPLIED = "definitely-not-applied"
    SUPERSEDED = "superseded"
    AMBIGUOUS = "ambiguous"


class HARollbackReconciliationAuthority(Protocol):
    def state_for(
        self, *, cluster_id: str, node_ids: tuple[str, ...]
    ) -> HARoleAuthorityState: ...

    def journal_entries(
        self, *, cluster_id: str, limit: int = 32
    ) -> tuple[HARoleJournalEntry, ...]: ...


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffRollbackReconciliationReceipt:
    cluster_id: str
    receipt_id: str
    admission_id: str
    member_node_ids: tuple[str, ...]
    rollback_writer_node_id: str
    fenced_successor_node_id: str
    expected_role_assignment_id: str
    expected_role_epoch: int
    expected_role_resource_version: int
    expected_role_journal_seq: int
    expected_role_transition_id: str
    target_role_assignment_id: str
    target_role_epoch: int
    expected_rollback_transition_id: str
    observed_role_assignment_id: str | None
    observed_role_epoch: int | None
    observed_role_resource_version: int | None
    observed_role_journal_seq: int | None
    observed_role_transition_id: str | None
    observed_role_transition_kind: str | None
    observed_writer_node_ids: tuple[str, ...]
    rollback_transition_observed: bool
    outcome: RollbackCommitOutcome
    reason: str
    rollback_completed: bool
    fresh_admission_required: bool
    operator_reconciliation_required: bool
    fresh_admission_authorized: bool = False
    automatic_retry_authorized: bool = False
    execution_authorized: bool = False
    failover_authorized: bool = False
    writer_service_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = (
        "home-center.ha-rolling-writer-handoff-rollback-reconciliation-receipt.v1"
    )

    def to_dict(self) -> dict[str, object]:
        result = {field: getattr(self, field) for field in self.__dataclass_fields__}
        result["member_node_ids"] = list(self.member_node_ids)
        result["observed_writer_node_ids"] = list(self.observed_writer_node_ids)
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


def _material(value, id_field: str) -> dict[str, object]:
    material = value.to_dict()
    material.pop(id_field)
    return material


def _target_snapshot(admission: RollingWriterHandoffRollbackAdmission):
    assignments = tuple(
        HARoleAssignment(
            node_id,
            NodeRole.WRITER
            if node_id == admission.rollback_writer_node_id
            else NodeRole.STANDBY,
        )
        for node_id in admission.member_node_ids
    )
    return build_role_assignment_snapshot(
        cluster_id=admission.cluster_id,
        role_epoch=admission.target_role_epoch,
        assignments=assignments,
    )


def _expected_transition_id(admission: RollingWriterHandoffRollbackAdmission) -> str:
    return _stable_id(
        "ha-role-transition",
        {
            "schema": "home-center.ha-role-transition.v1",
            "cluster_id": admission.cluster_id,
            "kind": "rollback",
            "previous_assignment_id": admission.expected_role_assignment_id,
            "assignment_id": admission.target_role_assignment_id,
            "role_epoch": admission.target_role_epoch,
            "resource_version": admission.expected_role_resource_version + 1,
            "journal_seq": admission.expected_role_journal_seq + 1,
        },
    )


def _verify_admission(admission: RollingWriterHandoffRollbackAdmission) -> str:
    if admission.schema != "home-center.ha-rolling-writer-handoff-rollback-admission.v1":
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_admission_schema_invalid"
        )
    if (
        not admission.cas_bound
        or not admission.single_use_by_cas
        or not admission.rollback_transition_admitted
        or admission.execution_authorized
        or admission.failover_authorized
        or admission.host_mutation_authorized
        or admission.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_admission_authority_invalid"
        )
    members = admission.member_node_ids
    if (
        len(members) < 2
        or members != tuple(sorted(members))
        or len(members) != len(set(members))
        or admission.rollback_writer_node_id not in members
        or admission.fenced_successor_node_id not in members
        or admission.rollback_writer_node_id == admission.fenced_successor_node_id
    ):
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_membership_invalid"
        )
    quorum = len(members) // 2 + 1
    if (
        admission.required_quorum_nodes != quorum
        or admission.ready_count != len(admission.ready_node_ids)
        or admission.ready_count < quorum
        or admission.ready_count < admission.minimum_ready_nodes
        or admission.rollback_writer_node_id not in admission.ready_node_ids
        or admission.fenced_successor_node_id in admission.ready_node_ids
    ):
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_ready_evidence_invalid"
        )
    if (
        admission.target_role_epoch != admission.expected_role_epoch + 1
        or admission.lease_revoked_for_role_transition_id
        != admission.expected_role_transition_id
    ):
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_revision_binding_invalid"
        )
    try:
        target = _target_snapshot(admission)
    except HARoleCoordinationError as exc:
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_target_identity_invalid"
        ) from exc
    if target.assignment_id != admission.target_role_assignment_id:
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_target_identity_invalid"
        )
    expected = _stable_id(
        "ha-roll-writer-handoff-rollback-admission",
        _material(admission, "admission_id"),
    )
    if admission.admission_id != expected:
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_admission_identity_invalid"
        )
    return _expected_transition_id(admission)


def _validate_state(
    state: HARoleAuthorityState,
    admission: RollingWriterHandoffRollbackAdmission,
) -> tuple[str, ...]:
    if state.production_mutation_enabled:
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_role_authority_unsafe"
        )
    canonical = build_role_assignment_snapshot(
        cluster_id=state.snapshot.cluster_id,
        role_epoch=state.snapshot.role_epoch,
        assignments=state.snapshot.assignments,
    )
    members = tuple(item.node_id for item in state.snapshot.assignments)
    if canonical.assignment_id != state.snapshot.assignment_id:
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_role_identity_invalid"
        )
    if state.snapshot.cluster_id != admission.cluster_id or members != admission.member_node_ids:
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_role_membership_invalid"
        )
    return tuple(
        item.node_id
        for item in state.snapshot.assignments
        if item.role is NodeRole.WRITER
    )


def _journal_matches_state(entry: HARoleJournalEntry, state: HARoleAuthorityState) -> bool:
    return (
        entry.cluster_id == state.snapshot.cluster_id
        and entry.journal_seq == state.journal_seq
        and entry.role_epoch == state.snapshot.role_epoch
        and entry.resource_version == state.resource_version
        and entry.transition_id == state.transition_id
        and entry.transition_kind == state.transition_kind
        and entry.assignment_id == state.snapshot.assignment_id
    )


def _expected_rollback_observed(
    entries: tuple[HARoleJournalEntry, ...],
    admission: RollingWriterHandoffRollbackAdmission,
    expected_transition_id: str,
) -> bool:
    expected_seq = admission.expected_role_journal_seq + 1
    for entry in entries:
        if entry.journal_seq != expected_seq:
            continue
        return (
            entry.cluster_id == admission.cluster_id
            and entry.role_epoch == admission.target_role_epoch
            and entry.resource_version == admission.expected_role_resource_version + 1
            and entry.transition_id == expected_transition_id
            and entry.transition_kind == "rollback"
            and entry.previous_assignment_id == admission.expected_role_assignment_id
            and entry.assignment_id == admission.target_role_assignment_id
        )
    return False


def _classify(
    state: HARoleAuthorityState,
    admission: RollingWriterHandoffRollbackAdmission,
    entries: tuple[HARoleJournalEntry, ...],
    expected_transition_id: str,
) -> tuple[RollbackCommitOutcome, str, bool]:
    current = next(
        (entry for entry in entries if entry.journal_seq == state.journal_seq),
        None,
    )
    if current is None or not _journal_matches_state(current, state):
        return RollbackCommitOutcome.AMBIGUOUS, "current_role_journal_evidence_missing", False
    rollback_seen = _expected_rollback_observed(entries, admission, expected_transition_id)
    precommit = (
        state.snapshot.assignment_id == admission.expected_role_assignment_id
        and state.snapshot.role_epoch == admission.expected_role_epoch
        and state.resource_version == admission.expected_role_resource_version
        and state.journal_seq == admission.expected_role_journal_seq
        and state.transition_id == admission.expected_role_transition_id
    )
    if precommit:
        return (
            RollbackCommitOutcome.DEFINITELY_NOT_APPLIED,
            "exact_precommit_revision_current",
            rollback_seen,
        )
    target = (
        state.snapshot.assignment_id == admission.target_role_assignment_id
        and state.snapshot.role_epoch == admission.target_role_epoch
        and state.resource_version == admission.expected_role_resource_version + 1
        and state.journal_seq == admission.expected_role_journal_seq + 1
        and state.transition_id == expected_transition_id
        and state.transition_kind == "rollback"
    )
    if target and rollback_seen:
        return RollbackCommitOutcome.COMMITTED, "exact_rollback_transition_current", True
    deltas = (
        state.snapshot.role_epoch - admission.expected_role_epoch,
        state.resource_version - admission.expected_role_resource_version,
        state.journal_seq - admission.expected_role_journal_seq,
    )
    if any(delta < 0 for delta in deltas):
        return RollbackCommitOutcome.AMBIGUOUS, "role_revision_regressed", rollback_seen
    if len(set(deltas)) != 1:
        return (
            RollbackCommitOutcome.AMBIGUOUS,
            "role_revision_counters_inconsistent",
            rollback_seen,
        )
    if deltas[0] >= 1:
        reason = (
            "rollback_transition_superseded"
            if rollback_seen
            else "competing_transition_superseded_admission"
        )
        return RollbackCommitOutcome.SUPERSEDED, reason, rollback_seen
    return RollbackCommitOutcome.AMBIGUOUS, "role_revision_not_classifiable", rollback_seen


def _verify_receipt(receipt: RollingWriterHandoffRollbackReconciliationReceipt) -> None:
    if (
        receipt.schema
        != "home-center.ha-rolling-writer-handoff-rollback-reconciliation-receipt.v1"
        or receipt.fresh_admission_authorized
        or receipt.automatic_retry_authorized
        or receipt.execution_authorized
        or receipt.failover_authorized
        or receipt.writer_service_authorized
        or receipt.host_mutation_authorized
        or receipt.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_receipt_authority_invalid"
        )
    expected_flags = {
        RollbackCommitOutcome.COMMITTED: (True, False, False),
        RollbackCommitOutcome.DEFINITELY_NOT_APPLIED: (False, True, False),
        RollbackCommitOutcome.SUPERSEDED: (False, False, True),
        RollbackCommitOutcome.AMBIGUOUS: (False, False, True),
    }
    actual = (
        receipt.rollback_completed,
        receipt.fresh_admission_required,
        receipt.operator_reconciliation_required,
    )
    if actual != expected_flags[receipt.outcome]:
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_receipt_semantics_invalid"
        )
    expected = _stable_id(
        "ha-roll-writer-handoff-rollback-reconciliation",
        _material(receipt, "receipt_id"),
    )
    if receipt.receipt_id != expected:
        raise HARollingWriterHandoffRollbackReconciliationError(
            "rollback_reconciliation_receipt_identity_invalid"
        )


def reconcile_writer_handoff_rollback(
    *,
    admission: RollingWriterHandoffRollbackAdmission,
    role_authority: HARollbackReconciliationAuthority,
) -> RollingWriterHandoffRollbackReconciliationReceipt:
    """Classify a possibly-lost rollback CAS without retrying or mutating roles."""

    expected_transition_id = _verify_admission(admission)
    observed: HARoleAuthorityState | None = None
    writers: tuple[str, ...] = ()
    outcome = RollbackCommitOutcome.AMBIGUOUS
    reason = "role_authority_unavailable"
    rollback_seen = False
    try:
        observed = role_authority.state_for(
            cluster_id=admission.cluster_id,
            node_ids=admission.member_node_ids,
        )
        writers = _validate_state(observed, admission)
        entries = role_authority.journal_entries(
            cluster_id=admission.cluster_id,
            limit=128,
        )
        outcome, reason, rollback_seen = _classify(
            observed,
            admission,
            entries,
            expected_transition_id,
        )
        if len(writers) != 1:
            outcome = RollbackCommitOutcome.AMBIGUOUS
            reason = "writer_cardinality_unsafe"
    except (
        HARoleCoordinationError,
        HARoleJournalError,
        HARollingWriterHandoffRollbackReconciliationError,
    ):
        outcome = RollbackCommitOutcome.AMBIGUOUS
        reason = "role_authority_unavailable"

    provisional = RollingWriterHandoffRollbackReconciliationReceipt(
        cluster_id=admission.cluster_id,
        receipt_id="pending",
        admission_id=admission.admission_id,
        member_node_ids=admission.member_node_ids,
        rollback_writer_node_id=admission.rollback_writer_node_id,
        fenced_successor_node_id=admission.fenced_successor_node_id,
        expected_role_assignment_id=admission.expected_role_assignment_id,
        expected_role_epoch=admission.expected_role_epoch,
        expected_role_resource_version=admission.expected_role_resource_version,
        expected_role_journal_seq=admission.expected_role_journal_seq,
        expected_role_transition_id=admission.expected_role_transition_id,
        target_role_assignment_id=admission.target_role_assignment_id,
        target_role_epoch=admission.target_role_epoch,
        expected_rollback_transition_id=expected_transition_id,
        observed_role_assignment_id=observed.snapshot.assignment_id if observed else None,
        observed_role_epoch=observed.snapshot.role_epoch if observed else None,
        observed_role_resource_version=observed.resource_version if observed else None,
        observed_role_journal_seq=observed.journal_seq if observed else None,
        observed_role_transition_id=observed.transition_id if observed else None,
        observed_role_transition_kind=observed.transition_kind if observed else None,
        observed_writer_node_ids=writers,
        rollback_transition_observed=rollback_seen,
        outcome=outcome,
        reason=reason,
        rollback_completed=outcome is RollbackCommitOutcome.COMMITTED,
        fresh_admission_required=outcome is RollbackCommitOutcome.DEFINITELY_NOT_APPLIED,
        operator_reconciliation_required=outcome
        in {RollbackCommitOutcome.SUPERSEDED, RollbackCommitOutcome.AMBIGUOUS},
    )
    result = replace(
        provisional,
        receipt_id=_stable_id(
            "ha-roll-writer-handoff-rollback-reconciliation",
            _material(provisional, "receipt_id"),
        ),
    )
    _verify_receipt(result)
    return result


def revalidate_writer_handoff_rollback_reconciliation_receipt(
    *, receipt: RollingWriterHandoffRollbackReconciliationReceipt
) -> RollingWriterHandoffRollbackReconciliationReceipt:
    """Validate immutable reconciliation evidence without granting authority."""

    _verify_receipt(receipt)
    return receipt
