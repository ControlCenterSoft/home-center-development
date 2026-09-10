"""Bind coordinated rolling safety to durable HA role-journal revision evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from .ha_peer_snapshot import HAPeerStateSnapshot
from .ha_rolling_authority import (
    HARoleAssignmentSnapshot,
    HARoleAuthority,
    CoordinatedRollingSafetyDecision,
    build_role_assignment_snapshot,
    evaluate_authoritative_rolling_safety,
)

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")


class HARollingRevisionError(ValueError):
    """Stable fail-closed error for revision-bound HA rolling decisions."""


class HARoleAuthorityStateView(Protocol):
    snapshot: HARoleAssignmentSnapshot
    journal_seq: int
    resource_version: int
    transition_id: str
    production_mutation_enabled: bool


class HARoleRevisionAuthority(HARoleAuthority, Protocol):
    def state_for(
        self,
        *,
        cluster_id: str,
        node_ids: tuple[str, ...],
    ) -> HARoleAuthorityStateView: ...


@dataclass(frozen=True, slots=True)
class RevisionBoundRollingSafetyDecision:
    safe: bool
    plan_id: str
    coordinated_plan_id: str
    blockers: tuple[str, ...]
    peer_snapshot_id: str
    peer_journal_seq: int
    role_assignment_id: str
    role_epoch: int
    role_resource_version: int
    role_journal_seq: int
    role_transition_id: str
    target_node_id: str
    minimum_ready_nodes: int
    required_predecessor_node_id: str | None
    required_predecessor_revision: str | None
    single_node_downtime_acknowledged: bool
    ready_before: int
    ready_after_target_stops: int
    writer_node_id: str | None
    rollback_state: str = "ready"
    rollback_required_on_failure: bool = True
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-revision-bound-rolling-safety-decision.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "safe": self.safe,
            "plan_id": self.plan_id,
            "coordinated_plan_id": self.coordinated_plan_id,
            "blockers": list(self.blockers),
            "peer_snapshot_id": self.peer_snapshot_id,
            "peer_journal_seq": self.peer_journal_seq,
            "role_assignment_id": self.role_assignment_id,
            "role_epoch": self.role_epoch,
            "role_resource_version": self.role_resource_version,
            "role_journal_seq": self.role_journal_seq,
            "role_transition_id": self.role_transition_id,
            "target_node_id": self.target_node_id,
            "minimum_ready_nodes": self.minimum_ready_nodes,
            "required_predecessor_node_id": self.required_predecessor_node_id,
            "required_predecessor_revision": self.required_predecessor_revision,
            "single_node_downtime_acknowledged": self.single_node_downtime_acknowledged,
            "ready_before": self.ready_before,
            "ready_after_target_stops": self.ready_after_target_stops,
            "writer_node_id": self.writer_node_id,
            "rollback_state": self.rollback_state,
            "rollback_required_on_failure": self.rollback_required_on_failure,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


def _verify_state(state: HARoleAuthorityStateView, *, cluster_id: str) -> None:
    if state.production_mutation_enabled:
        raise HARollingRevisionError("role_authority_mutation_enabled")
    if isinstance(state.journal_seq, bool) or not isinstance(state.journal_seq, int):
        raise HARollingRevisionError("invalid_role_journal_seq")
    if state.journal_seq < 1:
        raise HARollingRevisionError("invalid_role_journal_seq")
    if isinstance(state.resource_version, bool) or not isinstance(state.resource_version, int):
        raise HARollingRevisionError("invalid_role_resource_version")
    if state.resource_version < 1:
        raise HARollingRevisionError("invalid_role_resource_version")
    if (
        not isinstance(state.transition_id, str)
        or IDENTIFIER.fullmatch(state.transition_id) is None
    ):
        raise HARollingRevisionError("invalid_role_transition_id")
    if state.snapshot.cluster_id != cluster_id:
        raise HARollingRevisionError("role_cluster_mismatch")
    canonical = build_role_assignment_snapshot(
        cluster_id=state.snapshot.cluster_id,
        role_epoch=state.snapshot.role_epoch,
        assignments=state.snapshot.assignments,
    )
    if canonical.assignment_id != state.snapshot.assignment_id:
        raise HARollingRevisionError("role_assignment_identity_invalid")


def _require_expected_revision(
    state: HARoleAuthorityStateView,
    *,
    expected_role_resource_version: int,
    expected_role_journal_seq: int,
    expected_role_transition_id: str,
) -> None:
    for value, code in (
        (expected_role_resource_version, "invalid_expected_role_resource_version"),
        (expected_role_journal_seq, "invalid_expected_role_journal_seq"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise HARollingRevisionError(code)
    if (
        not isinstance(expected_role_transition_id, str)
        or IDENTIFIER.fullmatch(expected_role_transition_id) is None
    ):
        raise HARollingRevisionError("invalid_expected_role_transition_id")
    expected = (
        ("ha_role_resource_version_stale", state.resource_version, expected_role_resource_version),
        ("ha_role_journal_stale", state.journal_seq, expected_role_journal_seq),
        ("ha_role_transition_stale", state.transition_id, expected_role_transition_id),
    )
    for code, actual, wanted in expected:
        if actual != wanted:
            raise HARollingRevisionError(code)


def _same_revision(first: HARoleAuthorityStateView, second: HARoleAuthorityStateView) -> bool:
    return (
        first.snapshot.assignment_id == second.snapshot.assignment_id
        and first.snapshot.role_epoch == second.snapshot.role_epoch
        and first.resource_version == second.resource_version
        and first.journal_seq == second.journal_seq
        and first.transition_id == second.transition_id
    )


def _bound_plan_id(
    coordinated: CoordinatedRollingSafetyDecision,
    state: HARoleAuthorityStateView,
) -> str:
    payload = {
        "schema": "home-center.ha-revision-bound-rolling-safety-decision.v1",
        "coordinated_plan_id": coordinated.plan_id,
        "role_assignment_id": state.snapshot.assignment_id,
        "role_epoch": state.snapshot.role_epoch,
        "role_resource_version": state.resource_version,
        "role_journal_seq": state.journal_seq,
        "role_transition_id": state.transition_id,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"ha-roll-rev-{digest}"


def _verify_decision_identity(decision: RevisionBoundRollingSafetyDecision) -> None:
    if decision.schema != "home-center.ha-revision-bound-rolling-safety-decision.v1":
        raise HARollingRevisionError("rolling_revision_decision_schema_invalid")
    payload = {
        "schema": decision.schema,
        "coordinated_plan_id": decision.coordinated_plan_id,
        "role_assignment_id": decision.role_assignment_id,
        "role_epoch": decision.role_epoch,
        "role_resource_version": decision.role_resource_version,
        "role_journal_seq": decision.role_journal_seq,
        "role_transition_id": decision.role_transition_id,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if decision.plan_id != f"ha-roll-rev-{digest}":
        raise HARollingRevisionError("rolling_revision_decision_identity_invalid")
    if decision.production_mutation_enabled:
        raise HARollingRevisionError("rolling_revision_mutation_enabled")


def evaluate_revision_bound_rolling_safety(
    *,
    peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    target_node_id: str,
    minimum_ready_nodes: int,
    expected_peer_snapshot_id: str,
    expected_peer_journal_seq: int,
    expected_role_assignment_id: str,
    expected_role_epoch: int,
    expected_role_resource_version: int,
    expected_role_journal_seq: int,
    expected_role_transition_id: str,
    required_predecessor_node_id: str | None = None,
    required_predecessor_revision: str | None = None,
    single_node_downtime_acknowledged: bool = False,
) -> RevisionBoundRollingSafetyDecision:
    """Evaluate rolling safety while sealing durable role-journal revision evidence.

    The role authority is read before and after coordinated evaluation. Any role-journal
    movement during evaluation fails closed. The result is planning evidence only.
    """

    node_ids = tuple(member.node_id for member in peer_snapshot.members)
    before = role_authority.state_for(
        cluster_id=peer_snapshot.cluster_id,
        node_ids=node_ids,
    )
    _verify_state(before, cluster_id=peer_snapshot.cluster_id)
    _require_expected_revision(
        before,
        expected_role_resource_version=expected_role_resource_version,
        expected_role_journal_seq=expected_role_journal_seq,
        expected_role_transition_id=expected_role_transition_id,
    )
    if before.snapshot.assignment_id != expected_role_assignment_id:
        raise HARollingRevisionError("ha_role_assignment_stale")
    if before.snapshot.role_epoch != expected_role_epoch:
        raise HARollingRevisionError("ha_role_epoch_stale")

    coordinated = evaluate_authoritative_rolling_safety(
        peer_snapshot=peer_snapshot,
        role_authority=role_authority,
        target_node_id=target_node_id,
        minimum_ready_nodes=minimum_ready_nodes,
        expected_peer_snapshot_id=expected_peer_snapshot_id,
        expected_peer_journal_seq=expected_peer_journal_seq,
        expected_role_assignment_id=expected_role_assignment_id,
        expected_role_epoch=expected_role_epoch,
        required_predecessor_node_id=required_predecessor_node_id,
        required_predecessor_revision=required_predecessor_revision,
        single_node_downtime_acknowledged=single_node_downtime_acknowledged,
    )

    after = role_authority.state_for(
        cluster_id=peer_snapshot.cluster_id,
        node_ids=node_ids,
    )
    _verify_state(after, cluster_id=peer_snapshot.cluster_id)
    if not _same_revision(before, after):
        raise HARollingRevisionError("ha_role_revision_changed_during_evaluation")

    return RevisionBoundRollingSafetyDecision(
        safe=coordinated.safe,
        plan_id=_bound_plan_id(coordinated, after),
        coordinated_plan_id=coordinated.plan_id,
        blockers=coordinated.blockers,
        peer_snapshot_id=coordinated.peer_snapshot_id,
        peer_journal_seq=coordinated.peer_journal_seq,
        role_assignment_id=after.snapshot.assignment_id,
        role_epoch=after.snapshot.role_epoch,
        role_resource_version=after.resource_version,
        role_journal_seq=after.journal_seq,
        role_transition_id=after.transition_id,
        target_node_id=target_node_id,
        minimum_ready_nodes=minimum_ready_nodes,
        required_predecessor_node_id=required_predecessor_node_id,
        required_predecessor_revision=required_predecessor_revision,
        single_node_downtime_acknowledged=single_node_downtime_acknowledged,
        ready_before=coordinated.ready_before,
        ready_after_target_stops=coordinated.ready_after_target_stops,
        writer_node_id=coordinated.writer_node_id,
        rollback_state=coordinated.rollback_state,
        rollback_required_on_failure=coordinated.rollback_required_on_failure,
    )


def revalidate_revision_bound_rolling_safety(
    *,
    decision: RevisionBoundRollingSafetyDecision,
    peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
) -> RevisionBoundRollingSafetyDecision:
    """Rebuild exact rolling evidence; any peer or role revision drift fails closed."""

    _verify_decision_identity(decision)
    fresh = evaluate_revision_bound_rolling_safety(
        peer_snapshot=peer_snapshot,
        role_authority=role_authority,
        target_node_id=decision.target_node_id,
        minimum_ready_nodes=decision.minimum_ready_nodes,
        expected_peer_snapshot_id=decision.peer_snapshot_id,
        expected_peer_journal_seq=decision.peer_journal_seq,
        expected_role_assignment_id=decision.role_assignment_id,
        expected_role_epoch=decision.role_epoch,
        expected_role_resource_version=decision.role_resource_version,
        expected_role_journal_seq=decision.role_journal_seq,
        expected_role_transition_id=decision.role_transition_id,
        required_predecessor_node_id=decision.required_predecessor_node_id,
        required_predecessor_revision=decision.required_predecessor_revision,
        single_node_downtime_acknowledged=decision.single_node_downtime_acknowledged,
    )
    if fresh.plan_id != decision.plan_id:
        raise HARollingRevisionError("rolling_revision_decision_stale")
    return fresh
