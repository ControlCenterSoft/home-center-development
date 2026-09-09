"""Bind rolling HA safety decisions to exact peer-state and role-authority evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from .ha_peer_snapshot import HAPeerStateSnapshot, PeerHealthState
from .ha_rolling_safety import (
    NodeObservation,
    NodeRole,
    NodeState,
    RollingSafetyDecision,
    RollingSafetyRequest,
    evaluate_rolling_safety,
)

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")


class HARoleCoordinationError(ValueError):
    """Stable fail-closed validation error for HA role-coordinated planning."""


@dataclass(frozen=True, slots=True)
class HARoleAssignment:
    node_id: str
    role: NodeRole

    def __post_init__(self) -> None:
        if IDENTIFIER.fullmatch(self.node_id) is None:
            raise HARoleCoordinationError("invalid_role_node_id")
        if not isinstance(self.role, NodeRole):
            raise HARoleCoordinationError("invalid_role_assignment")

    def to_dict(self) -> dict[str, str]:
        return {"node_id": self.node_id, "role": self.role.value}


@dataclass(frozen=True, slots=True)
class HARoleAssignmentSnapshot:
    cluster_id: str
    role_epoch: int
    assignments: tuple[HARoleAssignment, ...]
    assignment_id: str
    schema: str = "home-center.ha-role-assignment-snapshot.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "role_epoch": self.role_epoch,
            "assignments": [item.to_dict() for item in self.assignments],
            "assignment_id": self.assignment_id,
        }


class HARoleAuthority(Protocol):
    """Trusted dependency that returns the current role assignment for exact members."""

    def snapshot_for(
        self,
        *,
        cluster_id: str,
        node_ids: tuple[str, ...],
    ) -> HARoleAssignmentSnapshot: ...


@dataclass(frozen=True, slots=True)
class CoordinatedRollingSafetyDecision:
    safe: bool
    plan_id: str
    base_plan_id: str
    blockers: tuple[str, ...]
    peer_snapshot_id: str
    peer_journal_seq: int
    role_assignment_id: str
    role_epoch: int
    ready_before: int
    ready_after_target_stops: int
    writer_node_id: str | None
    rollback_state: str = "ready"
    rollback_required_on_failure: bool = True
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-coordinated-rolling-safety-decision.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "safe": self.safe,
            "plan_id": self.plan_id,
            "base_plan_id": self.base_plan_id,
            "blockers": list(self.blockers),
            "peer_snapshot_id": self.peer_snapshot_id,
            "peer_journal_seq": self.peer_journal_seq,
            "role_assignment_id": self.role_assignment_id,
            "role_epoch": self.role_epoch,
            "ready_before": self.ready_before,
            "ready_after_target_stops": self.ready_after_target_stops,
            "writer_node_id": self.writer_node_id,
            "rollback_state": self.rollback_state,
            "rollback_required_on_failure": self.rollback_required_on_failure,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


def _canonical_role_assignment_id(
    *,
    cluster_id: str,
    role_epoch: int,
    assignments: tuple[HARoleAssignment, ...],
) -> str:
    payload = {
        "schema": "home-center.ha-role-assignment-snapshot.v1",
        "cluster_id": cluster_id,
        "role_epoch": role_epoch,
        "assignments": [item.to_dict() for item in assignments],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"ha-role-{digest}"


def build_role_assignment_snapshot(
    *,
    cluster_id: str,
    role_epoch: int,
    assignments: tuple[HARoleAssignment, ...],
) -> HARoleAssignmentSnapshot:
    """Build immutable role evidence for a trusted HA role authority implementation."""

    if IDENTIFIER.fullmatch(cluster_id) is None:
        raise HARoleCoordinationError("invalid_role_cluster_id")
    if isinstance(role_epoch, bool) or not isinstance(role_epoch, int) or role_epoch < 0:
        raise HARoleCoordinationError("invalid_role_epoch")
    if not 1 <= len(assignments) <= 64:
        raise HARoleCoordinationError("invalid_role_assignment_count")
    normalized = tuple(sorted(assignments, key=lambda item: item.node_id))
    node_ids = tuple(item.node_id for item in normalized)
    if len(node_ids) != len(set(node_ids)):
        raise HARoleCoordinationError("duplicate_role_node_id")
    writers = tuple(item for item in normalized if item.role is NodeRole.WRITER)
    if len(writers) != 1:
        raise HARoleCoordinationError("writer_assignment_not_unique")
    assignment_id = _canonical_role_assignment_id(
        cluster_id=cluster_id,
        role_epoch=role_epoch,
        assignments=normalized,
    )
    return HARoleAssignmentSnapshot(
        cluster_id=cluster_id,
        role_epoch=role_epoch,
        assignments=normalized,
        assignment_id=assignment_id,
    )


def _verify_role_assignment(snapshot: HARoleAssignmentSnapshot) -> None:
    expected = _canonical_role_assignment_id(
        cluster_id=snapshot.cluster_id,
        role_epoch=snapshot.role_epoch,
        assignments=snapshot.assignments,
    )
    if snapshot.assignment_id != expected:
        raise HARoleCoordinationError("role_assignment_identity_invalid")


def _verify_peer_snapshot(snapshot: HAPeerStateSnapshot) -> None:
    canonical = {
        "schema": snapshot.schema,
        "cluster_id": snapshot.cluster_id,
        "journal_seq": snapshot.journal_seq,
        "members": [member.to_dict() for member in snapshot.members],
    }
    expected = "ha-state-" + hashlib.sha256(
        json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    if snapshot.snapshot_id != expected:
        raise HARoleCoordinationError("peer_snapshot_identity_invalid")


def _node_state(state: PeerHealthState) -> NodeState:
    if state is PeerHealthState.READY:
        return NodeState.READY
    if state is PeerHealthState.DEGRADED:
        return NodeState.DEGRADED
    if state is PeerHealthState.MAINTENANCE:
        return NodeState.MAINTENANCE
    return NodeState.UNREACHABLE


def _coordinated_plan_id(
    *,
    base: RollingSafetyDecision,
    peer_snapshot: HAPeerStateSnapshot,
    roles: HARoleAssignmentSnapshot,
) -> str:
    payload = {
        "schema": "home-center.ha-coordinated-rolling-safety-decision.v1",
        "base_plan_id": base.plan_id,
        "peer_snapshot_id": peer_snapshot.snapshot_id,
        "peer_journal_seq": peer_snapshot.journal_seq,
        "role_assignment_id": roles.assignment_id,
        "role_epoch": roles.role_epoch,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"ha-coord-{digest}"


def evaluate_authoritative_rolling_safety(
    *,
    peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleAuthority,
    target_node_id: str,
    minimum_ready_nodes: int,
    expected_peer_snapshot_id: str,
    expected_peer_journal_seq: int,
    expected_role_assignment_id: str,
    expected_role_epoch: int,
    required_predecessor_node_id: str | None = None,
    required_predecessor_revision: str | None = None,
    single_node_downtime_acknowledged: bool = False,
) -> CoordinatedRollingSafetyDecision:
    """Evaluate rolling safety from exact reconciler and role-authority snapshots only.

    Peer-reported roles are deliberately ignored. Health, revision and journal sequence
    come only from the reconciler snapshot; writer/standby assignments come only from
    the injected HA role authority. Any evidence drift invalidates the decision.
    """

    _verify_peer_snapshot(peer_snapshot)
    peer_snapshot.require_exact(
        expected_snapshot_id=expected_peer_snapshot_id,
        expected_journal_seq=expected_peer_journal_seq,
    )
    node_ids = tuple(member.node_id for member in peer_snapshot.members)
    roles = role_authority.snapshot_for(
        cluster_id=peer_snapshot.cluster_id,
        node_ids=node_ids,
    )
    _verify_role_assignment(roles)
    if roles.cluster_id != peer_snapshot.cluster_id:
        raise HARoleCoordinationError("role_cluster_mismatch")
    if tuple(item.node_id for item in roles.assignments) != tuple(sorted(node_ids)):
        raise HARoleCoordinationError("role_membership_mismatch")
    if roles.assignment_id != expected_role_assignment_id:
        raise HARoleCoordinationError("ha_role_assignment_stale")
    if roles.role_epoch != expected_role_epoch:
        raise HARoleCoordinationError("ha_role_epoch_stale")

    role_by_node = {item.node_id: item.role for item in roles.assignments}
    unknown_nodes = tuple(
        member.node_id for member in peer_snapshot.members if member.state is PeerHealthState.UNKNOWN
    )
    request = RollingSafetyRequest(
        cluster_id=peer_snapshot.cluster_id,
        target_node_id=target_node_id,
        observations=tuple(
            NodeObservation(
                node_id=member.node_id,
                role=role_by_node[member.node_id],
                state=_node_state(member.state),
                revision=member.state_revision,
            )
            for member in peer_snapshot.members
        ),
        minimum_ready_nodes=minimum_ready_nodes,
        expected_transition_seq=expected_peer_journal_seq,
        observed_transition_seq=peer_snapshot.journal_seq,
        required_predecessor_node_id=required_predecessor_node_id,
        required_predecessor_revision=required_predecessor_revision,
        single_node_downtime_acknowledged=single_node_downtime_acknowledged,
    )
    base = evaluate_rolling_safety(request)
    blockers = list(base.blockers)
    if unknown_nodes:
        blockers.append("peer_state_unknown")
    blockers = list(dict.fromkeys(blockers))
    safe = base.safe and not unknown_nodes
    return CoordinatedRollingSafetyDecision(
        safe=safe,
        plan_id=_coordinated_plan_id(base=base, peer_snapshot=peer_snapshot, roles=roles),
        base_plan_id=base.plan_id,
        blockers=tuple(blockers),
        peer_snapshot_id=peer_snapshot.snapshot_id,
        peer_journal_seq=peer_snapshot.journal_seq,
        role_assignment_id=roles.assignment_id,
        role_epoch=roles.role_epoch,
        ready_before=base.ready_before,
        ready_after_target_stops=base.ready_after_target_stops,
        writer_node_id=base.writer_node_id,
    )
