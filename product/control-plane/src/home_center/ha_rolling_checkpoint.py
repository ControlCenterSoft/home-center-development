"""Seal rolling-step completion before another HA node may advance."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace

from .ha_peer_snapshot import HAPeerStateSnapshot, PeerHealthState
from .ha_rolling_authority import build_role_assignment_snapshot
from .ha_rolling_revision import (
    HARoleRevisionAuthority,
    RevisionBoundRollingSafetyDecision,
    evaluate_revision_bound_rolling_safety,
    revalidate_revision_bound_rolling_safety,
)

REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")


class HARollingCheckpointError(ValueError):
    """Stable fail-closed error for rolling-step checkpoint evidence."""


@dataclass(frozen=True, slots=True)
class RollingStepCheckpoint:
    cluster_id: str
    checkpoint_id: str
    completed_plan_id: str
    completed_node_id: str
    completed_revision: str
    completion_peer_snapshot_id: str
    completion_peer_journal_seq: int
    member_node_ids: tuple[str, ...]
    ready_node_ids: tuple[str, ...]
    minimum_ready_nodes: int
    writer_node_id: str
    role_assignment_id: str
    role_epoch: int
    role_resource_version: int
    role_journal_seq: int
    role_transition_id: str
    rollback_state: str = "ready"
    rollback_required_on_failure: bool = True
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-step-checkpoint.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "checkpoint_id": self.checkpoint_id,
            "completed_plan_id": self.completed_plan_id,
            "completed_node_id": self.completed_node_id,
            "completed_revision": self.completed_revision,
            "completion_peer_snapshot_id": self.completion_peer_snapshot_id,
            "completion_peer_journal_seq": self.completion_peer_journal_seq,
            "member_node_ids": list(self.member_node_ids),
            "ready_node_ids": list(self.ready_node_ids),
            "minimum_ready_nodes": self.minimum_ready_nodes,
            "writer_node_id": self.writer_node_id,
            "role_assignment_id": self.role_assignment_id,
            "role_epoch": self.role_epoch,
            "role_resource_version": self.role_resource_version,
            "role_journal_seq": self.role_journal_seq,
            "role_transition_id": self.role_transition_id,
            "rollback_state": self.rollback_state,
            "rollback_required_on_failure": self.rollback_required_on_failure,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


def _snapshot_identity(snapshot: HAPeerStateSnapshot) -> str:
    canonical = {
        "schema": snapshot.schema,
        "cluster_id": snapshot.cluster_id,
        "journal_seq": snapshot.journal_seq,
        "members": [member.to_dict() for member in snapshot.members],
    }
    digest = hashlib.sha256(
        json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return f"ha-state-{digest}"


def _checkpoint_id(material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"ha-roll-checkpoint-{digest}"


def _identity_material(checkpoint: RollingStepCheckpoint) -> dict[str, object]:
    return {
        "schema": checkpoint.schema,
        "cluster_id": checkpoint.cluster_id,
        "completed_plan_id": checkpoint.completed_plan_id,
        "completed_node_id": checkpoint.completed_node_id,
        "completed_revision": checkpoint.completed_revision,
        "completion_peer_snapshot_id": checkpoint.completion_peer_snapshot_id,
        "completion_peer_journal_seq": checkpoint.completion_peer_journal_seq,
        "member_node_ids": list(checkpoint.member_node_ids),
        "ready_node_ids": list(checkpoint.ready_node_ids),
        "minimum_ready_nodes": checkpoint.minimum_ready_nodes,
        "writer_node_id": checkpoint.writer_node_id,
        "role_assignment_id": checkpoint.role_assignment_id,
        "role_epoch": checkpoint.role_epoch,
        "role_resource_version": checkpoint.role_resource_version,
        "role_journal_seq": checkpoint.role_journal_seq,
        "role_transition_id": checkpoint.role_transition_id,
        "rollback_state": checkpoint.rollback_state,
        "rollback_required_on_failure": checkpoint.rollback_required_on_failure,
        "execution_authorized": checkpoint.execution_authorized,
        "production_mutation_enabled": checkpoint.production_mutation_enabled,
    }


def _verify_checkpoint_identity(checkpoint: RollingStepCheckpoint) -> None:
    if checkpoint.schema != "home-center.ha-rolling-step-checkpoint.v1":
        raise HARollingCheckpointError("rolling_checkpoint_schema_invalid")
    if checkpoint.execution_authorized or checkpoint.production_mutation_enabled:
        raise HARollingCheckpointError("rolling_checkpoint_mutation_enabled")
    if checkpoint.rollback_state != "ready" or not checkpoint.rollback_required_on_failure:
        raise HARollingCheckpointError("rolling_checkpoint_rollback_contract_invalid")
    if REVISION.fullmatch(checkpoint.completed_revision) is None:
        raise HARollingCheckpointError("rolling_checkpoint_revision_invalid")
    if checkpoint.checkpoint_id != _checkpoint_id(_identity_material(checkpoint)):
        raise HARollingCheckpointError("rolling_checkpoint_identity_invalid")


def _require_exact_peer_snapshot(
    snapshot: HAPeerStateSnapshot,
    *,
    expected_snapshot_id: str,
    expected_journal_seq: int,
) -> None:
    if _snapshot_identity(snapshot) != snapshot.snapshot_id:
        raise HARollingCheckpointError("peer_snapshot_identity_invalid")
    if snapshot.snapshot_id != expected_snapshot_id:
        raise HARollingCheckpointError("checkpoint_peer_snapshot_stale")
    if snapshot.journal_seq != expected_journal_seq:
        raise HARollingCheckpointError("checkpoint_peer_journal_stale")


def _role_revision(state: object) -> tuple[object, ...]:
    snapshot = state.snapshot
    canonical = build_role_assignment_snapshot(
        cluster_id=snapshot.cluster_id,
        role_epoch=snapshot.role_epoch,
        assignments=snapshot.assignments,
    )
    if canonical.assignment_id != snapshot.assignment_id:
        raise HARollingCheckpointError("role_assignment_identity_invalid")
    if state.production_mutation_enabled:
        raise HARollingCheckpointError("role_authority_mutation_enabled")
    return (
        snapshot.assignment_id,
        snapshot.role_epoch,
        state.resource_version,
        state.journal_seq,
        state.transition_id,
    )


def _require_role_revision(state: object, checkpoint_or_decision: object) -> tuple[object, ...]:
    revision = _role_revision(state)
    expected = (
        checkpoint_or_decision.role_assignment_id,
        checkpoint_or_decision.role_epoch,
        checkpoint_or_decision.role_resource_version,
        checkpoint_or_decision.role_journal_seq,
        checkpoint_or_decision.role_transition_id,
    )
    if revision != expected:
        raise HARollingCheckpointError("rolling_checkpoint_role_revision_stale")
    return revision


def _checkpoint_observation(
    *,
    decision: RevisionBoundRollingSafetyDecision,
    snapshot: HAPeerStateSnapshot,
    role_state: object,
    expected_completed_revision: str,
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    if REVISION.fullmatch(expected_completed_revision) is None:
        raise HARollingCheckpointError("invalid_expected_completed_revision")
    members = tuple(sorted(member.node_id for member in snapshot.members))
    target = next(
        (member for member in snapshot.members if member.node_id == decision.target_node_id),
        None,
    )
    if target is None:
        raise HARollingCheckpointError("completed_node_missing")
    if target.state is not PeerHealthState.READY:
        raise HARollingCheckpointError("completed_node_not_ready")
    if target.state_revision != expected_completed_revision:
        raise HARollingCheckpointError("completed_revision_mismatch")

    ready = tuple(
        sorted(
            member.node_id
            for member in snapshot.members
            if member.state is PeerHealthState.READY
        )
    )
    assignments = role_state.snapshot.assignments
    writer = next((item.node_id for item in assignments if item.role.value == "writer"), None)
    if writer is None or writer not in ready:
        raise HARollingCheckpointError("writer_not_ready_at_checkpoint")

    if len(members) == 1:
        if not decision.single_node_downtime_acknowledged:
            raise HARollingCheckpointError("single_node_downtime_not_acknowledged")
    elif len(ready) < decision.minimum_ready_nodes + 1:
        raise HARollingCheckpointError("next_step_ready_floor_not_met")
    return members, ready, writer


def seal_rolling_step_checkpoint(
    *,
    decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    expected_completion_peer_snapshot_id: str,
    expected_completion_peer_journal_seq: int,
    expected_completed_revision: str,
) -> RollingStepCheckpoint:
    """Seal proof that one rolling step completed and the cluster is safe to reassess."""

    verified = revalidate_revision_bound_rolling_safety(
        decision=decision,
        peer_snapshot=pre_step_peer_snapshot,
        role_authority=role_authority,
    )
    if not verified.safe or verified.blockers:
        raise HARollingCheckpointError("completed_plan_was_not_safe")

    _require_exact_peer_snapshot(
        completion_peer_snapshot,
        expected_snapshot_id=expected_completion_peer_snapshot_id,
        expected_journal_seq=expected_completion_peer_journal_seq,
    )
    if completion_peer_snapshot.cluster_id != pre_step_peer_snapshot.cluster_id:
        raise HARollingCheckpointError("checkpoint_cluster_mismatch")
    if completion_peer_snapshot.journal_seq < decision.peer_journal_seq:
        raise HARollingCheckpointError("completion_peer_journal_regressed")

    members = tuple(sorted(member.node_id for member in completion_peer_snapshot.members))
    pre_members = tuple(sorted(member.node_id for member in pre_step_peer_snapshot.members))
    if members != pre_members:
        raise HARollingCheckpointError("rolling_membership_changed")

    node_ids = members
    before = role_authority.state_for(
        cluster_id=completion_peer_snapshot.cluster_id,
        node_ids=node_ids,
    )
    before_revision = _require_role_revision(before, decision)
    observed_members, ready, writer = _checkpoint_observation(
        decision=decision,
        snapshot=completion_peer_snapshot,
        role_state=before,
        expected_completed_revision=expected_completed_revision,
    )
    if observed_members != members:
        raise HARollingCheckpointError("rolling_membership_changed")

    after = role_authority.state_for(
        cluster_id=completion_peer_snapshot.cluster_id,
        node_ids=node_ids,
    )
    if _require_role_revision(after, decision) != before_revision:
        raise HARollingCheckpointError("role_revision_changed_during_checkpoint")

    provisional = RollingStepCheckpoint(
        cluster_id=completion_peer_snapshot.cluster_id,
        checkpoint_id="pending",
        completed_plan_id=decision.plan_id,
        completed_node_id=decision.target_node_id,
        completed_revision=expected_completed_revision,
        completion_peer_snapshot_id=completion_peer_snapshot.snapshot_id,
        completion_peer_journal_seq=completion_peer_snapshot.journal_seq,
        member_node_ids=observed_members,
        ready_node_ids=ready,
        minimum_ready_nodes=decision.minimum_ready_nodes,
        writer_node_id=writer,
        role_assignment_id=decision.role_assignment_id,
        role_epoch=decision.role_epoch,
        role_resource_version=decision.role_resource_version,
        role_journal_seq=decision.role_journal_seq,
        role_transition_id=decision.role_transition_id,
    )
    return replace(
        provisional,
        checkpoint_id=_checkpoint_id(_identity_material(provisional)),
    )


def revalidate_rolling_step_checkpoint(
    *,
    checkpoint: RollingStepCheckpoint,
    completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
) -> RollingStepCheckpoint:
    """Reject a saved checkpoint after any peer, readiness, or role-revision drift."""

    _verify_checkpoint_identity(checkpoint)
    _require_exact_peer_snapshot(
        completion_peer_snapshot,
        expected_snapshot_id=checkpoint.completion_peer_snapshot_id,
        expected_journal_seq=checkpoint.completion_peer_journal_seq,
    )
    if completion_peer_snapshot.cluster_id != checkpoint.cluster_id:
        raise HARollingCheckpointError("checkpoint_cluster_mismatch")
    node_ids = tuple(sorted(member.node_id for member in completion_peer_snapshot.members))
    state = role_authority.state_for(cluster_id=checkpoint.cluster_id, node_ids=node_ids)
    _require_role_revision(state, checkpoint)

    members = tuple(sorted(member.node_id for member in completion_peer_snapshot.members))
    ready = tuple(
        sorted(
            member.node_id
            for member in completion_peer_snapshot.members
            if member.state is PeerHealthState.READY
        )
    )
    target = next(
        (
            member
            for member in completion_peer_snapshot.members
            if member.node_id == checkpoint.completed_node_id
        ),
        None,
    )
    if members != checkpoint.member_node_ids or ready != checkpoint.ready_node_ids:
        raise HARollingCheckpointError("rolling_checkpoint_peer_state_stale")
    if target is None or target.state is not PeerHealthState.READY:
        raise HARollingCheckpointError("completed_node_not_ready")
    if target.state_revision != checkpoint.completed_revision:
        raise HARollingCheckpointError("completed_revision_stale")
    if checkpoint.writer_node_id not in ready:
        raise HARollingCheckpointError("writer_not_ready_at_checkpoint")
    return checkpoint


def evaluate_next_rolling_step(
    *,
    checkpoint: RollingStepCheckpoint,
    peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    target_node_id: str,
) -> RevisionBoundRollingSafetyDecision:
    """Evaluate the next node only from an exact, still-current checkpoint."""

    revalidate_rolling_step_checkpoint(
        checkpoint=checkpoint,
        completion_peer_snapshot=peer_snapshot,
        role_authority=role_authority,
    )
    if len(checkpoint.member_node_ids) == 1:
        raise HARollingCheckpointError("single_node_has_no_next_rolling_step")
    if target_node_id == checkpoint.completed_node_id:
        raise HARollingCheckpointError("completed_node_cannot_be_next_target")
    if target_node_id not in checkpoint.member_node_ids:
        raise HARollingCheckpointError("next_target_missing")

    return evaluate_revision_bound_rolling_safety(
        peer_snapshot=peer_snapshot,
        role_authority=role_authority,
        target_node_id=target_node_id,
        minimum_ready_nodes=checkpoint.minimum_ready_nodes,
        expected_peer_snapshot_id=checkpoint.completion_peer_snapshot_id,
        expected_peer_journal_seq=checkpoint.completion_peer_journal_seq,
        expected_role_assignment_id=checkpoint.role_assignment_id,
        expected_role_epoch=checkpoint.role_epoch,
        expected_role_resource_version=checkpoint.role_resource_version,
        expected_role_journal_seq=checkpoint.role_journal_seq,
        expected_role_transition_id=checkpoint.role_transition_id,
        required_predecessor_node_id=checkpoint.completed_node_id,
        required_predecessor_revision=checkpoint.completed_revision,
    )
