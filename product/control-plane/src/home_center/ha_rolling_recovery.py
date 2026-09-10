"""Seal fail-closed recovery handoff evidence for a failed rolling HA step."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace

from .ha_peer_snapshot import HAPeerStateSnapshot, PeerHealthState
from .ha_rolling_authority import build_role_assignment_snapshot
from .ha_rolling_checkpoint import RollingStepCheckpoint, revalidate_rolling_step_checkpoint
from .ha_rolling_revision import (
    HARoleRevisionAuthority,
    RevisionBoundRollingSafetyDecision,
    revalidate_revision_bound_rolling_safety,
)

REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")


class HARollingRecoveryError(ValueError):
    """Stable fail-closed error for rolling recovery handoff evidence."""


@dataclass(frozen=True, slots=True)
class RollingRecoveryHandoff:
    cluster_id: str
    handoff_id: str
    predecessor_checkpoint_id: str | None
    failed_plan_id: str
    failed_node_id: str
    rollback_target_revision: str
    failed_observed_revision: str
    pre_step_peer_snapshot_id: str
    pre_step_peer_journal_seq: int
    failure_peer_snapshot_id: str
    failure_peer_journal_seq: int
    member_node_ids: tuple[str, ...]
    ready_node_ids: tuple[str, ...]
    minimum_ready_nodes: int
    writer_node_id: str
    role_assignment_id: str
    role_epoch: int
    role_resource_version: int
    role_journal_seq: int
    role_transition_id: str
    recovery_mode: str
    rollback_required: bool = True
    execution_authorized: bool = False
    failover_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-recovery-handoff.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "handoff_id": self.handoff_id,
            "predecessor_checkpoint_id": self.predecessor_checkpoint_id,
            "failed_plan_id": self.failed_plan_id,
            "failed_node_id": self.failed_node_id,
            "rollback_target_revision": self.rollback_target_revision,
            "failed_observed_revision": self.failed_observed_revision,
            "pre_step_peer_snapshot_id": self.pre_step_peer_snapshot_id,
            "pre_step_peer_journal_seq": self.pre_step_peer_journal_seq,
            "failure_peer_snapshot_id": self.failure_peer_snapshot_id,
            "failure_peer_journal_seq": self.failure_peer_journal_seq,
            "member_node_ids": list(self.member_node_ids),
            "ready_node_ids": list(self.ready_node_ids),
            "minimum_ready_nodes": self.minimum_ready_nodes,
            "writer_node_id": self.writer_node_id,
            "role_assignment_id": self.role_assignment_id,
            "role_epoch": self.role_epoch,
            "role_resource_version": self.role_resource_version,
            "role_journal_seq": self.role_journal_seq,
            "role_transition_id": self.role_transition_id,
            "recovery_mode": self.recovery_mode,
            "rollback_required": self.rollback_required,
            "execution_authorized": self.execution_authorized,
            "failover_authorized": self.failover_authorized,
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


def _handoff_id(material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"ha-roll-recovery-{digest}"


def _identity_material(handoff: RollingRecoveryHandoff) -> dict[str, object]:
    data = handoff.to_dict()
    data.pop("handoff_id")
    return data


def _verify_handoff_identity(handoff: RollingRecoveryHandoff) -> None:
    if handoff.schema != "home-center.ha-rolling-recovery-handoff.v1":
        raise HARollingRecoveryError("rolling_recovery_schema_invalid")
    if (
        not handoff.rollback_required
        or handoff.execution_authorized
        or handoff.failover_authorized
        or handoff.production_mutation_enabled
    ):
        raise HARollingRecoveryError("rolling_recovery_authority_invalid")
    expected_mode = (
        "single-node-rollback" if len(handoff.member_node_ids) == 1 else "ha-target-rollback"
    )
    if handoff.recovery_mode != expected_mode:
        raise HARollingRecoveryError("rolling_recovery_mode_invalid")
    if REVISION.fullmatch(handoff.rollback_target_revision) is None:
        raise HARollingRecoveryError("rolling_recovery_target_revision_invalid")
    if REVISION.fullmatch(handoff.failed_observed_revision) is None:
        raise HARollingRecoveryError("rolling_recovery_failed_revision_invalid")
    if handoff.failure_peer_journal_seq <= handoff.pre_step_peer_journal_seq:
        raise HARollingRecoveryError("rolling_recovery_peer_journal_not_advanced")
    if handoff.handoff_id != _handoff_id(_identity_material(handoff)):
        raise HARollingRecoveryError("rolling_recovery_identity_invalid")


def _require_exact_snapshot(
    snapshot: HAPeerStateSnapshot,
    *,
    expected_snapshot_id: str,
    expected_journal_seq: int,
    stale_code: str,
) -> None:
    if _snapshot_identity(snapshot) != snapshot.snapshot_id:
        raise HARollingRecoveryError("peer_snapshot_identity_invalid")
    if snapshot.snapshot_id != expected_snapshot_id or snapshot.journal_seq != expected_journal_seq:
        raise HARollingRecoveryError(stale_code)


def _role_revision(state: object) -> tuple[object, ...]:
    snapshot = state.snapshot
    canonical = build_role_assignment_snapshot(
        cluster_id=snapshot.cluster_id,
        role_epoch=snapshot.role_epoch,
        assignments=snapshot.assignments,
    )
    if canonical.assignment_id != snapshot.assignment_id:
        raise HARollingRecoveryError("role_assignment_identity_invalid")
    if state.production_mutation_enabled:
        raise HARollingRecoveryError("role_authority_mutation_enabled")
    return (
        snapshot.assignment_id,
        snapshot.role_epoch,
        state.resource_version,
        state.journal_seq,
        state.transition_id,
    )


def _require_role_revision(
    state: object,
    decision: RevisionBoundRollingSafetyDecision,
) -> tuple[object, ...]:
    revision = _role_revision(state)
    expected = (
        decision.role_assignment_id,
        decision.role_epoch,
        decision.role_resource_version,
        decision.role_journal_seq,
        decision.role_transition_id,
    )
    if revision != expected:
        raise HARollingRecoveryError("rolling_recovery_role_revision_stale")
    return revision


def _validate_predecessor(
    *,
    decision: RevisionBoundRollingSafetyDecision,
    predecessor_checkpoint: RollingStepCheckpoint | None,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
) -> str | None:
    predecessor_id = decision.required_predecessor_node_id
    if predecessor_id is None:
        if predecessor_checkpoint is not None:
            raise HARollingRecoveryError("rolling_recovery_unexpected_predecessor_checkpoint")
        return None
    if predecessor_checkpoint is None:
        raise HARollingRecoveryError("rolling_recovery_predecessor_checkpoint_required")
    revalidate_rolling_step_checkpoint(
        checkpoint=predecessor_checkpoint,
        completion_peer_snapshot=pre_step_peer_snapshot,
        role_authority=role_authority,
    )
    if predecessor_checkpoint.completed_node_id != predecessor_id:
        raise HARollingRecoveryError("rolling_recovery_predecessor_node_mismatch")
    if predecessor_checkpoint.completed_revision != decision.required_predecessor_revision:
        raise HARollingRecoveryError("rolling_recovery_predecessor_revision_mismatch")
    return predecessor_checkpoint.checkpoint_id


def _validate_failure_observation(
    *,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    writer_node_id: str,
) -> tuple[tuple[str, ...], tuple[str, ...], str, str, str]:
    if failure_peer_snapshot.cluster_id != pre_step_peer_snapshot.cluster_id:
        raise HARollingRecoveryError("rolling_recovery_cluster_mismatch")
    pre_members = {member.node_id: member for member in pre_step_peer_snapshot.members}
    failure_members = {member.node_id: member for member in failure_peer_snapshot.members}
    if tuple(sorted(pre_members)) != tuple(sorted(failure_members)):
        raise HARollingRecoveryError("rolling_recovery_membership_changed")
    if failure_peer_snapshot.journal_seq <= pre_step_peer_snapshot.journal_seq:
        raise HARollingRecoveryError("rolling_recovery_peer_journal_not_advanced")

    failed_node = failure_members.get(failed_decision.target_node_id)
    pre_target = pre_members.get(failed_decision.target_node_id)
    if failed_node is None or pre_target is None:
        raise HARollingRecoveryError("rolling_recovery_target_missing")
    if pre_target.state is not PeerHealthState.READY:
        raise HARollingRecoveryError("rolling_recovery_pre_step_target_not_ready")
    if failed_node.state in (PeerHealthState.READY, PeerHealthState.UNKNOWN):
        raise HARollingRecoveryError("rolling_recovery_failure_not_proven")
    if failed_node.state_revision == pre_target.state_revision:
        raise HARollingRecoveryError("rolling_recovery_failure_revision_not_changed")

    for node_id, before in pre_members.items():
        if node_id == failed_decision.target_node_id:
            continue
        if failure_members[node_id] != before:
            raise HARollingRecoveryError("rolling_recovery_non_target_peer_drift")

    ready = tuple(
        sorted(
            member.node_id
            for member in failure_peer_snapshot.members
            if member.state is PeerHealthState.READY
        )
    )
    members = tuple(sorted(failure_members))
    if len(members) == 1:
        if not failed_decision.single_node_downtime_acknowledged:
            raise HARollingRecoveryError("single_node_downtime_not_acknowledged")
        if (
            failed_decision.minimum_ready_nodes != 0
            or writer_node_id != failed_decision.target_node_id
        ):
            raise HARollingRecoveryError("single_node_recovery_contract_invalid")
        mode = "single-node-rollback"
    else:
        if len(ready) < failed_decision.minimum_ready_nodes:
            raise HARollingRecoveryError("rolling_recovery_minimum_ready_not_met")
        if writer_node_id == failed_decision.target_node_id or writer_node_id not in ready:
            raise HARollingRecoveryError("rolling_recovery_writer_not_ready")
        mode = "ha-target-rollback"

    return members, ready, pre_target.state_revision, failed_node.state_revision, mode


def seal_rolling_recovery_handoff(
    *,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    expected_failure_peer_snapshot_id: str,
    expected_failure_peer_journal_seq: int,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RollingRecoveryHandoff:
    """Seal immutable evidence for a rollback handoff after one rolling step fails."""

    fresh_decision = revalidate_revision_bound_rolling_safety(
        decision=failed_decision,
        peer_snapshot=pre_step_peer_snapshot,
        role_authority=role_authority,
    )
    if fresh_decision != failed_decision:
        raise HARollingRecoveryError("rolling_recovery_failed_plan_stale")
    if not failed_decision.safe or failed_decision.blockers:
        raise HARollingRecoveryError("rolling_recovery_failed_plan_was_not_safe")
    predecessor_checkpoint_id = _validate_predecessor(
        decision=failed_decision,
        predecessor_checkpoint=predecessor_checkpoint,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        role_authority=role_authority,
    )

    _require_exact_snapshot(
        failure_peer_snapshot,
        expected_snapshot_id=expected_failure_peer_snapshot_id,
        expected_journal_seq=expected_failure_peer_journal_seq,
        stale_code="rolling_recovery_failure_snapshot_stale",
    )
    node_ids = tuple(sorted(member.node_id for member in failure_peer_snapshot.members))
    before = role_authority.state_for(
        cluster_id=failure_peer_snapshot.cluster_id,
        node_ids=node_ids,
    )
    before_revision = _require_role_revision(before, failed_decision)
    writer = next(
        (item.node_id for item in before.snapshot.assignments if item.role.value == "writer"),
        None,
    )
    if writer is None:
        raise HARollingRecoveryError("rolling_recovery_writer_missing")

    members, ready, rollback_revision, failed_revision, mode = _validate_failure_observation(
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        writer_node_id=writer,
    )

    after = role_authority.state_for(
        cluster_id=failure_peer_snapshot.cluster_id,
        node_ids=node_ids,
    )
    if _require_role_revision(after, failed_decision) != before_revision:
        raise HARollingRecoveryError("role_revision_changed_during_recovery_handoff")

    provisional = RollingRecoveryHandoff(
        cluster_id=pre_step_peer_snapshot.cluster_id,
        handoff_id="pending",
        predecessor_checkpoint_id=predecessor_checkpoint_id,
        failed_plan_id=failed_decision.plan_id,
        failed_node_id=failed_decision.target_node_id,
        rollback_target_revision=rollback_revision,
        failed_observed_revision=failed_revision,
        pre_step_peer_snapshot_id=pre_step_peer_snapshot.snapshot_id,
        pre_step_peer_journal_seq=pre_step_peer_snapshot.journal_seq,
        failure_peer_snapshot_id=failure_peer_snapshot.snapshot_id,
        failure_peer_journal_seq=failure_peer_snapshot.journal_seq,
        member_node_ids=members,
        ready_node_ids=ready,
        minimum_ready_nodes=failed_decision.minimum_ready_nodes,
        writer_node_id=writer,
        role_assignment_id=failed_decision.role_assignment_id,
        role_epoch=failed_decision.role_epoch,
        role_resource_version=failed_decision.role_resource_version,
        role_journal_seq=failed_decision.role_journal_seq,
        role_transition_id=failed_decision.role_transition_id,
        recovery_mode=mode,
    )
    return replace(
        provisional,
        handoff_id=_handoff_id(_identity_material(provisional)),
    )


def revalidate_rolling_recovery_handoff(
    *,
    handoff: RollingRecoveryHandoff,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RollingRecoveryHandoff:
    """Reject saved recovery evidence after any peer, plan, or role-journal drift."""

    _verify_handoff_identity(handoff)
    if failed_decision.plan_id != handoff.failed_plan_id:
        raise HARollingRecoveryError("rolling_recovery_failed_plan_stale")
    expected_predecessor_id = (
        predecessor_checkpoint.checkpoint_id if predecessor_checkpoint is not None else None
    )
    if expected_predecessor_id != handoff.predecessor_checkpoint_id:
        raise HARollingRecoveryError("rolling_recovery_predecessor_checkpoint_stale")
    if pre_step_peer_snapshot.snapshot_id != handoff.pre_step_peer_snapshot_id:
        raise HARollingRecoveryError("rolling_recovery_pre_step_snapshot_stale")
    if pre_step_peer_snapshot.journal_seq != handoff.pre_step_peer_journal_seq:
        raise HARollingRecoveryError("rolling_recovery_pre_step_journal_stale")
    fresh = seal_rolling_recovery_handoff(
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        role_authority=role_authority,
        expected_failure_peer_snapshot_id=handoff.failure_peer_snapshot_id,
        expected_failure_peer_journal_seq=handoff.failure_peer_journal_seq,
        predecessor_checkpoint=predecessor_checkpoint,
    )
    if fresh != handoff:
        raise HARollingRecoveryError("rolling_recovery_handoff_stale")
    return handoff
