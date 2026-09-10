"""Seal rollback completion and recovery-to-ready evidence for rolling HA recovery."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

from .ha_peer_snapshot import HAPeerStateSnapshot, PeerHealthState
from .ha_rolling_authority import build_role_assignment_snapshot
from .ha_rolling_checkpoint import RollingStepCheckpoint
from .ha_rolling_recovery import (
    RollingRecoveryHandoff,
    revalidate_rolling_recovery_handoff,
)
from .ha_rolling_revision import HARoleRevisionAuthority, RevisionBoundRollingSafetyDecision


class HARollingRecoveryCompletionError(ValueError):
    """Stable fail-closed error for rolling recovery completion evidence."""


@dataclass(frozen=True, slots=True)
class RollingRecoveryCompletionReceipt:
    cluster_id: str
    receipt_id: str
    recovery_handoff_id: str
    predecessor_checkpoint_id: str | None
    failed_plan_id: str
    recovered_node_id: str
    rollback_target_revision: str
    failure_peer_snapshot_id: str
    failure_peer_journal_seq: int
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
    recovery_mode: str
    rollback_completed: bool = True
    ready_for_reassessment: bool = True
    next_step_authorized: bool = False
    failover_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-recovery-completion.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "receipt_id": self.receipt_id,
            "recovery_handoff_id": self.recovery_handoff_id,
            "predecessor_checkpoint_id": self.predecessor_checkpoint_id,
            "failed_plan_id": self.failed_plan_id,
            "recovered_node_id": self.recovered_node_id,
            "rollback_target_revision": self.rollback_target_revision,
            "failure_peer_snapshot_id": self.failure_peer_snapshot_id,
            "failure_peer_journal_seq": self.failure_peer_journal_seq,
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
            "recovery_mode": self.recovery_mode,
            "rollback_completed": self.rollback_completed,
            "ready_for_reassessment": self.ready_for_reassessment,
            "next_step_authorized": self.next_step_authorized,
            "failover_authorized": self.failover_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


@dataclass(frozen=True, slots=True)
class RollingRecoveryReadyGate:
    cluster_id: str
    gate_id: str
    completion_receipt_id: str
    recovery_handoff_id: str
    recovered_node_id: str
    completion_peer_snapshot_id: str
    completion_peer_journal_seq: int
    role_assignment_id: str
    role_epoch: int
    role_resource_version: int
    role_journal_seq: int
    role_transition_id: str
    reassessment_authorized: bool = True
    next_step_authorized: bool = False
    execution_authorized: bool = False
    failover_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-recovery-ready-gate.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "gate_id": self.gate_id,
            "completion_receipt_id": self.completion_receipt_id,
            "recovery_handoff_id": self.recovery_handoff_id,
            "recovered_node_id": self.recovered_node_id,
            "completion_peer_snapshot_id": self.completion_peer_snapshot_id,
            "completion_peer_journal_seq": self.completion_peer_journal_seq,
            "role_assignment_id": self.role_assignment_id,
            "role_epoch": self.role_epoch,
            "role_resource_version": self.role_resource_version,
            "role_journal_seq": self.role_journal_seq,
            "role_transition_id": self.role_transition_id,
            "reassessment_authorized": self.reassessment_authorized,
            "next_step_authorized": self.next_step_authorized,
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


def _stable_id(prefix: str, material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"{prefix}{digest}"


def _receipt_material(receipt: RollingRecoveryCompletionReceipt) -> dict[str, object]:
    data = receipt.to_dict()
    data.pop("receipt_id")
    return data


def _gate_material(gate: RollingRecoveryReadyGate) -> dict[str, object]:
    data = gate.to_dict()
    data.pop("gate_id")
    return data


def _require_exact_snapshot(
    snapshot: HAPeerStateSnapshot,
    *,
    expected_snapshot_id: str,
    expected_journal_seq: int,
    stale_code: str,
) -> None:
    if _snapshot_identity(snapshot) != snapshot.snapshot_id:
        raise HARollingRecoveryCompletionError("peer_snapshot_identity_invalid")
    if snapshot.snapshot_id != expected_snapshot_id or snapshot.journal_seq != expected_journal_seq:
        raise HARollingRecoveryCompletionError(stale_code)


def _role_revision(state: object) -> tuple[object, ...]:
    snapshot = state.snapshot
    canonical = build_role_assignment_snapshot(
        cluster_id=snapshot.cluster_id,
        role_epoch=snapshot.role_epoch,
        assignments=snapshot.assignments,
    )
    if canonical.assignment_id != snapshot.assignment_id:
        raise HARollingRecoveryCompletionError("role_assignment_identity_invalid")
    if state.production_mutation_enabled:
        raise HARollingRecoveryCompletionError("role_authority_mutation_enabled")
    return (
        snapshot.assignment_id,
        snapshot.role_epoch,
        state.resource_version,
        state.journal_seq,
        state.transition_id,
    )


def _require_role_revision(
    state: object,
    handoff: RollingRecoveryHandoff,
) -> tuple[object, ...]:
    revision = _role_revision(state)
    expected = (
        handoff.role_assignment_id,
        handoff.role_epoch,
        handoff.role_resource_version,
        handoff.role_journal_seq,
        handoff.role_transition_id,
    )
    if revision != expected:
        raise HARollingRecoveryCompletionError("rolling_recovery_role_revision_stale")
    return revision


def _verify_receipt_identity(receipt: RollingRecoveryCompletionReceipt) -> None:
    if receipt.schema != "home-center.ha-rolling-recovery-completion.v1":
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_schema_invalid")
    if (
        not receipt.rollback_completed
        or not receipt.ready_for_reassessment
        or receipt.next_step_authorized
        or receipt.failover_authorized
        or receipt.production_mutation_enabled
    ):
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_authority_invalid")
    expected = _stable_id("ha-roll-recovery-complete-", _receipt_material(receipt))
    if receipt.receipt_id != expected:
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_identity_invalid")


def _verify_gate_identity(gate: RollingRecoveryReadyGate) -> None:
    if gate.schema != "home-center.ha-rolling-recovery-ready-gate.v1":
        raise HARollingRecoveryCompletionError("rolling_recovery_ready_gate_schema_invalid")
    if (
        not gate.reassessment_authorized
        or gate.next_step_authorized
        or gate.execution_authorized
        or gate.failover_authorized
        or gate.production_mutation_enabled
    ):
        raise HARollingRecoveryCompletionError("rolling_recovery_ready_gate_authority_invalid")
    expected = _stable_id("ha-roll-recovery-ready-", _gate_material(gate))
    if gate.gate_id != expected:
        raise HARollingRecoveryCompletionError("rolling_recovery_ready_gate_identity_invalid")


def _validate_recovery_observation(
    *,
    handoff: RollingRecoveryHandoff,
    failure_peer_snapshot: HAPeerStateSnapshot,
    completion_peer_snapshot: HAPeerStateSnapshot,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if completion_peer_snapshot.cluster_id != handoff.cluster_id:
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_cluster_mismatch")
    if completion_peer_snapshot.journal_seq <= failure_peer_snapshot.journal_seq:
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_journal_not_advanced")

    failure = {member.node_id: member for member in failure_peer_snapshot.members}
    completion = {member.node_id: member for member in completion_peer_snapshot.members}
    members = tuple(sorted(completion))
    if members != handoff.member_node_ids or tuple(sorted(failure)) != handoff.member_node_ids:
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_membership_changed")

    recovered = completion.get(handoff.failed_node_id)
    failed = failure.get(handoff.failed_node_id)
    if recovered is None or failed is None:
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_target_missing")
    if recovered.state is not PeerHealthState.READY:
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_target_not_ready")
    if recovered.state_revision != handoff.rollback_target_revision:
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_revision_mismatch")
    if failed.state_revision != handoff.failed_observed_revision:
        raise HARollingRecoveryCompletionError("rolling_recovery_failure_revision_stale")

    for node_id, before in failure.items():
        if node_id == handoff.failed_node_id:
            continue
        if completion[node_id] != before:
            raise HARollingRecoveryCompletionError("rolling_recovery_completion_non_target_drift")

    ready = tuple(
        sorted(
            member.node_id
            for member in completion_peer_snapshot.members
            if member.state is PeerHealthState.READY
        )
    )
    if len(members) == 1:
        if (
            handoff.recovery_mode != "single-node-rollback"
            or handoff.minimum_ready_nodes != 0
            or handoff.writer_node_id != handoff.failed_node_id
            or ready != members
        ):
            raise HARollingRecoveryCompletionError("single_node_recovery_completion_invalid")
    else:
        if handoff.recovery_mode != "ha-target-rollback":
            raise HARollingRecoveryCompletionError("ha_recovery_completion_mode_invalid")
        if len(ready) < handoff.minimum_ready_nodes + 1:
            raise HARollingRecoveryCompletionError("rolling_recovery_ready_floor_not_restored")
        if handoff.writer_node_id not in ready:
            raise HARollingRecoveryCompletionError("rolling_recovery_writer_not_ready")

    return members, ready


def seal_rolling_recovery_completion(
    *,
    handoff: RollingRecoveryHandoff,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    expected_completion_peer_snapshot_id: str,
    expected_completion_peer_journal_seq: int,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RollingRecoveryCompletionReceipt:
    """Seal proof that rollback restored the exact pre-step revision and readiness floor."""

    revalidate_rolling_recovery_handoff(
        handoff=handoff,
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        role_authority=role_authority,
        predecessor_checkpoint=predecessor_checkpoint,
    )
    _require_exact_snapshot(
        completion_peer_snapshot,
        expected_snapshot_id=expected_completion_peer_snapshot_id,
        expected_journal_seq=expected_completion_peer_journal_seq,
        stale_code="rolling_recovery_completion_snapshot_stale",
    )

    node_ids = tuple(sorted(member.node_id for member in completion_peer_snapshot.members))
    before = role_authority.state_for(cluster_id=handoff.cluster_id, node_ids=node_ids)
    before_revision = _require_role_revision(before, handoff)
    members, ready = _validate_recovery_observation(
        handoff=handoff,
        failure_peer_snapshot=failure_peer_snapshot,
        completion_peer_snapshot=completion_peer_snapshot,
    )
    after = role_authority.state_for(cluster_id=handoff.cluster_id, node_ids=node_ids)
    if _require_role_revision(after, handoff) != before_revision:
        raise HARollingRecoveryCompletionError("role_revision_changed_during_recovery_completion")

    provisional = RollingRecoveryCompletionReceipt(
        cluster_id=handoff.cluster_id,
        receipt_id="pending",
        recovery_handoff_id=handoff.handoff_id,
        predecessor_checkpoint_id=handoff.predecessor_checkpoint_id,
        failed_plan_id=handoff.failed_plan_id,
        recovered_node_id=handoff.failed_node_id,
        rollback_target_revision=handoff.rollback_target_revision,
        failure_peer_snapshot_id=handoff.failure_peer_snapshot_id,
        failure_peer_journal_seq=handoff.failure_peer_journal_seq,
        completion_peer_snapshot_id=completion_peer_snapshot.snapshot_id,
        completion_peer_journal_seq=completion_peer_snapshot.journal_seq,
        member_node_ids=members,
        ready_node_ids=ready,
        minimum_ready_nodes=handoff.minimum_ready_nodes,
        writer_node_id=handoff.writer_node_id,
        role_assignment_id=handoff.role_assignment_id,
        role_epoch=handoff.role_epoch,
        role_resource_version=handoff.role_resource_version,
        role_journal_seq=handoff.role_journal_seq,
        role_transition_id=handoff.role_transition_id,
        recovery_mode=handoff.recovery_mode,
    )
    return replace(
        provisional,
        receipt_id=_stable_id("ha-roll-recovery-complete-", _receipt_material(provisional)),
    )


def revalidate_rolling_recovery_completion(
    *,
    receipt: RollingRecoveryCompletionReceipt,
    handoff: RollingRecoveryHandoff,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RollingRecoveryCompletionReceipt:
    """Reject saved completion evidence after any recovery, peer, or role drift."""

    _verify_receipt_identity(receipt)
    if receipt.recovery_handoff_id != handoff.handoff_id:
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_handoff_stale")
    fresh = seal_rolling_recovery_completion(
        handoff=handoff,
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        completion_peer_snapshot=completion_peer_snapshot,
        role_authority=role_authority,
        expected_completion_peer_snapshot_id=receipt.completion_peer_snapshot_id,
        expected_completion_peer_journal_seq=receipt.completion_peer_journal_seq,
        predecessor_checkpoint=predecessor_checkpoint,
    )
    if fresh != receipt:
        raise HARollingRecoveryCompletionError("rolling_recovery_completion_stale")
    return receipt


def seal_rolling_recovery_ready_gate(
    *,
    receipt: RollingRecoveryCompletionReceipt,
    handoff: RollingRecoveryHandoff,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RollingRecoveryReadyGate:
    """Authorize only fresh safety reassessment after verified rollback completion."""

    revalidate_rolling_recovery_completion(
        receipt=receipt,
        handoff=handoff,
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        completion_peer_snapshot=completion_peer_snapshot,
        role_authority=role_authority,
        predecessor_checkpoint=predecessor_checkpoint,
    )
    provisional = RollingRecoveryReadyGate(
        cluster_id=receipt.cluster_id,
        gate_id="pending",
        completion_receipt_id=receipt.receipt_id,
        recovery_handoff_id=receipt.recovery_handoff_id,
        recovered_node_id=receipt.recovered_node_id,
        completion_peer_snapshot_id=receipt.completion_peer_snapshot_id,
        completion_peer_journal_seq=receipt.completion_peer_journal_seq,
        role_assignment_id=receipt.role_assignment_id,
        role_epoch=receipt.role_epoch,
        role_resource_version=receipt.role_resource_version,
        role_journal_seq=receipt.role_journal_seq,
        role_transition_id=receipt.role_transition_id,
    )
    return replace(
        provisional,
        gate_id=_stable_id("ha-roll-recovery-ready-", _gate_material(provisional)),
    )


def revalidate_rolling_recovery_ready_gate(
    *,
    gate: RollingRecoveryReadyGate,
    receipt: RollingRecoveryCompletionReceipt,
    handoff: RollingRecoveryHandoff,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RollingRecoveryReadyGate:
    """Reject a ready gate after any completion evidence or HA revision drift."""

    _verify_gate_identity(gate)
    fresh = seal_rolling_recovery_ready_gate(
        receipt=receipt,
        handoff=handoff,
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        completion_peer_snapshot=completion_peer_snapshot,
        role_authority=role_authority,
        predecessor_checkpoint=predecessor_checkpoint,
    )
    if fresh != gate:
        raise HARollingRecoveryCompletionError("rolling_recovery_ready_gate_stale")
    return gate
