"""Staged, replay-safe writer handoff for a blocked Home Center HA rolling step."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import Protocol

from .ha_peer_snapshot import HAPeerStateSnapshot, PeerHealthState
from .ha_role_journal import HARoleTransitionKind
from .ha_rolling_authority import HARoleAssignment
from .ha_rolling_revision import (
    HARoleAuthorityStateView,
    HARoleRevisionAuthority,
    RevisionBoundRollingSafetyDecision,
    evaluate_revision_bound_rolling_safety,
    revalidate_revision_bound_rolling_safety,
)
from .ha_rolling_safety import NodeRole

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")


class HARollingWriterHandoffError(ValueError):
    """Stable fail-closed error for staged rolling writer handoff."""


class HARollingWriterHandoffAuthority(HARoleRevisionAuthority, Protocol):
    def transition(
        self,
        *,
        cluster_id: str,
        assignments: tuple[HARoleAssignment, ...],
        transition_kind: HARoleTransitionKind,
        expected_assignment_id: str,
        expected_role_epoch: int,
        expected_resource_version: int,
        expected_journal_seq: int,
    ) -> HARoleAuthorityStateView: ...


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffIntent:
    cluster_id: str
    intent_id: str
    blocked_plan_id: str
    target_writer_node_id: str
    successor_writer_node_id: str
    member_node_ids: tuple[str, ...]
    peer_snapshot_id: str
    peer_journal_seq: int
    role_assignment_id: str
    role_epoch: int
    role_resource_version: int
    role_journal_seq: int
    role_transition_id: str
    minimum_ready_nodes: int
    required_quorum_nodes: int
    ready_before: int
    ready_after_target_stops: int
    required_predecessor_node_id: str | None
    required_predecessor_revision: str | None
    transition_kind: str = "election"
    transition_reason: str = "rolling_writer_handoff"
    cas_bound: bool = True
    single_use_by_cas: bool = True
    execution_authorized: bool = False
    failover_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-writer-handoff-intent.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "intent_id": self.intent_id,
            "blocked_plan_id": self.blocked_plan_id,
            "target_writer_node_id": self.target_writer_node_id,
            "successor_writer_node_id": self.successor_writer_node_id,
            "member_node_ids": list(self.member_node_ids),
            "peer_snapshot_id": self.peer_snapshot_id,
            "peer_journal_seq": self.peer_journal_seq,
            "role_assignment_id": self.role_assignment_id,
            "role_epoch": self.role_epoch,
            "role_resource_version": self.role_resource_version,
            "role_journal_seq": self.role_journal_seq,
            "role_transition_id": self.role_transition_id,
            "minimum_ready_nodes": self.minimum_ready_nodes,
            "required_quorum_nodes": self.required_quorum_nodes,
            "ready_before": self.ready_before,
            "ready_after_target_stops": self.ready_after_target_stops,
            "required_predecessor_node_id": self.required_predecessor_node_id,
            "required_predecessor_revision": self.required_predecessor_revision,
            "transition_kind": self.transition_kind,
            "transition_reason": self.transition_reason,
            "cas_bound": self.cas_bound,
            "single_use_by_cas": self.single_use_by_cas,
            "execution_authorized": self.execution_authorized,
            "failover_authorized": self.failover_authorized,
            "host_mutation_authorized": self.host_mutation_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffReceipt:
    cluster_id: str
    receipt_id: str
    intent_id: str
    blocked_plan_id: str
    target_writer_node_id: str
    successor_writer_node_id: str
    peer_snapshot_id: str
    peer_journal_seq: int
    previous_role_assignment_id: str
    previous_role_epoch: int
    previous_role_resource_version: int
    previous_role_journal_seq: int
    previous_role_transition_id: str
    role_assignment_id: str
    role_epoch: int
    role_resource_version: int
    role_journal_seq: int
    role_transition_id: str
    transition_kind: str = "election"
    transition_reason: str = "rolling_writer_handoff"
    writer_handoff_completed: bool = True
    execution_authorized: bool = False
    failover_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-writer-handoff-receipt.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "blocked_plan_id": self.blocked_plan_id,
            "target_writer_node_id": self.target_writer_node_id,
            "successor_writer_node_id": self.successor_writer_node_id,
            "peer_snapshot_id": self.peer_snapshot_id,
            "peer_journal_seq": self.peer_journal_seq,
            "previous_role_assignment_id": self.previous_role_assignment_id,
            "previous_role_epoch": self.previous_role_epoch,
            "previous_role_resource_version": self.previous_role_resource_version,
            "previous_role_journal_seq": self.previous_role_journal_seq,
            "previous_role_transition_id": self.previous_role_transition_id,
            "role_assignment_id": self.role_assignment_id,
            "role_epoch": self.role_epoch,
            "role_resource_version": self.role_resource_version,
            "role_journal_seq": self.role_journal_seq,
            "role_transition_id": self.role_transition_id,
            "transition_kind": self.transition_kind,
            "transition_reason": self.transition_reason,
            "writer_handoff_completed": self.writer_handoff_completed,
            "execution_authorized": self.execution_authorized,
            "failover_authorized": self.failover_authorized,
            "host_mutation_authorized": self.host_mutation_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


def _stable_id(prefix: str, material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"{prefix}-{digest}"


def _intent_material(intent: RollingWriterHandoffIntent) -> dict[str, object]:
    material = intent.to_dict()
    material.pop("intent_id")
    return material


def _receipt_material(receipt: RollingWriterHandoffReceipt) -> dict[str, object]:
    material = receipt.to_dict()
    material.pop("receipt_id")
    return material


def _verify_peer_evidence(snapshot: HAPeerStateSnapshot) -> None:
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
        raise HARollingWriterHandoffError("rolling_writer_handoff_peer_identity_invalid")


def _verify_intent(intent: RollingWriterHandoffIntent) -> None:
    if intent.schema != "home-center.ha-rolling-writer-handoff-intent.v1":
        raise HARollingWriterHandoffError("rolling_writer_handoff_intent_schema_invalid")
    if (
        not intent.cas_bound
        or not intent.single_use_by_cas
        or intent.execution_authorized
        or intent.failover_authorized
        or intent.host_mutation_authorized
        or intent.production_mutation_enabled
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_intent_authority_invalid")
    if (
        intent.transition_kind != HARoleTransitionKind.ELECTION.value
        or intent.transition_reason != "rolling_writer_handoff"
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_transition_invalid")
    if (
        IDENTIFIER.fullmatch(intent.cluster_id) is None
        or IDENTIFIER.fullmatch(intent.target_writer_node_id) is None
        or IDENTIFIER.fullmatch(intent.successor_writer_node_id) is None
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_identity_field_invalid")
    if intent.target_writer_node_id == intent.successor_writer_node_id:
        raise HARollingWriterHandoffError("rolling_writer_handoff_successor_invalid")
    if (
        len(intent.member_node_ids) < 2
        or tuple(sorted(intent.member_node_ids)) != intent.member_node_ids
        or len(set(intent.member_node_ids)) != len(intent.member_node_ids)
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_membership_invalid")
    if (
        intent.target_writer_node_id not in intent.member_node_ids
        or intent.successor_writer_node_id not in intent.member_node_ids
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_member_binding_invalid")
    revisions = (
        intent.peer_journal_seq,
        intent.role_epoch,
        intent.role_resource_version,
        intent.role_journal_seq,
        intent.minimum_ready_nodes,
        intent.required_quorum_nodes,
        intent.ready_before,
        intent.ready_after_target_stops,
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in revisions
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_revision_invalid")
    if intent.role_resource_version < 1 or intent.role_journal_seq < 1:
        raise HARollingWriterHandoffError("rolling_writer_handoff_revision_invalid")
    if intent.minimum_ready_nodes < 1:
        raise HARollingWriterHandoffError("rolling_writer_handoff_ready_floor_invalid")
    expected_quorum = len(intent.member_node_ids) // 2 + 1
    if intent.required_quorum_nodes != expected_quorum:
        raise HARollingWriterHandoffError("rolling_writer_handoff_quorum_invalid")
    if intent.ready_before < intent.required_quorum_nodes:
        raise HARollingWriterHandoffError("rolling_writer_handoff_quorum_not_met")
    if intent.ready_after_target_stops < intent.minimum_ready_nodes:
        raise HARollingWriterHandoffError("rolling_writer_handoff_ready_floor_invalid")
    if intent.intent_id != _stable_id("ha-roll-writer-handoff", _intent_material(intent)):
        raise HARollingWriterHandoffError("rolling_writer_handoff_intent_identity_invalid")


def _verify_receipt(receipt: RollingWriterHandoffReceipt) -> None:
    if receipt.schema != "home-center.ha-rolling-writer-handoff-receipt.v1":
        raise HARollingWriterHandoffError("rolling_writer_handoff_receipt_schema_invalid")
    if (
        not receipt.writer_handoff_completed
        or receipt.execution_authorized
        or receipt.failover_authorized
        or receipt.host_mutation_authorized
        or receipt.production_mutation_enabled
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_receipt_authority_invalid")
    if (
        receipt.transition_kind != HARoleTransitionKind.ELECTION.value
        or receipt.transition_reason != "rolling_writer_handoff"
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_transition_invalid")
    if receipt.target_writer_node_id == receipt.successor_writer_node_id:
        raise HARollingWriterHandoffError("rolling_writer_handoff_successor_invalid")
    if (
        receipt.role_epoch != receipt.previous_role_epoch + 1
        or receipt.role_resource_version != receipt.previous_role_resource_version + 1
        or receipt.role_journal_seq != receipt.previous_role_journal_seq + 1
        or receipt.role_assignment_id == receipt.previous_role_assignment_id
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_receipt_revision_invalid")
    if receipt.receipt_id != _stable_id(
        "ha-roll-writer-handoff-receipt", _receipt_material(receipt)
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_receipt_identity_invalid")


def _decision_binding(decision: RevisionBoundRollingSafetyDecision) -> tuple[object, ...]:
    return (
        decision.plan_id,
        decision.target_node_id,
        decision.peer_snapshot_id,
        decision.peer_journal_seq,
        decision.role_assignment_id,
        decision.role_epoch,
        decision.role_resource_version,
        decision.role_journal_seq,
        decision.role_transition_id,
        decision.minimum_ready_nodes,
        decision.ready_before,
        decision.ready_after_target_stops,
        decision.writer_node_id,
        decision.required_predecessor_node_id,
        decision.required_predecessor_revision,
    )


def _intent_binding(intent: RollingWriterHandoffIntent) -> tuple[object, ...]:
    return (
        intent.blocked_plan_id,
        intent.target_writer_node_id,
        intent.peer_snapshot_id,
        intent.peer_journal_seq,
        intent.role_assignment_id,
        intent.role_epoch,
        intent.role_resource_version,
        intent.role_journal_seq,
        intent.role_transition_id,
        intent.minimum_ready_nodes,
        intent.ready_before,
        intent.ready_after_target_stops,
        intent.target_writer_node_id,
        intent.required_predecessor_node_id,
        intent.required_predecessor_revision,
    )


def _state_matches_old_intent(
    state: HARoleAuthorityStateView,
    intent: RollingWriterHandoffIntent,
) -> bool:
    return (
        state.snapshot.assignment_id == intent.role_assignment_id
        and state.snapshot.role_epoch == intent.role_epoch
        and state.resource_version == intent.role_resource_version
        and state.journal_seq == intent.role_journal_seq
        and state.transition_id == intent.role_transition_id
    )


def _state_matches_decision(
    state: HARoleAuthorityStateView,
    decision: RevisionBoundRollingSafetyDecision,
) -> bool:
    return (
        state.snapshot.assignment_id == decision.role_assignment_id
        and state.snapshot.role_epoch == decision.role_epoch
        and state.resource_version == decision.role_resource_version
        and state.journal_seq == decision.role_journal_seq
        and state.transition_id == decision.role_transition_id
    )


def _handoff_assignments(
    intent: RollingWriterHandoffIntent,
) -> tuple[HARoleAssignment, ...]:
    return tuple(
        HARoleAssignment(
            node_id,
            NodeRole.WRITER if node_id == intent.successor_writer_node_id else NodeRole.STANDBY,
        )
        for node_id in intent.member_node_ids
    )


def _require_post_state(
    state: HARoleAuthorityStateView,
    *,
    intent: RollingWriterHandoffIntent,
) -> None:
    if (
        state.snapshot.role_epoch != intent.role_epoch + 1
        or state.resource_version != intent.role_resource_version + 1
        or state.journal_seq != intent.role_journal_seq + 1
        or state.transition_kind != HARoleTransitionKind.ELECTION.value
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_post_revision_invalid")
    expected = _handoff_assignments(intent)
    if state.snapshot.assignments != expected:
        raise HARollingWriterHandoffError("rolling_writer_handoff_post_assignment_invalid")
    writers = tuple(
        item.node_id for item in state.snapshot.assignments if item.role is NodeRole.WRITER
    )
    if writers != (intent.successor_writer_node_id,):
        raise HARollingWriterHandoffError("rolling_writer_handoff_writer_not_unique")


def plan_rolling_writer_handoff(
    *,
    decision: RevisionBoundRollingSafetyDecision,
    peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
) -> RollingWriterHandoffIntent:
    """Plan a deterministic writer handoff only when it is the sole rolling blocker."""

    fresh = revalidate_revision_bound_rolling_safety(
        decision=decision,
        peer_snapshot=peer_snapshot,
        role_authority=role_authority,
    )
    if fresh != decision:
        raise HARollingWriterHandoffError("rolling_writer_handoff_decision_stale")
    if decision.safe or decision.blockers != ("writer_handoff_required",):
        raise HARollingWriterHandoffError("rolling_writer_handoff_not_required")
    if decision.writer_node_id != decision.target_node_id:
        raise HARollingWriterHandoffError("rolling_writer_handoff_target_not_writer")

    member_node_ids = tuple(sorted(member.node_id for member in peer_snapshot.members))
    if len(member_node_ids) < 2:
        raise HARollingWriterHandoffError("rolling_writer_handoff_requires_ha")

    state = role_authority.state_for(
        cluster_id=peer_snapshot.cluster_id,
        node_ids=member_node_ids,
    )
    if not _state_matches_decision(state, decision):
        raise HARollingWriterHandoffError("rolling_writer_handoff_role_stale")

    ready = {
        member.node_id
        for member in peer_snapshot.members
        if member.state is PeerHealthState.READY
    }
    role_by_node = {item.node_id: item.role for item in state.snapshot.assignments}
    candidates = tuple(
        node_id
        for node_id in member_node_ids
        if node_id in ready and role_by_node.get(node_id) is NodeRole.STANDBY
    )
    if not candidates:
        raise HARollingWriterHandoffError("rolling_writer_handoff_no_ready_successor")
    successor = candidates[0]

    provisional = RollingWriterHandoffIntent(
        cluster_id=peer_snapshot.cluster_id,
        intent_id="pending",
        blocked_plan_id=decision.plan_id,
        target_writer_node_id=decision.target_node_id,
        successor_writer_node_id=successor,
        member_node_ids=member_node_ids,
        peer_snapshot_id=decision.peer_snapshot_id,
        peer_journal_seq=decision.peer_journal_seq,
        role_assignment_id=decision.role_assignment_id,
        role_epoch=decision.role_epoch,
        role_resource_version=decision.role_resource_version,
        role_journal_seq=decision.role_journal_seq,
        role_transition_id=decision.role_transition_id,
        minimum_ready_nodes=decision.minimum_ready_nodes,
        required_quorum_nodes=len(member_node_ids) // 2 + 1,
        ready_before=decision.ready_before,
        ready_after_target_stops=decision.ready_after_target_stops,
        required_predecessor_node_id=decision.required_predecessor_node_id,
        required_predecessor_revision=decision.required_predecessor_revision,
    )
    result = replace(
        provisional,
        intent_id=_stable_id("ha-roll-writer-handoff", _intent_material(provisional)),
    )
    _verify_intent(result)
    return result


def commit_rolling_writer_handoff(
    *,
    intent: RollingWriterHandoffIntent,
    decision: RevisionBoundRollingSafetyDecision,
    peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARollingWriterHandoffAuthority,
) -> RollingWriterHandoffReceipt:
    """CAS a typed role-journal election; exact retry is idempotent."""

    _verify_intent(intent)
    _verify_peer_evidence(peer_snapshot)
    peer_snapshot.require_exact(
        expected_snapshot_id=intent.peer_snapshot_id,
        expected_journal_seq=intent.peer_journal_seq,
    )
    if peer_snapshot.cluster_id != intent.cluster_id:
        raise HARollingWriterHandoffError("rolling_writer_handoff_cluster_mismatch")
    if (
        tuple(sorted(member.node_id for member in peer_snapshot.members))
        != intent.member_node_ids
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_membership_stale")
    if _decision_binding(decision) != _intent_binding(intent):
        raise HARollingWriterHandoffError("rolling_writer_handoff_decision_binding_drift")

    current = role_authority.state_for(
        cluster_id=intent.cluster_id,
        node_ids=intent.member_node_ids,
    )
    if _state_matches_old_intent(current, intent):
        fresh_intent = plan_rolling_writer_handoff(
            decision=decision,
            peer_snapshot=peer_snapshot,
            role_authority=role_authority,
        )
        if fresh_intent != intent:
            raise HARollingWriterHandoffError("rolling_writer_handoff_intent_stale")

    changed = role_authority.transition(
        cluster_id=intent.cluster_id,
        assignments=_handoff_assignments(intent),
        transition_kind=HARoleTransitionKind.ELECTION,
        expected_assignment_id=intent.role_assignment_id,
        expected_role_epoch=intent.role_epoch,
        expected_resource_version=intent.role_resource_version,
        expected_journal_seq=intent.role_journal_seq,
    )
    _require_post_state(changed, intent=intent)

    provisional = RollingWriterHandoffReceipt(
        cluster_id=intent.cluster_id,
        receipt_id="pending",
        intent_id=intent.intent_id,
        blocked_plan_id=intent.blocked_plan_id,
        target_writer_node_id=intent.target_writer_node_id,
        successor_writer_node_id=intent.successor_writer_node_id,
        peer_snapshot_id=intent.peer_snapshot_id,
        peer_journal_seq=intent.peer_journal_seq,
        previous_role_assignment_id=intent.role_assignment_id,
        previous_role_epoch=intent.role_epoch,
        previous_role_resource_version=intent.role_resource_version,
        previous_role_journal_seq=intent.role_journal_seq,
        previous_role_transition_id=intent.role_transition_id,
        role_assignment_id=changed.snapshot.assignment_id,
        role_epoch=changed.snapshot.role_epoch,
        role_resource_version=changed.resource_version,
        role_journal_seq=changed.journal_seq,
        role_transition_id=changed.transition_id,
    )
    result = replace(
        provisional,
        receipt_id=_stable_id(
            "ha-roll-writer-handoff-receipt",
            _receipt_material(provisional),
        ),
    )
    _verify_receipt(result)
    return result


def revalidate_rolling_writer_handoff_receipt(
    *,
    receipt: RollingWriterHandoffReceipt,
    intent: RollingWriterHandoffIntent,
    peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARollingWriterHandoffAuthority,
) -> RollingWriterHandoffReceipt:
    """Reject saved handoff evidence after peer or role-journal drift."""

    _verify_receipt(receipt)
    _verify_intent(intent)
    if (
        receipt.intent_id != intent.intent_id
        or receipt.blocked_plan_id != intent.blocked_plan_id
        or receipt.target_writer_node_id != intent.target_writer_node_id
        or receipt.successor_writer_node_id != intent.successor_writer_node_id
        or receipt.peer_snapshot_id != intent.peer_snapshot_id
        or receipt.peer_journal_seq != intent.peer_journal_seq
        or receipt.previous_role_assignment_id != intent.role_assignment_id
        or receipt.previous_role_epoch != intent.role_epoch
        or receipt.previous_role_resource_version != intent.role_resource_version
        or receipt.previous_role_journal_seq != intent.role_journal_seq
        or receipt.previous_role_transition_id != intent.role_transition_id
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_receipt_binding_drift")

    _verify_peer_evidence(peer_snapshot)
    peer_snapshot.require_exact(
        expected_snapshot_id=receipt.peer_snapshot_id,
        expected_journal_seq=receipt.peer_journal_seq,
    )
    if peer_snapshot.cluster_id != receipt.cluster_id:
        raise HARollingWriterHandoffError("rolling_writer_handoff_cluster_mismatch")
    if (
        tuple(sorted(member.node_id for member in peer_snapshot.members))
        != intent.member_node_ids
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_membership_stale")

    state = role_authority.state_for(
        cluster_id=receipt.cluster_id,
        node_ids=intent.member_node_ids,
    )
    _require_post_state(state, intent=intent)
    if (
        state.snapshot.assignment_id != receipt.role_assignment_id
        or state.snapshot.role_epoch != receipt.role_epoch
        or state.resource_version != receipt.role_resource_version
        or state.journal_seq != receipt.role_journal_seq
        or state.transition_id != receipt.role_transition_id
    ):
        raise HARollingWriterHandoffError("rolling_writer_handoff_receipt_stale")
    return receipt


def evaluate_rolling_after_writer_handoff(
    *,
    receipt: RollingWriterHandoffReceipt,
    intent: RollingWriterHandoffIntent,
    peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARollingWriterHandoffAuthority,
) -> RevisionBoundRollingSafetyDecision:
    """Re-evaluate the same rolling target against the new exact role revision."""

    revalidate_rolling_writer_handoff_receipt(
        receipt=receipt,
        intent=intent,
        peer_snapshot=peer_snapshot,
        role_authority=role_authority,
    )
    return evaluate_revision_bound_rolling_safety(
        peer_snapshot=peer_snapshot,
        role_authority=role_authority,
        target_node_id=intent.target_writer_node_id,
        minimum_ready_nodes=intent.minimum_ready_nodes,
        expected_peer_snapshot_id=intent.peer_snapshot_id,
        expected_peer_journal_seq=intent.peer_journal_seq,
        expected_role_assignment_id=receipt.role_assignment_id,
        expected_role_epoch=receipt.role_epoch,
        expected_role_resource_version=receipt.role_resource_version,
        expected_role_journal_seq=receipt.role_journal_seq,
        expected_role_transition_id=receipt.role_transition_id,
        required_predecessor_node_id=intent.required_predecessor_node_id,
        required_predecessor_revision=intent.required_predecessor_revision,
    )
