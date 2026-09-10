"""Fail-closed recovery assessment for a completed rolling writer handoff."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum

from .ha_peer_snapshot import HAPeerStateSnapshot, PeerHealthState
from .ha_rolling_revision import HARoleRevisionAuthority
from .ha_rolling_safety import NodeRole
from .ha_rolling_writer_handoff import (
    RollingWriterHandoffIntent,
    RollingWriterHandoffReceipt,
)

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")


class HARollingWriterHandoffRecoveryError(ValueError):
    """Stable fail-closed error for writer-handoff recovery assessment."""


class WriterHandoffRecoveryDisposition(StrEnum):
    HEALTHY = "healthy"
    HOLD = "hold"
    RECONCILE = "reconcile"


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffRecoveryAssessment:
    cluster_id: str
    assessment_id: str
    handoff_receipt_id: str
    handoff_intent_id: str
    blocked_plan_id: str
    previous_writer_node_id: str
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
    ready_node_ids: tuple[str, ...]
    ready_count: int
    previous_writer_health: str
    successor_writer_health: str
    disposition: WriterHandoffRecoveryDisposition
    reason: str
    fencing_required: bool
    reconciliation_required: bool
    role_transition_authorized: bool = False
    failover_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-writer-handoff-recovery-assessment.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "assessment_id": self.assessment_id,
            "handoff_receipt_id": self.handoff_receipt_id,
            "handoff_intent_id": self.handoff_intent_id,
            "blocked_plan_id": self.blocked_plan_id,
            "previous_writer_node_id": self.previous_writer_node_id,
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
            "ready_node_ids": list(self.ready_node_ids),
            "ready_count": self.ready_count,
            "previous_writer_health": self.previous_writer_health,
            "successor_writer_health": self.successor_writer_health,
            "disposition": self.disposition.value,
            "reason": self.reason,
            "fencing_required": self.fencing_required,
            "reconciliation_required": self.reconciliation_required,
            "role_transition_authorized": self.role_transition_authorized,
            "failover_authorized": self.failover_authorized,
            "host_mutation_authorized": self.host_mutation_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


def _stable_id(prefix: str, material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"{prefix}-{digest}"


def _assessment_material(
    assessment: RollingWriterHandoffRecoveryAssessment,
) -> dict[str, object]:
    material = assessment.to_dict()
    material.pop("assessment_id")
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
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_peer_identity_invalid"
        )


def _verify_source_evidence(
    intent: RollingWriterHandoffIntent,
    receipt: RollingWriterHandoffReceipt,
) -> None:
    if intent.schema != "home-center.ha-rolling-writer-handoff-intent.v1":
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_source_intent_invalid"
        )
    if receipt.schema != "home-center.ha-rolling-writer-handoff-receipt.v1":
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_source_receipt_invalid"
        )
    if (
        not intent.cas_bound
        or not intent.single_use_by_cas
        or intent.execution_authorized
        or intent.failover_authorized
        or intent.host_mutation_authorized
        or intent.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_source_intent_authority_invalid"
        )
    if (
        not receipt.writer_handoff_completed
        or receipt.execution_authorized
        or receipt.failover_authorized
        or receipt.host_mutation_authorized
        or receipt.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_source_receipt_authority_invalid"
        )
    if (
        intent.cluster_id != receipt.cluster_id
        or intent.intent_id != receipt.intent_id
        or intent.blocked_plan_id != receipt.blocked_plan_id
        or intent.target_writer_node_id != receipt.target_writer_node_id
        or intent.successor_writer_node_id != receipt.successor_writer_node_id
        or intent.role_assignment_id != receipt.previous_role_assignment_id
        or intent.role_epoch != receipt.previous_role_epoch
        or intent.role_resource_version != receipt.previous_role_resource_version
        or intent.role_journal_seq != receipt.previous_role_journal_seq
        or intent.role_transition_id != receipt.previous_role_transition_id
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_source_binding_drift"
        )
    if (
        len(intent.member_node_ids) < 2
        or intent.member_node_ids != tuple(sorted(intent.member_node_ids))
        or len(intent.member_node_ids) != len(set(intent.member_node_ids))
        or intent.target_writer_node_id not in intent.member_node_ids
        or intent.successor_writer_node_id not in intent.member_node_ids
        or intent.target_writer_node_id == intent.successor_writer_node_id
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_source_membership_invalid"
        )
    if (
        receipt.role_epoch != receipt.previous_role_epoch + 1
        or receipt.role_resource_version != receipt.previous_role_resource_version + 1
        or receipt.role_journal_seq != receipt.previous_role_journal_seq + 1
        or receipt.role_assignment_id == receipt.previous_role_assignment_id
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_source_revision_invalid"
        )
    if (
        isinstance(intent.minimum_ready_nodes, bool)
        or not isinstance(intent.minimum_ready_nodes, int)
        or intent.minimum_ready_nodes < 1
        or intent.minimum_ready_nodes > len(intent.member_node_ids)
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_ready_floor_invalid"
        )


def _require_exact_handoff_role_state(
    *,
    intent: RollingWriterHandoffIntent,
    receipt: RollingWriterHandoffReceipt,
    role_authority: HARoleRevisionAuthority,
) -> None:
    state = role_authority.state_for(
        cluster_id=receipt.cluster_id,
        node_ids=intent.member_node_ids,
    )
    if (
        state.snapshot.assignment_id != receipt.role_assignment_id
        or state.snapshot.role_epoch != receipt.role_epoch
        or state.resource_version != receipt.role_resource_version
        or state.journal_seq != receipt.role_journal_seq
        or state.transition_id != receipt.role_transition_id
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_role_stale"
        )
    if tuple(item.node_id for item in state.snapshot.assignments) != intent.member_node_ids:
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_membership_stale"
        )
    writers = tuple(
        item.node_id for item in state.snapshot.assignments if item.role is NodeRole.WRITER
    )
    if writers != (receipt.successor_writer_node_id,):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_writer_state_invalid"
        )


def _verify_assessment(assessment: RollingWriterHandoffRecoveryAssessment) -> None:
    if assessment.schema != "home-center.ha-rolling-writer-handoff-recovery-assessment.v1":
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_assessment_schema_invalid"
        )
    if (
        assessment.role_transition_authorized
        or assessment.failover_authorized
        or assessment.host_mutation_authorized
        or assessment.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_assessment_authority_invalid"
        )
    if (
        IDENTIFIER.fullmatch(assessment.cluster_id) is None
        or assessment.member_node_ids != tuple(sorted(assessment.member_node_ids))
        or len(assessment.member_node_ids) < 2
        or len(assessment.member_node_ids) != len(set(assessment.member_node_ids))
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_assessment_membership_invalid"
        )
    expected_quorum = len(assessment.member_node_ids) // 2 + 1
    if assessment.required_quorum_nodes != expected_quorum:
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_assessment_quorum_invalid"
        )
    if (
        assessment.ready_node_ids != tuple(sorted(assessment.ready_node_ids))
        or assessment.ready_count != len(assessment.ready_node_ids)
        or not set(assessment.ready_node_ids).issubset(assessment.member_node_ids)
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_assessment_ready_invalid"
        )
    if assessment.disposition is WriterHandoffRecoveryDisposition.HEALTHY:
        expected = (
            assessment.successor_writer_health == PeerHealthState.READY.value
            and assessment.ready_count >= assessment.required_quorum_nodes
            and assessment.ready_count >= assessment.minimum_ready_nodes
            and assessment.reason == "handoff_healthy"
            and not assessment.fencing_required
            and not assessment.reconciliation_required
        )
    elif assessment.disposition is WriterHandoffRecoveryDisposition.HOLD:
        expected = (
            assessment.successor_writer_health == PeerHealthState.READY.value
            and assessment.reason in {"majority_quorum_not_met", "minimum_ready_not_met"}
            and not assessment.fencing_required
            and assessment.reconciliation_required
        )
    else:
        expected = (
            assessment.successor_writer_health != PeerHealthState.READY.value
            and assessment.reason
            in {
                "previous_writer_not_ready",
                "majority_quorum_not_met",
                "minimum_ready_not_met",
                "successor_not_ready_fencing_required",
            }
            and assessment.fencing_required
            and assessment.reconciliation_required
        )
    if not expected:
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_assessment_semantics_invalid"
        )
    if assessment.assessment_id != _stable_id(
        "ha-roll-writer-handoff-recovery", _assessment_material(assessment)
    ):
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_assessment_identity_invalid"
        )


def assess_rolling_writer_handoff_recovery(
    *,
    intent: RollingWriterHandoffIntent,
    receipt: RollingWriterHandoffReceipt,
    peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
) -> RollingWriterHandoffRecoveryAssessment:
    """Assess post-handoff health without granting a second-writer transition."""

    _verify_source_evidence(intent, receipt)
    _verify_peer_evidence(peer_snapshot)
    if peer_snapshot.cluster_id != receipt.cluster_id:
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_cluster_mismatch"
        )
    member_node_ids = tuple(sorted(member.node_id for member in peer_snapshot.members))
    if member_node_ids != intent.member_node_ids:
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_membership_stale"
        )
    _require_exact_handoff_role_state(
        intent=intent,
        receipt=receipt,
        role_authority=role_authority,
    )

    health = {member.node_id: member.state for member in peer_snapshot.members}
    previous_health = health[intent.target_writer_node_id]
    successor_health = health[intent.successor_writer_node_id]
    ready_node_ids = tuple(
        sorted(node_id for node_id, state in health.items() if state is PeerHealthState.READY)
    )
    ready_count = len(ready_node_ids)
    required_quorum_nodes = len(member_node_ids) // 2 + 1

    if successor_health is PeerHealthState.READY:
        fencing_required = False
        if ready_count < required_quorum_nodes:
            disposition = WriterHandoffRecoveryDisposition.HOLD
            reason = "majority_quorum_not_met"
            reconciliation_required = True
        elif ready_count < intent.minimum_ready_nodes:
            disposition = WriterHandoffRecoveryDisposition.HOLD
            reason = "minimum_ready_not_met"
            reconciliation_required = True
        else:
            disposition = WriterHandoffRecoveryDisposition.HEALTHY
            reason = "handoff_healthy"
            reconciliation_required = False
    else:
        disposition = WriterHandoffRecoveryDisposition.RECONCILE
        fencing_required = True
        reconciliation_required = True
        if previous_health is not PeerHealthState.READY:
            reason = "previous_writer_not_ready"
        elif ready_count < required_quorum_nodes:
            reason = "majority_quorum_not_met"
        elif ready_count < intent.minimum_ready_nodes:
            reason = "minimum_ready_not_met"
        else:
            reason = "successor_not_ready_fencing_required"

    provisional = RollingWriterHandoffRecoveryAssessment(
        cluster_id=receipt.cluster_id,
        assessment_id="pending",
        handoff_receipt_id=receipt.receipt_id,
        handoff_intent_id=intent.intent_id,
        blocked_plan_id=intent.blocked_plan_id,
        previous_writer_node_id=intent.target_writer_node_id,
        successor_writer_node_id=intent.successor_writer_node_id,
        member_node_ids=member_node_ids,
        peer_snapshot_id=peer_snapshot.snapshot_id,
        peer_journal_seq=peer_snapshot.journal_seq,
        role_assignment_id=receipt.role_assignment_id,
        role_epoch=receipt.role_epoch,
        role_resource_version=receipt.role_resource_version,
        role_journal_seq=receipt.role_journal_seq,
        role_transition_id=receipt.role_transition_id,
        minimum_ready_nodes=intent.minimum_ready_nodes,
        required_quorum_nodes=required_quorum_nodes,
        ready_node_ids=ready_node_ids,
        ready_count=ready_count,
        previous_writer_health=previous_health.value,
        successor_writer_health=successor_health.value,
        disposition=disposition,
        reason=reason,
        fencing_required=fencing_required,
        reconciliation_required=reconciliation_required,
    )
    result = replace(
        provisional,
        assessment_id=_stable_id(
            "ha-roll-writer-handoff-recovery",
            _assessment_material(provisional),
        ),
    )
    _verify_assessment(result)
    return result


def revalidate_rolling_writer_handoff_recovery_assessment(
    *,
    assessment: RollingWriterHandoffRecoveryAssessment,
    intent: RollingWriterHandoffIntent,
    receipt: RollingWriterHandoffReceipt,
    peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
) -> RollingWriterHandoffRecoveryAssessment:
    """Reject saved recovery advice after peer or role-authority drift."""

    _verify_assessment(assessment)
    current = assess_rolling_writer_handoff_recovery(
        intent=intent,
        receipt=receipt,
        peer_snapshot=peer_snapshot,
        role_authority=role_authority,
    )
    if current != assessment:
        raise HARollingWriterHandoffRecoveryError(
            "rolling_writer_handoff_recovery_assessment_stale"
        )
    return assessment
