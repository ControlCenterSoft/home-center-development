"""CAS-bound rollback admission after a verified rolling writer fence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Protocol

from .ha_peer_snapshot import HAPeerStateSnapshot, PeerHealthState
from .ha_rolling_authority import HARoleAssignment, build_role_assignment_snapshot
from .ha_rolling_revision import HARoleRevisionAuthority
from .ha_rolling_safety import NodeRole
from .ha_rolling_writer_handoff_fencing import (
    HAWriterLeaseRevisionAuthority,
    WriterHandoffFencingEvidence,
    revalidate_writer_handoff_fencing_evidence,
)
from .ha_rolling_writer_handoff_recovery import RollingWriterHandoffRecoveryAssessment


class HARollingWriterHandoffRollbackAdmissionError(ValueError):
    """Stable fail-closed error for rollback admission construction."""


class HAPeerSnapshotAuthority(Protocol):
    def snapshot_for(
        self,
        *,
        cluster_id: str,
        node_ids: tuple[str, ...],
    ) -> HAPeerStateSnapshot: ...


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffRollbackAdmission:
    cluster_id: str
    admission_id: str
    fencing_evidence_id: str
    recovery_assessment_id: str
    handoff_receipt_id: str
    handoff_intent_id: str
    blocked_plan_id: str
    rollback_writer_node_id: str
    fenced_successor_node_id: str
    member_node_ids: tuple[str, ...]
    peer_snapshot_id: str
    peer_journal_seq: int
    ready_node_ids: tuple[str, ...]
    ready_count: int
    minimum_ready_nodes: int
    required_quorum_nodes: int
    expected_role_assignment_id: str
    expected_role_epoch: int
    expected_role_resource_version: int
    expected_role_journal_seq: int
    expected_role_transition_id: str
    target_role_assignment_id: str
    target_role_epoch: int
    lease_id: str
    lease_epoch: int
    lease_resource_version: int
    lease_state_id: str
    lease_revoked_for_role_transition_id: str
    cas_bound: bool = True
    single_use_by_cas: bool = True
    rollback_transition_admitted: bool = True
    execution_authorized: bool = False
    failover_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-writer-handoff-rollback-admission.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "admission_id": self.admission_id,
            "fencing_evidence_id": self.fencing_evidence_id,
            "recovery_assessment_id": self.recovery_assessment_id,
            "handoff_receipt_id": self.handoff_receipt_id,
            "handoff_intent_id": self.handoff_intent_id,
            "blocked_plan_id": self.blocked_plan_id,
            "rollback_writer_node_id": self.rollback_writer_node_id,
            "fenced_successor_node_id": self.fenced_successor_node_id,
            "member_node_ids": list(self.member_node_ids),
            "peer_snapshot_id": self.peer_snapshot_id,
            "peer_journal_seq": self.peer_journal_seq,
            "ready_node_ids": list(self.ready_node_ids),
            "ready_count": self.ready_count,
            "minimum_ready_nodes": self.minimum_ready_nodes,
            "required_quorum_nodes": self.required_quorum_nodes,
            "expected_role_assignment_id": self.expected_role_assignment_id,
            "expected_role_epoch": self.expected_role_epoch,
            "expected_role_resource_version": self.expected_role_resource_version,
            "expected_role_journal_seq": self.expected_role_journal_seq,
            "expected_role_transition_id": self.expected_role_transition_id,
            "target_role_assignment_id": self.target_role_assignment_id,
            "target_role_epoch": self.target_role_epoch,
            "lease_id": self.lease_id,
            "lease_epoch": self.lease_epoch,
            "lease_resource_version": self.lease_resource_version,
            "lease_state_id": self.lease_state_id,
            "lease_revoked_for_role_transition_id": (
                self.lease_revoked_for_role_transition_id
            ),
            "cas_bound": self.cas_bound,
            "single_use_by_cas": self.single_use_by_cas,
            "rollback_transition_admitted": self.rollback_transition_admitted,
            "execution_authorized": self.execution_authorized,
            "failover_authorized": self.failover_authorized,
            "host_mutation_authorized": self.host_mutation_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


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


def _admission_material(
    admission: RollingWriterHandoffRollbackAdmission,
) -> dict[str, object]:
    material = admission.to_dict()
    material.pop("admission_id")
    return material


def _verify_peer_snapshot(snapshot: HAPeerStateSnapshot) -> None:
    canonical = {
        "schema": snapshot.schema,
        "cluster_id": snapshot.cluster_id,
        "journal_seq": snapshot.journal_seq,
        "members": [member.to_dict() for member in snapshot.members],
    }
    expected = _stable_id("ha-state", canonical)
    if snapshot.snapshot_id != expected:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_peer_identity_invalid"
        )


def _peer_safety(
    snapshot: HAPeerStateSnapshot,
    *,
    evidence: WriterHandoffFencingEvidence,
) -> tuple[tuple[str, ...], int]:
    _verify_peer_snapshot(snapshot)
    members = tuple(member.node_id for member in snapshot.members)
    if snapshot.cluster_id != evidence.cluster_id or members != evidence.member_node_ids:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_membership_stale"
        )
    if snapshot.journal_seq < evidence.peer_journal_seq:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_peer_journal_regressed"
        )
    ready = tuple(
        member.node_id
        for member in snapshot.members
        if member.state is PeerHealthState.READY
    )
    required_quorum = len(members) // 2 + 1
    if evidence.required_quorum_nodes != required_quorum:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_quorum_binding_invalid"
        )
    if (
        len(ready) < required_quorum
        or len(ready) < evidence.minimum_ready_nodes
        or evidence.previous_writer_node_id not in ready
        or evidence.successor_writer_node_id in ready
    ):
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_safety_boundary_not_met"
        )
    return ready, required_quorum


def _verify_role_state(state, *, evidence: WriterHandoffFencingEvidence) -> None:
    if state.production_mutation_enabled:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_role_mutation_enabled"
        )
    assignments = tuple(state.snapshot.assignments)
    canonical = build_role_assignment_snapshot(
        cluster_id=state.snapshot.cluster_id,
        role_epoch=state.snapshot.role_epoch,
        assignments=assignments,
    )
    if canonical.assignment_id != state.snapshot.assignment_id:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_role_identity_invalid"
        )
    if (
        state.snapshot.cluster_id != evidence.cluster_id
        or tuple(item.node_id for item in assignments) != evidence.member_node_ids
    ):
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_role_membership_stale"
        )
    expected = (
        (state.snapshot.assignment_id, evidence.role_assignment_id),
        (state.snapshot.role_epoch, evidence.role_epoch),
        (state.resource_version, evidence.role_resource_version),
        (state.journal_seq, evidence.role_journal_seq),
        (state.transition_id, evidence.role_transition_id),
    )
    if any(actual != wanted for actual, wanted in expected):
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_role_revision_stale"
        )
    writers = tuple(
        item.node_id for item in assignments if item.role is NodeRole.WRITER
    )
    if writers != (evidence.successor_writer_node_id,):
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_writer_state_invalid"
        )


def _same_role_revision(first, second) -> bool:
    return (
        first.snapshot == second.snapshot
        and first.resource_version == second.resource_version
        and first.journal_seq == second.journal_seq
        and first.transition_id == second.transition_id
        and first.production_mutation_enabled == second.production_mutation_enabled
    )


def _target_assignment(state, *, evidence: WriterHandoffFencingEvidence):
    assignments = tuple(
        HARoleAssignment(
            item.node_id,
            NodeRole.WRITER
            if item.node_id == evidence.previous_writer_node_id
            else NodeRole.STANDBY,
        )
        for item in state.snapshot.assignments
    )
    return build_role_assignment_snapshot(
        cluster_id=evidence.cluster_id,
        role_epoch=state.snapshot.role_epoch + 1,
        assignments=assignments,
    )


def _verify_admission(admission: RollingWriterHandoffRollbackAdmission) -> None:
    if admission.schema != "home-center.ha-rolling-writer-handoff-rollback-admission.v1":
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_admission_schema_invalid"
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
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_admission_authority_invalid"
        )
    if admission.rollback_writer_node_id == admission.fenced_successor_node_id:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_target_invalid"
        )
    if admission.required_quorum_nodes != len(admission.member_node_ids) // 2 + 1:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_admission_quorum_invalid"
        )
    if (
        admission.ready_count != len(admission.ready_node_ids)
        or admission.ready_count < admission.required_quorum_nodes
        or admission.ready_count < admission.minimum_ready_nodes
        or admission.rollback_writer_node_id not in admission.ready_node_ids
        or admission.fenced_successor_node_id in admission.ready_node_ids
    ):
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_admission_ready_invalid"
        )
    if admission.target_role_epoch != admission.expected_role_epoch + 1:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_target_epoch_invalid"
        )
    if (
        admission.lease_revoked_for_role_transition_id
        != admission.expected_role_transition_id
    ):
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_lease_binding_invalid"
        )
    expected = _stable_id(
        "ha-roll-writer-handoff-rollback-admission",
        _admission_material(admission),
    )
    if admission.admission_id != expected:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_admission_identity_invalid"
        )


def build_writer_handoff_rollback_admission(
    *,
    evidence: WriterHandoffFencingEvidence,
    assessment: RollingWriterHandoffRecoveryAssessment,
    peer_authority: HAPeerSnapshotAuthority,
    role_authority: HARoleRevisionAuthority,
    lease_authority: HAWriterLeaseRevisionAuthority,
) -> RollingWriterHandoffRollbackAdmission:
    """Seal a single-use CAS admission without executing the role rollback."""

    revalidate_writer_handoff_fencing_evidence(
        evidence=evidence,
        assessment=assessment,
        lease_authority=lease_authority,
    )
    if evidence.recovery_assessment_id != assessment.assessment_id:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_recovery_binding_invalid"
        )

    peer_before = peer_authority.snapshot_for(
        cluster_id=evidence.cluster_id,
        node_ids=evidence.member_node_ids,
    )
    ready, required_quorum = _peer_safety(peer_before, evidence=evidence)

    role_before = role_authority.state_for(
        cluster_id=evidence.cluster_id,
        node_ids=evidence.member_node_ids,
    )
    _verify_role_state(role_before, evidence=evidence)

    peer_after = peer_authority.snapshot_for(
        cluster_id=evidence.cluster_id,
        node_ids=evidence.member_node_ids,
    )
    _peer_safety(peer_after, evidence=evidence)
    if peer_after != peer_before:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_peer_state_moved"
        )

    role_after = role_authority.state_for(
        cluster_id=evidence.cluster_id,
        node_ids=evidence.member_node_ids,
    )
    _verify_role_state(role_after, evidence=evidence)
    if not _same_role_revision(role_before, role_after):
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_role_state_moved"
        )

    revalidate_writer_handoff_fencing_evidence(
        evidence=evidence,
        assessment=assessment,
        lease_authority=lease_authority,
    )

    target = _target_assignment(role_after, evidence=evidence)
    provisional = RollingWriterHandoffRollbackAdmission(
        cluster_id=evidence.cluster_id,
        admission_id="pending",
        fencing_evidence_id=evidence.evidence_id,
        recovery_assessment_id=evidence.recovery_assessment_id,
        handoff_receipt_id=evidence.handoff_receipt_id,
        handoff_intent_id=evidence.handoff_intent_id,
        blocked_plan_id=evidence.blocked_plan_id,
        rollback_writer_node_id=evidence.previous_writer_node_id,
        fenced_successor_node_id=evidence.successor_writer_node_id,
        member_node_ids=evidence.member_node_ids,
        peer_snapshot_id=peer_after.snapshot_id,
        peer_journal_seq=peer_after.journal_seq,
        ready_node_ids=ready,
        ready_count=len(ready),
        minimum_ready_nodes=evidence.minimum_ready_nodes,
        required_quorum_nodes=required_quorum,
        expected_role_assignment_id=role_after.snapshot.assignment_id,
        expected_role_epoch=role_after.snapshot.role_epoch,
        expected_role_resource_version=role_after.resource_version,
        expected_role_journal_seq=role_after.journal_seq,
        expected_role_transition_id=role_after.transition_id,
        target_role_assignment_id=target.assignment_id,
        target_role_epoch=target.role_epoch,
        lease_id=evidence.lease_id,
        lease_epoch=evidence.lease_epoch,
        lease_resource_version=evidence.lease_resource_version,
        lease_state_id=evidence.lease_state_id,
        lease_revoked_for_role_transition_id=(
            evidence.lease_revoked_for_role_transition_id
        ),
    )
    result = replace(
        provisional,
        admission_id=_stable_id(
            "ha-roll-writer-handoff-rollback-admission",
            _admission_material(provisional),
        ),
    )
    _verify_admission(result)
    return result


def revalidate_writer_handoff_rollback_admission(
    *,
    admission: RollingWriterHandoffRollbackAdmission,
    evidence: WriterHandoffFencingEvidence,
    assessment: RollingWriterHandoffRecoveryAssessment,
    peer_authority: HAPeerSnapshotAuthority,
    role_authority: HARoleRevisionAuthority,
    lease_authority: HAWriterLeaseRevisionAuthority,
) -> RollingWriterHandoffRollbackAdmission:
    """Reject a saved admission after any peer, role, lease, or lineage drift."""

    _verify_admission(admission)
    current = build_writer_handoff_rollback_admission(
        evidence=evidence,
        assessment=assessment,
        peer_authority=peer_authority,
        role_authority=role_authority,
        lease_authority=lease_authority,
    )
    if current != admission:
        raise HARollingWriterHandoffRollbackAdmissionError(
            "rolling_writer_handoff_rollback_admission_stale"
        )
    return admission
