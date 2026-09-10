"""Bounded role-journal commit for a fenced rolling-writer rollback admission."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Protocol

from .ha_peer_snapshot import HAPeerStateSnapshot, PeerHealthState
from .ha_role_journal import (
    HARoleAuthorityState,
    HARoleJournalError,
    HARoleTransitionKind,
)
from .ha_rolling_authority import HARoleAssignment, build_role_assignment_snapshot
from .ha_rolling_safety import NodeRole
from .ha_rolling_writer_handoff_fencing import (
    HARollingWriterHandoffFencingError,
    HAWriterLeaseRevisionAuthority,
    WriterHandoffFencingEvidence,
    revalidate_writer_handoff_fencing_evidence,
)
from .ha_rolling_writer_handoff_recovery import RollingWriterHandoffRecoveryAssessment
from .ha_rolling_writer_handoff_rollback_admission import (
    HAPeerSnapshotAuthority,
    HARollingWriterHandoffRollbackAdmissionError,
    RollingWriterHandoffRollbackAdmission,
    revalidate_writer_handoff_rollback_admission,
)


class HARollingWriterHandoffRollbackCommitError(ValueError):
    """Stable fail-closed error for a bounded rollback role commit."""


class HARollbackRoleCommitAuthority(Protocol):
    def state_for(
        self,
        *,
        cluster_id: str,
        node_ids: tuple[str, ...],
    ) -> HARoleAuthorityState: ...

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
    ) -> HARoleAuthorityState: ...


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffRollbackCommitReceipt:
    cluster_id: str
    receipt_id: str
    admission_id: str
    fencing_evidence_id: str
    recovery_assessment_id: str
    handoff_receipt_id: str
    handoff_intent_id: str
    blocked_plan_id: str
    rollback_writer_node_id: str
    fenced_successor_node_id: str
    member_node_ids: tuple[str, ...]
    precommit_peer_snapshot_id: str
    precommit_peer_journal_seq: int
    precommit_ready_node_ids: tuple[str, ...]
    minimum_ready_nodes: int
    required_quorum_nodes: int
    previous_role_assignment_id: str
    previous_role_epoch: int
    previous_role_resource_version: int
    previous_role_journal_seq: int
    previous_role_transition_id: str
    committed_role_assignment_id: str
    committed_role_epoch: int
    committed_role_resource_version: int
    committed_role_journal_seq: int
    committed_role_transition_id: str
    lease_id: str
    lease_epoch: int
    lease_resource_version: int
    lease_state_id: str
    transition_kind: str = HARoleTransitionKind.ROLLBACK.value
    role_commit_applied: bool = True
    single_use_by_cas: bool = True
    retry_authorized: bool = False
    execution_authorized: bool = False
    failover_authorized: bool = False
    writer_service_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-writer-handoff-rollback-commit-receipt.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "receipt_id": self.receipt_id,
            "admission_id": self.admission_id,
            "fencing_evidence_id": self.fencing_evidence_id,
            "recovery_assessment_id": self.recovery_assessment_id,
            "handoff_receipt_id": self.handoff_receipt_id,
            "handoff_intent_id": self.handoff_intent_id,
            "blocked_plan_id": self.blocked_plan_id,
            "rollback_writer_node_id": self.rollback_writer_node_id,
            "fenced_successor_node_id": self.fenced_successor_node_id,
            "member_node_ids": list(self.member_node_ids),
            "precommit_peer_snapshot_id": self.precommit_peer_snapshot_id,
            "precommit_peer_journal_seq": self.precommit_peer_journal_seq,
            "precommit_ready_node_ids": list(self.precommit_ready_node_ids),
            "minimum_ready_nodes": self.minimum_ready_nodes,
            "required_quorum_nodes": self.required_quorum_nodes,
            "previous_role_assignment_id": self.previous_role_assignment_id,
            "previous_role_epoch": self.previous_role_epoch,
            "previous_role_resource_version": self.previous_role_resource_version,
            "previous_role_journal_seq": self.previous_role_journal_seq,
            "previous_role_transition_id": self.previous_role_transition_id,
            "committed_role_assignment_id": self.committed_role_assignment_id,
            "committed_role_epoch": self.committed_role_epoch,
            "committed_role_resource_version": self.committed_role_resource_version,
            "committed_role_journal_seq": self.committed_role_journal_seq,
            "committed_role_transition_id": self.committed_role_transition_id,
            "lease_id": self.lease_id,
            "lease_epoch": self.lease_epoch,
            "lease_resource_version": self.lease_resource_version,
            "lease_state_id": self.lease_state_id,
            "transition_kind": self.transition_kind,
            "role_commit_applied": self.role_commit_applied,
            "single_use_by_cas": self.single_use_by_cas,
            "retry_authorized": self.retry_authorized,
            "execution_authorized": self.execution_authorized,
            "failover_authorized": self.failover_authorized,
            "writer_service_authorized": self.writer_service_authorized,
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


def _receipt_material(
    receipt: RollingWriterHandoffRollbackCommitReceipt,
) -> dict[str, object]:
    material = receipt.to_dict()
    material.pop("receipt_id")
    return material


def _peer_identity(snapshot: HAPeerStateSnapshot) -> str:
    return _stable_id(
        "ha-state",
        {
            "schema": snapshot.schema,
            "cluster_id": snapshot.cluster_id,
            "journal_seq": snapshot.journal_seq,
            "members": [member.to_dict() for member in snapshot.members],
        },
    )


def _validate_precommit_peer(
    snapshot: HAPeerStateSnapshot,
    *,
    admission: RollingWriterHandoffRollbackAdmission,
) -> tuple[str, ...]:
    if snapshot.snapshot_id != _peer_identity(snapshot):
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_peer_identity_invalid"
        )
    members = tuple(member.node_id for member in snapshot.members)
    ready = tuple(
        member.node_id
        for member in snapshot.members
        if member.state is PeerHealthState.READY
    )
    if (
        snapshot.cluster_id != admission.cluster_id
        or members != admission.member_node_ids
        or snapshot.snapshot_id != admission.peer_snapshot_id
        or snapshot.journal_seq != admission.peer_journal_seq
        or ready != admission.ready_node_ids
        or len(ready) < admission.required_quorum_nodes
        or len(ready) < admission.minimum_ready_nodes
        or admission.rollback_writer_node_id not in ready
        or admission.fenced_successor_node_id in ready
    ):
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_peer_state_stale"
        )
    return ready


def _target_assignments(
    admission: RollingWriterHandoffRollbackAdmission,
) -> tuple[HARoleAssignment, ...]:
    target = tuple(
        HARoleAssignment(
            node_id,
            NodeRole.WRITER
            if node_id == admission.rollback_writer_node_id
            else NodeRole.STANDBY,
        )
        for node_id in admission.member_node_ids
    )
    snapshot = build_role_assignment_snapshot(
        cluster_id=admission.cluster_id,
        role_epoch=admission.target_role_epoch,
        assignments=target,
    )
    if snapshot.assignment_id != admission.target_role_assignment_id:
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_target_identity_invalid"
        )
    return snapshot.assignments


def _validate_precommit_role(
    state: HARoleAuthorityState,
    *,
    admission: RollingWriterHandoffRollbackAdmission,
) -> None:
    expected = (
        (state.snapshot.assignment_id, admission.expected_role_assignment_id),
        (state.snapshot.role_epoch, admission.expected_role_epoch),
        (state.resource_version, admission.expected_role_resource_version),
        (state.journal_seq, admission.expected_role_journal_seq),
        (state.transition_id, admission.expected_role_transition_id),
    )
    if state.production_mutation_enabled or any(
        actual != wanted for actual, wanted in expected
    ):
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_role_state_stale"
        )


def _validate_committed_role(
    state: HARoleAuthorityState,
    *,
    admission: RollingWriterHandoffRollbackAdmission,
) -> None:
    if (
        state.production_mutation_enabled
        or state.transition_kind != HARoleTransitionKind.ROLLBACK.value
        or state.snapshot.assignment_id != admission.target_role_assignment_id
        or state.snapshot.role_epoch != admission.target_role_epoch
        or state.resource_version != admission.expected_role_resource_version + 1
        or state.journal_seq != admission.expected_role_journal_seq + 1
    ):
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_result_ambiguous"
        )
    writers = tuple(
        item.node_id
        for item in state.snapshot.assignments
        if item.role is NodeRole.WRITER
    )
    if writers != (admission.rollback_writer_node_id,):
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_writer_invalid"
        )


def _verify_receipt(receipt: RollingWriterHandoffRollbackCommitReceipt) -> None:
    if (
        receipt.schema
        != "home-center.ha-rolling-writer-handoff-rollback-commit-receipt.v1"
        or receipt.transition_kind != HARoleTransitionKind.ROLLBACK.value
        or not receipt.role_commit_applied
        or not receipt.single_use_by_cas
        or receipt.retry_authorized
        or receipt.execution_authorized
        or receipt.failover_authorized
        or receipt.writer_service_authorized
        or receipt.host_mutation_authorized
        or receipt.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_receipt_authority_invalid"
        )
    if receipt.committed_role_epoch != receipt.previous_role_epoch + 1:
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_receipt_epoch_invalid"
        )
    if (
        receipt.committed_role_resource_version
        != receipt.previous_role_resource_version + 1
        or receipt.committed_role_journal_seq != receipt.previous_role_journal_seq + 1
    ):
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_receipt_revision_invalid"
        )
    expected = _stable_id(
        "ha-roll-writer-handoff-rollback-commit",
        _receipt_material(receipt),
    )
    if receipt.receipt_id != expected:
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_receipt_identity_invalid"
        )


def commit_writer_handoff_rollback(
    *,
    admission: RollingWriterHandoffRollbackAdmission,
    evidence: WriterHandoffFencingEvidence,
    assessment: RollingWriterHandoffRecoveryAssessment,
    peer_authority: HAPeerSnapshotAuthority,
    role_authority: HARollbackRoleCommitAuthority,
    lease_authority: HAWriterLeaseRevisionAuthority,
) -> RollingWriterHandoffRollbackCommitReceipt:
    """Apply exactly one typed role-journal CAS after fresh safety revalidation."""

    try:
        revalidate_writer_handoff_rollback_admission(
            admission=admission,
            evidence=evidence,
            assessment=assessment,
            peer_authority=peer_authority,
            role_authority=role_authority,
            lease_authority=lease_authority,
        )
        precommit_peer = peer_authority.snapshot_for(
            cluster_id=admission.cluster_id,
            node_ids=admission.member_node_ids,
        )
        ready = _validate_precommit_peer(precommit_peer, admission=admission)
        revalidate_writer_handoff_fencing_evidence(
            evidence=evidence,
            assessment=assessment,
            lease_authority=lease_authority,
        )
        precommit_role = role_authority.state_for(
            cluster_id=admission.cluster_id,
            node_ids=admission.member_node_ids,
        )
        _validate_precommit_role(precommit_role, admission=admission)
        target = _target_assignments(admission)
        committed = role_authority.transition(
            cluster_id=admission.cluster_id,
            assignments=target,
            transition_kind=HARoleTransitionKind.ROLLBACK,
            expected_assignment_id=admission.expected_role_assignment_id,
            expected_role_epoch=admission.expected_role_epoch,
            expected_resource_version=admission.expected_role_resource_version,
            expected_journal_seq=admission.expected_role_journal_seq,
        )
    except (
        HARollingWriterHandoffRollbackAdmissionError,
        HARollingWriterHandoffFencingError,
        HARoleJournalError,
    ) as exc:
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_reconciliation_required"
        ) from exc

    _validate_committed_role(committed, admission=admission)
    revalidate_writer_handoff_fencing_evidence(
        evidence=evidence,
        assessment=assessment,
        lease_authority=lease_authority,
    )

    provisional = RollingWriterHandoffRollbackCommitReceipt(
        cluster_id=admission.cluster_id,
        receipt_id="pending",
        admission_id=admission.admission_id,
        fencing_evidence_id=admission.fencing_evidence_id,
        recovery_assessment_id=admission.recovery_assessment_id,
        handoff_receipt_id=admission.handoff_receipt_id,
        handoff_intent_id=admission.handoff_intent_id,
        blocked_plan_id=admission.blocked_plan_id,
        rollback_writer_node_id=admission.rollback_writer_node_id,
        fenced_successor_node_id=admission.fenced_successor_node_id,
        member_node_ids=admission.member_node_ids,
        precommit_peer_snapshot_id=precommit_peer.snapshot_id,
        precommit_peer_journal_seq=precommit_peer.journal_seq,
        precommit_ready_node_ids=ready,
        minimum_ready_nodes=admission.minimum_ready_nodes,
        required_quorum_nodes=admission.required_quorum_nodes,
        previous_role_assignment_id=admission.expected_role_assignment_id,
        previous_role_epoch=admission.expected_role_epoch,
        previous_role_resource_version=admission.expected_role_resource_version,
        previous_role_journal_seq=admission.expected_role_journal_seq,
        previous_role_transition_id=admission.expected_role_transition_id,
        committed_role_assignment_id=committed.snapshot.assignment_id,
        committed_role_epoch=committed.snapshot.role_epoch,
        committed_role_resource_version=committed.resource_version,
        committed_role_journal_seq=committed.journal_seq,
        committed_role_transition_id=committed.transition_id,
        lease_id=admission.lease_id,
        lease_epoch=admission.lease_epoch,
        lease_resource_version=admission.lease_resource_version,
        lease_state_id=admission.lease_state_id,
    )
    result = replace(
        provisional,
        receipt_id=_stable_id(
            "ha-roll-writer-handoff-rollback-commit",
            _receipt_material(provisional),
        ),
    )
    _verify_receipt(result)
    return result


def revalidate_writer_handoff_rollback_commit_receipt(
    *,
    receipt: RollingWriterHandoffRollbackCommitReceipt,
    role_authority: HARollbackRoleCommitAuthority,
) -> RollingWriterHandoffRollbackCommitReceipt:
    """Verify immutable commit lineage against current role-journal authority."""

    _verify_receipt(receipt)
    state = role_authority.state_for(
        cluster_id=receipt.cluster_id,
        node_ids=receipt.member_node_ids,
    )
    if (
        state.snapshot.assignment_id != receipt.committed_role_assignment_id
        or state.snapshot.role_epoch != receipt.committed_role_epoch
        or state.resource_version != receipt.committed_role_resource_version
        or state.journal_seq != receipt.committed_role_journal_seq
        or state.transition_id != receipt.committed_role_transition_id
        or state.transition_kind != HARoleTransitionKind.ROLLBACK.value
        or state.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_receipt_stale"
        )
    return receipt
