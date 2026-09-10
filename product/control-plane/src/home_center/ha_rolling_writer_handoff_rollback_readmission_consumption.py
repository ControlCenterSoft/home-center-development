"""Final CAS consumption for a reconciled rollback readmission."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

from .ha_rolling_writer_handoff_fencing import (
    HAWriterLeaseRevisionAuthority,
    WriterHandoffFencingEvidence,
)
from .ha_rolling_writer_handoff_recovery import RollingWriterHandoffRecoveryAssessment
from .ha_rolling_writer_handoff_rollback_admission import (
    HAPeerSnapshotAuthority,
    RollingWriterHandoffRollbackAdmission,
)
from .ha_rolling_writer_handoff_rollback_commit import (
    HARollbackRoleCommitAuthority,
    RollingWriterHandoffRollbackCommitReceipt,
    commit_writer_handoff_rollback,
    revalidate_writer_handoff_rollback_commit_receipt,
)
from .ha_rolling_writer_handoff_rollback_readmission import (
    RollingWriterHandoffRollbackReadmission,
    revalidate_writer_handoff_rollback_readmission,
)
from .ha_rolling_writer_handoff_rollback_reconciliation import (
    RollingWriterHandoffRollbackReconciliationReceipt,
)


class HARollingWriterHandoffRollbackReadmissionConsumptionError(ValueError):
    """Stable fail-closed error for final rollback-readmission consumption."""


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffRollbackReadmissionConsumptionReceipt:
    cluster_id: str
    consumption_id: str
    readmission_id: str
    reconciliation_receipt_id: str
    prior_admission_id: str
    candidate_admission_id: str
    commit_receipt_id: str
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
    recovery_generation: int = 1
    maximum_recovery_generation: int = 1
    readmission_consumed: bool = True
    role_commit_applied: bool = True
    single_use_by_cas: bool = True
    fresh_admission_required: bool = False
    further_readmission_authorized: bool = False
    automatic_retry_authorized: bool = False
    execution_authorized: bool = False
    failover_authorized: bool = False
    writer_service_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = (
        "home-center.ha-rolling-writer-handoff-rollback-readmission-consumption.v1"
    )

    def to_dict(self) -> dict[str, object]:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["member_node_ids"] = list(self.member_node_ids)
        result["precommit_ready_node_ids"] = list(self.precommit_ready_node_ids)
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


def _material(
    value: RollingWriterHandoffRollbackReadmissionConsumptionReceipt,
) -> dict[str, object]:
    material = value.to_dict()
    material.pop("consumption_id")
    return material


def _same_fields(first, second, names: tuple[str, ...]) -> bool:
    return all(getattr(first, name) == getattr(second, name) for name in names)


def _verify_candidate_binding(
    readmission: RollingWriterHandoffRollbackReadmission,
    candidate: RollingWriterHandoffRollbackAdmission,
) -> None:
    shared = (
        "cluster_id",
        "fencing_evidence_id",
        "recovery_assessment_id",
        "rollback_writer_node_id",
        "fenced_successor_node_id",
        "member_node_ids",
        "peer_snapshot_id",
        "peer_journal_seq",
        "ready_node_ids",
        "ready_count",
        "minimum_ready_nodes",
        "required_quorum_nodes",
        "expected_role_assignment_id",
        "expected_role_epoch",
        "expected_role_resource_version",
        "expected_role_journal_seq",
        "expected_role_transition_id",
        "target_role_assignment_id",
        "target_role_epoch",
        "lease_id",
        "lease_epoch",
        "lease_resource_version",
        "lease_state_id",
        "lease_revoked_for_role_transition_id",
    )
    if (
        candidate.admission_id != readmission.candidate_admission_id
        or not _same_fields(candidate, readmission, shared)
        or not candidate.cas_bound
        or not candidate.single_use_by_cas
        or not candidate.rollback_transition_admitted
        or candidate.execution_authorized
        or candidate.failover_authorized
        or candidate.host_mutation_authorized
        or candidate.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackReadmissionConsumptionError(
            "rollback_readmission_consumption_candidate_lineage_invalid"
        )


def _verify_commit_binding(
    readmission: RollingWriterHandoffRollbackReadmission,
    candidate: RollingWriterHandoffRollbackAdmission,
    commit: RollingWriterHandoffRollbackCommitReceipt,
) -> None:
    if (
        commit.admission_id != candidate.admission_id
        or commit.admission_id != readmission.candidate_admission_id
        or commit.fencing_evidence_id != candidate.fencing_evidence_id
        or commit.recovery_assessment_id != candidate.recovery_assessment_id
        or commit.handoff_receipt_id != candidate.handoff_receipt_id
        or commit.handoff_intent_id != candidate.handoff_intent_id
        or commit.blocked_plan_id != candidate.blocked_plan_id
        or commit.rollback_writer_node_id != candidate.rollback_writer_node_id
        or commit.fenced_successor_node_id != candidate.fenced_successor_node_id
        or commit.member_node_ids != candidate.member_node_ids
        or commit.precommit_peer_snapshot_id != candidate.peer_snapshot_id
        or commit.precommit_peer_journal_seq != candidate.peer_journal_seq
        or commit.precommit_ready_node_ids != candidate.ready_node_ids
        or commit.minimum_ready_nodes != candidate.minimum_ready_nodes
        or commit.required_quorum_nodes != candidate.required_quorum_nodes
        or commit.previous_role_assignment_id != candidate.expected_role_assignment_id
        or commit.previous_role_epoch != candidate.expected_role_epoch
        or commit.previous_role_resource_version
        != candidate.expected_role_resource_version
        or commit.previous_role_journal_seq != candidate.expected_role_journal_seq
        or commit.previous_role_transition_id != candidate.expected_role_transition_id
        or commit.committed_role_assignment_id != candidate.target_role_assignment_id
        or commit.committed_role_epoch != candidate.target_role_epoch
        or commit.lease_id != candidate.lease_id
        or commit.lease_epoch != candidate.lease_epoch
        or commit.lease_resource_version != candidate.lease_resource_version
        or commit.lease_state_id != candidate.lease_state_id
        or commit.transition_kind != "rollback"
        or not commit.role_commit_applied
        or not commit.single_use_by_cas
        or commit.retry_authorized
        or commit.execution_authorized
        or commit.failover_authorized
        or commit.writer_service_authorized
        or commit.host_mutation_authorized
        or commit.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackReadmissionConsumptionError(
            "rollback_readmission_consumption_commit_lineage_invalid"
        )


def _verify_consumption(
    value: RollingWriterHandoffRollbackReadmissionConsumptionReceipt,
) -> None:
    if (
        value.schema
        != "home-center.ha-rolling-writer-handoff-rollback-readmission-consumption.v1"
        or value.recovery_generation != 1
        or value.maximum_recovery_generation != 1
        or not value.readmission_consumed
        or not value.role_commit_applied
        or not value.single_use_by_cas
        or value.fresh_admission_required
        or value.further_readmission_authorized
        or value.automatic_retry_authorized
        or value.execution_authorized
        or value.failover_authorized
        or value.writer_service_authorized
        or value.host_mutation_authorized
        or value.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackReadmissionConsumptionError(
            "rollback_readmission_consumption_authority_invalid"
        )
    if (
        value.member_node_ids != tuple(sorted(value.member_node_ids))
        or len(value.member_node_ids) != len(set(value.member_node_ids))
        or value.required_quorum_nodes != len(value.member_node_ids) // 2 + 1
        or len(value.precommit_ready_node_ids) < value.required_quorum_nodes
        or len(value.precommit_ready_node_ids) < value.minimum_ready_nodes
        or value.rollback_writer_node_id not in value.precommit_ready_node_ids
        or value.fenced_successor_node_id in value.precommit_ready_node_ids
    ):
        raise HARollingWriterHandoffRollbackReadmissionConsumptionError(
            "rollback_readmission_consumption_safety_evidence_invalid"
        )
    if (
        value.committed_role_epoch != value.previous_role_epoch + 1
        or value.committed_role_resource_version
        != value.previous_role_resource_version + 1
        or value.committed_role_journal_seq != value.previous_role_journal_seq + 1
    ):
        raise HARollingWriterHandoffRollbackReadmissionConsumptionError(
            "rollback_readmission_consumption_revision_invalid"
        )
    expected = _stable_id(
        "ha-roll-writer-handoff-rollback-readmission-consumption",
        _material(value),
    )
    if value.consumption_id != expected:
        raise HARollingWriterHandoffRollbackReadmissionConsumptionError(
            "rollback_readmission_consumption_identity_invalid"
        )


def consume_writer_handoff_rollback_readmission(
    *,
    readmission: RollingWriterHandoffRollbackReadmission,
    prior_admission: RollingWriterHandoffRollbackAdmission,
    reconciliation: RollingWriterHandoffRollbackReconciliationReceipt,
    candidate_admission: RollingWriterHandoffRollbackAdmission,
    evidence: WriterHandoffFencingEvidence,
    assessment: RollingWriterHandoffRecoveryAssessment,
    peer_authority: HAPeerSnapshotAuthority,
    role_authority: HARollbackRoleCommitAuthority,
    lease_authority: HAWriterLeaseRevisionAuthority,
) -> RollingWriterHandoffRollbackReadmissionConsumptionReceipt:
    """Consume exactly one generation-1 readmission through the typed rollback CAS."""

    revalidate_writer_handoff_rollback_readmission(
        readmission=readmission,
        prior_admission=prior_admission,
        reconciliation=reconciliation,
        evidence=evidence,
        assessment=assessment,
        peer_authority=peer_authority,
        role_authority=role_authority,
        lease_authority=lease_authority,
    )
    _verify_candidate_binding(readmission, candidate_admission)
    commit = commit_writer_handoff_rollback(
        admission=candidate_admission,
        evidence=evidence,
        assessment=assessment,
        peer_authority=peer_authority,
        role_authority=role_authority,
        lease_authority=lease_authority,
    )
    _verify_commit_binding(readmission, candidate_admission, commit)

    provisional = RollingWriterHandoffRollbackReadmissionConsumptionReceipt(
        cluster_id=commit.cluster_id,
        consumption_id="pending",
        readmission_id=readmission.readmission_id,
        reconciliation_receipt_id=readmission.reconciliation_receipt_id,
        prior_admission_id=readmission.prior_admission_id,
        candidate_admission_id=readmission.candidate_admission_id,
        commit_receipt_id=commit.receipt_id,
        fencing_evidence_id=commit.fencing_evidence_id,
        recovery_assessment_id=commit.recovery_assessment_id,
        handoff_receipt_id=commit.handoff_receipt_id,
        handoff_intent_id=commit.handoff_intent_id,
        blocked_plan_id=commit.blocked_plan_id,
        rollback_writer_node_id=commit.rollback_writer_node_id,
        fenced_successor_node_id=commit.fenced_successor_node_id,
        member_node_ids=commit.member_node_ids,
        precommit_peer_snapshot_id=commit.precommit_peer_snapshot_id,
        precommit_peer_journal_seq=commit.precommit_peer_journal_seq,
        precommit_ready_node_ids=commit.precommit_ready_node_ids,
        minimum_ready_nodes=commit.minimum_ready_nodes,
        required_quorum_nodes=commit.required_quorum_nodes,
        previous_role_assignment_id=commit.previous_role_assignment_id,
        previous_role_epoch=commit.previous_role_epoch,
        previous_role_resource_version=commit.previous_role_resource_version,
        previous_role_journal_seq=commit.previous_role_journal_seq,
        previous_role_transition_id=commit.previous_role_transition_id,
        committed_role_assignment_id=commit.committed_role_assignment_id,
        committed_role_epoch=commit.committed_role_epoch,
        committed_role_resource_version=commit.committed_role_resource_version,
        committed_role_journal_seq=commit.committed_role_journal_seq,
        committed_role_transition_id=commit.committed_role_transition_id,
        lease_id=commit.lease_id,
        lease_epoch=commit.lease_epoch,
        lease_resource_version=commit.lease_resource_version,
        lease_state_id=commit.lease_state_id,
    )
    result = replace(
        provisional,
        consumption_id=_stable_id(
            "ha-roll-writer-handoff-rollback-readmission-consumption",
            _material(provisional),
        ),
    )
    _verify_consumption(result)
    return result


def revalidate_writer_handoff_rollback_readmission_consumption_receipt(
    *,
    receipt: RollingWriterHandoffRollbackReadmissionConsumptionReceipt,
    commit_receipt: RollingWriterHandoffRollbackCommitReceipt,
    role_authority: HARollbackRoleCommitAuthority,
) -> RollingWriterHandoffRollbackReadmissionConsumptionReceipt:
    """Verify sealed consumption against the durable committed role-journal state."""

    _verify_consumption(receipt)
    revalidate_writer_handoff_rollback_commit_receipt(
        receipt=commit_receipt,
        role_authority=role_authority,
    )
    if (
        receipt.commit_receipt_id != commit_receipt.receipt_id
        or receipt.candidate_admission_id != commit_receipt.admission_id
        or receipt.cluster_id != commit_receipt.cluster_id
        or receipt.fencing_evidence_id != commit_receipt.fencing_evidence_id
        or receipt.recovery_assessment_id != commit_receipt.recovery_assessment_id
        or receipt.handoff_receipt_id != commit_receipt.handoff_receipt_id
        or receipt.handoff_intent_id != commit_receipt.handoff_intent_id
        or receipt.blocked_plan_id != commit_receipt.blocked_plan_id
        or receipt.rollback_writer_node_id != commit_receipt.rollback_writer_node_id
        or receipt.fenced_successor_node_id != commit_receipt.fenced_successor_node_id
        or receipt.member_node_ids != commit_receipt.member_node_ids
        or receipt.precommit_peer_snapshot_id
        != commit_receipt.precommit_peer_snapshot_id
        or receipt.precommit_peer_journal_seq != commit_receipt.precommit_peer_journal_seq
        or receipt.precommit_ready_node_ids != commit_receipt.precommit_ready_node_ids
        or receipt.minimum_ready_nodes != commit_receipt.minimum_ready_nodes
        or receipt.required_quorum_nodes != commit_receipt.required_quorum_nodes
        or receipt.previous_role_assignment_id
        != commit_receipt.previous_role_assignment_id
        or receipt.previous_role_epoch != commit_receipt.previous_role_epoch
        or receipt.previous_role_resource_version
        != commit_receipt.previous_role_resource_version
        or receipt.previous_role_journal_seq != commit_receipt.previous_role_journal_seq
        or receipt.previous_role_transition_id
        != commit_receipt.previous_role_transition_id
        or receipt.committed_role_assignment_id
        != commit_receipt.committed_role_assignment_id
        or receipt.committed_role_epoch != commit_receipt.committed_role_epoch
        or receipt.committed_role_resource_version
        != commit_receipt.committed_role_resource_version
        or receipt.committed_role_journal_seq != commit_receipt.committed_role_journal_seq
        or receipt.committed_role_transition_id
        != commit_receipt.committed_role_transition_id
        or receipt.lease_id != commit_receipt.lease_id
        or receipt.lease_epoch != commit_receipt.lease_epoch
        or receipt.lease_resource_version != commit_receipt.lease_resource_version
        or receipt.lease_state_id != commit_receipt.lease_state_id
    ):
        raise HARollingWriterHandoffRollbackReadmissionConsumptionError(
            "rollback_readmission_consumption_receipt_stale"
        )
    return receipt
