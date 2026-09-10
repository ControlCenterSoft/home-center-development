"""Fresh CAS admission after a definitely-not-applied rollback reconciliation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

from .ha_rolling_revision import HARoleRevisionAuthority
from .ha_rolling_writer_handoff_fencing import (
    HAWriterLeaseRevisionAuthority,
    WriterHandoffFencingEvidence,
)
from .ha_rolling_writer_handoff_recovery import RollingWriterHandoffRecoveryAssessment
from .ha_rolling_writer_handoff_rollback_admission import (
    HAPeerSnapshotAuthority,
    RollingWriterHandoffRollbackAdmission,
    _verify_admission as _verify_rollback_admission,
    build_writer_handoff_rollback_admission,
    revalidate_writer_handoff_rollback_admission,
)
from .ha_rolling_writer_handoff_rollback_reconciliation import (
    RollbackCommitOutcome,
    RollingWriterHandoffRollbackReconciliationReceipt,
    revalidate_writer_handoff_rollback_reconciliation_receipt,
)


class HARollingWriterHandoffRollbackReadmissionError(ValueError):
    """Stable fail-closed error for reconciled rollback readmission."""


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffRollbackReadmission:
    cluster_id: str
    readmission_id: str
    reconciliation_receipt_id: str
    prior_admission_id: str
    candidate_admission_id: str
    fencing_evidence_id: str
    recovery_assessment_id: str
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
    recovery_generation: int = 1
    maximum_recovery_generation: int = 1
    fresh_cas_admission: bool = True
    single_use_by_cas: bool = True
    rollback_transition_admitted: bool = True
    automatic_retry_authorized: bool = False
    execution_authorized: bool = False
    failover_authorized: bool = False
    writer_service_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-writer-handoff-rollback-readmission.v1"

    def to_dict(self) -> dict[str, object]:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["member_node_ids"] = list(self.member_node_ids)
        result["ready_node_ids"] = list(self.ready_node_ids)
        return result


def _stable_id(prefix: str, material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f"{prefix}-{digest}"


def _material(value: RollingWriterHandoffRollbackReadmission) -> dict[str, object]:
    material = value.to_dict()
    material.pop("readmission_id")
    return material


def _same_fields(first, second, names: tuple[str, ...]) -> bool:
    return all(getattr(first, name) == getattr(second, name) for name in names)


def _verify_reconciled_precommit(
    prior: RollingWriterHandoffRollbackAdmission,
    receipt: RollingWriterHandoffRollbackReconciliationReceipt,
) -> None:
    _verify_rollback_admission(prior)
    revalidate_writer_handoff_rollback_reconciliation_receipt(receipt=receipt)
    if (
        receipt.outcome is not RollbackCommitOutcome.DEFINITELY_NOT_APPLIED
        or receipt.reason != "exact_precommit_revision_current"
        or not receipt.fresh_admission_required
        or receipt.rollback_completed
        or receipt.operator_reconciliation_required
        or receipt.rollback_transition_observed
    ):
        raise HARollingWriterHandoffRollbackReadmissionError(
            "rollback_readmission_reconciliation_not_eligible"
        )
    shared = (
        "cluster_id",
        "admission_id",
        "member_node_ids",
        "rollback_writer_node_id",
        "fenced_successor_node_id",
        "expected_role_assignment_id",
        "expected_role_epoch",
        "expected_role_resource_version",
        "expected_role_journal_seq",
        "expected_role_transition_id",
        "target_role_assignment_id",
        "target_role_epoch",
    )
    if not _same_fields(receipt, prior, shared) or (
        receipt.observed_role_assignment_id != prior.expected_role_assignment_id
        or receipt.observed_role_epoch != prior.expected_role_epoch
        or receipt.observed_role_resource_version != prior.expected_role_resource_version
        or receipt.observed_role_journal_seq != prior.expected_role_journal_seq
        or receipt.observed_role_transition_id != prior.expected_role_transition_id
        or receipt.observed_writer_node_ids != (prior.fenced_successor_node_id,)
    ):
        raise HARollingWriterHandoffRollbackReadmissionError(
            "rollback_readmission_reconciliation_lineage_invalid"
        )


def _verify_candidate_lineage(
    prior: RollingWriterHandoffRollbackAdmission,
    candidate: RollingWriterHandoffRollbackAdmission,
) -> None:
    immutable = (
        "cluster_id",
        "fencing_evidence_id",
        "recovery_assessment_id",
        "handoff_receipt_id",
        "handoff_intent_id",
        "blocked_plan_id",
        "rollback_writer_node_id",
        "fenced_successor_node_id",
        "member_node_ids",
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
    if not _same_fields(candidate, prior, immutable):
        raise HARollingWriterHandoffRollbackReadmissionError(
            "rollback_readmission_current_lineage_moved"
        )


def _verify_readmission(value: RollingWriterHandoffRollbackReadmission) -> None:
    if (
        value.schema != "home-center.ha-rolling-writer-handoff-rollback-readmission.v1"
        or value.recovery_generation != 1
        or value.maximum_recovery_generation != 1
        or not value.fresh_cas_admission
        or not value.single_use_by_cas
        or not value.rollback_transition_admitted
        or value.automatic_retry_authorized
        or value.execution_authorized
        or value.failover_authorized
        or value.writer_service_authorized
        or value.host_mutation_authorized
        or value.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackReadmissionError(
            "rollback_readmission_authority_invalid"
        )
    if (
        value.member_node_ids != tuple(sorted(value.member_node_ids))
        or len(value.member_node_ids) != len(set(value.member_node_ids))
        or value.required_quorum_nodes != len(value.member_node_ids) // 2 + 1
        or value.ready_count != len(value.ready_node_ids)
        or value.ready_count < value.required_quorum_nodes
        or value.ready_count < value.minimum_ready_nodes
        or value.rollback_writer_node_id not in value.ready_node_ids
        or value.fenced_successor_node_id in value.ready_node_ids
    ):
        raise HARollingWriterHandoffRollbackReadmissionError(
            "rollback_readmission_safety_evidence_invalid"
        )
    if value.target_role_epoch != value.expected_role_epoch + 1:
        raise HARollingWriterHandoffRollbackReadmissionError(
            "rollback_readmission_target_epoch_invalid"
        )
    expected = _stable_id("ha-roll-writer-handoff-rollback-readmission", _material(value))
    if value.readmission_id != expected:
        raise HARollingWriterHandoffRollbackReadmissionError(
            "rollback_readmission_identity_invalid"
        )


def build_writer_handoff_rollback_readmission(
    *,
    prior_admission: RollingWriterHandoffRollbackAdmission,
    reconciliation: RollingWriterHandoffRollbackReconciliationReceipt,
    evidence: WriterHandoffFencingEvidence,
    assessment: RollingWriterHandoffRecoveryAssessment,
    peer_authority: HAPeerSnapshotAuthority,
    role_authority: HARoleRevisionAuthority,
    lease_authority: HAWriterLeaseRevisionAuthority,
) -> RollingWriterHandoffRollbackReadmission:
    """Seal one fresh CAS admission after definitely-not-applied reconciliation."""

    _verify_reconciled_precommit(prior_admission, reconciliation)
    candidate = build_writer_handoff_rollback_admission(
        evidence=evidence,
        assessment=assessment,
        peer_authority=peer_authority,
        role_authority=role_authority,
        lease_authority=lease_authority,
    )
    _verify_candidate_lineage(prior_admission, candidate)
    revalidate_writer_handoff_rollback_admission(
        admission=candidate,
        evidence=evidence,
        assessment=assessment,
        peer_authority=peer_authority,
        role_authority=role_authority,
        lease_authority=lease_authority,
    )
    provisional = RollingWriterHandoffRollbackReadmission(
        cluster_id=candidate.cluster_id,
        readmission_id="pending",
        reconciliation_receipt_id=reconciliation.receipt_id,
        prior_admission_id=prior_admission.admission_id,
        candidate_admission_id=candidate.admission_id,
        fencing_evidence_id=candidate.fencing_evidence_id,
        recovery_assessment_id=candidate.recovery_assessment_id,
        rollback_writer_node_id=candidate.rollback_writer_node_id,
        fenced_successor_node_id=candidate.fenced_successor_node_id,
        member_node_ids=candidate.member_node_ids,
        peer_snapshot_id=candidate.peer_snapshot_id,
        peer_journal_seq=candidate.peer_journal_seq,
        ready_node_ids=candidate.ready_node_ids,
        ready_count=candidate.ready_count,
        minimum_ready_nodes=candidate.minimum_ready_nodes,
        required_quorum_nodes=candidate.required_quorum_nodes,
        expected_role_assignment_id=candidate.expected_role_assignment_id,
        expected_role_epoch=candidate.expected_role_epoch,
        expected_role_resource_version=candidate.expected_role_resource_version,
        expected_role_journal_seq=candidate.expected_role_journal_seq,
        expected_role_transition_id=candidate.expected_role_transition_id,
        target_role_assignment_id=candidate.target_role_assignment_id,
        target_role_epoch=candidate.target_role_epoch,
        lease_id=candidate.lease_id,
        lease_epoch=candidate.lease_epoch,
        lease_resource_version=candidate.lease_resource_version,
        lease_state_id=candidate.lease_state_id,
        lease_revoked_for_role_transition_id=candidate.lease_revoked_for_role_transition_id,
    )
    result = replace(
        provisional,
        readmission_id=_stable_id(
            "ha-roll-writer-handoff-rollback-readmission", _material(provisional)
        ),
    )
    _verify_readmission(result)
    return result


def revalidate_writer_handoff_rollback_readmission(
    *,
    readmission: RollingWriterHandoffRollbackReadmission,
    prior_admission: RollingWriterHandoffRollbackAdmission,
    reconciliation: RollingWriterHandoffRollbackReconciliationReceipt,
    evidence: WriterHandoffFencingEvidence,
    assessment: RollingWriterHandoffRecoveryAssessment,
    peer_authority: HAPeerSnapshotAuthority,
    role_authority: HARoleRevisionAuthority,
    lease_authority: HAWriterLeaseRevisionAuthority,
) -> RollingWriterHandoffRollbackReadmission:
    """Reject saved readmission after peer, role, fence, or lineage movement."""

    _verify_readmission(readmission)
    current = build_writer_handoff_rollback_readmission(
        prior_admission=prior_admission,
        reconciliation=reconciliation,
        evidence=evidence,
        assessment=assessment,
        peer_authority=peer_authority,
        role_authority=role_authority,
        lease_authority=lease_authority,
    )
    if current != readmission:
        raise HARollingWriterHandoffRollbackReadmissionError(
            "rollback_readmission_stale"
        )
    return readmission
