"""Revision-bound fencing evidence for failed rolling writer handoffs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import Protocol

from .ha_rolling_writer_handoff_recovery import (
    RollingWriterHandoffRecoveryAssessment,
    WriterHandoffRecoveryDisposition,
)

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")


class HARollingWriterHandoffFencingError(ValueError):
    """Stable fail-closed error for writer fencing evidence."""


class HAWriterLeaseStateView(Protocol):
    cluster_id: str
    node_id: str
    lease_id: str
    lease_epoch: int
    resource_version: int
    holder_node_id: str | None
    revoked: bool
    revoked_for_role_transition_id: str
    state_id: str
    production_mutation_enabled: bool


class HAWriterLeaseRevisionAuthority(Protocol):
    def state_for(
        self,
        *,
        cluster_id: str,
        node_id: str,
    ) -> HAWriterLeaseStateView: ...


@dataclass(frozen=True, slots=True)
class WriterHandoffFencingEvidence:
    cluster_id: str
    evidence_id: str
    recovery_assessment_id: str
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
    lease_id: str
    lease_epoch: int
    lease_resource_version: int
    lease_state_id: str
    lease_revoked: bool
    lease_revoked_for_role_transition_id: str
    fence_confirmed: bool
    rollback_candidate_node_id: str
    rollback_admission_authorized: bool = False
    role_transition_authorized: bool = False
    failover_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-writer-handoff-fencing-evidence.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "evidence_id": self.evidence_id,
            "recovery_assessment_id": self.recovery_assessment_id,
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
            "lease_id": self.lease_id,
            "lease_epoch": self.lease_epoch,
            "lease_resource_version": self.lease_resource_version,
            "lease_state_id": self.lease_state_id,
            "lease_revoked": self.lease_revoked,
            "lease_revoked_for_role_transition_id": self.lease_revoked_for_role_transition_id,
            "fence_confirmed": self.fence_confirmed,
            "rollback_candidate_node_id": self.rollback_candidate_node_id,
            "rollback_admission_authorized": self.rollback_admission_authorized,
            "role_transition_authorized": self.role_transition_authorized,
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


def _assessment_material(
    assessment: RollingWriterHandoffRecoveryAssessment,
) -> dict[str, object]:
    material = assessment.to_dict()
    material.pop("assessment_id")
    return material


def _evidence_material(evidence: WriterHandoffFencingEvidence) -> dict[str, object]:
    material = evidence.to_dict()
    material.pop("evidence_id")
    return material


def _verify_recovery_assessment(
    assessment: RollingWriterHandoffRecoveryAssessment,
) -> None:
    if assessment.schema != "home-center.ha-rolling-writer-handoff-recovery-assessment.v1":
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_recovery_schema_invalid"
        )
    expected_assessment_id = _stable_id(
        "ha-roll-writer-handoff-recovery",
        _assessment_material(assessment),
    )
    if assessment.assessment_id != expected_assessment_id:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_recovery_identity_invalid"
        )
    if (
        assessment.role_transition_authorized
        or assessment.failover_authorized
        or assessment.host_mutation_authorized
        or assessment.production_mutation_enabled
    ):
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_recovery_authority_invalid"
        )
    if (
        assessment.disposition is not WriterHandoffRecoveryDisposition.RECONCILE
        or assessment.reason != "successor_not_ready_fencing_required"
        or not assessment.fencing_required
        or not assessment.reconciliation_required
        or assessment.previous_writer_health != "ready"
        or assessment.successor_writer_health == "ready"
    ):
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_recovery_not_eligible"
        )

    members = assessment.member_node_ids
    if (
        len(members) < 2
        or len(members) > 64
        or members != tuple(sorted(members))
        or len(members) != len(set(members))
        or assessment.previous_writer_node_id not in members
        or assessment.successor_writer_node_id not in members
        or assessment.previous_writer_node_id == assessment.successor_writer_node_id
    ):
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_membership_invalid"
        )
    for node_id in members:
        if IDENTIFIER.fullmatch(node_id) is None:
            raise HARollingWriterHandoffFencingError(
                "rolling_writer_handoff_fencing_membership_invalid"
            )

    expected_quorum = len(members) // 2 + 1
    if assessment.required_quorum_nodes != expected_quorum:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_quorum_invalid"
        )
    if (
        isinstance(assessment.minimum_ready_nodes, bool)
        or not isinstance(assessment.minimum_ready_nodes, int)
        or assessment.minimum_ready_nodes < 1
        or assessment.minimum_ready_nodes > len(members)
    ):
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_ready_floor_invalid"
        )
    ready = assessment.ready_node_ids
    if (
        ready != tuple(sorted(ready))
        or len(ready) != len(set(ready))
        or not set(ready).issubset(members)
        or assessment.ready_count != len(ready)
    ):
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_ready_evidence_invalid"
        )
    if (
        assessment.ready_count < expected_quorum
        or assessment.ready_count < assessment.minimum_ready_nodes
        or assessment.previous_writer_node_id not in ready
        or assessment.successor_writer_node_id in ready
    ):
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_safety_boundary_not_met"
        )


def _lease_material(state: HAWriterLeaseStateView) -> dict[str, object]:
    return {
        "schema": "home-center.ha-writer-lease-state.v1",
        "cluster_id": state.cluster_id,
        "node_id": state.node_id,
        "lease_id": state.lease_id,
        "lease_epoch": state.lease_epoch,
        "resource_version": state.resource_version,
        "holder_node_id": state.holder_node_id,
        "revoked": state.revoked,
        "revoked_for_role_transition_id": state.revoked_for_role_transition_id,
    }


def _verify_lease_state(
    state: HAWriterLeaseStateView,
    *,
    cluster_id: str,
    successor_writer_node_id: str,
    assessment_role_transition_id: str,
) -> None:
    if state.production_mutation_enabled:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_lease_mutation_enabled"
        )
    if state.cluster_id != cluster_id or state.node_id != successor_writer_node_id:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_lease_binding_invalid"
        )
    if (
        IDENTIFIER.fullmatch(state.cluster_id) is None
        or IDENTIFIER.fullmatch(state.node_id) is None
        or IDENTIFIER.fullmatch(state.lease_id) is None
    ):
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_lease_identity_invalid"
        )
    for value, code in (
        (state.lease_epoch, "rolling_writer_handoff_fencing_lease_epoch_invalid"),
        (
            state.resource_version,
            "rolling_writer_handoff_fencing_lease_resource_version_invalid",
        ),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise HARollingWriterHandoffFencingError(code)
    expected_state_id = _stable_id("ha-writer-lease", _lease_material(state))
    if state.state_id != expected_state_id:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_lease_state_identity_invalid"
        )
    if not state.revoked:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_lease_not_revoked"
        )
    if state.revoked_for_role_transition_id != assessment_role_transition_id:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_lease_transition_binding_invalid"
        )
    if state.holder_node_id is not None:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_lease_holder_present"
        )


def _same_lease_revision(
    first: HAWriterLeaseStateView,
    second: HAWriterLeaseStateView,
) -> bool:
    return first.state_id == second.state_id and _lease_material(first) == _lease_material(
        second
    )


def _verify_evidence(evidence: WriterHandoffFencingEvidence) -> None:
    if evidence.schema != "home-center.ha-rolling-writer-handoff-fencing-evidence.v1":
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_evidence_schema_invalid"
        )
    if (
        evidence.rollback_admission_authorized
        or evidence.role_transition_authorized
        or evidence.failover_authorized
        or evidence.host_mutation_authorized
        or evidence.production_mutation_enabled
    ):
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_evidence_authority_invalid"
        )
    if not evidence.lease_revoked or not evidence.fence_confirmed:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_evidence_not_confirmed"
        )
    if evidence.lease_revoked_for_role_transition_id != evidence.role_transition_id:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_evidence_transition_binding_invalid"
        )
    if evidence.rollback_candidate_node_id != evidence.previous_writer_node_id:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_rollback_candidate_invalid"
        )
    if evidence.required_quorum_nodes != len(evidence.member_node_ids) // 2 + 1:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_evidence_quorum_invalid"
        )
    if (
        evidence.ready_count != len(evidence.ready_node_ids)
        or evidence.ready_count < evidence.required_quorum_nodes
        or evidence.ready_count < evidence.minimum_ready_nodes
        or evidence.previous_writer_node_id not in evidence.ready_node_ids
        or evidence.successor_writer_node_id in evidence.ready_node_ids
    ):
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_evidence_ready_invalid"
        )
    expected = _stable_id(
        "ha-roll-writer-handoff-fencing",
        _evidence_material(evidence),
    )
    if evidence.evidence_id != expected:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_evidence_identity_invalid"
        )


def build_writer_handoff_fencing_evidence(
    *,
    assessment: RollingWriterHandoffRecoveryAssessment,
    lease_authority: HAWriterLeaseRevisionAuthority,
) -> WriterHandoffFencingEvidence:
    """Seal authoritative lease-revocation evidence without authorizing rollback."""

    _verify_recovery_assessment(assessment)
    before = lease_authority.state_for(
        cluster_id=assessment.cluster_id,
        node_id=assessment.successor_writer_node_id,
    )
    _verify_lease_state(
        before,
        cluster_id=assessment.cluster_id,
        successor_writer_node_id=assessment.successor_writer_node_id,
        assessment_role_transition_id=assessment.role_transition_id,
    )
    after = lease_authority.state_for(
        cluster_id=assessment.cluster_id,
        node_id=assessment.successor_writer_node_id,
    )
    _verify_lease_state(
        after,
        cluster_id=assessment.cluster_id,
        successor_writer_node_id=assessment.successor_writer_node_id,
        assessment_role_transition_id=assessment.role_transition_id,
    )
    if not _same_lease_revision(before, after):
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_lease_state_stale"
        )

    provisional = WriterHandoffFencingEvidence(
        cluster_id=assessment.cluster_id,
        evidence_id="pending",
        recovery_assessment_id=assessment.assessment_id,
        handoff_receipt_id=assessment.handoff_receipt_id,
        handoff_intent_id=assessment.handoff_intent_id,
        blocked_plan_id=assessment.blocked_plan_id,
        previous_writer_node_id=assessment.previous_writer_node_id,
        successor_writer_node_id=assessment.successor_writer_node_id,
        member_node_ids=assessment.member_node_ids,
        peer_snapshot_id=assessment.peer_snapshot_id,
        peer_journal_seq=assessment.peer_journal_seq,
        role_assignment_id=assessment.role_assignment_id,
        role_epoch=assessment.role_epoch,
        role_resource_version=assessment.role_resource_version,
        role_journal_seq=assessment.role_journal_seq,
        role_transition_id=assessment.role_transition_id,
        minimum_ready_nodes=assessment.minimum_ready_nodes,
        required_quorum_nodes=assessment.required_quorum_nodes,
        ready_node_ids=assessment.ready_node_ids,
        ready_count=assessment.ready_count,
        lease_id=after.lease_id,
        lease_epoch=after.lease_epoch,
        lease_resource_version=after.resource_version,
        lease_state_id=after.state_id,
        lease_revoked=after.revoked,
        lease_revoked_for_role_transition_id=after.revoked_for_role_transition_id,
        fence_confirmed=True,
        rollback_candidate_node_id=assessment.previous_writer_node_id,
    )
    result = replace(
        provisional,
        evidence_id=_stable_id(
            "ha-roll-writer-handoff-fencing",
            _evidence_material(provisional),
        ),
    )
    _verify_evidence(result)
    return result


def revalidate_writer_handoff_fencing_evidence(
    *,
    evidence: WriterHandoffFencingEvidence,
    assessment: RollingWriterHandoffRecoveryAssessment,
    lease_authority: HAWriterLeaseRevisionAuthority,
) -> WriterHandoffFencingEvidence:
    """Reject saved fencing evidence after recovery or lease revision movement."""

    _verify_evidence(evidence)
    current = build_writer_handoff_fencing_evidence(
        assessment=assessment,
        lease_authority=lease_authority,
    )
    if current != evidence:
        raise HARollingWriterHandoffFencingError(
            "rolling_writer_handoff_fencing_evidence_stale"
        )
    return evidence
