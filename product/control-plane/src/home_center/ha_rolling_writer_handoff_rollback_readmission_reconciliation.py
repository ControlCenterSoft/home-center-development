"""Terminal reconciliation for a lost generation-1 rollback readmission CAS response."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

from .ha_rolling_writer_handoff_rollback_admission import (
    RollingWriterHandoffRollbackAdmission,
)
from .ha_rolling_writer_handoff_rollback_commit import (
    RollingWriterHandoffRollbackCommitReceipt,
    revalidate_writer_handoff_rollback_commit_receipt,
)
from .ha_rolling_writer_handoff_rollback_readmission import (
    RollingWriterHandoffRollbackReadmission,
    _verify_readmission,
)
from .ha_rolling_writer_handoff_rollback_readmission_consumption import (
    RollingWriterHandoffRollbackReadmissionConsumptionReceipt,
    revalidate_writer_handoff_rollback_readmission_consumption_receipt,
)
from .ha_rolling_writer_handoff_rollback_reconciliation import (
    HARollbackReconciliationAuthority,
    RollbackCommitOutcome,
    RollingWriterHandoffRollbackReconciliationReceipt,
    reconcile_writer_handoff_rollback,
    revalidate_writer_handoff_rollback_reconciliation_receipt,
)


class HARollingWriterHandoffRollbackReadmissionReconciliationError(ValueError):
    """Stable fail-closed error for terminal generation-1 reconciliation."""


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffRollbackReadmissionReconciliationReceipt:
    cluster_id: str
    receipt_id: str
    readmission_id: str
    source_reconciliation_receipt_id: str
    prior_admission_id: str
    candidate_admission_id: str
    observed_reconciliation_receipt_id: str
    recovered_commit_receipt_id: str | None
    recovered_consumption_id: str | None
    rollback_writer_node_id: str
    fenced_successor_node_id: str
    member_node_ids: tuple[str, ...]
    expected_role_assignment_id: str
    expected_role_epoch: int
    expected_role_resource_version: int
    expected_role_journal_seq: int
    expected_role_transition_id: str
    target_role_assignment_id: str
    target_role_epoch: int
    observed_role_assignment_id: str | None
    observed_role_epoch: int | None
    observed_role_resource_version: int | None
    observed_role_journal_seq: int | None
    observed_role_transition_id: str | None
    observed_writer_node_ids: tuple[str, ...]
    outcome: RollbackCommitOutcome
    reason: str
    terminal_consumption_recovered: bool
    operator_recovery_closure_required: bool
    recovery_generation: int = 1
    maximum_recovery_generation: int = 1
    terminal_generation: bool = True
    further_readmission_authorized: bool = False
    fresh_admission_authorized: bool = False
    automatic_retry_authorized: bool = False
    execution_authorized: bool = False
    failover_authorized: bool = False
    writer_service_authorized: bool = False
    host_mutation_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = (
        "home-center.ha-rolling-writer-handoff-rollback-readmission-reconciliation.v1"
    )

    def to_dict(self) -> dict[str, object]:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["member_node_ids"] = list(self.member_node_ids)
        result["observed_writer_node_ids"] = list(self.observed_writer_node_ids)
        result["outcome"] = self.outcome.value
        return result


@dataclass(frozen=True, slots=True)
class RollingWriterHandoffRollbackReadmissionReconciliationResult:
    receipt: RollingWriterHandoffRollbackReadmissionReconciliationReceipt
    recovered_commit_receipt: RollingWriterHandoffRollbackCommitReceipt | None
    recovered_consumption_receipt: (
        RollingWriterHandoffRollbackReadmissionConsumptionReceipt | None
    )


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
    value: RollingWriterHandoffRollbackReadmissionReconciliationReceipt,
) -> dict[str, object]:
    material = value.to_dict()
    material.pop("receipt_id")
    return material


def _same_fields(first, second, names: tuple[str, ...]) -> bool:
    return all(getattr(first, name) == getattr(second, name) for name in names)


def _verify_readmission_candidate(
    readmission: RollingWriterHandoffRollbackReadmission,
    candidate: RollingWriterHandoffRollbackAdmission,
) -> None:
    try:
        _verify_readmission(readmission)
    except ValueError as exc:
        raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
            "rollback_readmission_reconciliation_readmission_invalid"
        ) from exc
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
        readmission.candidate_admission_id != candidate.admission_id
        or not _same_fields(readmission, candidate, shared)
        or not candidate.cas_bound
        or not candidate.single_use_by_cas
        or not candidate.rollback_transition_admitted
        or candidate.execution_authorized
        or candidate.failover_authorized
        or candidate.host_mutation_authorized
        or candidate.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
            "rollback_readmission_reconciliation_candidate_lineage_invalid"
        )


def _verify_observation(
    candidate: RollingWriterHandoffRollbackAdmission,
    observation: RollingWriterHandoffRollbackReconciliationReceipt,
) -> None:
    try:
        revalidate_writer_handoff_rollback_reconciliation_receipt(
            receipt=observation
        )
    except ValueError as exc:
        raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
            "rollback_readmission_reconciliation_observation_invalid"
        ) from exc
    shared = (
        "cluster_id",
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
    if (
        observation.admission_id != candidate.admission_id
        or not _same_fields(observation, candidate, shared)
        or observation.fresh_admission_authorized
        or observation.automatic_retry_authorized
        or observation.execution_authorized
        or observation.failover_authorized
        or observation.writer_service_authorized
        or observation.host_mutation_authorized
        or observation.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
            "rollback_readmission_reconciliation_observation_lineage_invalid"
        )


def _recover_commit_receipt(
    candidate: RollingWriterHandoffRollbackAdmission,
    observation: RollingWriterHandoffRollbackReconciliationReceipt,
) -> RollingWriterHandoffRollbackCommitReceipt:
    if (
        observation.outcome is not RollbackCommitOutcome.COMMITTED
        or observation.reason != "exact_rollback_transition_current"
        or not observation.rollback_completed
        or observation.fresh_admission_required
        or observation.operator_reconciliation_required
        or not observation.rollback_transition_observed
        or observation.observed_role_assignment_id != candidate.target_role_assignment_id
        or observation.observed_role_epoch != candidate.target_role_epoch
        or observation.observed_role_resource_version
        != candidate.expected_role_resource_version + 1
        or observation.observed_role_journal_seq
        != candidate.expected_role_journal_seq + 1
        or observation.observed_role_transition_id
        != observation.expected_rollback_transition_id
        or observation.observed_role_transition_kind != "rollback"
        or observation.observed_writer_node_ids
        != (candidate.rollback_writer_node_id,)
    ):
        raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
            "rollback_readmission_reconciliation_committed_evidence_invalid"
        )
    provisional = RollingWriterHandoffRollbackCommitReceipt(
        cluster_id=candidate.cluster_id,
        receipt_id="pending",
        admission_id=candidate.admission_id,
        fencing_evidence_id=candidate.fencing_evidence_id,
        recovery_assessment_id=candidate.recovery_assessment_id,
        handoff_receipt_id=candidate.handoff_receipt_id,
        handoff_intent_id=candidate.handoff_intent_id,
        blocked_plan_id=candidate.blocked_plan_id,
        rollback_writer_node_id=candidate.rollback_writer_node_id,
        fenced_successor_node_id=candidate.fenced_successor_node_id,
        member_node_ids=candidate.member_node_ids,
        precommit_peer_snapshot_id=candidate.peer_snapshot_id,
        precommit_peer_journal_seq=candidate.peer_journal_seq,
        precommit_ready_node_ids=candidate.ready_node_ids,
        minimum_ready_nodes=candidate.minimum_ready_nodes,
        required_quorum_nodes=candidate.required_quorum_nodes,
        previous_role_assignment_id=candidate.expected_role_assignment_id,
        previous_role_epoch=candidate.expected_role_epoch,
        previous_role_resource_version=candidate.expected_role_resource_version,
        previous_role_journal_seq=candidate.expected_role_journal_seq,
        previous_role_transition_id=candidate.expected_role_transition_id,
        committed_role_assignment_id=observation.observed_role_assignment_id,
        committed_role_epoch=observation.observed_role_epoch,
        committed_role_resource_version=observation.observed_role_resource_version,
        committed_role_journal_seq=observation.observed_role_journal_seq,
        committed_role_transition_id=observation.observed_role_transition_id,
        lease_id=candidate.lease_id,
        lease_epoch=candidate.lease_epoch,
        lease_resource_version=candidate.lease_resource_version,
        lease_state_id=candidate.lease_state_id,
    )
    material = provisional.to_dict()
    material.pop("receipt_id")
    result = replace(
        provisional,
        receipt_id=_stable_id(
            "ha-roll-writer-handoff-rollback-commit",
            material,
        ),
    )
    return result


def _recover_consumption_receipt(
    readmission: RollingWriterHandoffRollbackReadmission,
    commit: RollingWriterHandoffRollbackCommitReceipt,
) -> RollingWriterHandoffRollbackReadmissionConsumptionReceipt:
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
    material = provisional.to_dict()
    material.pop("consumption_id")
    return replace(
        provisional,
        consumption_id=_stable_id(
            "ha-roll-writer-handoff-rollback-readmission-consumption",
            material,
        ),
    )


def _verify_terminal_receipt(
    value: RollingWriterHandoffRollbackReadmissionReconciliationReceipt,
) -> None:
    if (
        value.schema
        != "home-center.ha-rolling-writer-handoff-rollback-readmission-reconciliation.v1"
        or value.recovery_generation != 1
        or value.maximum_recovery_generation != 1
        or not value.terminal_generation
        or value.further_readmission_authorized
        or value.fresh_admission_authorized
        or value.automatic_retry_authorized
        or value.execution_authorized
        or value.failover_authorized
        or value.writer_service_authorized
        or value.host_mutation_authorized
        or value.production_mutation_enabled
    ):
        raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
            "rollback_readmission_reconciliation_authority_invalid"
        )
    committed = value.outcome is RollbackCommitOutcome.COMMITTED
    if (
        value.terminal_consumption_recovered != committed
        or value.operator_recovery_closure_required == committed
        or committed
        != (
            value.recovered_commit_receipt_id is not None
            and value.recovered_consumption_id is not None
        )
        or (not committed)
        and (
            value.recovered_commit_receipt_id is not None
            or value.recovered_consumption_id is not None
        )
    ):
        raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
            "rollback_readmission_reconciliation_semantics_invalid"
        )
    if (
        value.member_node_ids != tuple(sorted(value.member_node_ids))
        or len(value.member_node_ids) != len(set(value.member_node_ids))
        or value.rollback_writer_node_id not in value.member_node_ids
        or value.fenced_successor_node_id not in value.member_node_ids
        or value.rollback_writer_node_id == value.fenced_successor_node_id
    ):
        raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
            "rollback_readmission_reconciliation_membership_invalid"
        )
    expected = _stable_id(
        "ha-roll-writer-handoff-rollback-readmission-reconciliation",
        _material(value),
    )
    if value.receipt_id != expected:
        raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
            "rollback_readmission_reconciliation_identity_invalid"
        )


def reconcile_writer_handoff_rollback_readmission(
    *,
    readmission: RollingWriterHandoffRollbackReadmission,
    candidate_admission: RollingWriterHandoffRollbackAdmission,
    role_authority: HARollbackReconciliationAuthority,
) -> RollingWriterHandoffRollbackReadmissionReconciliationResult:
    """Classify a lost final CAS response without granting generation-2 authority."""

    _verify_readmission_candidate(readmission, candidate_admission)
    observation = reconcile_writer_handoff_rollback(
        admission=candidate_admission,
        role_authority=role_authority,
    )
    _verify_observation(candidate_admission, observation)

    recovered_commit = None
    recovered_consumption = None
    if observation.outcome is RollbackCommitOutcome.COMMITTED:
        recovered_commit = _recover_commit_receipt(candidate_admission, observation)
        try:
            revalidate_writer_handoff_rollback_commit_receipt(
                receipt=recovered_commit,
                role_authority=role_authority,
            )
        except ValueError as exc:
            raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
                "rollback_readmission_reconciliation_commit_revalidation_failed"
            ) from exc
        recovered_consumption = _recover_consumption_receipt(
            readmission,
            recovered_commit,
        )
        try:
            revalidate_writer_handoff_rollback_readmission_consumption_receipt(
                receipt=recovered_consumption,
                commit_receipt=recovered_commit,
                role_authority=role_authority,
            )
        except ValueError as exc:
            raise HARollingWriterHandoffRollbackReadmissionReconciliationError(
                "rollback_readmission_reconciliation_consumption_revalidation_failed"
            ) from exc

    provisional = RollingWriterHandoffRollbackReadmissionReconciliationReceipt(
        cluster_id=readmission.cluster_id,
        receipt_id="pending",
        readmission_id=readmission.readmission_id,
        source_reconciliation_receipt_id=readmission.reconciliation_receipt_id,
        prior_admission_id=readmission.prior_admission_id,
        candidate_admission_id=readmission.candidate_admission_id,
        observed_reconciliation_receipt_id=observation.receipt_id,
        recovered_commit_receipt_id=(
            recovered_commit.receipt_id if recovered_commit else None
        ),
        recovered_consumption_id=(
            recovered_consumption.consumption_id if recovered_consumption else None
        ),
        rollback_writer_node_id=readmission.rollback_writer_node_id,
        fenced_successor_node_id=readmission.fenced_successor_node_id,
        member_node_ids=readmission.member_node_ids,
        expected_role_assignment_id=readmission.expected_role_assignment_id,
        expected_role_epoch=readmission.expected_role_epoch,
        expected_role_resource_version=readmission.expected_role_resource_version,
        expected_role_journal_seq=readmission.expected_role_journal_seq,
        expected_role_transition_id=readmission.expected_role_transition_id,
        target_role_assignment_id=readmission.target_role_assignment_id,
        target_role_epoch=readmission.target_role_epoch,
        observed_role_assignment_id=observation.observed_role_assignment_id,
        observed_role_epoch=observation.observed_role_epoch,
        observed_role_resource_version=observation.observed_role_resource_version,
        observed_role_journal_seq=observation.observed_role_journal_seq,
        observed_role_transition_id=observation.observed_role_transition_id,
        observed_writer_node_ids=observation.observed_writer_node_ids,
        outcome=observation.outcome,
        reason=observation.reason,
        terminal_consumption_recovered=recovered_consumption is not None,
        operator_recovery_closure_required=(
            observation.outcome is not RollbackCommitOutcome.COMMITTED
        ),
    )
    receipt = replace(
        provisional,
        receipt_id=_stable_id(
            "ha-roll-writer-handoff-rollback-readmission-reconciliation",
            _material(provisional),
        ),
    )
    _verify_terminal_receipt(receipt)
    return RollingWriterHandoffRollbackReadmissionReconciliationResult(
        receipt=receipt,
        recovered_commit_receipt=recovered_commit,
        recovered_consumption_receipt=recovered_consumption,
    )


def revalidate_writer_handoff_rollback_readmission_reconciliation_receipt(
    *,
    receipt: RollingWriterHandoffRollbackReadmissionReconciliationReceipt,
) -> RollingWriterHandoffRollbackReadmissionReconciliationReceipt:
    """Validate terminal evidence without granting retry, failover, or mutation authority."""

    _verify_terminal_receipt(receipt)
    return receipt
