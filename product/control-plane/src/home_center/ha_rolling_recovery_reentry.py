"""Reassess a recovered rolling HA step without authorizing execution."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

from .ha_peer_snapshot import HAPeerStateSnapshot
from .ha_rolling_checkpoint import RollingStepCheckpoint
from .ha_rolling_recovery import RollingRecoveryHandoff
from .ha_rolling_recovery_completion import (
    RollingRecoveryCompletionReceipt,
    RollingRecoveryReadyGate,
    revalidate_rolling_recovery_ready_gate,
)
from .ha_rolling_revision import (
    HARoleRevisionAuthority,
    RevisionBoundRollingSafetyDecision,
    evaluate_revision_bound_rolling_safety,
)


class HARollingRecoveryReentryError(ValueError):
    """Stable fail-closed error for post-recovery rolling reassessment."""


@dataclass(frozen=True, slots=True)
class RollingRecoveryReentryDecision:
    safe: bool
    cluster_id: str
    decision_id: str
    ready_gate_id: str
    completion_receipt_id: str
    recovery_handoff_id: str
    previous_failed_plan_id: str
    candidate_plan_id: str
    target_node_id: str
    peer_snapshot_id: str
    peer_journal_seq: int
    role_assignment_id: str
    role_epoch: int
    role_resource_version: int
    role_journal_seq: int
    role_transition_id: str
    minimum_ready_nodes: int
    required_predecessor_node_id: str | None
    required_predecessor_revision: str | None
    single_node_downtime_acknowledged: bool
    recovery_mode: str
    blockers: tuple[str, ...]
    ready_before: int
    ready_after_target_stops: int
    writer_node_id: str | None
    retry_same_failed_node: bool = True
    reassessment_completed: bool = True
    execution_authorized: bool = False
    failover_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-recovery-reentry-decision.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "safe": self.safe,
            "cluster_id": self.cluster_id,
            "decision_id": self.decision_id,
            "ready_gate_id": self.ready_gate_id,
            "completion_receipt_id": self.completion_receipt_id,
            "recovery_handoff_id": self.recovery_handoff_id,
            "previous_failed_plan_id": self.previous_failed_plan_id,
            "candidate_plan_id": self.candidate_plan_id,
            "target_node_id": self.target_node_id,
            "peer_snapshot_id": self.peer_snapshot_id,
            "peer_journal_seq": self.peer_journal_seq,
            "role_assignment_id": self.role_assignment_id,
            "role_epoch": self.role_epoch,
            "role_resource_version": self.role_resource_version,
            "role_journal_seq": self.role_journal_seq,
            "role_transition_id": self.role_transition_id,
            "minimum_ready_nodes": self.minimum_ready_nodes,
            "required_predecessor_node_id": self.required_predecessor_node_id,
            "required_predecessor_revision": self.required_predecessor_revision,
            "single_node_downtime_acknowledged": self.single_node_downtime_acknowledged,
            "recovery_mode": self.recovery_mode,
            "blockers": list(self.blockers),
            "ready_before": self.ready_before,
            "ready_after_target_stops": self.ready_after_target_stops,
            "writer_node_id": self.writer_node_id,
            "retry_same_failed_node": self.retry_same_failed_node,
            "reassessment_completed": self.reassessment_completed,
            "execution_authorized": self.execution_authorized,
            "failover_authorized": self.failover_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


def _stable_id(material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"ha-roll-reentry-{digest}"


def _identity_material(decision: RollingRecoveryReentryDecision) -> dict[str, object]:
    data = decision.to_dict()
    data.pop("decision_id")
    return data


def _verify_identity(decision: RollingRecoveryReentryDecision) -> None:
    if decision.schema != "home-center.ha-rolling-recovery-reentry-decision.v1":
        raise HARollingRecoveryReentryError("rolling_reentry_schema_invalid")
    if (
        not decision.retry_same_failed_node
        or not decision.reassessment_completed
        or decision.execution_authorized
        or decision.failover_authorized
        or decision.production_mutation_enabled
    ):
        raise HARollingRecoveryReentryError("rolling_reentry_authority_invalid")
    if decision.safe and decision.blockers:
        raise HARollingRecoveryReentryError("rolling_reentry_safety_inconsistent")
    if decision.decision_id != _stable_id(_identity_material(decision)):
        raise HARollingRecoveryReentryError("rolling_reentry_identity_invalid")


def evaluate_rolling_recovery_reentry(
    *,
    gate: RollingRecoveryReadyGate,
    receipt: RollingRecoveryCompletionReceipt,
    handoff: RollingRecoveryHandoff,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    target_node_id: str,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RollingRecoveryReentryDecision:
    """Reassess only the recovered failed node from exact, still-current evidence."""

    revalidate_rolling_recovery_ready_gate(
        gate=gate,
        receipt=receipt,
        handoff=handoff,
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        completion_peer_snapshot=completion_peer_snapshot,
        role_authority=role_authority,
        predecessor_checkpoint=predecessor_checkpoint,
    )

    expected_target = receipt.recovered_node_id
    if (
        expected_target != handoff.failed_node_id
        or expected_target != failed_decision.target_node_id
    ):
        raise HARollingRecoveryReentryError("rolling_reentry_recovery_lineage_invalid")
    if target_node_id != expected_target:
        raise HARollingRecoveryReentryError("rolling_reentry_target_must_retry_failed_node")
    if receipt.completion_peer_snapshot_id != gate.completion_peer_snapshot_id:
        raise HARollingRecoveryReentryError("rolling_reentry_completion_gate_mismatch")
    if receipt.minimum_ready_nodes != failed_decision.minimum_ready_nodes:
        raise HARollingRecoveryReentryError("rolling_reentry_minimum_ready_drift")

    candidate = evaluate_revision_bound_rolling_safety(
        peer_snapshot=completion_peer_snapshot,
        role_authority=role_authority,
        target_node_id=target_node_id,
        minimum_ready_nodes=receipt.minimum_ready_nodes,
        expected_peer_snapshot_id=gate.completion_peer_snapshot_id,
        expected_peer_journal_seq=gate.completion_peer_journal_seq,
        expected_role_assignment_id=gate.role_assignment_id,
        expected_role_epoch=gate.role_epoch,
        expected_role_resource_version=gate.role_resource_version,
        expected_role_journal_seq=gate.role_journal_seq,
        expected_role_transition_id=gate.role_transition_id,
        required_predecessor_node_id=failed_decision.required_predecessor_node_id,
        required_predecessor_revision=failed_decision.required_predecessor_revision,
        single_node_downtime_acknowledged=(
            failed_decision.single_node_downtime_acknowledged
        ),
    )
    if candidate.plan_id == failed_decision.plan_id:
        raise HARollingRecoveryReentryError("rolling_reentry_reused_failed_plan")
    if candidate.production_mutation_enabled:
        raise HARollingRecoveryReentryError("rolling_reentry_candidate_mutation_enabled")

    provisional = RollingRecoveryReentryDecision(
        safe=candidate.safe and not candidate.blockers,
        cluster_id=receipt.cluster_id,
        decision_id="pending",
        ready_gate_id=gate.gate_id,
        completion_receipt_id=receipt.receipt_id,
        recovery_handoff_id=receipt.recovery_handoff_id,
        previous_failed_plan_id=failed_decision.plan_id,
        candidate_plan_id=candidate.plan_id,
        target_node_id=target_node_id,
        peer_snapshot_id=candidate.peer_snapshot_id,
        peer_journal_seq=candidate.peer_journal_seq,
        role_assignment_id=candidate.role_assignment_id,
        role_epoch=candidate.role_epoch,
        role_resource_version=candidate.role_resource_version,
        role_journal_seq=candidate.role_journal_seq,
        role_transition_id=candidate.role_transition_id,
        minimum_ready_nodes=candidate.minimum_ready_nodes,
        required_predecessor_node_id=candidate.required_predecessor_node_id,
        required_predecessor_revision=candidate.required_predecessor_revision,
        single_node_downtime_acknowledged=candidate.single_node_downtime_acknowledged,
        recovery_mode=handoff.recovery_mode,
        blockers=candidate.blockers,
        ready_before=candidate.ready_before,
        ready_after_target_stops=candidate.ready_after_target_stops,
        writer_node_id=candidate.writer_node_id,
    )
    return replace(
        provisional,
        decision_id=_stable_id(_identity_material(provisional)),
    )


def revalidate_rolling_recovery_reentry(
    *,
    decision: RollingRecoveryReentryDecision,
    gate: RollingRecoveryReadyGate,
    receipt: RollingRecoveryCompletionReceipt,
    handoff: RollingRecoveryHandoff,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RollingRecoveryReentryDecision:
    """Reject saved reassessment after any recovery, peer, or role evidence drift."""

    _verify_identity(decision)
    fresh = evaluate_rolling_recovery_reentry(
        gate=gate,
        receipt=receipt,
        handoff=handoff,
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        completion_peer_snapshot=completion_peer_snapshot,
        role_authority=role_authority,
        target_node_id=decision.target_node_id,
        predecessor_checkpoint=predecessor_checkpoint,
    )
    if fresh != decision:
        raise HARollingRecoveryReentryError("rolling_reentry_decision_stale")
    return decision
