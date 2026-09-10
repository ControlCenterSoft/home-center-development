"""Bind a recovered rolling retry to a fresh immutable continuation checkpoint."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

from .ha_peer_snapshot import HAPeerStateSnapshot
from .ha_rolling_checkpoint import (
    RollingStepCheckpoint,
    evaluate_next_rolling_step,
    revalidate_rolling_step_checkpoint,
    seal_rolling_step_checkpoint,
)
from .ha_rolling_recovery import RollingRecoveryHandoff
from .ha_rolling_recovery_completion import (
    RollingRecoveryCompletionReceipt,
    RollingRecoveryReadyGate,
)
from .ha_rolling_recovery_reentry import (
    RollingRecoveryReentryDecision,
    revalidate_rolling_recovery_reentry,
)
from .ha_rolling_revision import (
    HARoleRevisionAuthority,
    RevisionBoundRollingSafetyDecision,
    revalidate_revision_bound_rolling_safety,
)


class HARollingRecoveryRetryCheckpointError(ValueError):
    """Stable fail-closed error for recovered rolling retry checkpoints."""


@dataclass(frozen=True, slots=True)
class RollingRecoveryRetryCheckpoint:
    cluster_id: str
    checkpoint_id: str
    reentry_decision_id: str
    ready_gate_id: str
    recovery_completion_receipt_id: str
    recovery_handoff_id: str
    failed_plan_id: str
    retry_plan_id: str
    retry_node_id: str
    completed_revision: str
    predecessor_checkpoint_id: str | None
    required_predecessor_node_id: str | None
    required_predecessor_revision: str | None
    recovery_mode: str
    rolling_checkpoint: RollingStepCheckpoint
    retry_completed: bool = True
    failed_plan_retired: bool = True
    recovery_lineage_consumed: bool = True
    continuation_reassessment_required: bool = True
    execution_authorized: bool = False
    failover_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-recovery-retry-checkpoint.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "checkpoint_id": self.checkpoint_id,
            "reentry_decision_id": self.reentry_decision_id,
            "ready_gate_id": self.ready_gate_id,
            "recovery_completion_receipt_id": self.recovery_completion_receipt_id,
            "recovery_handoff_id": self.recovery_handoff_id,
            "failed_plan_id": self.failed_plan_id,
            "retry_plan_id": self.retry_plan_id,
            "retry_node_id": self.retry_node_id,
            "completed_revision": self.completed_revision,
            "predecessor_checkpoint_id": self.predecessor_checkpoint_id,
            "required_predecessor_node_id": self.required_predecessor_node_id,
            "required_predecessor_revision": self.required_predecessor_revision,
            "recovery_mode": self.recovery_mode,
            "rolling_checkpoint": self.rolling_checkpoint.to_dict(),
            "retry_completed": self.retry_completed,
            "failed_plan_retired": self.failed_plan_retired,
            "recovery_lineage_consumed": self.recovery_lineage_consumed,
            "continuation_reassessment_required": self.continuation_reassessment_required,
            "execution_authorized": self.execution_authorized,
            "failover_authorized": self.failover_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


def _stable_id(material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"ha-roll-recovery-retry-{digest}"


def _identity_material(checkpoint: RollingRecoveryRetryCheckpoint) -> dict[str, object]:
    material = checkpoint.to_dict()
    material.pop("checkpoint_id")
    return material


def _verify_identity(checkpoint: RollingRecoveryRetryCheckpoint) -> None:
    if checkpoint.schema != "home-center.ha-rolling-recovery-retry-checkpoint.v1":
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_checkpoint_schema_invalid")
    if (
        not checkpoint.retry_completed
        or not checkpoint.failed_plan_retired
        or not checkpoint.recovery_lineage_consumed
        or not checkpoint.continuation_reassessment_required
        or checkpoint.execution_authorized
        or checkpoint.failover_authorized
        or checkpoint.production_mutation_enabled
    ):
        raise HARollingRecoveryRetryCheckpointError(
            "rolling_retry_checkpoint_authority_invalid"
        )
    rolling = checkpoint.rolling_checkpoint
    if checkpoint.cluster_id != rolling.cluster_id:
        raise HARollingRecoveryRetryCheckpointError(
            "rolling_retry_checkpoint_cluster_mismatch"
        )
    if checkpoint.retry_plan_id != rolling.completed_plan_id:
        raise HARollingRecoveryRetryCheckpointError(
            "rolling_retry_checkpoint_plan_mismatch"
        )
    if checkpoint.retry_node_id != rolling.completed_node_id:
        raise HARollingRecoveryRetryCheckpointError(
            "rolling_retry_checkpoint_node_mismatch"
        )
    if checkpoint.completed_revision != rolling.completed_revision:
        raise HARollingRecoveryRetryCheckpointError(
            "rolling_retry_checkpoint_revision_mismatch"
        )
    if checkpoint.failed_plan_id == checkpoint.retry_plan_id:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_reused_failed_plan")
    if checkpoint.checkpoint_id != _stable_id(_identity_material(checkpoint)):
        raise HARollingRecoveryRetryCheckpointError(
            "rolling_retry_checkpoint_identity_invalid"
        )


def _require_retry_binding(
    *,
    reentry: RollingRecoveryReentryDecision,
    retry_decision: RevisionBoundRollingSafetyDecision,
    failed_decision: RevisionBoundRollingSafetyDecision,
) -> None:
    if not reentry.safe or reentry.blockers:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_reentry_not_safe")
    if not retry_decision.safe or retry_decision.blockers:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_decision_not_safe")
    if failed_decision.plan_id != reentry.previous_failed_plan_id:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_failed_plan_drift")
    if retry_decision.plan_id == failed_decision.plan_id:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_reused_failed_plan")

    expected = (
        reentry.candidate_plan_id,
        reentry.target_node_id,
        reentry.peer_snapshot_id,
        reentry.peer_journal_seq,
        reentry.role_assignment_id,
        reentry.role_epoch,
        reentry.role_resource_version,
        reentry.role_journal_seq,
        reentry.role_transition_id,
        reentry.minimum_ready_nodes,
        reentry.required_predecessor_node_id,
        reentry.required_predecessor_revision,
        reentry.single_node_downtime_acknowledged,
        reentry.ready_before,
        reentry.ready_after_target_stops,
        reentry.writer_node_id,
    )
    actual = (
        retry_decision.plan_id,
        retry_decision.target_node_id,
        retry_decision.peer_snapshot_id,
        retry_decision.peer_journal_seq,
        retry_decision.role_assignment_id,
        retry_decision.role_epoch,
        retry_decision.role_resource_version,
        retry_decision.role_journal_seq,
        retry_decision.role_transition_id,
        retry_decision.minimum_ready_nodes,
        retry_decision.required_predecessor_node_id,
        retry_decision.required_predecessor_revision,
        retry_decision.single_node_downtime_acknowledged,
        retry_decision.ready_before,
        retry_decision.ready_after_target_stops,
        retry_decision.writer_node_id,
    )
    if actual != expected:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_candidate_binding_drift")
    if (
        retry_decision.production_mutation_enabled
        or retry_decision.rollback_state != "ready"
        or not retry_decision.rollback_required_on_failure
    ):
        raise HARollingRecoveryRetryCheckpointError(
            "rolling_retry_candidate_authority_invalid"
        )


def seal_rolling_recovery_retry_checkpoint(
    *,
    reentry: RollingRecoveryReentryDecision,
    retry_decision: RevisionBoundRollingSafetyDecision,
    gate: RollingRecoveryReadyGate,
    receipt: RollingRecoveryCompletionReceipt,
    handoff: RollingRecoveryHandoff,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    recovery_completion_peer_snapshot: HAPeerStateSnapshot,
    retry_completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    expected_retry_completion_peer_snapshot_id: str,
    expected_retry_completion_peer_journal_seq: int,
    expected_completed_revision: str,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RollingRecoveryRetryCheckpoint:
    """Seal a successful retry and consume the prior failed/recovery lineage."""

    revalidate_rolling_recovery_reentry(
        decision=reentry,
        gate=gate,
        receipt=receipt,
        handoff=handoff,
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        completion_peer_snapshot=recovery_completion_peer_snapshot,
        role_authority=role_authority,
        predecessor_checkpoint=predecessor_checkpoint,
    )

    fresh_retry = revalidate_revision_bound_rolling_safety(
        decision=retry_decision,
        peer_snapshot=recovery_completion_peer_snapshot,
        role_authority=role_authority,
    )
    if fresh_retry != retry_decision:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_decision_stale")
    _require_retry_binding(
        reentry=reentry,
        retry_decision=retry_decision,
        failed_decision=failed_decision,
    )

    rolling = seal_rolling_step_checkpoint(
        decision=retry_decision,
        pre_step_peer_snapshot=recovery_completion_peer_snapshot,
        completion_peer_snapshot=retry_completion_peer_snapshot,
        role_authority=role_authority,
        expected_completion_peer_snapshot_id=expected_retry_completion_peer_snapshot_id,
        expected_completion_peer_journal_seq=expected_retry_completion_peer_journal_seq,
        expected_completed_revision=expected_completed_revision,
    )

    if receipt.receipt_id != reentry.completion_receipt_id:
        raise HARollingRecoveryRetryCheckpointError(
            "rolling_retry_completion_receipt_drift"
        )
    if gate.gate_id != reentry.ready_gate_id:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_ready_gate_drift")
    if handoff.handoff_id != reentry.recovery_handoff_id:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_handoff_drift")
    if rolling.completed_plan_id == failed_decision.plan_id:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_reused_failed_plan")

    provisional = RollingRecoveryRetryCheckpoint(
        cluster_id=reentry.cluster_id,
        checkpoint_id="pending",
        reentry_decision_id=reentry.decision_id,
        ready_gate_id=gate.gate_id,
        recovery_completion_receipt_id=receipt.receipt_id,
        recovery_handoff_id=handoff.handoff_id,
        failed_plan_id=failed_decision.plan_id,
        retry_plan_id=retry_decision.plan_id,
        retry_node_id=retry_decision.target_node_id,
        completed_revision=rolling.completed_revision,
        predecessor_checkpoint_id=receipt.predecessor_checkpoint_id,
        required_predecessor_node_id=retry_decision.required_predecessor_node_id,
        required_predecessor_revision=retry_decision.required_predecessor_revision,
        recovery_mode=reentry.recovery_mode,
        rolling_checkpoint=rolling,
    )
    return replace(
        provisional,
        checkpoint_id=_stable_id(_identity_material(provisional)),
    )


def revalidate_rolling_recovery_retry_checkpoint(
    *,
    checkpoint: RollingRecoveryRetryCheckpoint,
    reentry: RollingRecoveryReentryDecision,
    retry_decision: RevisionBoundRollingSafetyDecision,
    gate: RollingRecoveryReadyGate,
    receipt: RollingRecoveryCompletionReceipt,
    handoff: RollingRecoveryHandoff,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    recovery_completion_peer_snapshot: HAPeerStateSnapshot,
    retry_completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RollingRecoveryRetryCheckpoint:
    """Reject a retry checkpoint after any recovery, peer, role, or retry drift."""

    _verify_identity(checkpoint)
    revalidate_rolling_step_checkpoint(
        checkpoint=checkpoint.rolling_checkpoint,
        completion_peer_snapshot=retry_completion_peer_snapshot,
        role_authority=role_authority,
    )
    fresh = seal_rolling_recovery_retry_checkpoint(
        reentry=reentry,
        retry_decision=retry_decision,
        gate=gate,
        receipt=receipt,
        handoff=handoff,
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        recovery_completion_peer_snapshot=recovery_completion_peer_snapshot,
        retry_completion_peer_snapshot=retry_completion_peer_snapshot,
        role_authority=role_authority,
        expected_retry_completion_peer_snapshot_id=(
            checkpoint.rolling_checkpoint.completion_peer_snapshot_id
        ),
        expected_retry_completion_peer_journal_seq=(
            checkpoint.rolling_checkpoint.completion_peer_journal_seq
        ),
        expected_completed_revision=checkpoint.completed_revision,
        predecessor_checkpoint=predecessor_checkpoint,
    )
    if fresh != checkpoint:
        raise HARollingRecoveryRetryCheckpointError("rolling_retry_checkpoint_stale")
    return checkpoint


def evaluate_next_rolling_step_after_recovery_retry(
    *,
    checkpoint: RollingRecoveryRetryCheckpoint,
    reentry: RollingRecoveryReentryDecision,
    retry_decision: RevisionBoundRollingSafetyDecision,
    gate: RollingRecoveryReadyGate,
    receipt: RollingRecoveryCompletionReceipt,
    handoff: RollingRecoveryHandoff,
    failed_decision: RevisionBoundRollingSafetyDecision,
    pre_step_peer_snapshot: HAPeerStateSnapshot,
    failure_peer_snapshot: HAPeerStateSnapshot,
    recovery_completion_peer_snapshot: HAPeerStateSnapshot,
    retry_completion_peer_snapshot: HAPeerStateSnapshot,
    role_authority: HARoleRevisionAuthority,
    target_node_id: str,
    predecessor_checkpoint: RollingStepCheckpoint | None = None,
) -> RevisionBoundRollingSafetyDecision:
    """Reassess the next node only through a still-current recovered-retry checkpoint."""

    revalidate_rolling_recovery_retry_checkpoint(
        checkpoint=checkpoint,
        reentry=reentry,
        retry_decision=retry_decision,
        gate=gate,
        receipt=receipt,
        handoff=handoff,
        failed_decision=failed_decision,
        pre_step_peer_snapshot=pre_step_peer_snapshot,
        failure_peer_snapshot=failure_peer_snapshot,
        recovery_completion_peer_snapshot=recovery_completion_peer_snapshot,
        retry_completion_peer_snapshot=retry_completion_peer_snapshot,
        role_authority=role_authority,
        predecessor_checkpoint=predecessor_checkpoint,
    )
    return evaluate_next_rolling_step(
        checkpoint=checkpoint.rolling_checkpoint,
        peer_snapshot=retry_completion_peer_snapshot,
        role_authority=role_authority,
        target_node_id=target_node_id,
    )
