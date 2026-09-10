"""Durably consume one recovered-retry checkpoint for one safe next rolling plan."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, replace

from .ha_peer_snapshot import HAPeerStateSnapshot
from .ha_rolling_checkpoint import RollingStepCheckpoint
from .ha_rolling_recovery import RollingRecoveryHandoff
from .ha_rolling_recovery_completion import (
    RollingRecoveryCompletionReceipt,
    RollingRecoveryReadyGate,
)
from .ha_rolling_recovery_reentry import RollingRecoveryReentryDecision
from .ha_rolling_recovery_retry_checkpoint import (
    RollingRecoveryRetryCheckpoint,
    evaluate_next_rolling_step_after_recovery_retry,
    revalidate_rolling_recovery_retry_checkpoint,
)
from .ha_rolling_revision import (
    HARoleRevisionAuthority,
    RevisionBoundRollingSafetyDecision,
)


class HARollingContinuationGuardError(ValueError):
    """Stable fail-closed error for recovered-retry continuation consumption."""


@dataclass(frozen=True, slots=True)
class RollingRecoveryContinuationConsumption:
    cluster_id: str
    consumption_id: str
    retry_checkpoint_id: str
    rolling_checkpoint_id: str
    completed_retry_plan_id: str
    completed_retry_node_id: str
    completed_retry_revision: str
    next_plan_id: str
    next_target_node_id: str
    peer_snapshot_id: str
    peer_journal_seq: int
    role_assignment_id: str
    role_epoch: int
    role_resource_version: int
    role_journal_seq: int
    role_transition_id: str
    minimum_ready_nodes: int
    required_predecessor_node_id: str
    required_predecessor_revision: str
    ready_before: int
    ready_after_target_stops: int
    writer_node_id: str
    checkpoint_consumed: bool = True
    execution_authorized: bool = False
    failover_authorized: bool = False
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-rolling-recovery-continuation-consumption.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "consumption_id": self.consumption_id,
            "retry_checkpoint_id": self.retry_checkpoint_id,
            "rolling_checkpoint_id": self.rolling_checkpoint_id,
            "completed_retry_plan_id": self.completed_retry_plan_id,
            "completed_retry_node_id": self.completed_retry_node_id,
            "completed_retry_revision": self.completed_retry_revision,
            "next_plan_id": self.next_plan_id,
            "next_target_node_id": self.next_target_node_id,
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
            "ready_before": self.ready_before,
            "ready_after_target_stops": self.ready_after_target_stops,
            "writer_node_id": self.writer_node_id,
            "checkpoint_consumed": self.checkpoint_consumed,
            "execution_authorized": self.execution_authorized,
            "failover_authorized": self.failover_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


def _identity_material(
    consumption: RollingRecoveryContinuationConsumption,
) -> dict[str, object]:
    material = consumption.to_dict()
    material.pop("consumption_id")
    return material


def _stable_id(material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"ha-roll-recovery-continuation-{digest}"


def _canonical_json(consumption: RollingRecoveryContinuationConsumption) -> str:
    return json.dumps(
        consumption.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    )


def _verify_consumption_identity(
    consumption: RollingRecoveryContinuationConsumption,
) -> None:
    if consumption.schema != (
        "home-center.ha-rolling-recovery-continuation-consumption.v1"
    ):
        raise HARollingContinuationGuardError("rolling_continuation_schema_invalid")
    if (
        not consumption.checkpoint_consumed
        or consumption.execution_authorized
        or consumption.failover_authorized
        or consumption.production_mutation_enabled
    ):
        raise HARollingContinuationGuardError("rolling_continuation_authority_invalid")
    text_fields = (
        consumption.cluster_id,
        consumption.retry_checkpoint_id,
        consumption.rolling_checkpoint_id,
        consumption.completed_retry_plan_id,
        consumption.completed_retry_node_id,
        consumption.completed_retry_revision,
        consumption.next_plan_id,
        consumption.next_target_node_id,
        consumption.peer_snapshot_id,
        consumption.role_assignment_id,
        consumption.role_transition_id,
        consumption.required_predecessor_node_id,
        consumption.required_predecessor_revision,
        consumption.writer_node_id,
    )
    if any(not isinstance(value, str) or not value for value in text_fields):
        raise HARollingContinuationGuardError("rolling_continuation_field_invalid")
    numbers = (
        consumption.peer_journal_seq,
        consumption.role_epoch,
        consumption.role_resource_version,
        consumption.role_journal_seq,
        consumption.minimum_ready_nodes,
        consumption.ready_before,
        consumption.ready_after_target_stops,
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in numbers
    ):
        raise HARollingContinuationGuardError("rolling_continuation_revision_invalid")
    if consumption.minimum_ready_nodes < 1:
        raise HARollingContinuationGuardError("rolling_continuation_ready_floor_invalid")
    if consumption.retry_checkpoint_id == consumption.rolling_checkpoint_id:
        raise HARollingContinuationGuardError(
            "rolling_continuation_checkpoint_binding_invalid"
        )
    if (
        consumption.required_predecessor_node_id
        != consumption.completed_retry_node_id
        or consumption.required_predecessor_revision
        != consumption.completed_retry_revision
    ):
        raise HARollingContinuationGuardError(
            "rolling_continuation_predecessor_binding_invalid"
        )
    if consumption.next_target_node_id == consumption.completed_retry_node_id:
        raise HARollingContinuationGuardError(
            "rolling_continuation_reuses_completed_node"
        )
    if consumption.ready_after_target_stops < consumption.minimum_ready_nodes:
        raise HARollingContinuationGuardError("rolling_continuation_ready_floor_invalid")
    if consumption.consumption_id != _stable_id(_identity_material(consumption)):
        raise HARollingContinuationGuardError("rolling_continuation_identity_invalid")


def _build_consumption(
    *,
    checkpoint: RollingRecoveryRetryCheckpoint,
    decision: RevisionBoundRollingSafetyDecision,
) -> RollingRecoveryContinuationConsumption:
    if not decision.safe or decision.blockers:
        raise HARollingContinuationGuardError("rolling_continuation_next_step_not_safe")
    if decision.production_mutation_enabled:
        raise HARollingContinuationGuardError(
            "rolling_continuation_next_step_mutation_enabled"
        )
    if (
        decision.required_predecessor_node_id != checkpoint.retry_node_id
        or decision.required_predecessor_revision != checkpoint.completed_revision
    ):
        raise HARollingContinuationGuardError(
            "rolling_continuation_predecessor_binding_invalid"
        )
    if decision.cluster_id != checkpoint.cluster_id:
        raise HARollingContinuationGuardError("rolling_continuation_cluster_mismatch")

    provisional = RollingRecoveryContinuationConsumption(
        cluster_id=checkpoint.cluster_id,
        consumption_id="pending",
        retry_checkpoint_id=checkpoint.checkpoint_id,
        rolling_checkpoint_id=checkpoint.rolling_checkpoint.checkpoint_id,
        completed_retry_plan_id=checkpoint.retry_plan_id,
        completed_retry_node_id=checkpoint.retry_node_id,
        completed_retry_revision=checkpoint.completed_revision,
        next_plan_id=decision.plan_id,
        next_target_node_id=decision.target_node_id,
        peer_snapshot_id=decision.peer_snapshot_id,
        peer_journal_seq=decision.peer_journal_seq,
        role_assignment_id=decision.role_assignment_id,
        role_epoch=decision.role_epoch,
        role_resource_version=decision.role_resource_version,
        role_journal_seq=decision.role_journal_seq,
        role_transition_id=decision.role_transition_id,
        minimum_ready_nodes=decision.minimum_ready_nodes,
        required_predecessor_node_id=decision.required_predecessor_node_id,
        required_predecessor_revision=decision.required_predecessor_revision,
        ready_before=decision.ready_before,
        ready_after_target_stops=decision.ready_after_target_stops,
        writer_node_id=decision.writer_node_id,
    )
    result = replace(
        provisional,
        consumption_id=_stable_id(_identity_material(provisional)),
    )
    _verify_consumption_identity(result)
    return result


class HARollingContinuationJournal:
    """SQLite CAS-like journal that consumes each retry checkpoint at most once."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise HARollingContinuationGuardError(
                "invalid_rolling_continuation_connection"
            )
        self._db = connection
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS hc_ha_rolling_retry_continuation (
              cluster_id TEXT NOT NULL,
              retry_checkpoint_id TEXT NOT NULL,
              consumption_id TEXT NOT NULL,
              material_json TEXT NOT NULL,
              PRIMARY KEY (cluster_id, retry_checkpoint_id),
              UNIQUE (consumption_id)
            )
            """
        )
        self._db.commit()

    @staticmethod
    def _verify_row(row: sqlite3.Row) -> str:
        try:
            payload = json.loads(row["material_json"])
            stored = RollingRecoveryContinuationConsumption(**payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise HARollingContinuationGuardError(
                "rolling_continuation_journal_corrupt"
            ) from exc
        try:
            _verify_consumption_identity(stored)
        except HARollingContinuationGuardError as exc:
            raise HARollingContinuationGuardError(
                "rolling_continuation_journal_corrupt"
            ) from exc
        if (
            stored.consumption_id != row["consumption_id"]
            or stored.cluster_id != row["cluster_id"]
            or stored.retry_checkpoint_id != row["retry_checkpoint_id"]
        ):
            raise HARollingContinuationGuardError(
                "rolling_continuation_journal_corrupt"
            )
        return _canonical_json(stored)

    def _current_row(
        self,
        *,
        cluster_id: str,
        retry_checkpoint_id: str,
    ) -> sqlite3.Row | None:
        return self._db.execute(
            """
            SELECT cluster_id, retry_checkpoint_id, consumption_id, material_json
            FROM hc_ha_rolling_retry_continuation
            WHERE cluster_id=? AND retry_checkpoint_id=?
            """,
            (cluster_id, retry_checkpoint_id),
        ).fetchone()

    def consume_after_recovery_retry(
        self,
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
    ) -> RollingRecoveryContinuationConsumption:
        """Consume the exact retry checkpoint for one freshly safe next plan."""

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
        decision = evaluate_next_rolling_step_after_recovery_retry(
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
            target_node_id=target_node_id,
            predecessor_checkpoint=predecessor_checkpoint,
        )
        expected = _build_consumption(checkpoint=checkpoint, decision=decision)
        encoded = _canonical_json(expected)

        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._current_row(
                    cluster_id=expected.cluster_id,
                    retry_checkpoint_id=expected.retry_checkpoint_id,
                )
                if row is not None:
                    stored = self._verify_row(row)
                    if stored == encoded:
                        self._db.commit()
                        return expected
                    raise HARollingContinuationGuardError(
                        "rolling_retry_checkpoint_already_consumed"
                    )
                self._db.execute(
                    """
                    INSERT INTO hc_ha_rolling_retry_continuation
                    (cluster_id, retry_checkpoint_id, consumption_id, material_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        expected.cluster_id,
                        expected.retry_checkpoint_id,
                        expected.consumption_id,
                        encoded,
                    ),
                )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return expected

    def revalidate_consumption(
        self,
        *,
        consumption: RollingRecoveryContinuationConsumption,
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
    ) -> RollingRecoveryContinuationConsumption:
        """Reject consumption after peer/role/recovery evidence or journal drift."""

        _verify_consumption_identity(consumption)
        if consumption.retry_checkpoint_id != checkpoint.checkpoint_id:
            raise HARollingContinuationGuardError(
                "rolling_continuation_checkpoint_mismatch"
            )
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
        fresh_decision = evaluate_next_rolling_step_after_recovery_retry(
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
            target_node_id=consumption.next_target_node_id,
            predecessor_checkpoint=predecessor_checkpoint,
        )
        fresh = _build_consumption(checkpoint=checkpoint, decision=fresh_decision)
        if fresh != consumption:
            raise HARollingContinuationGuardError(
                "rolling_continuation_evidence_stale"
            )

        with self._lock:
            row = self._current_row(
                cluster_id=consumption.cluster_id,
                retry_checkpoint_id=consumption.retry_checkpoint_id,
            )
            if row is None:
                raise HARollingContinuationGuardError(
                    "rolling_continuation_not_consumed"
                )
            stored = self._verify_row(row)
            if stored != _canonical_json(consumption):
                raise HARollingContinuationGuardError(
                    "rolling_continuation_journal_mismatch"
                )
        return consumption
