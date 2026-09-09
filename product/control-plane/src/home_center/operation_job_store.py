"""Durable compare-and-swap storage for bounded operation command jobs."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from typing import Any

from .operation_commands import (
    OperationCommandError,
    OperationCommandPlan,
    OperationJobState,
    validate_job_transition,
)
from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now


OPERATION_JOB_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation_job_metadata (
    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    plan_id TEXT NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL,
    snapshot_sha256 TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    service TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    state_version INTEGER NOT NULL CHECK(state_version >= 1),
    mutation_may_have_occurred INTEGER NOT NULL CHECK(mutation_may_have_occurred IN (0,1)),
    recovery_required INTEGER NOT NULL CHECK(recovery_required IN (0,1)),
    last_audit_event_id TEXT NOT NULL REFERENCES audit(event_id),
    UNIQUE(action_id, target_node_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_operation_job_state
    ON operation_job_metadata(target_node_id, service, state_version);
"""


class OperationJobPreconditionFailed(RuntimeError):
    """A durable operation job changed after the caller observed it."""


class OperationJobStateStore(StateStore):
    """StateStore extension for immutable operation plans and CAS job transitions."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._migrate_operation_jobs()

    def _migrate_operation_jobs(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(OPERATION_JOB_SCHEMA)

    @staticmethod
    def _plan_sha256(value: dict[str, Any]) -> str:
        return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()

    @staticmethod
    def _audit_target(plan: dict[str, Any]) -> str:
        return f"{plan['target_node_id']}:{plan['service']}"

    def _append_operation_audit_locked(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        outcome: str,
        correlation_id: str,
        details: dict[str, Any],
    ) -> str:
        """Append to the canonical audit chain inside the caller's DB transaction."""

        import uuid

        event_id = str(uuid.uuid4())
        occurred_at = utc_now()
        details_json = canonical_json(details)
        row = self._connection.execute(
            "SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous_hash = row[0] if row else "0" * 64
        material = canonical_json(
            {
                "event_id": event_id,
                "occurred_at": occurred_at,
                "actor": actor,
                "action": action,
                "target": target,
                "outcome": outcome,
                "correlation_id": correlation_id,
                "details": json.loads(details_json),
                "previous_hash": previous_hash,
            }
        ).encode("utf-8")
        entry_hash = hmac.new(self.audit_key, material, hashlib.sha256).hexdigest()
        self._connection.execute(
            """INSERT INTO audit(
            event_id,occurred_at,actor,action,target,outcome,correlation_id,
            details_json,previous_hash,entry_hash
            ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                event_id,
                occurred_at,
                actor,
                action,
                target,
                outcome,
                correlation_id,
                details_json,
                previous_hash,
                entry_hash,
            ),
        )
        return event_id

    def _operation_job_row(self, job_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            """SELECT j.*,o.action_id,o.plan_id,o.request_sha256,o.plan_sha256,
            o.snapshot_sha256,o.authorization_id,o.idempotency_key,o.target_node_id,
            o.service,o.correlation_id,o.plan_json,o.state_version,
            o.mutation_may_have_occurred,o.recovery_required,o.last_audit_event_id
            FROM jobs AS j JOIN operation_job_metadata AS o ON o.job_id=j.job_id
            WHERE j.job_id=?""",
            (job_id,),
        ).fetchone()

    @classmethod
    def _decode_operation_job(cls, row: sqlite3.Row) -> dict[str, Any]:
        plan = json.loads(row["plan_json"])
        plan_sha256 = cls._plan_sha256(plan)
        if plan_sha256 != row["plan_sha256"]:
            raise RuntimeError("operation job plan integrity mismatch")
        if plan.get("plan_id") != row["plan_id"]:
            raise RuntimeError("operation job plan identity mismatch")
        if plan.get("request_sha256") != row["request_sha256"]:
            raise RuntimeError("operation job request integrity mismatch")
        if plan.get("snapshot_sha256") != row["snapshot_sha256"]:
            raise RuntimeError("operation job snapshot integrity mismatch")
        return {
            "schema": "home-center.operation-job-record.v1",
            "job_id": row["job_id"],
            "action_id": row["action_id"],
            "state": row["state"],
            "state_version": row["state_version"],
            "initiator": row["initiator"],
            "reason": row["reason"],
            "plan_id": row["plan_id"],
            "request_sha256": row["request_sha256"],
            "plan_sha256": row["plan_sha256"],
            "snapshot_sha256": row["snapshot_sha256"],
            "authorization_id": row["authorization_id"],
            "idempotency_key": row["idempotency_key"],
            "target_node_id": row["target_node_id"],
            "service": row["service"],
            "correlation_id": row["correlation_id"],
            "plan": plan,
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
            "evidence": json.loads(row["evidence_json"]) if row["evidence_json"] else None,
            "recovery": json.loads(row["recovery_json"]),
            "mutation_may_have_occurred": bool(row["mutation_may_have_occurred"]),
            "recovery_required": bool(row["recovery_required"]),
            "last_audit_event_id": row["last_audit_event_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def operation_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._operation_job_row(job_id)
        return self._decode_operation_job(row) if row else None

    def create_operation_job(
        self,
        *,
        plan: OperationCommandPlan,
        actor: str,
    ) -> tuple[dict[str, Any], bool]:
        if not isinstance(plan, OperationCommandPlan):
            raise TypeError("plan must be OperationCommandPlan")
        if not isinstance(actor, str) or not 1 <= len(actor) <= 128:
            raise OperationCommandError("invalid_actor")

        value = plan.to_dict()
        if value["execution_authorized"] or value["production_mutation_enabled"]:
            raise OperationCommandError("authoritative_plan_not_allowed")
        if value["accepts_caller_argv"] or value["accepts_shell"]:
            raise OperationCommandError("unbounded_plan_not_allowed")

        plan_sha256 = self._plan_sha256(value)
        job_id = f"opjob-{plan_sha256[:24]}"
        now = utc_now()
        target = self._audit_target(value)

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._connection.execute(
                    """SELECT j.*,o.action_id,o.plan_id,o.request_sha256,o.plan_sha256,
                    o.snapshot_sha256,o.authorization_id,o.idempotency_key,o.target_node_id,
                    o.service,o.correlation_id,o.plan_json,o.state_version,
                    o.mutation_may_have_occurred,o.recovery_required,o.last_audit_event_id
                    FROM operation_job_metadata AS o JOIN jobs AS j ON j.job_id=o.job_id
                    WHERE o.action_id=? AND o.target_node_id=? AND o.idempotency_key=?""",
                    (
                        value["action_id"],
                        value["target_node_id"],
                        value["idempotency_key"],
                    ),
                ).fetchone()
                if replay:
                    if (
                        replay["request_sha256"] != value["request_sha256"]
                        or replay["plan_sha256"] != plan_sha256
                    ):
                        raise IdempotencyConflict(value["idempotency_key"])
                    self._connection.commit()
                    return self._decode_operation_job(replay), False

                audit_event_id = self._append_operation_audit_locked(
                    actor=actor,
                    action="operation.job.create",
                    target=target,
                    outcome=OperationJobState.PREPARED.value,
                    correlation_id=value["audit"]["correlation_id"],
                    details={
                        "job_id": job_id,
                        "plan_id": value["plan_id"],
                        "request_sha256": value["request_sha256"],
                        "plan_sha256": plan_sha256,
                        "snapshot_sha256": value["snapshot_sha256"],
                        "authorization_id": value["authorization_id"],
                        "idempotency_key": value["idempotency_key"],
                        "state_version": 1,
                    },
                )
                self._connection.execute(
                    """INSERT INTO jobs(
                    job_id,job_type,state,initiator,reason,preflight_json,result_json,
                    evidence_json,recovery_json,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        job_id,
                        value["action_id"],
                        OperationJobState.PREPARED.value,
                        actor,
                        value["audit"]["reason"],
                        canonical_json(value),
                        None,
                        None,
                        canonical_json(value["recovery"]),
                        now,
                        now,
                    ),
                )
                self._connection.execute(
                    """INSERT INTO operation_job_metadata(
                    job_id,action_id,plan_id,request_sha256,plan_sha256,snapshot_sha256,
                    authorization_id,idempotency_key,target_node_id,service,correlation_id,
                    plan_json,state_version,mutation_may_have_occurred,recovery_required,
                    last_audit_event_id
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        job_id,
                        value["action_id"],
                        value["plan_id"],
                        value["request_sha256"],
                        plan_sha256,
                        value["snapshot_sha256"],
                        value["authorization_id"],
                        value["idempotency_key"],
                        value["target_node_id"],
                        value["service"],
                        value["audit"]["correlation_id"],
                        canonical_json(value),
                        1,
                        0,
                        0,
                        audit_event_id,
                    ),
                )
                row = self._operation_job_row(job_id)
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

        if row is None:
            raise RuntimeError("operation job persistence failed")
        return self._decode_operation_job(row), True

    def transition_operation_job(
        self,
        job_id: str,
        *,
        expected_state: OperationJobState,
        expected_state_version: int,
        target_state: OperationJobState,
        mutation_may_have_occurred: bool = False,
        result: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
        recovery: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(expected_state, OperationJobState) or not isinstance(
            target_state, OperationJobState
        ):
            raise TypeError("operation job states must use OperationJobState")
        if (
            not isinstance(expected_state_version, int)
            or isinstance(expected_state_version, bool)
            or expected_state_version < 1
        ):
            raise OperationCommandError("invalid_state_version")
        if not isinstance(mutation_may_have_occurred, bool):
            raise OperationCommandError("invalid_mutation_flag")

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._operation_job_row(job_id)
                if row is None:
                    raise KeyError(job_id)
                if (
                    row["state"] != expected_state.value
                    or row["state_version"] != expected_state_version
                ):
                    raise OperationJobPreconditionFailed(job_id)

                mutation_possible = bool(row["mutation_may_have_occurred"]) or (
                    mutation_may_have_occurred
                )
                validate_job_transition(
                    expected_state,
                    target_state,
                    mutation_may_have_occurred=mutation_possible,
                )

                if target_state in {
                    OperationJobState.VERIFYING,
                    OperationJobState.SUCCEEDED,
                } and not mutation_possible:
                    raise OperationCommandError("mutation_evidence_required")
                if target_state == OperationJobState.SUCCEEDED and evidence is None:
                    raise OperationCommandError("verification_evidence_required")
                if target_state in {
                    OperationJobState.ROLLED_BACK,
                    OperationJobState.FAILED,
                } and expected_state == OperationJobState.ROLLING_BACK and recovery is None:
                    raise OperationCommandError("recovery_evidence_required")

                recovery_required = bool(row["recovery_required"])
                if target_state == OperationJobState.ROLLED_BACK:
                    recovery_required = False
                elif (
                    target_state == OperationJobState.FAILED
                    and expected_state == OperationJobState.ROLLING_BACK
                ):
                    recovery_required = True

                next_version = expected_state_version + 1
                audit_event_id = self._append_operation_audit_locked(
                    actor=row["initiator"],
                    action="operation.job.transition",
                    target=f"{row['target_node_id']}:{row['service']}",
                    outcome=target_state.value,
                    correlation_id=row["correlation_id"],
                    details={
                        "job_id": job_id,
                        "plan_id": row["plan_id"],
                        "request_sha256": row["request_sha256"],
                        "plan_sha256": row["plan_sha256"],
                        "from_state": expected_state.value,
                        "to_state": target_state.value,
                        "from_state_version": expected_state_version,
                        "to_state_version": next_version,
                        "mutation_may_have_occurred": mutation_possible,
                        "recovery_required": recovery_required,
                    },
                )

                cursor = self._connection.execute(
                    """UPDATE jobs SET state=?,result_json=COALESCE(?,result_json),
                    evidence_json=COALESCE(?,evidence_json),
                    recovery_json=COALESCE(?,recovery_json),updated_at=?
                    WHERE job_id=? AND state=?""",
                    (
                        target_state.value,
                        canonical_json(result) if result is not None else None,
                        canonical_json(evidence) if evidence is not None else None,
                        canonical_json(recovery) if recovery is not None else None,
                        utc_now(),
                        job_id,
                        expected_state.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationJobPreconditionFailed(job_id)
                cursor = self._connection.execute(
                    """UPDATE operation_job_metadata
                    SET state_version=?,mutation_may_have_occurred=?,recovery_required=?,
                    last_audit_event_id=?
                    WHERE job_id=? AND state_version=?""",
                    (
                        next_version,
                        1 if mutation_possible else 0,
                        1 if recovery_required else 0,
                        audit_event_id,
                        job_id,
                        expected_state_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationJobPreconditionFailed(job_id)
                updated = self._operation_job_row(job_id)
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

        if updated is None:
            raise RuntimeError("operation job transition failed")
        return self._decode_operation_job(updated)
