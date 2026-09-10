"""Atomic, replay-safe worker claims for bounded operation jobs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_commands import OperationJobState, validate_job_transition
from .operation_worker_handoff import (
    OperationWorkerHandoff,
    OperationWorkerHandoffError,
    OperationWorkerIdentity,
    prepare_operation_worker_handoff,
)
from .util import canonical_json, utc_now


SCHEMA = "home-center.operation-worker-claim.v1"
CLAIM_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation_worker_claims (
    claim_id TEXT PRIMARY KEY,
    handoff_id TEXT NOT NULL UNIQUE,
    job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    from_state_version INTEGER NOT NULL CHECK(from_state_version >= 1),
    to_state_version INTEGER NOT NULL CHECK(to_state_version > from_state_version),
    claim_sha256 TEXT NOT NULL,
    claim_json TEXT NOT NULL,
    audit_event_id TEXT NOT NULL REFERENCES audit(event_id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operation_worker_claim_job
    ON operation_worker_claims(job_id, worker_id, to_state_version);
"""


class OperationWorkerClaimError(RuntimeError):
    """A worker claim could not be admitted without weakening operation safety."""


class OperationWorkerClaimStore(Protocol):
    _lock: Any
    _connection: sqlite3.Connection

    def operation_job(self, job_id: str) -> dict[str, Any] | None: ...

    def _operation_job_row(self, job_id: str) -> sqlite3.Row | None: ...

    @classmethod
    def _decode_operation_job(cls, row: sqlite3.Row) -> dict[str, Any]: ...

    def _append_operation_audit_locked(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        outcome: str,
        correlation_id: str,
        details: dict[str, Any],
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class OperationWorkerClaim:
    claim_id: str
    handoff_id: str
    job_id: str
    action_id: str
    plan_id: str
    plan_sha256: str
    request_sha256: str
    snapshot_sha256: str
    authorization_id: str
    target_node_id: str
    worker_id: str
    from_state_version: int
    to_state_version: int
    audit_event_id: str | None = None
    schema: str = field(default=SCHEMA, init=False)
    from_state: str = field(default="prepared", init=False)
    to_state: str = field(default="running", init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "claim_id": self.claim_id,
            "handoff_id": self.handoff_id,
            "job_id": self.job_id,
            "action_id": self.action_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "request_sha256": self.request_sha256,
            "snapshot_sha256": self.snapshot_sha256,
            "authorization_id": self.authorization_id,
            "target_node_id": self.target_node_id,
            "worker_id": self.worker_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "from_state_version": self.from_state_version,
            "to_state_version": self.to_state_version,
            "audit_event_id": self.audit_event_id,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }


class OperationWorkerClaimCoordinator:
    """CAS-claim one prepared job without exposing command material or execution authority."""

    def __init__(self, store: OperationWorkerClaimStore) -> None:
        self._store = store
        for name in (
            "_lock",
            "_connection",
            "operation_job",
            "_operation_job_row",
            "_decode_operation_job",
            "_append_operation_audit_locked",
        ):
            if not hasattr(store, name):
                raise TypeError("store does not provide operation worker claim primitives")
        with store._lock, store._connection:
            store._connection.executescript(CLAIM_SCHEMA)

    def claim(
        self,
        handoff: OperationWorkerHandoff,
        *,
        worker: OperationWorkerIdentity,
    ) -> tuple[OperationWorkerClaim, bool]:
        if not isinstance(handoff, OperationWorkerHandoff):
            raise TypeError("handoff must be OperationWorkerHandoff")
        if not isinstance(worker, OperationWorkerIdentity):
            raise TypeError("worker must be OperationWorkerIdentity")
        if worker.worker_id != handoff.worker_id or worker.node_id != handoff.target_node_id:
            raise OperationWorkerClaimError("operation_worker_identity_mismatch")

        provisional = _build_claim(handoff, audit_event_id=None)
        store = self._store
        with store._lock:
            store._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = store._connection.execute(
                    "SELECT * FROM operation_worker_claims WHERE handoff_id=?",
                    (handoff.handoff_id,),
                ).fetchone()
                if replay is not None:
                    claim = _decode_claim(replay)
                    if _without_audit(claim) != _without_audit(provisional):
                        raise OperationWorkerClaimError("operation_worker_claim_conflict")
                    store._connection.commit()
                    return claim, False

                row = store._operation_job_row(handoff.job_id)
                if row is None:
                    raise OperationWorkerClaimError("operation_job_not_found")
                job = store._decode_operation_job(row)
                if job.get("state") != OperationJobState.PREPARED.value:
                    raise OperationWorkerClaimError("operation_job_not_prepared")
                if job.get("state_version") != handoff.expected_state_version:
                    raise OperationWorkerClaimError("operation_job_state_stale")
                if job.get("mutation_may_have_occurred") is not False:
                    raise OperationWorkerClaimError("operation_job_mutation_already_possible")
                if job.get("recovery_required") is not False:
                    raise OperationWorkerClaimError("operation_job_recovery_required")
                if job.get("evidence") is not None:
                    raise OperationWorkerClaimError("operation_job_unexpected_evidence")

                expected_handoff = prepare_operation_worker_handoff(
                    store,
                    job_id=handoff.job_id,
                    expected_state_version=handoff.expected_state_version,
                    worker=worker,
                )
                if expected_handoff != handoff:
                    raise OperationWorkerClaimError("operation_worker_handoff_stale")

                validate_job_transition(OperationJobState.PREPARED, OperationJobState.RUNNING)
                audit_event_id = store._append_operation_audit_locked(
                    actor=worker.worker_id,
                    action="operation.worker.claim",
                    target=f"{job['target_node_id']}:{job['service']}",
                    outcome=OperationJobState.RUNNING.value,
                    correlation_id=job["correlation_id"],
                    details={
                        "claim_id": provisional.claim_id,
                        "handoff_id": handoff.handoff_id,
                        "job_id": handoff.job_id,
                        "worker_id": worker.worker_id,
                        "target_node_id": worker.node_id,
                        "plan_id": handoff.plan_id,
                        "plan_sha256": handoff.plan_sha256,
                        "from_state": OperationJobState.PREPARED.value,
                        "to_state": OperationJobState.RUNNING.value,
                        "from_state_version": handoff.expected_state_version,
                        "to_state_version": handoff.expected_state_version + 1,
                    },
                )
                claim = _build_claim(handoff, audit_event_id=audit_event_id)
                claim_json = canonical_json(claim.to_dict())
                claim_sha256 = hashlib.sha256(claim_json.encode("utf-8")).hexdigest()

                cursor = store._connection.execute(
                    """UPDATE jobs SET state=?,evidence_json=?,updated_at=?
                    WHERE job_id=? AND state=? AND evidence_json IS NULL""",
                    (
                        OperationJobState.RUNNING.value,
                        canonical_json({"worker_claim": claim.to_dict()}),
                        utc_now(),
                        handoff.job_id,
                        OperationJobState.PREPARED.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationWorkerClaimError("operation_worker_claim_stale")
                cursor = store._connection.execute(
                    """UPDATE operation_job_metadata
                    SET state_version=?,last_audit_event_id=?
                    WHERE job_id=? AND state_version=?
                    AND mutation_may_have_occurred=0 AND recovery_required=0""",
                    (
                        handoff.expected_state_version + 1,
                        audit_event_id,
                        handoff.job_id,
                        handoff.expected_state_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationWorkerClaimError("operation_worker_claim_stale")
                store._connection.execute(
                    """INSERT INTO operation_worker_claims(
                    claim_id,handoff_id,job_id,worker_id,target_node_id,plan_id,
                    from_state_version,to_state_version,claim_sha256,claim_json,
                    audit_event_id,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        claim.claim_id,
                        claim.handoff_id,
                        claim.job_id,
                        claim.worker_id,
                        claim.target_node_id,
                        claim.plan_id,
                        claim.from_state_version,
                        claim.to_state_version,
                        claim_sha256,
                        claim_json,
                        audit_event_id,
                        utc_now(),
                    ),
                )
                store._connection.commit()
                return claim, True
            except (OperationWorkerHandoffError, sqlite3.IntegrityError) as exc:
                store._connection.rollback()
                raise OperationWorkerClaimError("operation_worker_claim_rejected") from exc
            except Exception:
                store._connection.rollback()
                raise


def _build_claim(
    handoff: OperationWorkerHandoff,
    *,
    audit_event_id: str | None,
) -> OperationWorkerClaim:
    identity = {
        "handoff_id": handoff.handoff_id,
        "job_id": handoff.job_id,
        "action_id": handoff.action_id,
        "plan_id": handoff.plan_id,
        "plan_sha256": handoff.plan_sha256,
        "request_sha256": handoff.request_sha256,
        "snapshot_sha256": handoff.snapshot_sha256,
        "authorization_id": handoff.authorization_id,
        "target_node_id": handoff.target_node_id,
        "worker_id": handoff.worker_id,
        "from_state": OperationJobState.PREPARED.value,
        "to_state": OperationJobState.RUNNING.value,
        "from_state_version": handoff.expected_state_version,
        "to_state_version": handoff.expected_state_version + 1,
    }
    digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return OperationWorkerClaim(
        claim_id=f"opclaim-{digest[:24]}",
        handoff_id=handoff.handoff_id,
        job_id=handoff.job_id,
        action_id=handoff.action_id,
        plan_id=handoff.plan_id,
        plan_sha256=handoff.plan_sha256,
        request_sha256=handoff.request_sha256,
        snapshot_sha256=handoff.snapshot_sha256,
        authorization_id=handoff.authorization_id,
        target_node_id=handoff.target_node_id,
        worker_id=handoff.worker_id,
        from_state_version=handoff.expected_state_version,
        to_state_version=handoff.expected_state_version + 1,
        audit_event_id=audit_event_id,
    )


def _without_audit(claim: OperationWorkerClaim) -> dict[str, Any]:
    value = claim.to_dict()
    value["audit_event_id"] = None
    return value


def _decode_claim(row: sqlite3.Row) -> OperationWorkerClaim:
    value = json.loads(row["claim_json"])
    encoded = canonical_json(value)
    actual_sha256 = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    if actual_sha256 != row["claim_sha256"]:
        raise OperationWorkerClaimError("operation_worker_claim_integrity_mismatch")
    claim = OperationWorkerClaim(
        claim_id=value["claim_id"],
        handoff_id=value["handoff_id"],
        job_id=value["job_id"],
        action_id=value["action_id"],
        plan_id=value["plan_id"],
        plan_sha256=value["plan_sha256"],
        request_sha256=value["request_sha256"],
        snapshot_sha256=value["snapshot_sha256"],
        authorization_id=value["authorization_id"],
        target_node_id=value["target_node_id"],
        worker_id=value["worker_id"],
        from_state_version=value["from_state_version"],
        to_state_version=value["to_state_version"],
        audit_event_id=value["audit_event_id"],
    )
    if claim.to_dict() != value:
        raise OperationWorkerClaimError("operation_worker_claim_shape_mismatch")
    if (
        row["claim_id"] != claim.claim_id
        or row["handoff_id"] != claim.handoff_id
        or row["job_id"] != claim.job_id
        or row["worker_id"] != claim.worker_id
        or row["target_node_id"] != claim.target_node_id
        or row["plan_id"] != claim.plan_id
        or row["from_state_version"] != claim.from_state_version
        or row["to_state_version"] != claim.to_state_version
        or row["audit_event_id"] != claim.audit_event_id
    ):
        raise OperationWorkerClaimError("operation_worker_claim_identity_mismatch")
    return claim
