"""Replay-safe execution receipts for one bounded operation worker claim."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_commands import ACTION_ID, SYSTEMCTL, OperationJobState, validate_job_transition
from .operation_worker_claim import OperationWorkerClaim, OperationWorkerClaimError, _decode_claim
from .operation_worker_handoff import OperationWorkerIdentity
from .util import canonical_json, utc_now


SCHEMA = "home-center.operation-execution-receipt.v1"
CLAIM_ID = re.compile(r"^opclaim-[a-f0-9]{24}$")
RECEIPT_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation_execution_receipts (
    receipt_id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL UNIQUE REFERENCES operation_worker_claims(claim_id) ON DELETE CASCADE,
    job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    from_state_version INTEGER NOT NULL CHECK(from_state_version >= 2),
    to_state_version INTEGER NOT NULL CHECK(to_state_version > from_state_version),
    next_state TEXT NOT NULL CHECK(next_state IN ('verifying','rolling_back','failed')),
    command_sha256 TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    audit_event_id TEXT NOT NULL REFERENCES audit(event_id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operation_execution_receipt_job
    ON operation_execution_receipts(job_id, worker_id, to_state_version);
"""


class OperationExecutionReceiptError(RuntimeError):
    """Execution evidence could not be recorded without weakening operation safety."""


class OperationExecutionReceiptStore(Protocol):
    _lock: Any
    _connection: sqlite3.Connection

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
class OperationExecutionObservation:
    """Sanitized worker observation; never contains argv, shell, stdout, stderr, or secrets."""

    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.started, bool) or not isinstance(self.timed_out, bool):
            raise OperationExecutionReceiptError("invalid_execution_flags")
        if (
            not isinstance(self.elapsed_ms, int)
            or isinstance(self.elapsed_ms, bool)
            or not 0 <= self.elapsed_ms <= 15_000
        ):
            raise OperationExecutionReceiptError("invalid_execution_elapsed_ms")
        if self.exit_code is not None and (
            not isinstance(self.exit_code, int)
            or isinstance(self.exit_code, bool)
            or not -255 <= self.exit_code <= 255
        ):
            raise OperationExecutionReceiptError("invalid_execution_exit_code")
        if not self.started:
            if self.timed_out or self.exit_code is not None or self.elapsed_ms != 0:
                raise OperationExecutionReceiptError("invalid_not_started_observation")
        elif not self.timed_out and self.exit_code is None:
            raise OperationExecutionReceiptError("missing_execution_exit_code")
        elif self.timed_out and self.exit_code is not None:
            raise OperationExecutionReceiptError("timeout_with_exit_code")


@dataclass(frozen=True, slots=True)
class OperationExecutionReceipt:
    receipt_id: str
    claim_id: str
    job_id: str
    action_id: str
    plan_id: str
    plan_sha256: str
    worker_id: str
    target_node_id: str
    command_sha256: str
    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int
    mutation_may_have_occurred: bool
    next_state: str
    from_state_version: int
    to_state_version: int
    audit_event_id: str | None = None
    schema: str = field(default=SCHEMA, init=False)
    from_state: str = field(default="running", init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    grants_execution_authority: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "job_id": self.job_id,
            "action_id": self.action_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "worker_id": self.worker_id,
            "target_node_id": self.target_node_id,
            "command_sha256": self.command_sha256,
            "started": self.started,
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
            "elapsed_ms": self.elapsed_ms,
            "mutation_may_have_occurred": self.mutation_may_have_occurred,
            "from_state": self.from_state,
            "next_state": self.next_state,
            "from_state_version": self.from_state_version,
            "to_state_version": self.to_state_version,
            "audit_event_id": self.audit_event_id,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "production_mutation_enabled": False,
        }


class OperationExecutionReceiptCoordinator:
    """Commit one sanitized execution observation against an exact durable worker claim."""

    def __init__(self, store: OperationExecutionReceiptStore) -> None:
        self._store = store
        for name in (
            "_lock",
            "_connection",
            "_operation_job_row",
            "_decode_operation_job",
            "_append_operation_audit_locked",
        ):
            if not hasattr(store, name):
                raise TypeError("store does not provide operation execution receipt primitives")
        with store._lock, store._connection:
            store._connection.executescript(RECEIPT_SCHEMA)

    def record(
        self,
        claim_id: str,
        *,
        worker: OperationWorkerIdentity,
        observation: OperationExecutionObservation,
    ) -> tuple[OperationExecutionReceipt, bool]:
        if not isinstance(claim_id, str) or not CLAIM_ID.fullmatch(claim_id):
            raise OperationExecutionReceiptError("invalid_operation_worker_claim_id")
        if not isinstance(worker, OperationWorkerIdentity):
            raise TypeError("worker must be OperationWorkerIdentity")
        if not isinstance(observation, OperationExecutionObservation):
            raise TypeError("observation must be OperationExecutionObservation")

        store = self._store
        with store._lock:
            store._connection.execute("BEGIN IMMEDIATE")
            try:
                claim_row = store._connection.execute(
                    "SELECT * FROM operation_worker_claims WHERE claim_id=?",
                    (claim_id,),
                ).fetchone()
                if claim_row is None:
                    raise OperationExecutionReceiptError("operation_worker_claim_not_found")
                claim = _decode_claim(claim_row)
                _validate_claim_worker(claim, worker)

                replay = store._connection.execute(
                    "SELECT * FROM operation_execution_receipts WHERE claim_id=?",
                    (claim_id,),
                ).fetchone()
                if replay is not None:
                    receipt = _decode_receipt(replay)
                    provisional = _build_receipt(
                        claim,
                        command_sha256=receipt.command_sha256,
                        observation=observation,
                        audit_event_id=None,
                    )
                    if _without_audit(receipt) != _without_audit(provisional):
                        raise OperationExecutionReceiptError("operation_execution_receipt_conflict")
                    store._connection.commit()
                    return receipt, False

                job_row = store._operation_job_row(claim.job_id)
                if job_row is None:
                    raise OperationExecutionReceiptError("operation_job_not_found")
                job = store._decode_operation_job(job_row)
                command_sha256 = _validate_running_job(job, claim)
                provisional = _build_receipt(
                    claim,
                    command_sha256=command_sha256,
                    observation=observation,
                    audit_event_id=None,
                )
                next_state = OperationJobState(provisional.next_state)
                validate_job_transition(
                    OperationJobState.RUNNING,
                    next_state,
                    mutation_may_have_occurred=provisional.mutation_may_have_occurred,
                )
                audit_event_id = store._append_operation_audit_locked(
                    actor=worker.worker_id,
                    action="operation.execution.receipt",
                    target=f"{claim.target_node_id}:{job['service']}",
                    outcome=provisional.next_state,
                    correlation_id=job["correlation_id"],
                    details={
                        "receipt_id": provisional.receipt_id,
                        "claim_id": claim.claim_id,
                        "job_id": claim.job_id,
                        "worker_id": worker.worker_id,
                        "plan_id": claim.plan_id,
                        "plan_sha256": claim.plan_sha256,
                        "command_sha256": command_sha256,
                        "from_state": OperationJobState.RUNNING.value,
                        "to_state": provisional.next_state,
                        "from_state_version": provisional.from_state_version,
                        "to_state_version": provisional.to_state_version,
                        "started": observation.started,
                        "timed_out": observation.timed_out,
                        "exit_code": observation.exit_code,
                        "elapsed_ms": observation.elapsed_ms,
                        "mutation_may_have_occurred": provisional.mutation_may_have_occurred,
                    },
                )
                receipt = _build_receipt(
                    claim,
                    command_sha256=command_sha256,
                    observation=observation,
                    audit_event_id=audit_event_id,
                )
                receipt_json = canonical_json(receipt.to_dict())
                receipt_sha256 = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
                evidence = {
                    "worker_claim": claim.to_dict(),
                    "execution_receipt": receipt.to_dict(),
                }
                result = {
                    "execution": {
                        "receipt_id": receipt.receipt_id,
                        "started": receipt.started,
                        "timed_out": receipt.timed_out,
                        "exit_code": receipt.exit_code,
                        "elapsed_ms": receipt.elapsed_ms,
                    }
                }

                cursor = store._connection.execute(
                    """UPDATE jobs SET state=?,result_json=?,evidence_json=?,updated_at=?
                    WHERE job_id=? AND state=?""",
                    (
                        receipt.next_state,
                        canonical_json(result),
                        canonical_json(evidence),
                        utc_now(),
                        claim.job_id,
                        OperationJobState.RUNNING.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationExecutionReceiptError("operation_execution_receipt_stale")
                cursor = store._connection.execute(
                    """UPDATE operation_job_metadata
                    SET state_version=?,mutation_may_have_occurred=?,last_audit_event_id=?
                    WHERE job_id=? AND state_version=? AND recovery_required=0""",
                    (
                        receipt.to_state_version,
                        1 if receipt.mutation_may_have_occurred else 0,
                        audit_event_id,
                        claim.job_id,
                        receipt.from_state_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationExecutionReceiptError("operation_execution_receipt_stale")
                store._connection.execute(
                    """INSERT INTO operation_execution_receipts(
                    receipt_id,claim_id,job_id,worker_id,plan_id,from_state_version,
                    to_state_version,next_state,command_sha256,receipt_sha256,
                    receipt_json,audit_event_id,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        receipt.receipt_id,
                        receipt.claim_id,
                        receipt.job_id,
                        receipt.worker_id,
                        receipt.plan_id,
                        receipt.from_state_version,
                        receipt.to_state_version,
                        receipt.next_state,
                        receipt.command_sha256,
                        receipt_sha256,
                        receipt_json,
                        audit_event_id,
                        utc_now(),
                    ),
                )
                store._connection.commit()
                return receipt, True
            except (OperationWorkerClaimError, sqlite3.IntegrityError, ValueError) as exc:
                store._connection.rollback()
                raise OperationExecutionReceiptError("operation_execution_receipt_rejected") from exc
            except Exception:
                store._connection.rollback()
                raise


def _validate_claim_worker(
    claim: OperationWorkerClaim,
    worker: OperationWorkerIdentity,
) -> None:
    value = claim.to_dict()
    if worker.worker_id != claim.worker_id or worker.node_id != claim.target_node_id:
        raise OperationExecutionReceiptError("operation_worker_identity_mismatch")
    if claim.action_id != ACTION_ID:
        raise OperationExecutionReceiptError("unsupported_operation_action")
    if (
        value.get("contains_command_material") is not False
        or value.get("accepts_caller_argv") is not False
        or value.get("accepts_shell") is not False
        or value.get("execution_authorized") is not False
        or value.get("production_mutation_enabled") is not False
    ):
        raise OperationExecutionReceiptError("unsafe_operation_worker_claim")


def _validate_running_job(job: dict[str, Any], claim: OperationWorkerClaim) -> str:
    if job.get("state") != OperationJobState.RUNNING.value:
        raise OperationExecutionReceiptError("operation_job_not_running")
    if job.get("state_version") != claim.to_state_version:
        raise OperationExecutionReceiptError("operation_job_state_stale")
    if job.get("mutation_may_have_occurred") is not False:
        raise OperationExecutionReceiptError("operation_job_mutation_already_possible")
    if job.get("recovery_required") is not False:
        raise OperationExecutionReceiptError("operation_job_recovery_required")
    for name in (
        "job_id",
        "action_id",
        "plan_id",
        "plan_sha256",
        "request_sha256",
        "snapshot_sha256",
        "authorization_id",
        "target_node_id",
    ):
        if job.get(name) != getattr(claim, name):
            raise OperationExecutionReceiptError(f"operation_job_{name}_mismatch")
    expected_evidence = {"worker_claim": claim.to_dict()}
    if job.get("evidence") != expected_evidence:
        raise OperationExecutionReceiptError("operation_worker_claim_evidence_mismatch")

    plan = job.get("plan")
    if not isinstance(plan, dict):
        raise OperationExecutionReceiptError("operation_plan_missing")
    if (
        plan.get("action_id") != ACTION_ID
        or plan.get("service") != job.get("service")
        or plan.get("target_node_id") != claim.target_node_id
        or plan.get("execution_authorized") is not False
        or plan.get("production_mutation_enabled") is not False
        or plan.get("accepts_caller_argv") is not False
        or plan.get("accepts_shell") is not False
    ):
        raise OperationExecutionReceiptError("unsafe_operation_plan")
    execution = plan.get("execution")
    expected_execution = {
        "executable": SYSTEMCTL,
        "argv": [SYSTEMCTL, "restart", job["service"]],
        "timeout_seconds": 15,
        "shell": False,
    }
    if execution != expected_execution:
        raise OperationExecutionReceiptError("operation_execution_contract_mismatch")
    return hashlib.sha256(canonical_json(execution).encode("utf-8")).hexdigest()


def _build_receipt(
    claim: OperationWorkerClaim,
    *,
    command_sha256: str,
    observation: OperationExecutionObservation,
    audit_event_id: str | None,
) -> OperationExecutionReceipt:
    mutation_possible = observation.started
    if not observation.started:
        next_state = OperationJobState.FAILED
    elif observation.timed_out or observation.exit_code != 0:
        next_state = OperationJobState.ROLLING_BACK
    else:
        next_state = OperationJobState.VERIFYING
    identity = {
        "claim_id": claim.claim_id,
        "job_id": claim.job_id,
        "action_id": claim.action_id,
        "plan_id": claim.plan_id,
        "plan_sha256": claim.plan_sha256,
        "worker_id": claim.worker_id,
        "target_node_id": claim.target_node_id,
        "command_sha256": command_sha256,
        "started": observation.started,
        "timed_out": observation.timed_out,
        "exit_code": observation.exit_code,
        "elapsed_ms": observation.elapsed_ms,
        "mutation_may_have_occurred": mutation_possible,
        "from_state": OperationJobState.RUNNING.value,
        "next_state": next_state.value,
        "from_state_version": claim.to_state_version,
        "to_state_version": claim.to_state_version + 1,
    }
    digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return OperationExecutionReceipt(
        receipt_id=f"opreceipt-{digest[:24]}",
        claim_id=claim.claim_id,
        job_id=claim.job_id,
        action_id=claim.action_id,
        plan_id=claim.plan_id,
        plan_sha256=claim.plan_sha256,
        worker_id=claim.worker_id,
        target_node_id=claim.target_node_id,
        command_sha256=command_sha256,
        started=observation.started,
        timed_out=observation.timed_out,
        exit_code=observation.exit_code,
        elapsed_ms=observation.elapsed_ms,
        mutation_may_have_occurred=mutation_possible,
        next_state=next_state.value,
        from_state_version=claim.to_state_version,
        to_state_version=claim.to_state_version + 1,
        audit_event_id=audit_event_id,
    )


def _without_audit(receipt: OperationExecutionReceipt) -> dict[str, Any]:
    value = receipt.to_dict()
    value["audit_event_id"] = None
    return value


def _decode_receipt(row: sqlite3.Row) -> OperationExecutionReceipt:
    value = json.loads(row["receipt_json"])
    actual_sha256 = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    if actual_sha256 != row["receipt_sha256"]:
        raise OperationExecutionReceiptError("operation_execution_receipt_integrity_mismatch")
    receipt = OperationExecutionReceipt(
        receipt_id=value["receipt_id"],
        claim_id=value["claim_id"],
        job_id=value["job_id"],
        action_id=value["action_id"],
        plan_id=value["plan_id"],
        plan_sha256=value["plan_sha256"],
        worker_id=value["worker_id"],
        target_node_id=value["target_node_id"],
        command_sha256=value["command_sha256"],
        started=value["started"],
        timed_out=value["timed_out"],
        exit_code=value["exit_code"],
        elapsed_ms=value["elapsed_ms"],
        mutation_may_have_occurred=value["mutation_may_have_occurred"],
        next_state=value["next_state"],
        from_state_version=value["from_state_version"],
        to_state_version=value["to_state_version"],
        audit_event_id=value["audit_event_id"],
    )
    if receipt.to_dict() != value:
        raise OperationExecutionReceiptError("operation_execution_receipt_shape_mismatch")
    if (
        row["receipt_id"] != receipt.receipt_id
        or row["claim_id"] != receipt.claim_id
        or row["job_id"] != receipt.job_id
        or row["worker_id"] != receipt.worker_id
        or row["plan_id"] != receipt.plan_id
        or row["from_state_version"] != receipt.from_state_version
        or row["to_state_version"] != receipt.to_state_version
        or row["next_state"] != receipt.next_state
        or row["command_sha256"] != receipt.command_sha256
        or row["audit_event_id"] != receipt.audit_event_id
    ):
        raise OperationExecutionReceiptError("operation_execution_receipt_identity_mismatch")
    return receipt
