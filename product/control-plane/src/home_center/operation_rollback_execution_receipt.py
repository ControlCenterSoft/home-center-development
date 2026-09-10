"""Replay-safe receipts for one bounded rollback execution."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_commands import ACTION_ID, ALLOWED_SERVICES, SYSTEMCTL, OperationJobState
from .operation_rollback_claim import (
    OperationRollbackClaim,
    OperationRollbackClaimError,
    _decode_claim,
    revalidate_operation_rollback_claim,
)
from .operation_worker_handoff import OperationWorkerIdentity
from .util import canonical_json, utc_now


SCHEMA = "home-center.operation-rollback-execution-receipt.v1"
ROLLBACK_CLAIM_ID = re.compile(r"^oprollback-[a-f0-9]{24}$")
RECEIPT_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation_rollback_execution_receipts (
    receipt_id TEXT PRIMARY KEY,
    rollback_claim_id TEXT NOT NULL UNIQUE
        REFERENCES operation_rollback_claims(claim_id) ON DELETE CASCADE,
    verification_receipt_id TEXT NOT NULL UNIQUE,
    execution_receipt_id TEXT NOT NULL UNIQUE,
    job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    from_state_version INTEGER NOT NULL CHECK(from_state_version >= 5),
    to_state_version INTEGER NOT NULL CHECK(to_state_version > from_state_version),
    next_state TEXT NOT NULL CHECK(next_state IN ('rolling_back','failed')),
    recovery_sha256 TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    audit_event_id TEXT NOT NULL REFERENCES audit(event_id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operation_rollback_execution_receipt_job
    ON operation_rollback_execution_receipts(job_id, worker_id, to_state_version);
"""


class OperationRollbackExecutionReceiptError(RuntimeError):
    """Rollback execution evidence could not be recorded without weakening safety."""


class OperationRollbackExecutionReceiptStore(Protocol):
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
class OperationRollbackExecutionObservation:
    """Sanitized rollback observation; never contains command material or output."""

    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.started, bool) or not isinstance(self.timed_out, bool):
            raise OperationRollbackExecutionReceiptError("invalid_rollback_execution_flags")
        if (
            not isinstance(self.elapsed_ms, int)
            or isinstance(self.elapsed_ms, bool)
            or not 0 <= self.elapsed_ms <= 15_000
        ):
            raise OperationRollbackExecutionReceiptError("invalid_rollback_execution_elapsed_ms")
        if self.exit_code is not None and (
            not isinstance(self.exit_code, int)
            or isinstance(self.exit_code, bool)
            or not -255 <= self.exit_code <= 255
        ):
            raise OperationRollbackExecutionReceiptError("invalid_rollback_execution_exit_code")
        if not self.started:
            if self.timed_out or self.exit_code is not None or self.elapsed_ms != 0:
                raise OperationRollbackExecutionReceiptError(
                    "invalid_rollback_not_started_observation"
                )
        elif not self.timed_out and self.exit_code is None:
            raise OperationRollbackExecutionReceiptError(
                "missing_rollback_execution_exit_code"
            )
        elif self.timed_out and self.exit_code is not None:
            raise OperationRollbackExecutionReceiptError(
                "rollback_timeout_with_exit_code"
            )


@dataclass(frozen=True, slots=True)
class OperationRollbackExecutionReceipt:
    receipt_id: str
    rollback_claim_id: str
    verification_receipt_id: str
    execution_receipt_id: str
    job_id: str
    action_id: str
    plan_id: str
    plan_sha256: str
    worker_id: str
    target_node_id: str
    recovery_sha256: str
    recovery_strategy: str
    expected_active_state: str
    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int
    rollback_succeeded: bool
    recovery_required: bool
    next_state: str
    from_state_version: int
    to_state_version: int
    verification_required: bool
    audit_event_id: str | None = None
    schema: str = field(default=SCHEMA, init=False)
    from_state: str = field(default="rolling_back", init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    grants_execution_authority: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "rollback_claim_id": self.rollback_claim_id,
            "verification_receipt_id": self.verification_receipt_id,
            "execution_receipt_id": self.execution_receipt_id,
            "job_id": self.job_id,
            "action_id": self.action_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "worker_id": self.worker_id,
            "target_node_id": self.target_node_id,
            "recovery_sha256": self.recovery_sha256,
            "recovery_strategy": self.recovery_strategy,
            "expected_active_state": self.expected_active_state,
            "started": self.started,
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
            "elapsed_ms": self.elapsed_ms,
            "rollback_succeeded": self.rollback_succeeded,
            "recovery_required": self.recovery_required,
            "from_state": self.from_state,
            "next_state": self.next_state,
            "from_state_version": self.from_state_version,
            "to_state_version": self.to_state_version,
            "audit_event_id": self.audit_event_id,
            "verification_required": self.verification_required,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "production_mutation_enabled": False,
        }


class OperationRollbackExecutionReceiptCoordinator:
    """Record one exact rollback execution observation against a durable rollback claim."""

    def __init__(self, store: OperationRollbackExecutionReceiptStore) -> None:
        self._store = store
        for name in (
            "_lock",
            "_connection",
            "_operation_job_row",
            "_decode_operation_job",
            "_append_operation_audit_locked",
        ):
            if not hasattr(store, name):
                raise TypeError("store does not provide rollback execution receipt primitives")
        with store._lock, store._connection:
            store._connection.executescript(RECEIPT_SCHEMA)

    def record(
        self,
        rollback_claim_id: str,
        *,
        worker: OperationWorkerIdentity,
        observation: OperationRollbackExecutionObservation,
    ) -> tuple[OperationRollbackExecutionReceipt, bool]:
        if (
            not isinstance(rollback_claim_id, str)
            or not ROLLBACK_CLAIM_ID.fullmatch(rollback_claim_id)
        ):
            raise OperationRollbackExecutionReceiptError("invalid_operation_rollback_claim_id")
        if not isinstance(worker, OperationWorkerIdentity):
            raise TypeError("worker must be OperationWorkerIdentity")
        if not isinstance(observation, OperationRollbackExecutionObservation):
            raise TypeError("observation must be OperationRollbackExecutionObservation")

        store = self._store
        with store._lock:
            store._connection.execute("BEGIN IMMEDIATE")
            try:
                claim_row = store._connection.execute(
                    "SELECT * FROM operation_rollback_claims WHERE claim_id=?",
                    (rollback_claim_id,),
                ).fetchone()
                if claim_row is None:
                    raise OperationRollbackExecutionReceiptError(
                        "operation_rollback_claim_not_found"
                    )
                claim = _decode_claim(claim_row)
                _validate_claim_worker(claim, worker)

                replay = store._connection.execute(
                    """SELECT * FROM operation_rollback_execution_receipts
                    WHERE rollback_claim_id=?""",
                    (rollback_claim_id,),
                ).fetchone()
                if replay is not None:
                    receipt = _decode_receipt(replay)
                    provisional = _build_receipt(
                        claim,
                        observation=observation,
                        audit_event_id=None,
                    )
                    if _without_audit(receipt) != _without_audit(provisional):
                        raise OperationRollbackExecutionReceiptError(
                            "operation_rollback_execution_receipt_conflict"
                        )
                    _revalidate_persisted_receipt(store, receipt, claim)
                    store._connection.commit()
                    return receipt, False

                revalidate_operation_rollback_claim(store, claim)
                job_row = store._operation_job_row(claim.job_id)
                if job_row is None:
                    raise OperationRollbackExecutionReceiptError("operation_job_not_found")
                job = store._decode_operation_job(job_row)
                _validate_rolling_back_job(job, claim)

                provisional = _build_receipt(
                    claim,
                    observation=observation,
                    audit_event_id=None,
                )
                audit_event_id = store._append_operation_audit_locked(
                    actor=worker.worker_id,
                    action="operation.rollback.execution.receipt",
                    target=f"{claim.target_node_id}:{job['service']}",
                    outcome=provisional.next_state,
                    correlation_id=job["correlation_id"],
                    details={
                        "receipt_id": provisional.receipt_id,
                        "rollback_claim_id": claim.claim_id,
                        "verification_receipt_id": claim.verification_receipt_id,
                        "execution_receipt_id": claim.execution_receipt_id,
                        "job_id": claim.job_id,
                        "worker_id": worker.worker_id,
                        "target_node_id": worker.node_id,
                        "plan_id": claim.plan_id,
                        "plan_sha256": claim.plan_sha256,
                        "recovery_sha256": claim.recovery_sha256,
                        "expected_active_state": claim.expected_active_state,
                        "from_state": OperationJobState.ROLLING_BACK.value,
                        "to_state": provisional.next_state,
                        "from_state_version": provisional.from_state_version,
                        "to_state_version": provisional.to_state_version,
                        "started": observation.started,
                        "timed_out": observation.timed_out,
                        "exit_code": observation.exit_code,
                        "elapsed_ms": observation.elapsed_ms,
                        "rollback_succeeded": provisional.rollback_succeeded,
                        "recovery_required": provisional.recovery_required,
                    },
                )
                receipt = _build_receipt(
                    claim,
                    observation=observation,
                    audit_event_id=audit_event_id,
                )
                receipt_json = canonical_json(receipt.to_dict())
                receipt_sha256 = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()

                evidence = dict(job["evidence"])
                evidence["rollback_execution_receipt"] = receipt.to_dict()
                result = dict(job["result"]) if isinstance(job.get("result"), dict) else {}
                result["rollback_execution"] = {
                    "receipt_id": receipt.receipt_id,
                    "started": receipt.started,
                    "timed_out": receipt.timed_out,
                    "exit_code": receipt.exit_code,
                    "elapsed_ms": receipt.elapsed_ms,
                    "rollback_succeeded": receipt.rollback_succeeded,
                    "verification_required": receipt.verification_required,
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
                        OperationJobState.ROLLING_BACK.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationRollbackExecutionReceiptError(
                        "operation_rollback_execution_receipt_stale"
                    )
                cursor = store._connection.execute(
                    """UPDATE operation_job_metadata
                    SET state_version=?,recovery_required=?,last_audit_event_id=?
                    WHERE job_id=? AND state_version=?
                    AND mutation_may_have_occurred=1 AND recovery_required=0""",
                    (
                        receipt.to_state_version,
                        1 if receipt.recovery_required else 0,
                        audit_event_id,
                        claim.job_id,
                        receipt.from_state_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationRollbackExecutionReceiptError(
                        "operation_rollback_execution_receipt_stale"
                    )
                store._connection.execute(
                    """INSERT INTO operation_rollback_execution_receipts(
                    receipt_id,rollback_claim_id,verification_receipt_id,
                    execution_receipt_id,job_id,worker_id,plan_id,from_state_version,
                    to_state_version,next_state,recovery_sha256,receipt_sha256,
                    receipt_json,audit_event_id,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        receipt.receipt_id,
                        receipt.rollback_claim_id,
                        receipt.verification_receipt_id,
                        receipt.execution_receipt_id,
                        receipt.job_id,
                        receipt.worker_id,
                        receipt.plan_id,
                        receipt.from_state_version,
                        receipt.to_state_version,
                        receipt.next_state,
                        receipt.recovery_sha256,
                        receipt_sha256,
                        receipt_json,
                        audit_event_id,
                        utc_now(),
                    ),
                )
                store._connection.commit()
                return receipt, True
            except (
                OperationRollbackClaimError,
                sqlite3.IntegrityError,
                ValueError,
            ) as exc:
                store._connection.rollback()
                raise OperationRollbackExecutionReceiptError(
                    "operation_rollback_execution_receipt_rejected"
                ) from exc
            except Exception:
                store._connection.rollback()
                raise


def revalidate_operation_rollback_execution_receipt(
    store: OperationRollbackExecutionReceiptStore,
    receipt: OperationRollbackExecutionReceipt,
) -> None:
    """Fail closed before rollback verification consumes execution evidence."""

    if not isinstance(receipt, OperationRollbackExecutionReceipt):
        raise TypeError("receipt must be OperationRollbackExecutionReceipt")
    with store._lock:
        row = store._connection.execute(
            "SELECT * FROM operation_rollback_execution_receipts WHERE receipt_id=?",
            (receipt.receipt_id,),
        ).fetchone()
        if row is None:
            raise OperationRollbackExecutionReceiptError(
                "operation_rollback_execution_receipt_not_found"
            )
        persisted = _decode_receipt(row)
        if persisted != receipt:
            raise OperationRollbackExecutionReceiptError(
                "operation_rollback_execution_receipt_stale"
            )
        claim_row = store._connection.execute(
            "SELECT * FROM operation_rollback_claims WHERE claim_id=?",
            (receipt.rollback_claim_id,),
        ).fetchone()
        if claim_row is None:
            raise OperationRollbackExecutionReceiptError("operation_rollback_claim_not_found")
        claim = _decode_claim(claim_row)
        _revalidate_persisted_receipt(store, receipt, claim)


def _validate_claim_worker(
    claim: OperationRollbackClaim,
    worker: OperationWorkerIdentity,
) -> None:
    value = claim.to_dict()
    if worker.worker_id != claim.worker_id or worker.node_id != claim.target_node_id:
        raise OperationRollbackExecutionReceiptError("operation_worker_identity_mismatch")
    if claim.action_id != ACTION_ID:
        raise OperationRollbackExecutionReceiptError("unsupported_operation_action")
    if (
        value.get("contains_command_material") is not False
        or value.get("accepts_caller_argv") is not False
        or value.get("accepts_shell") is not False
        or value.get("execution_authorized") is not False
        or value.get("production_mutation_enabled") is not False
    ):
        raise OperationRollbackExecutionReceiptError("unsafe_operation_rollback_claim")


def _validate_rolling_back_job(
    job: dict[str, Any],
    claim: OperationRollbackClaim,
    *,
    receipt: OperationRollbackExecutionReceipt | None = None,
) -> None:
    expected_version = claim.to_state_version if receipt is None else receipt.to_state_version
    expected_state = (
        OperationJobState.ROLLING_BACK.value if receipt is None else receipt.next_state
    )
    expected_recovery_required = False if receipt is None else receipt.recovery_required

    if job.get("state") != expected_state:
        raise OperationRollbackExecutionReceiptError("operation_rollback_job_state_stale")
    if job.get("state_version") != expected_version:
        raise OperationRollbackExecutionReceiptError("operation_rollback_job_version_stale")
    if job.get("mutation_may_have_occurred") is not True:
        raise OperationRollbackExecutionReceiptError(
            "operation_job_mutation_evidence_missing"
        )
    if job.get("recovery_required") is not expected_recovery_required:
        raise OperationRollbackExecutionReceiptError(
            "operation_job_recovery_state_mismatch"
        )
    for name in ("job_id", "action_id", "plan_id", "plan_sha256", "target_node_id"):
        if job.get(name) != getattr(claim, name):
            raise OperationRollbackExecutionReceiptError(
                f"operation_rollback_job_{name}_mismatch"
            )

    evidence = job.get("evidence")
    expected_keys = {
        "worker_claim",
        "execution_receipt",
        "verification_receipt",
        "rollback_claim",
    }
    if receipt is not None:
        expected_keys.add("rollback_execution_receipt")
    if not isinstance(evidence, dict) or set(evidence) != expected_keys:
        raise OperationRollbackExecutionReceiptError(
            "operation_rollback_execution_evidence_mismatch"
        )
    if evidence.get("rollback_claim") != claim.to_dict():
        raise OperationRollbackExecutionReceiptError(
            "operation_rollback_claim_evidence_mismatch"
        )
    if (
        receipt is not None
        and evidence.get("rollback_execution_receipt") != receipt.to_dict()
    ):
        raise OperationRollbackExecutionReceiptError(
            "operation_rollback_execution_receipt_evidence_mismatch"
        )

    plan = job.get("plan")
    if not isinstance(plan, dict):
        raise OperationRollbackExecutionReceiptError("operation_plan_missing")
    plan_sha256 = hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()
    if plan_sha256 != claim.plan_sha256:
        raise OperationRollbackExecutionReceiptError("operation_plan_integrity_mismatch")
    if (
        plan.get("action_id") != ACTION_ID
        or plan.get("plan_id") != claim.plan_id
        or plan.get("target_node_id") != claim.target_node_id
        or plan.get("service") not in ALLOWED_SERVICES
        or plan.get("accepts_caller_argv") is not False
        or plan.get("accepts_shell") is not False
        or plan.get("execution_authorized") is not False
        or plan.get("production_mutation_enabled") is not False
    ):
        raise OperationRollbackExecutionReceiptError("unsafe_operation_plan")

    expected_verb = "start" if claim.expected_active_state == "active" else "stop"
    expected_recovery = {
        "strategy": "restore-observed-active-state",
        "argv": [SYSTEMCTL, expected_verb, job["service"]],
        "timeout_seconds": 15,
        "expected_active_state": claim.expected_active_state,
        "verification_required": True,
    }
    recovery = job.get("recovery")
    if recovery != expected_recovery or plan.get("recovery") != expected_recovery:
        raise OperationRollbackExecutionReceiptError(
            "operation_recovery_contract_mismatch"
        )
    recovery_sha256 = hashlib.sha256(
        canonical_json(expected_recovery).encode("utf-8")
    ).hexdigest()
    if recovery_sha256 != claim.recovery_sha256:
        raise OperationRollbackExecutionReceiptError("operation_recovery_integrity_mismatch")


def _build_receipt(
    claim: OperationRollbackClaim,
    *,
    observation: OperationRollbackExecutionObservation,
    audit_event_id: str | None,
) -> OperationRollbackExecutionReceipt:
    rollback_succeeded = (
        observation.started and not observation.timed_out and observation.exit_code == 0
    )
    next_state = (
        OperationJobState.ROLLING_BACK
        if rollback_succeeded
        else OperationJobState.FAILED
    )
    identity = {
        "rollback_claim_id": claim.claim_id,
        "verification_receipt_id": claim.verification_receipt_id,
        "execution_receipt_id": claim.execution_receipt_id,
        "job_id": claim.job_id,
        "action_id": claim.action_id,
        "plan_id": claim.plan_id,
        "plan_sha256": claim.plan_sha256,
        "worker_id": claim.worker_id,
        "target_node_id": claim.target_node_id,
        "recovery_sha256": claim.recovery_sha256,
        "recovery_strategy": claim.recovery_strategy,
        "expected_active_state": claim.expected_active_state,
        "started": observation.started,
        "timed_out": observation.timed_out,
        "exit_code": observation.exit_code,
        "elapsed_ms": observation.elapsed_ms,
        "rollback_succeeded": rollback_succeeded,
        "recovery_required": not rollback_succeeded,
        "verification_required": rollback_succeeded,
        "from_state": OperationJobState.ROLLING_BACK.value,
        "next_state": next_state.value,
        "from_state_version": claim.to_state_version,
        "to_state_version": claim.to_state_version + 1,
    }
    digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return OperationRollbackExecutionReceipt(
        receipt_id=f"oprollbackexec-{digest[:24]}",
        rollback_claim_id=claim.claim_id,
        verification_receipt_id=claim.verification_receipt_id,
        execution_receipt_id=claim.execution_receipt_id,
        job_id=claim.job_id,
        action_id=claim.action_id,
        plan_id=claim.plan_id,
        plan_sha256=claim.plan_sha256,
        worker_id=claim.worker_id,
        target_node_id=claim.target_node_id,
        recovery_sha256=claim.recovery_sha256,
        recovery_strategy=claim.recovery_strategy,
        expected_active_state=claim.expected_active_state,
        started=observation.started,
        timed_out=observation.timed_out,
        exit_code=observation.exit_code,
        elapsed_ms=observation.elapsed_ms,
        rollback_succeeded=rollback_succeeded,
        recovery_required=not rollback_succeeded,
        next_state=next_state.value,
        from_state_version=claim.to_state_version,
        to_state_version=claim.to_state_version + 1,
        verification_required=rollback_succeeded,
        audit_event_id=audit_event_id,
    )


def _without_audit(receipt: OperationRollbackExecutionReceipt) -> dict[str, Any]:
    value = receipt.to_dict()
    value["audit_event_id"] = None
    return value


def _revalidate_persisted_receipt(
    store: OperationRollbackExecutionReceiptStore,
    receipt: OperationRollbackExecutionReceipt,
    claim: OperationRollbackClaim,
) -> None:
    if (
        receipt.rollback_claim_id != claim.claim_id
        or receipt.verification_receipt_id != claim.verification_receipt_id
        or receipt.execution_receipt_id != claim.execution_receipt_id
        or receipt.job_id != claim.job_id
        or receipt.action_id != claim.action_id
        or receipt.plan_id != claim.plan_id
        or receipt.plan_sha256 != claim.plan_sha256
        or receipt.worker_id != claim.worker_id
        or receipt.target_node_id != claim.target_node_id
        or receipt.recovery_sha256 != claim.recovery_sha256
        or receipt.recovery_strategy != claim.recovery_strategy
        or receipt.expected_active_state != claim.expected_active_state
        or receipt.from_state_version != claim.to_state_version
        or receipt.to_state_version != claim.to_state_version + 1
    ):
        raise OperationRollbackExecutionReceiptError(
            "operation_rollback_execution_lineage_mismatch"
        )
    _validate_claim_worker(
        claim,
        OperationWorkerIdentity(claim.worker_id, claim.target_node_id),
    )
    job_row = store._operation_job_row(claim.job_id)
    if job_row is None:
        raise OperationRollbackExecutionReceiptError("operation_job_not_found")
    job = store._decode_operation_job(job_row)
    _validate_rolling_back_job(job, claim, receipt=receipt)


def _decode_receipt(row: sqlite3.Row) -> OperationRollbackExecutionReceipt:
    value = json.loads(row["receipt_json"])
    actual_sha256 = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    if actual_sha256 != row["receipt_sha256"]:
        raise OperationRollbackExecutionReceiptError(
            "operation_rollback_execution_receipt_integrity_mismatch"
        )
    receipt = OperationRollbackExecutionReceipt(
        receipt_id=value["receipt_id"],
        rollback_claim_id=value["rollback_claim_id"],
        verification_receipt_id=value["verification_receipt_id"],
        execution_receipt_id=value["execution_receipt_id"],
        job_id=value["job_id"],
        action_id=value["action_id"],
        plan_id=value["plan_id"],
        plan_sha256=value["plan_sha256"],
        worker_id=value["worker_id"],
        target_node_id=value["target_node_id"],
        recovery_sha256=value["recovery_sha256"],
        recovery_strategy=value["recovery_strategy"],
        expected_active_state=value["expected_active_state"],
        started=value["started"],
        timed_out=value["timed_out"],
        exit_code=value["exit_code"],
        elapsed_ms=value["elapsed_ms"],
        rollback_succeeded=value["rollback_succeeded"],
        recovery_required=value["recovery_required"],
        next_state=value["next_state"],
        from_state_version=value["from_state_version"],
        to_state_version=value["to_state_version"],
        verification_required=value["verification_required"],
        audit_event_id=value["audit_event_id"],
    )
    if receipt.to_dict() != value:
        raise OperationRollbackExecutionReceiptError(
            "operation_rollback_execution_receipt_shape_mismatch"
        )
    if (
        row["receipt_id"] != receipt.receipt_id
        or row["rollback_claim_id"] != receipt.rollback_claim_id
        or row["verification_receipt_id"] != receipt.verification_receipt_id
        or row["execution_receipt_id"] != receipt.execution_receipt_id
        or row["job_id"] != receipt.job_id
        or row["worker_id"] != receipt.worker_id
        or row["plan_id"] != receipt.plan_id
        or row["from_state_version"] != receipt.from_state_version
        or row["to_state_version"] != receipt.to_state_version
        or row["next_state"] != receipt.next_state
        or row["recovery_sha256"] != receipt.recovery_sha256
        or row["audit_event_id"] != receipt.audit_event_id
    ):
        raise OperationRollbackExecutionReceiptError(
            "operation_rollback_execution_receipt_identity_mismatch"
        )
    return receipt
