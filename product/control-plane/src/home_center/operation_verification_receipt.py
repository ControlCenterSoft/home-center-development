"""Replay-safe verification receipts for bounded Home Center operations."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_commands import (
    ACTION_ID,
    STATE_VALUE,
    SYSTEMCTL,
    OperationJobState,
    validate_job_transition,
)
from .operation_execution_receipt import (
    OperationExecutionReceipt,
    OperationExecutionReceiptError,
    _decode_receipt,
)
from .operation_worker_handoff import OperationWorkerIdentity
from .util import canonical_json, utc_now


SCHEMA = "home-center.operation-verification-receipt.v1"
EXECUTION_RECEIPT_ID = re.compile(r"^opreceipt-[a-f0-9]{24}$")
VERIFICATION_RECEIPT_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation_verification_receipts (
    receipt_id TEXT PRIMARY KEY,
    execution_receipt_id TEXT NOT NULL UNIQUE
        REFERENCES operation_execution_receipts(receipt_id) ON DELETE CASCADE,
    job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    from_state_version INTEGER NOT NULL CHECK(from_state_version >= 3),
    to_state_version INTEGER NOT NULL CHECK(to_state_version > from_state_version),
    next_state TEXT NOT NULL CHECK(next_state IN ('succeeded','rolling_back')),
    verification_sha256 TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    audit_event_id TEXT NOT NULL REFERENCES audit(event_id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operation_verification_receipt_job
    ON operation_verification_receipts(job_id, worker_id, to_state_version);
"""


class OperationVerificationReceiptError(RuntimeError):
    """Verification evidence could not be recorded without weakening operation safety."""


class OperationVerificationReceiptStore(Protocol):
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
class OperationVerificationObservation:
    """Sanitized systemd state observation with no raw command output or caller argv."""

    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int
    load_state: str | None = None
    active_state: str | None = None
    sub_state: str | None = None
    unit_file_state: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.started, bool) or not isinstance(self.timed_out, bool):
            raise OperationVerificationReceiptError("invalid_verification_flags")
        if (
            not isinstance(self.elapsed_ms, int)
            or isinstance(self.elapsed_ms, bool)
            or not 0 <= self.elapsed_ms <= 5_000
        ):
            raise OperationVerificationReceiptError("invalid_verification_elapsed_ms")
        if self.exit_code is not None and (
            not isinstance(self.exit_code, int)
            or isinstance(self.exit_code, bool)
            or not -255 <= self.exit_code <= 255
        ):
            raise OperationVerificationReceiptError("invalid_verification_exit_code")

        states = (
            self.load_state,
            self.active_state,
            self.sub_state,
            self.unit_file_state,
        )
        if not self.started:
            if self.timed_out or self.exit_code is not None or self.elapsed_ms != 0:
                raise OperationVerificationReceiptError("invalid_not_started_verification")
            if any(value is not None for value in states):
                raise OperationVerificationReceiptError("state_without_verification_execution")
            return
        if self.timed_out:
            if self.exit_code is not None or any(value is not None for value in states):
                raise OperationVerificationReceiptError("invalid_timeout_verification")
            return
        if self.exit_code is None:
            raise OperationVerificationReceiptError("missing_verification_exit_code")
        if self.exit_code != 0:
            if any(value is not None for value in states):
                raise OperationVerificationReceiptError("state_from_failed_verification")
            return
        for value in states:
            if not isinstance(value, str) or not STATE_VALUE.fullmatch(value):
                raise OperationVerificationReceiptError("invalid_verified_service_state")


@dataclass(frozen=True, slots=True)
class OperationVerificationReceipt:
    receipt_id: str
    execution_receipt_id: str
    job_id: str
    action_id: str
    plan_id: str
    plan_sha256: str
    worker_id: str
    target_node_id: str
    verification_sha256: str
    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int
    load_state: str | None
    active_state: str | None
    sub_state: str | None
    unit_file_state: str | None
    verified: bool
    next_state: str
    from_state_version: int
    to_state_version: int
    audit_event_id: str | None = None
    schema: str = field(default=SCHEMA, init=False)
    from_state: str = field(default="verifying", init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    grants_execution_authority: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "execution_receipt_id": self.execution_receipt_id,
            "job_id": self.job_id,
            "action_id": self.action_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "worker_id": self.worker_id,
            "target_node_id": self.target_node_id,
            "verification_sha256": self.verification_sha256,
            "started": self.started,
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
            "elapsed_ms": self.elapsed_ms,
            "load_state": self.load_state,
            "active_state": self.active_state,
            "sub_state": self.sub_state,
            "unit_file_state": self.unit_file_state,
            "verified": self.verified,
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


class OperationVerificationReceiptCoordinator:
    """Commit one bounded verification observation against an exact execution receipt."""

    def __init__(self, store: OperationVerificationReceiptStore) -> None:
        self._store = store
        for name in (
            "_lock",
            "_connection",
            "_operation_job_row",
            "_decode_operation_job",
            "_append_operation_audit_locked",
        ):
            if not hasattr(store, name):
                raise TypeError("store does not provide operation verification receipt primitives")
        with store._lock, store._connection:
            store._connection.executescript(VERIFICATION_RECEIPT_SCHEMA)

    def record(
        self,
        execution_receipt_id: str,
        *,
        worker: OperationWorkerIdentity,
        observation: OperationVerificationObservation,
    ) -> tuple[OperationVerificationReceipt, bool]:
        if not isinstance(execution_receipt_id, str) or not EXECUTION_RECEIPT_ID.fullmatch(
            execution_receipt_id
        ):
            raise OperationVerificationReceiptError("invalid_operation_execution_receipt_id")
        if not isinstance(worker, OperationWorkerIdentity):
            raise TypeError("worker must be OperationWorkerIdentity")
        if not isinstance(observation, OperationVerificationObservation):
            raise TypeError("observation must be OperationVerificationObservation")

        store = self._store
        with store._lock:
            store._connection.execute("BEGIN IMMEDIATE")
            try:
                execution_row = store._connection.execute(
                    "SELECT * FROM operation_execution_receipts WHERE receipt_id=?",
                    (execution_receipt_id,),
                ).fetchone()
                if execution_row is None:
                    raise OperationVerificationReceiptError("operation_execution_receipt_not_found")
                execution_receipt = _decode_receipt(execution_row)
                _validate_execution_receipt(execution_receipt, worker)

                replay = store._connection.execute(
                    "SELECT * FROM operation_verification_receipts WHERE execution_receipt_id=?",
                    (execution_receipt_id,),
                ).fetchone()
                if replay is not None:
                    receipt = _decode_verification_receipt(replay)
                    provisional = _build_receipt(
                        execution_receipt,
                        verification_sha256=receipt.verification_sha256,
                        observation=observation,
                        audit_event_id=None,
                    )
                    if _without_audit(receipt) != _without_audit(provisional):
                        raise OperationVerificationReceiptError(
                            "operation_verification_receipt_conflict"
                        )
                    store._connection.commit()
                    return receipt, False

                job_row = store._operation_job_row(execution_receipt.job_id)
                if job_row is None:
                    raise OperationVerificationReceiptError("operation_job_not_found")
                job = store._decode_operation_job(job_row)
                verification_sha256 = _validate_verifying_job(job, execution_receipt, worker)
                provisional = _build_receipt(
                    execution_receipt,
                    verification_sha256=verification_sha256,
                    observation=observation,
                    audit_event_id=None,
                )
                next_state = OperationJobState(provisional.next_state)
                validate_job_transition(
                    OperationJobState.VERIFYING,
                    next_state,
                    mutation_may_have_occurred=True,
                )
                audit_event_id = store._append_operation_audit_locked(
                    actor=worker.worker_id,
                    action="operation.verification.receipt",
                    target=f"{execution_receipt.target_node_id}:{job['service']}",
                    outcome=provisional.next_state,
                    correlation_id=job["correlation_id"],
                    details={
                        "receipt_id": provisional.receipt_id,
                        "execution_receipt_id": execution_receipt.receipt_id,
                        "job_id": execution_receipt.job_id,
                        "worker_id": worker.worker_id,
                        "plan_id": execution_receipt.plan_id,
                        "plan_sha256": execution_receipt.plan_sha256,
                        "verification_sha256": verification_sha256,
                        "from_state": OperationJobState.VERIFYING.value,
                        "to_state": provisional.next_state,
                        "from_state_version": provisional.from_state_version,
                        "to_state_version": provisional.to_state_version,
                        "started": observation.started,
                        "timed_out": observation.timed_out,
                        "exit_code": observation.exit_code,
                        "elapsed_ms": observation.elapsed_ms,
                        "verified": provisional.verified,
                    },
                )
                receipt = _build_receipt(
                    execution_receipt,
                    verification_sha256=verification_sha256,
                    observation=observation,
                    audit_event_id=audit_event_id,
                )
                receipt_json = canonical_json(receipt.to_dict())
                receipt_sha256 = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
                existing_evidence = job.get("evidence")
                if not isinstance(existing_evidence, dict):
                    raise OperationVerificationReceiptError("operation_execution_evidence_missing")
                evidence = dict(existing_evidence)
                evidence["verification_receipt"] = receipt.to_dict()
                result = {
                    "execution": job.get("result", {}).get("execution")
                    if isinstance(job.get("result"), dict)
                    else None,
                    "verification": {
                        "receipt_id": receipt.receipt_id,
                        "started": receipt.started,
                        "timed_out": receipt.timed_out,
                        "exit_code": receipt.exit_code,
                        "elapsed_ms": receipt.elapsed_ms,
                        "load_state": receipt.load_state,
                        "active_state": receipt.active_state,
                        "sub_state": receipt.sub_state,
                        "unit_file_state": receipt.unit_file_state,
                        "verified": receipt.verified,
                    },
                }

                cursor = store._connection.execute(
                    """UPDATE jobs SET state=?,result_json=?,evidence_json=?,updated_at=?
                    WHERE job_id=? AND state=?""",
                    (
                        receipt.next_state,
                        canonical_json(result),
                        canonical_json(evidence),
                        utc_now(),
                        receipt.job_id,
                        OperationJobState.VERIFYING.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationVerificationReceiptError("operation_verification_receipt_stale")
                cursor = store._connection.execute(
                    """UPDATE operation_job_metadata
                    SET state_version=?,last_audit_event_id=?
                    WHERE job_id=? AND state_version=?
                    AND mutation_may_have_occurred=1 AND recovery_required=0""",
                    (
                        receipt.to_state_version,
                        audit_event_id,
                        receipt.job_id,
                        receipt.from_state_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationVerificationReceiptError("operation_verification_receipt_stale")
                store._connection.execute(
                    """INSERT INTO operation_verification_receipts(
                    receipt_id,execution_receipt_id,job_id,worker_id,plan_id,
                    from_state_version,to_state_version,next_state,verification_sha256,
                    receipt_sha256,receipt_json,audit_event_id,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        receipt.receipt_id,
                        receipt.execution_receipt_id,
                        receipt.job_id,
                        receipt.worker_id,
                        receipt.plan_id,
                        receipt.from_state_version,
                        receipt.to_state_version,
                        receipt.next_state,
                        receipt.verification_sha256,
                        receipt_sha256,
                        receipt_json,
                        audit_event_id,
                        utc_now(),
                    ),
                )
                store._connection.commit()
                return receipt, True
            except (OperationExecutionReceiptError, sqlite3.IntegrityError, ValueError) as exc:
                store._connection.rollback()
                raise OperationVerificationReceiptError(
                    "operation_verification_receipt_rejected"
                ) from exc
            except Exception:
                store._connection.rollback()
                raise


def _validate_execution_receipt(
    receipt: OperationExecutionReceipt,
    worker: OperationWorkerIdentity,
) -> None:
    value = receipt.to_dict()
    if worker.worker_id != receipt.worker_id or worker.node_id != receipt.target_node_id:
        raise OperationVerificationReceiptError("operation_worker_identity_mismatch")
    if receipt.action_id != ACTION_ID:
        raise OperationVerificationReceiptError("unsupported_operation_action")
    if (
        not receipt.started
        or receipt.timed_out
        or receipt.exit_code != 0
        or not receipt.mutation_may_have_occurred
        or receipt.next_state != OperationJobState.VERIFYING.value
    ):
        raise OperationVerificationReceiptError("execution_receipt_not_verifiable")
    if (
        value.get("contains_command_material") is not False
        or value.get("accepts_caller_argv") is not False
        or value.get("accepts_shell") is not False
        or value.get("grants_execution_authority") is not False
        or value.get("production_mutation_enabled") is not False
    ):
        raise OperationVerificationReceiptError("unsafe_operation_execution_receipt")


def _validate_verifying_job(
    job: dict[str, Any],
    execution_receipt: OperationExecutionReceipt,
    worker: OperationWorkerIdentity,
) -> str:
    if job.get("state") != OperationJobState.VERIFYING.value:
        raise OperationVerificationReceiptError("operation_job_not_verifying")
    if job.get("state_version") != execution_receipt.to_state_version:
        raise OperationVerificationReceiptError("operation_job_state_stale")
    if job.get("mutation_may_have_occurred") is not True:
        raise OperationVerificationReceiptError("operation_job_mutation_evidence_missing")
    if job.get("recovery_required") is not False:
        raise OperationVerificationReceiptError("operation_job_recovery_required")
    for name in ("job_id", "action_id", "plan_id", "plan_sha256", "target_node_id"):
        if job.get(name) != getattr(execution_receipt, name):
            raise OperationVerificationReceiptError(f"operation_job_{name}_mismatch")
    if (
        worker.worker_id != execution_receipt.worker_id
        or worker.node_id != execution_receipt.target_node_id
    ):
        raise OperationVerificationReceiptError("operation_worker_identity_mismatch")

    evidence = job.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != {"worker_claim", "execution_receipt"}:
        raise OperationVerificationReceiptError("operation_execution_evidence_mismatch")
    if evidence.get("execution_receipt") != execution_receipt.to_dict():
        raise OperationVerificationReceiptError("operation_execution_receipt_evidence_mismatch")
    worker_claim = evidence.get("worker_claim")
    if not isinstance(worker_claim, dict):
        raise OperationVerificationReceiptError("operation_worker_claim_evidence_missing")
    expected_claim_values = {
        "claim_id": execution_receipt.claim_id,
        "job_id": execution_receipt.job_id,
        "action_id": execution_receipt.action_id,
        "plan_id": execution_receipt.plan_id,
        "plan_sha256": execution_receipt.plan_sha256,
        "worker_id": execution_receipt.worker_id,
        "target_node_id": execution_receipt.target_node_id,
        "to_state_version": execution_receipt.from_state_version,
    }
    if any(worker_claim.get(name) != value for name, value in expected_claim_values.items()):
        raise OperationVerificationReceiptError("operation_worker_claim_evidence_mismatch")
    for name in (
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "execution_authorized",
        "production_mutation_enabled",
    ):
        if worker_claim.get(name) is not False:
            raise OperationVerificationReceiptError("unsafe_operation_worker_claim_evidence")

    plan = job.get("plan")
    if not isinstance(plan, dict):
        raise OperationVerificationReceiptError("operation_plan_missing")
    if (
        plan.get("action_id") != ACTION_ID
        or plan.get("service") != job.get("service")
        or plan.get("target_node_id") != execution_receipt.target_node_id
        or plan.get("execution_authorized") is not False
        or plan.get("production_mutation_enabled") is not False
        or plan.get("accepts_caller_argv") is not False
        or plan.get("accepts_shell") is not False
    ):
        raise OperationVerificationReceiptError("unsafe_operation_plan")
    expected_verification = {
        "argv": [
            SYSTEMCTL,
            "show",
            job["service"],
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
            "--no-pager",
        ],
        "timeout_seconds": 5,
        "required_active_state": "active",
    }
    if plan.get("verification") != expected_verification:
        raise OperationVerificationReceiptError("operation_verification_contract_mismatch")
    return hashlib.sha256(canonical_json(expected_verification).encode("utf-8")).hexdigest()


def _build_receipt(
    execution_receipt: OperationExecutionReceipt,
    *,
    verification_sha256: str,
    observation: OperationVerificationObservation,
    audit_event_id: str | None,
) -> OperationVerificationReceipt:
    verified = (
        observation.started
        and not observation.timed_out
        and observation.exit_code == 0
        and observation.load_state == "loaded"
        and observation.active_state == "active"
    )
    next_state = OperationJobState.SUCCEEDED if verified else OperationJobState.ROLLING_BACK
    identity = {
        "execution_receipt_id": execution_receipt.receipt_id,
        "job_id": execution_receipt.job_id,
        "action_id": execution_receipt.action_id,
        "plan_id": execution_receipt.plan_id,
        "plan_sha256": execution_receipt.plan_sha256,
        "worker_id": execution_receipt.worker_id,
        "target_node_id": execution_receipt.target_node_id,
        "verification_sha256": verification_sha256,
        "started": observation.started,
        "timed_out": observation.timed_out,
        "exit_code": observation.exit_code,
        "elapsed_ms": observation.elapsed_ms,
        "load_state": observation.load_state,
        "active_state": observation.active_state,
        "sub_state": observation.sub_state,
        "unit_file_state": observation.unit_file_state,
        "verified": verified,
        "from_state": OperationJobState.VERIFYING.value,
        "next_state": next_state.value,
        "from_state_version": execution_receipt.to_state_version,
        "to_state_version": execution_receipt.to_state_version + 1,
    }
    digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return OperationVerificationReceipt(
        receipt_id=f"opverify-{digest[:24]}",
        execution_receipt_id=execution_receipt.receipt_id,
        job_id=execution_receipt.job_id,
        action_id=execution_receipt.action_id,
        plan_id=execution_receipt.plan_id,
        plan_sha256=execution_receipt.plan_sha256,
        worker_id=execution_receipt.worker_id,
        target_node_id=execution_receipt.target_node_id,
        verification_sha256=verification_sha256,
        started=observation.started,
        timed_out=observation.timed_out,
        exit_code=observation.exit_code,
        elapsed_ms=observation.elapsed_ms,
        load_state=observation.load_state,
        active_state=observation.active_state,
        sub_state=observation.sub_state,
        unit_file_state=observation.unit_file_state,
        verified=verified,
        next_state=next_state.value,
        from_state_version=execution_receipt.to_state_version,
        to_state_version=execution_receipt.to_state_version + 1,
        audit_event_id=audit_event_id,
    )


def _without_audit(receipt: OperationVerificationReceipt) -> dict[str, Any]:
    value = receipt.to_dict()
    value["audit_event_id"] = None
    return value


def _decode_verification_receipt(row: sqlite3.Row) -> OperationVerificationReceipt:
    value = json.loads(row["receipt_json"])
    actual_sha256 = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    if actual_sha256 != row["receipt_sha256"]:
        raise OperationVerificationReceiptError("operation_verification_receipt_integrity_mismatch")
    receipt = OperationVerificationReceipt(
        receipt_id=value["receipt_id"],
        execution_receipt_id=value["execution_receipt_id"],
        job_id=value["job_id"],
        action_id=value["action_id"],
        plan_id=value["plan_id"],
        plan_sha256=value["plan_sha256"],
        worker_id=value["worker_id"],
        target_node_id=value["target_node_id"],
        verification_sha256=value["verification_sha256"],
        started=value["started"],
        timed_out=value["timed_out"],
        exit_code=value["exit_code"],
        elapsed_ms=value["elapsed_ms"],
        load_state=value["load_state"],
        active_state=value["active_state"],
        sub_state=value["sub_state"],
        unit_file_state=value["unit_file_state"],
        verified=value["verified"],
        next_state=value["next_state"],
        from_state_version=value["from_state_version"],
        to_state_version=value["to_state_version"],
        audit_event_id=value["audit_event_id"],
    )
    if receipt.to_dict() != value:
        raise OperationVerificationReceiptError("operation_verification_receipt_shape_mismatch")
    if (
        row["receipt_id"] != receipt.receipt_id
        or row["execution_receipt_id"] != receipt.execution_receipt_id
        or row["job_id"] != receipt.job_id
        or row["worker_id"] != receipt.worker_id
        or row["plan_id"] != receipt.plan_id
        or row["from_state_version"] != receipt.from_state_version
        or row["to_state_version"] != receipt.to_state_version
        or row["next_state"] != receipt.next_state
        or row["verification_sha256"] != receipt.verification_sha256
        or row["audit_event_id"] != receipt.audit_event_id
    ):
        raise OperationVerificationReceiptError("operation_verification_receipt_identity_mismatch")
    return receipt
