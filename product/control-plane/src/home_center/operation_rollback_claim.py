"""Replay-safe rollback claims for bounded Home Center operations."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_commands import ACTION_ID, ALLOWED_SERVICES, SYSTEMCTL, OperationJobState
from .operation_verification_receipt import (
    OperationVerificationReceipt,
    OperationVerificationReceiptError,
    _decode_verification_receipt,
)
from .operation_worker_handoff import OperationWorkerIdentity
from .util import canonical_json, utc_now


SCHEMA = "home-center.operation-rollback-claim.v1"
VERIFICATION_RECEIPT_ID = re.compile(r"^opverify-[a-f0-9]{24}$")
ROLLBACK_CLAIM_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation_rollback_claims (
    claim_id TEXT PRIMARY KEY,
    verification_receipt_id TEXT NOT NULL UNIQUE
        REFERENCES operation_verification_receipts(receipt_id) ON DELETE CASCADE,
    execution_receipt_id TEXT NOT NULL UNIQUE,
    job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    from_state_version INTEGER NOT NULL CHECK(from_state_version >= 4),
    to_state_version INTEGER NOT NULL CHECK(to_state_version > from_state_version),
    recovery_sha256 TEXT NOT NULL,
    expected_active_state TEXT NOT NULL CHECK(expected_active_state IN ('active','inactive')),
    claim_sha256 TEXT NOT NULL,
    claim_json TEXT NOT NULL,
    audit_event_id TEXT NOT NULL REFERENCES audit(event_id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operation_rollback_claim_job
    ON operation_rollback_claims(job_id, worker_id, to_state_version);
"""


class OperationRollbackClaimError(RuntimeError):
    """Rollback work could not be claimed without weakening operation safety."""


class OperationRollbackClaimStore(Protocol):
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
class OperationRollbackClaim:
    claim_id: str
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
    from_state_version: int
    to_state_version: int
    audit_event_id: str | None = None
    schema: str = field(default=SCHEMA, init=False)
    state: str = field(default="rolling_back", init=False)
    verification_required: bool = field(default=True, init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "claim_id": self.claim_id,
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
            "state": self.state,
            "from_state_version": self.from_state_version,
            "to_state_version": self.to_state_version,
            "audit_event_id": self.audit_event_id,
            "verification_required": True,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }


class OperationRollbackClaimCoordinator:
    """Atomically claim one exact rollback without exposing recovery argv or authority."""

    def __init__(self, store: OperationRollbackClaimStore) -> None:
        self._store = store
        for name in (
            "_lock",
            "_connection",
            "_operation_job_row",
            "_decode_operation_job",
            "_append_operation_audit_locked",
        ):
            if not hasattr(store, name):
                raise TypeError("store does not provide operation rollback claim primitives")
        with store._lock, store._connection:
            store._connection.executescript(ROLLBACK_CLAIM_SCHEMA)

    def claim(
        self,
        verification_receipt_id: str,
        *,
        worker: OperationWorkerIdentity,
    ) -> tuple[OperationRollbackClaim, bool]:
        if (
            not isinstance(verification_receipt_id, str)
            or not VERIFICATION_RECEIPT_ID.fullmatch(verification_receipt_id)
        ):
            raise OperationRollbackClaimError("invalid_operation_verification_receipt_id")
        if not isinstance(worker, OperationWorkerIdentity):
            raise TypeError("worker must be OperationWorkerIdentity")

        store = self._store
        with store._lock:
            store._connection.execute("BEGIN IMMEDIATE")
            try:
                verification_row = store._connection.execute(
                    "SELECT * FROM operation_verification_receipts WHERE receipt_id=?",
                    (verification_receipt_id,),
                ).fetchone()
                if verification_row is None:
                    raise OperationRollbackClaimError("operation_verification_receipt_not_found")
                verification_receipt = _decode_verification_receipt(verification_row)
                _validate_verification_receipt(verification_receipt, worker)

                replay = store._connection.execute(
                    "SELECT * FROM operation_rollback_claims WHERE verification_receipt_id=?",
                    (verification_receipt_id,),
                ).fetchone()
                if replay is not None:
                    claim = _decode_claim(replay)
                    _revalidate_persisted_claim(store, claim, verification_receipt)
                    store._connection.commit()
                    return claim, False

                job_row = store._operation_job_row(verification_receipt.job_id)
                if job_row is None:
                    raise OperationRollbackClaimError("operation_job_not_found")
                job = store._decode_operation_job(job_row)
                recovery_sha256, expected_active_state = _validate_rolling_back_job(
                    job,
                    verification_receipt,
                    worker,
                )
                provisional = _build_claim(
                    verification_receipt,
                    recovery_sha256=recovery_sha256,
                    expected_active_state=expected_active_state,
                    audit_event_id=None,
                )
                audit_event_id = store._append_operation_audit_locked(
                    actor=worker.worker_id,
                    action="operation.rollback.claim",
                    target=f"{verification_receipt.target_node_id}:{job['service']}",
                    outcome=OperationJobState.ROLLING_BACK.value,
                    correlation_id=job["correlation_id"],
                    details={
                        "claim_id": provisional.claim_id,
                        "verification_receipt_id": verification_receipt.receipt_id,
                        "execution_receipt_id": verification_receipt.execution_receipt_id,
                        "job_id": verification_receipt.job_id,
                        "worker_id": worker.worker_id,
                        "target_node_id": worker.node_id,
                        "plan_id": verification_receipt.plan_id,
                        "plan_sha256": verification_receipt.plan_sha256,
                        "recovery_sha256": recovery_sha256,
                        "expected_active_state": expected_active_state,
                        "state": OperationJobState.ROLLING_BACK.value,
                        "from_state_version": provisional.from_state_version,
                        "to_state_version": provisional.to_state_version,
                    },
                )
                claim = _build_claim(
                    verification_receipt,
                    recovery_sha256=recovery_sha256,
                    expected_active_state=expected_active_state,
                    audit_event_id=audit_event_id,
                )
                claim_json = canonical_json(claim.to_dict())
                claim_sha256 = hashlib.sha256(claim_json.encode("utf-8")).hexdigest()

                existing_evidence = job.get("evidence")
                if not isinstance(existing_evidence, dict):
                    raise OperationRollbackClaimError("operation_verification_evidence_missing")
                evidence = dict(existing_evidence)
                evidence["rollback_claim"] = claim.to_dict()

                cursor = store._connection.execute(
                    """UPDATE jobs SET evidence_json=?,updated_at=?
                    WHERE job_id=? AND state=?""",
                    (
                        canonical_json(evidence),
                        utc_now(),
                        claim.job_id,
                        OperationJobState.ROLLING_BACK.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationRollbackClaimError("operation_rollback_claim_stale")
                cursor = store._connection.execute(
                    """UPDATE operation_job_metadata
                    SET state_version=?,last_audit_event_id=?
                    WHERE job_id=? AND state_version=?
                    AND mutation_may_have_occurred=1 AND recovery_required=0""",
                    (
                        claim.to_state_version,
                        audit_event_id,
                        claim.job_id,
                        claim.from_state_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationRollbackClaimError("operation_rollback_claim_stale")
                store._connection.execute(
                    """INSERT INTO operation_rollback_claims(
                    claim_id,verification_receipt_id,execution_receipt_id,job_id,worker_id,
                    target_node_id,plan_id,from_state_version,to_state_version,recovery_sha256,
                    expected_active_state,claim_sha256,claim_json,audit_event_id,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        claim.claim_id,
                        claim.verification_receipt_id,
                        claim.execution_receipt_id,
                        claim.job_id,
                        claim.worker_id,
                        claim.target_node_id,
                        claim.plan_id,
                        claim.from_state_version,
                        claim.to_state_version,
                        claim.recovery_sha256,
                        claim.expected_active_state,
                        claim_sha256,
                        claim_json,
                        audit_event_id,
                        utc_now(),
                    ),
                )
                store._connection.commit()
                return claim, True
            except (
                OperationVerificationReceiptError,
                sqlite3.IntegrityError,
                ValueError,
            ) as exc:
                store._connection.rollback()
                raise OperationRollbackClaimError("operation_rollback_claim_rejected") from exc
            except Exception:
                store._connection.rollback()
                raise


def revalidate_operation_rollback_claim(
    store: OperationRollbackClaimStore,
    claim: OperationRollbackClaim,
) -> None:
    """Fail closed before a later rollback executor consumes claim evidence."""

    if not isinstance(claim, OperationRollbackClaim):
        raise TypeError("claim must be OperationRollbackClaim")
    with store._lock:
        row = store._connection.execute(
            "SELECT * FROM operation_rollback_claims WHERE claim_id=?",
            (claim.claim_id,),
        ).fetchone()
        if row is None:
            raise OperationRollbackClaimError("operation_rollback_claim_not_found")
        persisted = _decode_claim(row)
        if persisted != claim:
            raise OperationRollbackClaimError("operation_rollback_claim_stale")
        verification_row = store._connection.execute(
            "SELECT * FROM operation_verification_receipts WHERE receipt_id=?",
            (claim.verification_receipt_id,),
        ).fetchone()
        if verification_row is None:
            raise OperationRollbackClaimError("operation_verification_receipt_not_found")
        verification_receipt = _decode_verification_receipt(verification_row)
        _revalidate_persisted_claim(store, claim, verification_receipt)


def _validate_verification_receipt(
    receipt: OperationVerificationReceipt,
    worker: OperationWorkerIdentity,
) -> None:
    value = receipt.to_dict()
    if worker.worker_id != receipt.worker_id or worker.node_id != receipt.target_node_id:
        raise OperationRollbackClaimError("operation_worker_identity_mismatch")
    if receipt.action_id != ACTION_ID:
        raise OperationRollbackClaimError("unsupported_operation_action")
    if receipt.verified or receipt.next_state != OperationJobState.ROLLING_BACK.value:
        raise OperationRollbackClaimError("verification_receipt_not_rollback_required")
    if (
        value.get("contains_command_material") is not False
        or value.get("accepts_caller_argv") is not False
        or value.get("accepts_shell") is not False
        or value.get("grants_execution_authority") is not False
        or value.get("production_mutation_enabled") is not False
    ):
        raise OperationRollbackClaimError("unsafe_operation_verification_receipt")


def _validate_rolling_back_job(
    job: dict[str, Any],
    receipt: OperationVerificationReceipt,
    worker: OperationWorkerIdentity,
    *,
    expected_state_version: int | None = None,
    rollback_claim: OperationRollbackClaim | None = None,
) -> tuple[str, str]:
    if job.get("state") != OperationJobState.ROLLING_BACK.value:
        raise OperationRollbackClaimError("operation_job_not_rolling_back")
    if expected_state_version is None:
        expected_state_version = receipt.to_state_version
    if job.get("state_version") != expected_state_version:
        raise OperationRollbackClaimError("operation_job_state_stale")
    if job.get("mutation_may_have_occurred") is not True:
        raise OperationRollbackClaimError("operation_job_mutation_evidence_missing")
    if job.get("recovery_required") is not False:
        raise OperationRollbackClaimError("operation_job_recovery_already_failed")
    for name in ("job_id", "action_id", "plan_id", "plan_sha256", "target_node_id"):
        if job.get(name) != getattr(receipt, name):
            raise OperationRollbackClaimError(f"operation_job_{name}_mismatch")
    if worker.worker_id != receipt.worker_id or worker.node_id != receipt.target_node_id:
        raise OperationRollbackClaimError("operation_worker_identity_mismatch")

    evidence = job.get("evidence")
    expected_evidence = {
        "worker_claim",
        "execution_receipt",
        "verification_receipt",
    }
    if rollback_claim is not None:
        expected_evidence.add("rollback_claim")
    if not isinstance(evidence, dict) or set(evidence) != expected_evidence:
        raise OperationRollbackClaimError("operation_verification_evidence_mismatch")
    if rollback_claim is not None and evidence.get("rollback_claim") != rollback_claim.to_dict():
        raise OperationRollbackClaimError("operation_rollback_claim_evidence_mismatch")
    if evidence.get("verification_receipt") != receipt.to_dict():
        raise OperationRollbackClaimError("operation_verification_receipt_evidence_mismatch")
    for name in ("worker_claim", "execution_receipt"):
        value = evidence.get(name)
        if not isinstance(value, dict):
            raise OperationRollbackClaimError(f"operation_{name}_evidence_missing")
        if value.get("job_id") != receipt.job_id:
            raise OperationRollbackClaimError(f"operation_{name}_job_mismatch")
        if value.get("plan_id") != receipt.plan_id:
            raise OperationRollbackClaimError(f"operation_{name}_plan_mismatch")
        if value.get("plan_sha256") != receipt.plan_sha256:
            raise OperationRollbackClaimError(f"operation_{name}_plan_integrity_mismatch")
        if value.get("worker_id") != receipt.worker_id:
            raise OperationRollbackClaimError(f"operation_{name}_worker_mismatch")
        if value.get("target_node_id") != receipt.target_node_id:
            raise OperationRollbackClaimError(f"operation_{name}_target_mismatch")
        for flag in (
            "contains_command_material",
            "accepts_caller_argv",
            "accepts_shell",
            "production_mutation_enabled",
        ):
            if value.get(flag) is not False:
                raise OperationRollbackClaimError(f"unsafe_operation_{name}_evidence")
        authority_flag = (
            "execution_authorized"
            if name == "worker_claim"
            else "grants_execution_authority"
        )
        if value.get(authority_flag) is not False:
            raise OperationRollbackClaimError(f"unsafe_operation_{name}_evidence")

    plan = job.get("plan")
    if not isinstance(plan, dict):
        raise OperationRollbackClaimError("operation_plan_missing")
    plan_sha256 = hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()
    if plan_sha256 != receipt.plan_sha256:
        raise OperationRollbackClaimError("operation_plan_integrity_mismatch")
    if (
        plan.get("action_id") != ACTION_ID
        or plan.get("plan_id") != receipt.plan_id
        or plan.get("target_node_id") != receipt.target_node_id
        or plan.get("service") not in ALLOWED_SERVICES
        or plan.get("accepts_caller_argv") is not False
        or plan.get("accepts_shell") is not False
        or plan.get("execution_authorized") is not False
        or plan.get("production_mutation_enabled") is not False
    ):
        raise OperationRollbackClaimError("unsafe_operation_plan")

    recovery = job.get("recovery")
    if not isinstance(recovery, dict) or recovery != plan.get("recovery"):
        raise OperationRollbackClaimError("operation_recovery_contract_mismatch")
    expected_active_state = recovery.get("expected_active_state")
    if expected_active_state not in {"active", "inactive"}:
        raise OperationRollbackClaimError("unsafe_operation_recovery_state")
    rollback_verb = "start" if expected_active_state == "active" else "stop"
    expected_recovery = {
        "strategy": "restore-observed-active-state",
        "argv": [SYSTEMCTL, rollback_verb, job["service"]],
        "timeout_seconds": 15,
        "expected_active_state": expected_active_state,
        "verification_required": True,
    }
    if recovery != expected_recovery:
        raise OperationRollbackClaimError("operation_recovery_contract_mismatch")
    recovery_sha256 = hashlib.sha256(canonical_json(recovery).encode("utf-8")).hexdigest()
    return recovery_sha256, expected_active_state


def _build_claim(
    receipt: OperationVerificationReceipt,
    *,
    recovery_sha256: str,
    expected_active_state: str,
    audit_event_id: str | None,
) -> OperationRollbackClaim:
    identity = {
        "verification_receipt_id": receipt.receipt_id,
        "execution_receipt_id": receipt.execution_receipt_id,
        "job_id": receipt.job_id,
        "action_id": receipt.action_id,
        "plan_id": receipt.plan_id,
        "plan_sha256": receipt.plan_sha256,
        "worker_id": receipt.worker_id,
        "target_node_id": receipt.target_node_id,
        "recovery_sha256": recovery_sha256,
        "recovery_strategy": "restore-observed-active-state",
        "expected_active_state": expected_active_state,
        "state": OperationJobState.ROLLING_BACK.value,
        "from_state_version": receipt.to_state_version,
        "to_state_version": receipt.to_state_version + 1,
    }
    digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return OperationRollbackClaim(
        claim_id=f"oprollback-{digest[:24]}",
        verification_receipt_id=receipt.receipt_id,
        execution_receipt_id=receipt.execution_receipt_id,
        job_id=receipt.job_id,
        action_id=receipt.action_id,
        plan_id=receipt.plan_id,
        plan_sha256=receipt.plan_sha256,
        worker_id=receipt.worker_id,
        target_node_id=receipt.target_node_id,
        recovery_sha256=recovery_sha256,
        recovery_strategy="restore-observed-active-state",
        expected_active_state=expected_active_state,
        from_state_version=receipt.to_state_version,
        to_state_version=receipt.to_state_version + 1,
        audit_event_id=audit_event_id,
    )


def _revalidate_persisted_claim(
    store: OperationRollbackClaimStore,
    claim: OperationRollbackClaim,
    receipt: OperationVerificationReceipt,
) -> None:
    if (
        claim.verification_receipt_id != receipt.receipt_id
        or claim.execution_receipt_id != receipt.execution_receipt_id
        or claim.job_id != receipt.job_id
        or claim.action_id != receipt.action_id
        or claim.plan_id != receipt.plan_id
        or claim.plan_sha256 != receipt.plan_sha256
        or claim.worker_id != receipt.worker_id
        or claim.target_node_id != receipt.target_node_id
        or claim.from_state_version != receipt.to_state_version
        or claim.to_state_version != receipt.to_state_version + 1
    ):
        raise OperationRollbackClaimError("operation_rollback_claim_lineage_mismatch")
    _validate_verification_receipt(
        receipt,
        OperationWorkerIdentity(claim.worker_id, claim.target_node_id),
    )
    job_row = store._operation_job_row(claim.job_id)
    if job_row is None:
        raise OperationRollbackClaimError("operation_job_not_found")
    job = store._decode_operation_job(job_row)
    if job.get("state") != OperationJobState.ROLLING_BACK.value:
        raise OperationRollbackClaimError("operation_rollback_claim_stale")
    if job.get("state_version") != claim.to_state_version:
        raise OperationRollbackClaimError("operation_rollback_claim_stale")
    if (
        job.get("mutation_may_have_occurred") is not True
        or job.get("recovery_required") is not False
    ):
        raise OperationRollbackClaimError("operation_rollback_claim_stale")
    recovery_sha256, expected_active_state = _validate_rolling_back_job(
        job,
        receipt,
        OperationWorkerIdentity(claim.worker_id, claim.target_node_id),
        expected_state_version=claim.to_state_version,
        rollback_claim=claim,
    )
    if recovery_sha256 != claim.recovery_sha256:
        raise OperationRollbackClaimError("operation_recovery_contract_drift")
    if expected_active_state != claim.expected_active_state:
        raise OperationRollbackClaimError("operation_recovery_state_drift")


def _decode_claim(row: sqlite3.Row) -> OperationRollbackClaim:
    value = json.loads(row["claim_json"])
    actual_sha256 = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    if actual_sha256 != row["claim_sha256"]:
        raise OperationRollbackClaimError("operation_rollback_claim_integrity_mismatch")
    claim = OperationRollbackClaim(
        claim_id=value["claim_id"],
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
        from_state_version=value["from_state_version"],
        to_state_version=value["to_state_version"],
        audit_event_id=value["audit_event_id"],
    )
    if claim.to_dict() != value:
        raise OperationRollbackClaimError("operation_rollback_claim_shape_mismatch")
    if (
        row["claim_id"] != claim.claim_id
        or row["verification_receipt_id"] != claim.verification_receipt_id
        or row["execution_receipt_id"] != claim.execution_receipt_id
        or row["job_id"] != claim.job_id
        or row["worker_id"] != claim.worker_id
        or row["target_node_id"] != claim.target_node_id
        or row["plan_id"] != claim.plan_id
        or row["from_state_version"] != claim.from_state_version
        or row["to_state_version"] != claim.to_state_version
        or row["recovery_sha256"] != claim.recovery_sha256
        or row["expected_active_state"] != claim.expected_active_state
        or row["audit_event_id"] != claim.audit_event_id
    ):
        raise OperationRollbackClaimError("operation_rollback_claim_identity_mismatch")
    return claim
