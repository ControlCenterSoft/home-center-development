"""Replay-safe execution receipts for one admitted recovery retry."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_commands import ACTION_ID, ALLOWED_SERVICES, SYSTEMCTL, OperationJobState
from .operation_recovery_retry_admission import (
    OperationRecoveryRetryAdmission,
    OperationRecoveryRetryRequest,
)
from .operation_recovery_retry_claim import (
    OperationRecoveryRetryClaim,
    OperationRecoveryRetryClaimError,
    _decode_claim,
    revalidate_operation_recovery_retry_claim,
)
from .operation_rollback_execution_receipt import OperationRollbackExecutionReceipt
from .operation_rollback_verification_receipt import OperationRollbackVerificationReceipt
from .operation_worker_handoff import OperationWorkerIdentity
from .util import canonical_json, utc_now


SCHEMA = "home-center.operation-recovery-retry-execution-receipt.v1"
CLAIM_ID = re.compile(r"^oprecoveryclaim-[a-f0-9]{24}$")
RECEIPT_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation_recovery_retry_execution_receipts (
    receipt_id TEXT PRIMARY KEY,
    retry_claim_id TEXT NOT NULL UNIQUE
        REFERENCES operation_recovery_retry_claims(claim_id) ON DELETE CASCADE,
    admission_id TEXT NOT NULL,
    rollback_verification_receipt_id TEXT NOT NULL,
    rollback_execution_receipt_id TEXT NOT NULL,
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    from_state_version INTEGER NOT NULL CHECK(from_state_version >= 1),
    to_state_version INTEGER NOT NULL CHECK(to_state_version = from_state_version + 1),
    next_state TEXT NOT NULL CHECK(next_state IN ('rolling_back','failed')),
    recovery_sha256 TEXT NOT NULL,
    command_sha256 TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    audit_event_id TEXT NOT NULL REFERENCES audit(event_id),
    created_at TEXT NOT NULL,
    UNIQUE(job_id, from_state_version)
);
CREATE INDEX IF NOT EXISTS idx_operation_recovery_retry_execution_job
    ON operation_recovery_retry_execution_receipts(job_id, worker_id, to_state_version);
"""


class OperationRecoveryRetryExecutionReceiptError(RuntimeError):
    """Recovery retry execution evidence could not be recorded safely."""


class OperationRecoveryRetryExecutionReceiptStore(Protocol):
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
class OperationRecoveryRetryExecutionObservation:
    """Sanitized observation; no argv, output, environment, or secret material."""

    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.started, bool) or not isinstance(self.timed_out, bool):
            raise OperationRecoveryRetryExecutionReceiptError(
                "invalid_recovery_retry_execution_flags"
            )
        if (
            not isinstance(self.elapsed_ms, int)
            or isinstance(self.elapsed_ms, bool)
            or not 0 <= self.elapsed_ms <= 15_000
        ):
            raise OperationRecoveryRetryExecutionReceiptError(
                "invalid_recovery_retry_execution_elapsed_ms"
            )
        if self.exit_code is not None and (
            not isinstance(self.exit_code, int)
            or isinstance(self.exit_code, bool)
            or not -255 <= self.exit_code <= 255
        ):
            raise OperationRecoveryRetryExecutionReceiptError(
                "invalid_recovery_retry_execution_exit_code"
            )
        if not self.started:
            if self.timed_out or self.exit_code is not None or self.elapsed_ms != 0:
                raise OperationRecoveryRetryExecutionReceiptError(
                    "invalid_recovery_retry_not_started_observation"
                )
        elif not self.timed_out and self.exit_code is None:
            raise OperationRecoveryRetryExecutionReceiptError(
                "missing_recovery_retry_execution_exit_code"
            )
        elif self.timed_out and self.exit_code is not None:
            raise OperationRecoveryRetryExecutionReceiptError(
                "recovery_retry_timeout_with_exit_code"
            )


@dataclass(frozen=True, slots=True)
class OperationRecoveryRetryExecutionReceipt:
    receipt_id: str
    retry_claim_id: str
    admission_id: str
    rollback_verification_receipt_id: str
    rollback_execution_receipt_id: str
    job_id: str
    action_id: str
    plan_id: str
    plan_sha256: str
    worker_id: str
    target_node_id: str
    recovery_sha256: str
    command_sha256: str
    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int
    retry_succeeded: bool
    recovery_required: bool
    next_state: str
    from_state_version: int
    to_state_version: int
    verification_required: bool
    audit_event_id: str | None = None
    schema: str = field(default=SCHEMA, init=False)
    from_state: str = field(default="rolling_back", init=False)
    single_use: bool = field(default=True, init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    grants_execution_authority: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "retry_claim_id": self.retry_claim_id,
            "admission_id": self.admission_id,
            "rollback_verification_receipt_id": self.rollback_verification_receipt_id,
            "rollback_execution_receipt_id": self.rollback_execution_receipt_id,
            "job_id": self.job_id,
            "action_id": self.action_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "worker_id": self.worker_id,
            "target_node_id": self.target_node_id,
            "recovery_sha256": self.recovery_sha256,
            "command_sha256": self.command_sha256,
            "started": self.started,
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
            "elapsed_ms": self.elapsed_ms,
            "retry_succeeded": self.retry_succeeded,
            "recovery_required": self.recovery_required,
            "from_state": self.from_state,
            "next_state": self.next_state,
            "from_state_version": self.from_state_version,
            "to_state_version": self.to_state_version,
            "audit_event_id": self.audit_event_id,
            "verification_required": self.verification_required,
            "single_use": True,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "production_mutation_enabled": False,
        }


class OperationRecoveryRetryExecutionReceiptCoordinator:
    """Commit one sanitized retry observation against an exact single-use claim."""

    def __init__(self, store: OperationRecoveryRetryExecutionReceiptStore) -> None:
        self._store = store
        for name in (
            "_lock",
            "_connection",
            "_operation_job_row",
            "_decode_operation_job",
            "_append_operation_audit_locked",
        ):
            if not hasattr(store, name):
                raise TypeError("store does not provide recovery retry execution primitives")
        with store._lock, store._connection:
            store._connection.executescript(RECEIPT_SCHEMA)

    def record(
        self,
        claim_id: str,
        admission: OperationRecoveryRetryAdmission,
        prior_verification: OperationRollbackVerificationReceipt,
        prior_execution: OperationRollbackExecutionReceipt,
        request: OperationRecoveryRetryRequest,
        *,
        worker: OperationWorkerIdentity,
        observation: OperationRecoveryRetryExecutionObservation,
    ) -> tuple[OperationRecoveryRetryExecutionReceipt, bool]:
        if not isinstance(claim_id, str) or not CLAIM_ID.fullmatch(claim_id):
            raise OperationRecoveryRetryExecutionReceiptError(
                "invalid_recovery_retry_claim_id"
            )
        _validate_inputs(
            admission,
            prior_verification,
            prior_execution,
            request,
            worker,
            observation,
        )

        store = self._store
        with store._lock:
            store._connection.execute("BEGIN IMMEDIATE")
            try:
                claim_row = store._connection.execute(
                    "SELECT * FROM operation_recovery_retry_claims WHERE claim_id=?",
                    (claim_id,),
                ).fetchone()
                if claim_row is None:
                    raise OperationRecoveryRetryExecutionReceiptError(
                        "recovery_retry_claim_not_found"
                    )
                claim = _decode_claim(claim_row)
                _validate_claim_inputs(
                    claim,
                    admission,
                    prior_verification,
                    prior_execution,
                    request,
                    worker,
                )

                replay = store._connection.execute(
                    """SELECT * FROM operation_recovery_retry_execution_receipts
                    WHERE retry_claim_id=?""",
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
                        raise OperationRecoveryRetryExecutionReceiptError(
                            "recovery_retry_execution_receipt_conflict"
                        )
                    _revalidate_persisted_receipt(
                        store,
                        receipt,
                        claim,
                        admission,
                        prior_verification,
                        prior_execution,
                        request,
                        worker,
                    )
                    store._connection.commit()
                    return receipt, False

                revalidate_operation_recovery_retry_claim(
                    store,
                    claim,
                    admission,
                    prior_verification,
                    prior_execution,
                    request,
                    worker=worker,
                )
                job_row = store._operation_job_row(claim.job_id)
                if job_row is None:
                    raise OperationRecoveryRetryExecutionReceiptError(
                        "operation_job_not_found"
                    )
                job = store._decode_operation_job(job_row)
                command_sha256 = _validate_pre_execution_job(
                    job,
                    claim,
                    admission,
                    prior_verification,
                    prior_execution,
                )
                provisional = _build_receipt(
                    claim,
                    command_sha256=command_sha256,
                    observation=observation,
                    audit_event_id=None,
                )
                audit_event_id = store._append_operation_audit_locked(
                    actor=worker.worker_id,
                    action="operation.recovery_retry.execution.receipt",
                    target=f"{claim.target_node_id}:{job['service']}",
                    outcome=provisional.next_state,
                    correlation_id=request.correlation_id,
                    details={
                        "receipt_id": provisional.receipt_id,
                        "retry_claim_id": claim.claim_id,
                        "admission_id": claim.admission_id,
                        "job_id": claim.job_id,
                        "worker_id": worker.worker_id,
                        "target_node_id": worker.node_id,
                        "plan_id": claim.plan_id,
                        "plan_sha256": claim.plan_sha256,
                        "recovery_sha256": claim.recovery_sha256,
                        "command_sha256": command_sha256,
                        "from_state": OperationJobState.ROLLING_BACK.value,
                        "to_state": provisional.next_state,
                        "from_state_version": provisional.from_state_version,
                        "to_state_version": provisional.to_state_version,
                        "started": observation.started,
                        "timed_out": observation.timed_out,
                        "exit_code": observation.exit_code,
                        "elapsed_ms": observation.elapsed_ms,
                        "retry_succeeded": provisional.retry_succeeded,
                        "recovery_required": provisional.recovery_required,
                        "verification_required": provisional.verification_required,
                    },
                )
                receipt = _build_receipt(
                    claim,
                    command_sha256=command_sha256,
                    observation=observation,
                    audit_event_id=audit_event_id,
                )
                value = canonical_json(receipt.to_dict())
                receipt_sha256 = hashlib.sha256(value.encode("utf-8")).hexdigest()

                evidence = dict(job["evidence"])
                evidence["recovery_retry_execution_receipt"] = receipt.to_dict()
                result = dict(job["result"]) if isinstance(job.get("result"), dict) else {}
                result["recovery_retry_execution"] = {
                    "receipt_id": receipt.receipt_id,
                    "started": receipt.started,
                    "timed_out": receipt.timed_out,
                    "exit_code": receipt.exit_code,
                    "elapsed_ms": receipt.elapsed_ms,
                    "retry_succeeded": receipt.retry_succeeded,
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
                    raise OperationRecoveryRetryExecutionReceiptError(
                        "recovery_retry_execution_receipt_stale"
                    )
                cursor = store._connection.execute(
                    """UPDATE operation_job_metadata
                    SET state_version=?,recovery_required=?,last_audit_event_id=?
                    WHERE job_id=? AND state_version=? AND last_audit_event_id=?
                    AND mutation_may_have_occurred=1 AND recovery_required=0""",
                    (
                        receipt.to_state_version,
                        1 if receipt.recovery_required else 0,
                        audit_event_id,
                        claim.job_id,
                        receipt.from_state_version,
                        claim.audit_event_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationRecoveryRetryExecutionReceiptError(
                        "recovery_retry_execution_receipt_stale"
                    )
                store._connection.execute(
                    """INSERT INTO operation_recovery_retry_execution_receipts(
                    receipt_id,retry_claim_id,admission_id,
                    rollback_verification_receipt_id,rollback_execution_receipt_id,
                    job_id,worker_id,plan_id,from_state_version,to_state_version,
                    next_state,recovery_sha256,command_sha256,receipt_sha256,
                    receipt_json,audit_event_id,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        receipt.receipt_id,
                        receipt.retry_claim_id,
                        receipt.admission_id,
                        receipt.rollback_verification_receipt_id,
                        receipt.rollback_execution_receipt_id,
                        receipt.job_id,
                        receipt.worker_id,
                        receipt.plan_id,
                        receipt.from_state_version,
                        receipt.to_state_version,
                        receipt.next_state,
                        receipt.recovery_sha256,
                        receipt.command_sha256,
                        receipt_sha256,
                        value,
                        receipt.audit_event_id,
                        utc_now(),
                    ),
                )
                store._connection.commit()
                return receipt, True
            except (
                OperationRecoveryRetryClaimError,
                sqlite3.IntegrityError,
                ValueError,
            ) as exc:
                store._connection.rollback()
                raise OperationRecoveryRetryExecutionReceiptError(
                    "recovery_retry_execution_receipt_rejected"
                ) from exc
            except Exception:
                store._connection.rollback()
                raise


def revalidate_operation_recovery_retry_execution_receipt(
    store: OperationRecoveryRetryExecutionReceiptStore,
    receipt: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
    *,
    worker: OperationWorkerIdentity,
) -> None:
    """Fail closed before retry verification consumes this receipt."""

    if not isinstance(receipt, OperationRecoveryRetryExecutionReceipt):
        raise TypeError("receipt must be OperationRecoveryRetryExecutionReceipt")
    _validate_inputs(
        admission,
        prior_verification,
        prior_execution,
        request,
        worker,
        OperationRecoveryRetryExecutionObservation(
            receipt.started,
            receipt.timed_out,
            receipt.exit_code,
            receipt.elapsed_ms,
        ),
    )
    with store._lock:
        row = store._connection.execute(
            """SELECT * FROM operation_recovery_retry_execution_receipts
            WHERE receipt_id=?""",
            (receipt.receipt_id,),
        ).fetchone()
        if row is None:
            raise OperationRecoveryRetryExecutionReceiptError(
                "recovery_retry_execution_receipt_not_found"
            )
        persisted = _decode_receipt(row)
        if persisted != receipt:
            raise OperationRecoveryRetryExecutionReceiptError(
                "recovery_retry_execution_receipt_stale"
            )
        claim_row = store._connection.execute(
            "SELECT * FROM operation_recovery_retry_claims WHERE claim_id=?",
            (receipt.retry_claim_id,),
        ).fetchone()
        if claim_row is None:
            raise OperationRecoveryRetryExecutionReceiptError(
                "recovery_retry_claim_not_found"
            )
        claim = _decode_claim(claim_row)
        _revalidate_persisted_receipt(
            store,
            receipt,
            claim,
            admission,
            prior_verification,
            prior_execution,
            request,
            worker,
        )


def _validate_inputs(
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
    worker: OperationWorkerIdentity,
    observation: OperationRecoveryRetryExecutionObservation,
) -> None:
    if not isinstance(admission, OperationRecoveryRetryAdmission):
        raise TypeError("admission must be OperationRecoveryRetryAdmission")
    if not isinstance(prior_verification, OperationRollbackVerificationReceipt):
        raise TypeError("prior_verification must be OperationRollbackVerificationReceipt")
    if not isinstance(prior_execution, OperationRollbackExecutionReceipt):
        raise TypeError("prior_execution must be OperationRollbackExecutionReceipt")
    if not isinstance(request, OperationRecoveryRetryRequest):
        raise TypeError("request must be OperationRecoveryRetryRequest")
    if not isinstance(worker, OperationWorkerIdentity):
        raise TypeError("worker must be OperationWorkerIdentity")
    if not isinstance(observation, OperationRecoveryRetryExecutionObservation):
        raise TypeError("observation must be OperationRecoveryRetryExecutionObservation")


def _validate_claim_inputs(
    claim: OperationRecoveryRetryClaim,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
    worker: OperationWorkerIdentity,
) -> None:
    if claim.action_id != ACTION_ID:
        raise OperationRecoveryRetryExecutionReceiptError("unsupported_operation_action")
    if worker.worker_id != claim.worker_id or worker.node_id != claim.target_node_id:
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_worker_identity_mismatch"
        )
    expected = {
        "admission_id": admission.admission_id,
        "rollback_verification_receipt_id": prior_verification.receipt_id,
        "rollback_execution_receipt_id": prior_execution.receipt_id,
        "job_id": prior_verification.job_id,
        "action_id": prior_verification.action_id,
        "plan_id": prior_verification.plan_id,
        "plan_sha256": prior_verification.plan_sha256,
        "target_node_id": prior_verification.target_node_id,
        "recovery_sha256": prior_verification.recovery_sha256,
        "retry_authorization_id": request.authorization_id,
        "retry_correlation_id": request.correlation_id,
    }
    for name, value in expected.items():
        if getattr(claim, name) != value:
            raise OperationRecoveryRetryExecutionReceiptError(
                f"recovery_retry_execution_{name}_mismatch"
            )
    reason_sha256 = hashlib.sha256(request.reason.encode("utf-8")).hexdigest()
    if claim.retry_reason_sha256 != reason_sha256:
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_execution_reason_mismatch"
        )
    claim_value = claim.to_dict()
    for flag in (
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "execution_authorized",
        "production_mutation_enabled",
    ):
        if claim_value.get(flag) is not False:
            raise OperationRecoveryRetryExecutionReceiptError(
                "unsafe_recovery_retry_claim"
            )


def _validate_pre_execution_job(
    job: dict[str, Any],
    claim: OperationRecoveryRetryClaim,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
) -> str:
    _validate_job_common(job, claim)
    if (
        job.get("state") != OperationJobState.ROLLING_BACK.value
        or job.get("state_version") != claim.to_state_version
        or job.get("recovery_required") is not False
        or job.get("last_audit_event_id") != claim.audit_event_id
    ):
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_execution_job_stale"
        )
    evidence = job.get("evidence")
    expected_keys = {
        "worker_claim",
        "execution_receipt",
        "verification_receipt",
        "rollback_claim",
        "rollback_execution_receipt",
        "rollback_verification_receipt",
        "recovery_retry_admission",
        "recovery_retry_claim",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected_keys:
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_execution_evidence_shape_mismatch"
        )
    if evidence.get("rollback_execution_receipt") != prior_execution.to_dict():
        raise OperationRecoveryRetryExecutionReceiptError(
            "rollback_execution_evidence_mismatch"
        )
    if evidence.get("rollback_verification_receipt") != prior_verification.to_dict():
        raise OperationRecoveryRetryExecutionReceiptError(
            "rollback_verification_evidence_mismatch"
        )
    if evidence.get("recovery_retry_admission") != admission.to_dict():
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_admission_evidence_mismatch"
        )
    if evidence.get("recovery_retry_claim") != claim.to_dict():
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_claim_evidence_mismatch"
        )
    return _validate_recovery_command(job, claim, prior_verification)


def _validate_job_common(
    job: dict[str, Any],
    claim: OperationRecoveryRetryClaim,
) -> None:
    if job.get("mutation_may_have_occurred") is not True:
        raise OperationRecoveryRetryExecutionReceiptError(
            "operation_job_mutation_evidence_missing"
        )
    for name in ("job_id", "action_id", "plan_id", "plan_sha256", "target_node_id"):
        if job.get(name) != getattr(claim, name):
            raise OperationRecoveryRetryExecutionReceiptError(
                f"recovery_retry_execution_job_{name}_mismatch"
            )
    if job.get("service") not in ALLOWED_SERVICES:
        raise OperationRecoveryRetryExecutionReceiptError(
            "operation_service_not_allowlisted"
        )


def _validate_recovery_command(
    job: dict[str, Any],
    claim: OperationRecoveryRetryClaim,
    prior_verification: OperationRollbackVerificationReceipt,
) -> str:
    plan = job.get("plan")
    if not isinstance(plan, dict):
        raise OperationRecoveryRetryExecutionReceiptError("operation_plan_missing")
    plan_sha256 = hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()
    if plan_sha256 != claim.plan_sha256:
        raise OperationRecoveryRetryExecutionReceiptError(
            "operation_plan_integrity_mismatch"
        )
    recovery = plan.get("recovery")
    if not isinstance(recovery, dict):
        raise OperationRecoveryRetryExecutionReceiptError(
            "operation_recovery_contract_missing"
        )
    expected_verb = (
        "start" if recovery.get("expected_active_state") == "active" else "stop"
    )
    expected_recovery = {
        "strategy": "restore-observed-active-state",
        "argv": [SYSTEMCTL, expected_verb, job["service"]],
        "timeout_seconds": 15,
        "expected_active_state": recovery.get("expected_active_state"),
        "verification_required": True,
    }
    if (
        recovery != expected_recovery
        or recovery.get("expected_active_state") not in {"active", "inactive"}
    ):
        raise OperationRecoveryRetryExecutionReceiptError(
            "unsafe_recovery_retry_command"
        )
    recovery_sha256 = hashlib.sha256(
        canonical_json(expected_recovery).encode("utf-8")
    ).hexdigest()
    if recovery_sha256 != claim.recovery_sha256:
        raise OperationRecoveryRetryExecutionReceiptError(
            "operation_recovery_integrity_mismatch"
        )
    current_recovery = job.get("recovery")
    expected_current = dict(expected_recovery)
    expected_current["verification"] = {
        "receipt_id": prior_verification.receipt_id,
        "recovery_verified": False,
        "recovery_required": True,
    }
    if current_recovery != expected_current:
        raise OperationRecoveryRetryExecutionReceiptError(
            "operation_recovery_evidence_drift"
        )
    command_identity = {
        "executable": SYSTEMCTL,
        "verb": expected_verb,
        "service": job["service"],
        "timeout_seconds": 15,
        "shell": False,
    }
    return hashlib.sha256(
        canonical_json(command_identity).encode("utf-8")
    ).hexdigest()


def _build_receipt(
    claim: OperationRecoveryRetryClaim,
    *,
    command_sha256: str,
    observation: OperationRecoveryRetryExecutionObservation,
    audit_event_id: str | None,
) -> OperationRecoveryRetryExecutionReceipt:
    retry_succeeded = (
        observation.started and not observation.timed_out and observation.exit_code == 0
    )
    next_state = (
        OperationJobState.ROLLING_BACK
        if retry_succeeded
        else OperationJobState.FAILED
    )
    identity = {
        "retry_claim_id": claim.claim_id,
        "admission_id": claim.admission_id,
        "rollback_verification_receipt_id": claim.rollback_verification_receipt_id,
        "rollback_execution_receipt_id": claim.rollback_execution_receipt_id,
        "job_id": claim.job_id,
        "action_id": claim.action_id,
        "plan_id": claim.plan_id,
        "plan_sha256": claim.plan_sha256,
        "worker_id": claim.worker_id,
        "target_node_id": claim.target_node_id,
        "recovery_sha256": claim.recovery_sha256,
        "command_sha256": command_sha256,
        "started": observation.started,
        "timed_out": observation.timed_out,
        "exit_code": observation.exit_code,
        "elapsed_ms": observation.elapsed_ms,
        "retry_succeeded": retry_succeeded,
        "recovery_required": not retry_succeeded,
        "verification_required": retry_succeeded,
        "from_state": OperationJobState.ROLLING_BACK.value,
        "next_state": next_state.value,
        "from_state_version": claim.to_state_version,
        "to_state_version": claim.to_state_version + 1,
    }
    digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return OperationRecoveryRetryExecutionReceipt(
        receipt_id=f"oprecoveryexec-{digest[:24]}",
        retry_claim_id=claim.claim_id,
        admission_id=claim.admission_id,
        rollback_verification_receipt_id=claim.rollback_verification_receipt_id,
        rollback_execution_receipt_id=claim.rollback_execution_receipt_id,
        job_id=claim.job_id,
        action_id=claim.action_id,
        plan_id=claim.plan_id,
        plan_sha256=claim.plan_sha256,
        worker_id=claim.worker_id,
        target_node_id=claim.target_node_id,
        recovery_sha256=claim.recovery_sha256,
        command_sha256=command_sha256,
        started=observation.started,
        timed_out=observation.timed_out,
        exit_code=observation.exit_code,
        elapsed_ms=observation.elapsed_ms,
        retry_succeeded=retry_succeeded,
        recovery_required=not retry_succeeded,
        next_state=next_state.value,
        from_state_version=claim.to_state_version,
        to_state_version=claim.to_state_version + 1,
        verification_required=retry_succeeded,
        audit_event_id=audit_event_id,
    )


def _without_audit(
    receipt: OperationRecoveryRetryExecutionReceipt,
) -> dict[str, Any]:
    value = receipt.to_dict()
    value["audit_event_id"] = None
    return value


def _revalidate_persisted_receipt(
    store: OperationRecoveryRetryExecutionReceiptStore,
    receipt: OperationRecoveryRetryExecutionReceipt,
    claim: OperationRecoveryRetryClaim,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
    worker: OperationWorkerIdentity,
) -> None:
    _validate_claim_inputs(
        claim,
        admission,
        prior_verification,
        prior_execution,
        request,
        worker,
    )
    if (
        receipt.retry_claim_id != claim.claim_id
        or receipt.admission_id != claim.admission_id
        or receipt.rollback_verification_receipt_id
        != claim.rollback_verification_receipt_id
        or receipt.rollback_execution_receipt_id != claim.rollback_execution_receipt_id
        or receipt.job_id != claim.job_id
        or receipt.action_id != claim.action_id
        or receipt.plan_id != claim.plan_id
        or receipt.plan_sha256 != claim.plan_sha256
        or receipt.worker_id != claim.worker_id
        or receipt.target_node_id != claim.target_node_id
        or receipt.recovery_sha256 != claim.recovery_sha256
        or receipt.from_state_version != claim.to_state_version
        or receipt.to_state_version != claim.to_state_version + 1
    ):
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_execution_lineage_mismatch"
        )
    job_row = store._operation_job_row(claim.job_id)
    if job_row is None:
        raise OperationRecoveryRetryExecutionReceiptError("operation_job_not_found")
    job = store._decode_operation_job(job_row)
    _validate_job_common(job, claim)
    if (
        job.get("state") != receipt.next_state
        or job.get("state_version") != receipt.to_state_version
        or job.get("recovery_required") is not receipt.recovery_required
        or job.get("last_audit_event_id") != receipt.audit_event_id
    ):
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_execution_receipt_stale"
        )
    evidence = job.get("evidence")
    expected_keys = {
        "worker_claim",
        "execution_receipt",
        "verification_receipt",
        "rollback_claim",
        "rollback_execution_receipt",
        "rollback_verification_receipt",
        "recovery_retry_admission",
        "recovery_retry_claim",
        "recovery_retry_execution_receipt",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected_keys:
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_execution_evidence_shape_mismatch"
        )
    if evidence.get("rollback_execution_receipt") != prior_execution.to_dict():
        raise OperationRecoveryRetryExecutionReceiptError(
            "rollback_execution_evidence_mismatch"
        )
    if evidence.get("rollback_verification_receipt") != prior_verification.to_dict():
        raise OperationRecoveryRetryExecutionReceiptError(
            "rollback_verification_evidence_mismatch"
        )
    if evidence.get("recovery_retry_admission") != admission.to_dict():
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_admission_evidence_mismatch"
        )
    if evidence.get("recovery_retry_claim") != claim.to_dict():
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_claim_evidence_mismatch"
        )
    if evidence.get("recovery_retry_execution_receipt") != receipt.to_dict():
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_execution_receipt_evidence_mismatch"
        )
    command_sha256 = _validate_recovery_command(job, claim, prior_verification)
    if command_sha256 != receipt.command_sha256:
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_command_integrity_mismatch"
        )


def _decode_receipt(row: sqlite3.Row) -> OperationRecoveryRetryExecutionReceipt:
    value = json.loads(row["receipt_json"])
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    if digest != row["receipt_sha256"]:
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_execution_receipt_integrity_mismatch"
        )
    receipt = OperationRecoveryRetryExecutionReceipt(
        receipt_id=value["receipt_id"],
        retry_claim_id=value["retry_claim_id"],
        admission_id=value["admission_id"],
        rollback_verification_receipt_id=value[
            "rollback_verification_receipt_id"
        ],
        rollback_execution_receipt_id=value["rollback_execution_receipt_id"],
        job_id=value["job_id"],
        action_id=value["action_id"],
        plan_id=value["plan_id"],
        plan_sha256=value["plan_sha256"],
        worker_id=value["worker_id"],
        target_node_id=value["target_node_id"],
        recovery_sha256=value["recovery_sha256"],
        command_sha256=value["command_sha256"],
        started=value["started"],
        timed_out=value["timed_out"],
        exit_code=value["exit_code"],
        elapsed_ms=value["elapsed_ms"],
        retry_succeeded=value["retry_succeeded"],
        recovery_required=value["recovery_required"],
        next_state=value["next_state"],
        from_state_version=value["from_state_version"],
        to_state_version=value["to_state_version"],
        verification_required=value["verification_required"],
        audit_event_id=value["audit_event_id"],
    )
    if receipt.to_dict() != value:
        raise OperationRecoveryRetryExecutionReceiptError(
            "recovery_retry_execution_receipt_shape_mismatch"
        )
    for name in (
        "receipt_id",
        "retry_claim_id",
        "admission_id",
        "rollback_verification_receipt_id",
        "rollback_execution_receipt_id",
        "job_id",
        "worker_id",
        "plan_id",
        "from_state_version",
        "to_state_version",
        "next_state",
        "recovery_sha256",
        "command_sha256",
        "audit_event_id",
    ):
        if row[name] != getattr(receipt, name):
            raise OperationRecoveryRetryExecutionReceiptError(
                "recovery_retry_execution_receipt_identity_mismatch"
            )
    return receipt
