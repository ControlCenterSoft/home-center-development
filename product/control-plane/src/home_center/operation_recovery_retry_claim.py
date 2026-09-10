"""Single-use recovery retry claims for bounded Home Center operations."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_commands import ACTION_ID, ALLOWED_SERVICES, OperationJobState
from .operation_recovery_retry_admission import (
    OperationRecoveryRetryAdmission,
    OperationRecoveryRetryRequest,
    revalidate_operation_recovery_retry_admission,
)
from .operation_rollback_execution_receipt import OperationRollbackExecutionReceipt
from .operation_rollback_verification_receipt import OperationRollbackVerificationReceipt
from .operation_worker_handoff import OperationWorkerIdentity
from .util import canonical_json, utc_now


SCHEMA = "home-center.operation-recovery-retry-claim.v1"
RECOVERY_RETRY_CLAIM_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation_recovery_retry_claims (
    claim_id TEXT PRIMARY KEY,
    admission_id TEXT NOT NULL UNIQUE,
    rollback_verification_receipt_id TEXT NOT NULL,
    rollback_execution_receipt_id TEXT NOT NULL,
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    recovery_sha256 TEXT NOT NULL,
    retry_authorization_id TEXT NOT NULL,
    retry_correlation_id TEXT NOT NULL,
    retry_reason_sha256 TEXT NOT NULL,
    failed_audit_event_id TEXT NOT NULL,
    from_state_version INTEGER NOT NULL CHECK(from_state_version >= 1),
    to_state_version INTEGER NOT NULL CHECK(to_state_version = from_state_version + 1),
    claim_sha256 TEXT NOT NULL,
    claim_json TEXT NOT NULL,
    audit_event_id TEXT NOT NULL REFERENCES audit(event_id),
    created_at TEXT NOT NULL,
    UNIQUE(job_id, from_state_version)
);
CREATE INDEX IF NOT EXISTS idx_operation_recovery_retry_claim_job
    ON operation_recovery_retry_claims(job_id, worker_id, to_state_version);
"""


class OperationRecoveryRetryClaimError(RuntimeError):
    """A recovery retry could not be claimed without weakening operation safety."""


class OperationRecoveryRetryClaimStore(Protocol):
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
class OperationRecoveryRetryClaim:
    claim_id: str
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
    retry_authorization_id: str
    retry_correlation_id: str
    retry_reason_sha256: str
    failed_audit_event_id: str
    from_state_version: int
    to_state_version: int
    audit_event_id: str
    schema: str = field(default=SCHEMA, init=False)
    state: str = field(default="rolling_back", init=False)
    single_use: bool = field(default=True, init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "claim_id": self.claim_id,
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
            "retry_authorization_id": self.retry_authorization_id,
            "retry_correlation_id": self.retry_correlation_id,
            "retry_reason_sha256": self.retry_reason_sha256,
            "failed_audit_event_id": self.failed_audit_event_id,
            "state": self.state,
            "from_state_version": self.from_state_version,
            "to_state_version": self.to_state_version,
            "audit_event_id": self.audit_event_id,
            "single_use": True,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }


class OperationRecoveryRetryClaimCoordinator:
    """Atomically claim one admitted recovery retry and re-enter rollback state."""

    def __init__(self, store: OperationRecoveryRetryClaimStore) -> None:
        self._store = store
        for name in (
            "_lock",
            "_connection",
            "_operation_job_row",
            "_decode_operation_job",
            "_append_operation_audit_locked",
        ):
            if not hasattr(store, name):
                raise TypeError("store does not provide recovery retry claim primitives")
        with store._lock, store._connection:
            store._connection.executescript(RECOVERY_RETRY_CLAIM_SCHEMA)

    def claim(
        self,
        admission: OperationRecoveryRetryAdmission,
        receipt: OperationRollbackVerificationReceipt,
        execution: OperationRollbackExecutionReceipt,
        request: OperationRecoveryRetryRequest,
        *,
        worker: OperationWorkerIdentity,
    ) -> tuple[OperationRecoveryRetryClaim, bool]:
        _validate_inputs(admission, receipt, execution, request, worker)
        store = self._store
        with store._lock:
            store._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = store._connection.execute(
                    "SELECT * FROM operation_recovery_retry_claims WHERE admission_id=?",
                    (admission.admission_id,),
                ).fetchone()
                if replay is not None:
                    claim = _decode_claim(replay)
                    _revalidate_persisted_claim(
                        store, claim, admission, receipt, execution, request, worker
                    )
                    store._connection.commit()
                    return claim, False

                revalidate_operation_recovery_retry_admission(
                    store, admission, receipt, execution, request
                )
                row = store._operation_job_row(admission.job_id)
                if row is None:
                    raise OperationRecoveryRetryClaimError("operation_job_not_found")
                job = store._decode_operation_job(row)
                _validate_failed_job(job, admission, receipt, execution, request)

                provisional = _build_claim(admission, worker=worker, audit_event_id="pending")
                audit_event_id = store._append_operation_audit_locked(
                    actor=worker.worker_id,
                    action="operation.recovery_retry.claim",
                    target=f"{admission.target_node_id}:{job['service']}",
                    outcome=OperationJobState.ROLLING_BACK.value,
                    correlation_id=request.correlation_id,
                    details={
                        "claim_id": provisional.claim_id,
                        "admission_id": admission.admission_id,
                        "job_id": admission.job_id,
                        "worker_id": worker.worker_id,
                        "target_node_id": worker.node_id,
                        "plan_id": admission.plan_id,
                        "plan_sha256": admission.plan_sha256,
                        "recovery_sha256": admission.recovery_sha256,
                        "retry_authorization_id": admission.retry_authorization_id,
                        "retry_reason_sha256": admission.retry_reason_sha256,
                        "from_state": OperationJobState.FAILED.value,
                        "to_state": OperationJobState.ROLLING_BACK.value,
                        "from_state_version": admission.failed_state_version,
                        "to_state_version": admission.failed_state_version + 1,
                    },
                )
                claim = _build_claim(
                    admission, worker=worker, audit_event_id=audit_event_id
                )
                evidence = dict(job["evidence"])
                evidence["recovery_retry_admission"] = admission.to_dict()
                evidence["recovery_retry_claim"] = claim.to_dict()

                cursor = store._connection.execute(
                    """UPDATE jobs SET state=?,evidence_json=?,updated_at=?
                    WHERE job_id=? AND state=?""",
                    (
                        OperationJobState.ROLLING_BACK.value,
                        canonical_json(evidence),
                        utc_now(),
                        claim.job_id,
                        OperationJobState.FAILED.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationRecoveryRetryClaimError("recovery_retry_claim_stale")
                cursor = store._connection.execute(
                    """UPDATE operation_job_metadata
                    SET state_version=?,recovery_required=0,last_audit_event_id=?
                    WHERE job_id=? AND state_version=? AND last_audit_event_id=?
                    AND mutation_may_have_occurred=1 AND recovery_required=1""",
                    (
                        claim.to_state_version,
                        audit_event_id,
                        claim.job_id,
                        claim.from_state_version,
                        claim.failed_audit_event_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OperationRecoveryRetryClaimError("recovery_retry_claim_stale")

                value = canonical_json(claim.to_dict())
                store._connection.execute(
                    """INSERT INTO operation_recovery_retry_claims(
                    claim_id,admission_id,rollback_verification_receipt_id,
                    rollback_execution_receipt_id,job_id,action_id,plan_id,plan_sha256,
                    worker_id,target_node_id,recovery_sha256,retry_authorization_id,
                    retry_correlation_id,retry_reason_sha256,failed_audit_event_id,
                    from_state_version,to_state_version,claim_sha256,claim_json,
                    audit_event_id,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        claim.claim_id,
                        claim.admission_id,
                        claim.rollback_verification_receipt_id,
                        claim.rollback_execution_receipt_id,
                        claim.job_id,
                        claim.action_id,
                        claim.plan_id,
                        claim.plan_sha256,
                        claim.worker_id,
                        claim.target_node_id,
                        claim.recovery_sha256,
                        claim.retry_authorization_id,
                        claim.retry_correlation_id,
                        claim.retry_reason_sha256,
                        claim.failed_audit_event_id,
                        claim.from_state_version,
                        claim.to_state_version,
                        hashlib.sha256(value.encode("utf-8")).hexdigest(),
                        value,
                        claim.audit_event_id,
                        utc_now(),
                    ),
                )
                store._connection.commit()
                return claim, True
            except sqlite3.IntegrityError as exc:
                store._connection.rollback()
                raise OperationRecoveryRetryClaimError(
                    "recovery_retry_claim_conflict"
                ) from exc
            except Exception:
                store._connection.rollback()
                raise


def revalidate_operation_recovery_retry_claim(
    store: OperationRecoveryRetryClaimStore,
    claim: OperationRecoveryRetryClaim,
    admission: OperationRecoveryRetryAdmission,
    receipt: OperationRollbackVerificationReceipt,
    execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
    *,
    worker: OperationWorkerIdentity,
) -> None:
    """Fail closed before a bounded retry executor consumes this claim."""

    if not isinstance(claim, OperationRecoveryRetryClaim):
        raise TypeError("claim must be OperationRecoveryRetryClaim")
    _validate_inputs(admission, receipt, execution, request, worker)
    with store._lock:
        row = store._connection.execute(
            "SELECT * FROM operation_recovery_retry_claims WHERE claim_id=?",
            (claim.claim_id,),
        ).fetchone()
        if row is None:
            raise OperationRecoveryRetryClaimError("recovery_retry_claim_not_found")
        persisted = _decode_claim(row)
        if persisted != claim:
            raise OperationRecoveryRetryClaimError("recovery_retry_claim_stale")
        _revalidate_persisted_claim(
            store, claim, admission, receipt, execution, request, worker
        )


def _validate_inputs(
    admission: OperationRecoveryRetryAdmission,
    receipt: OperationRollbackVerificationReceipt,
    execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
    worker: OperationWorkerIdentity,
) -> None:
    if not isinstance(admission, OperationRecoveryRetryAdmission):
        raise TypeError("admission must be OperationRecoveryRetryAdmission")
    if not isinstance(receipt, OperationRollbackVerificationReceipt):
        raise TypeError("receipt must be OperationRollbackVerificationReceipt")
    if not isinstance(execution, OperationRollbackExecutionReceipt):
        raise TypeError("execution must be OperationRollbackExecutionReceipt")
    if not isinstance(request, OperationRecoveryRetryRequest):
        raise TypeError("request must be OperationRecoveryRetryRequest")
    if not isinstance(worker, OperationWorkerIdentity):
        raise TypeError("worker must be OperationWorkerIdentity")
    if admission.action_id != ACTION_ID:
        raise OperationRecoveryRetryClaimError("unsupported_operation_action")
    if worker.node_id != admission.target_node_id:
        raise OperationRecoveryRetryClaimError("operation_worker_target_mismatch")

    expected = {
        "rollback_verification_receipt_id": receipt.receipt_id,
        "rollback_execution_receipt_id": execution.receipt_id,
        "job_id": receipt.job_id,
        "action_id": receipt.action_id,
        "plan_id": receipt.plan_id,
        "plan_sha256": receipt.plan_sha256,
        "target_node_id": receipt.target_node_id,
        "recovery_sha256": receipt.recovery_sha256,
        "failed_state_version": receipt.to_state_version,
        "retry_authorization_id": request.authorization_id,
        "retry_correlation_id": request.correlation_id,
    }
    for name, value in expected.items():
        if getattr(admission, name) != value:
            raise OperationRecoveryRetryClaimError(f"recovery_retry_{name}_mismatch")
    reason_sha256 = hashlib.sha256(request.reason.encode("utf-8")).hexdigest()
    if admission.retry_reason_sha256 != reason_sha256:
        raise OperationRecoveryRetryClaimError("recovery_retry_reason_mismatch")

    admission_value = admission.to_dict()
    if (
        admission_value.get("retry_eligible") is not True
        or admission_value.get("requires_new_worker_claim") is not True
        or admission_value.get("state_transition_authorized") is not False
        or admission_value.get("execution_authorized") is not False
    ):
        raise OperationRecoveryRetryClaimError("unsafe_recovery_retry_admission")
    for value in (admission_value, receipt.to_dict(), execution.to_dict()):
        for flag in (
            "contains_command_material",
            "accepts_caller_argv",
            "accepts_shell",
            "production_mutation_enabled",
        ):
            if value.get(flag) is not False:
                raise OperationRecoveryRetryClaimError("unsafe_recovery_retry_evidence")
    for value in (receipt.to_dict(), execution.to_dict()):
        if value.get("grants_execution_authority") is not False:
            raise OperationRecoveryRetryClaimError("unsafe_recovery_retry_evidence")


def _validate_failed_job(
    job: dict[str, Any],
    admission: OperationRecoveryRetryAdmission,
    receipt: OperationRollbackVerificationReceipt,
    execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
) -> None:
    if job.get("state") != OperationJobState.FAILED.value:
        raise OperationRecoveryRetryClaimError("operation_job_not_failed")
    if job.get("state_version") != admission.failed_state_version:
        raise OperationRecoveryRetryClaimError("operation_job_state_stale")
    if job.get("last_audit_event_id") != admission.failed_audit_event_id:
        raise OperationRecoveryRetryClaimError("operation_job_audit_stale")
    if job.get("mutation_may_have_occurred") is not True:
        raise OperationRecoveryRetryClaimError("mutation_evidence_missing")
    if job.get("recovery_required") is not True:
        raise OperationRecoveryRetryClaimError("recovery_not_required")
    for name in ("job_id", "action_id", "plan_id", "plan_sha256", "target_node_id"):
        if job.get(name) != getattr(admission, name):
            raise OperationRecoveryRetryClaimError(f"operation_job_{name}_mismatch")
    if job.get("service") not in ALLOWED_SERVICES:
        raise OperationRecoveryRetryClaimError("operation_service_not_allowlisted")
    if job.get("authorization_id") == request.authorization_id:
        raise OperationRecoveryRetryClaimError("fresh_retry_authorization_required")

    evidence = job.get("evidence")
    expected_keys = {
        "worker_claim",
        "execution_receipt",
        "verification_receipt",
        "rollback_claim",
        "rollback_execution_receipt",
        "rollback_verification_receipt",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected_keys:
        raise OperationRecoveryRetryClaimError("operation_recovery_evidence_shape_mismatch")
    if evidence["rollback_execution_receipt"] != execution.to_dict():
        raise OperationRecoveryRetryClaimError("rollback_execution_evidence_mismatch")
    if evidence["rollback_verification_receipt"] != receipt.to_dict():
        raise OperationRecoveryRetryClaimError("rollback_verification_evidence_mismatch")
    _validate_recovery_lineage(
        job,
        recovery_sha256=admission.recovery_sha256,
        receipt=receipt,
    )


def _validate_recovery_lineage(
    job: dict[str, Any],
    *,
    recovery_sha256: str,
    receipt: OperationRollbackVerificationReceipt,
) -> None:
    plan = job.get("plan")
    if not isinstance(plan, dict):
        raise OperationRecoveryRetryClaimError("operation_plan_missing")
    plan_sha256 = hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()
    if plan_sha256 != job.get("plan_sha256"):
        raise OperationRecoveryRetryClaimError("operation_plan_integrity_mismatch")
    recovery = plan.get("recovery")
    if not isinstance(recovery, dict):
        raise OperationRecoveryRetryClaimError("operation_recovery_contract_missing")
    actual_recovery_sha256 = hashlib.sha256(
        canonical_json(recovery).encode("utf-8")
    ).hexdigest()
    if actual_recovery_sha256 != recovery_sha256:
        raise OperationRecoveryRetryClaimError("operation_recovery_contract_drift")

    current_recovery = job.get("recovery")
    if not isinstance(current_recovery, dict):
        raise OperationRecoveryRetryClaimError("operation_recovery_evidence_missing")
    for name, value in recovery.items():
        if current_recovery.get(name) != value:
            raise OperationRecoveryRetryClaimError("operation_recovery_evidence_drift")
    if current_recovery.get("verification") != {
        "receipt_id": receipt.receipt_id,
        "recovery_verified": False,
        "recovery_required": True,
    }:
        raise OperationRecoveryRetryClaimError("operation_recovery_verification_drift")
    if set(current_recovery) != set(recovery) | {"verification"}:
        raise OperationRecoveryRetryClaimError("operation_recovery_evidence_shape_mismatch")


def _build_claim(
    admission: OperationRecoveryRetryAdmission,
    *,
    worker: OperationWorkerIdentity,
    audit_event_id: str,
) -> OperationRecoveryRetryClaim:
    identity = {
        "admission_id": admission.admission_id,
        "rollback_verification_receipt_id": admission.rollback_verification_receipt_id,
        "rollback_execution_receipt_id": admission.rollback_execution_receipt_id,
        "job_id": admission.job_id,
        "action_id": admission.action_id,
        "plan_id": admission.plan_id,
        "plan_sha256": admission.plan_sha256,
        "worker_id": worker.worker_id,
        "target_node_id": worker.node_id,
        "recovery_sha256": admission.recovery_sha256,
        "retry_authorization_id": admission.retry_authorization_id,
        "retry_correlation_id": admission.retry_correlation_id,
        "retry_reason_sha256": admission.retry_reason_sha256,
        "failed_audit_event_id": admission.failed_audit_event_id,
        "from_state_version": admission.failed_state_version,
        "to_state_version": admission.failed_state_version + 1,
    }
    digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return OperationRecoveryRetryClaim(
        claim_id=f"oprecoveryclaim-{digest[:24]}",
        admission_id=admission.admission_id,
        rollback_verification_receipt_id=admission.rollback_verification_receipt_id,
        rollback_execution_receipt_id=admission.rollback_execution_receipt_id,
        job_id=admission.job_id,
        action_id=admission.action_id,
        plan_id=admission.plan_id,
        plan_sha256=admission.plan_sha256,
        worker_id=worker.worker_id,
        target_node_id=worker.node_id,
        recovery_sha256=admission.recovery_sha256,
        retry_authorization_id=admission.retry_authorization_id,
        retry_correlation_id=admission.retry_correlation_id,
        retry_reason_sha256=admission.retry_reason_sha256,
        failed_audit_event_id=admission.failed_audit_event_id,
        from_state_version=admission.failed_state_version,
        to_state_version=admission.failed_state_version + 1,
        audit_event_id=audit_event_id,
    )


def _revalidate_persisted_claim(
    store: OperationRecoveryRetryClaimStore,
    claim: OperationRecoveryRetryClaim,
    admission: OperationRecoveryRetryAdmission,
    receipt: OperationRollbackVerificationReceipt,
    execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
    worker: OperationWorkerIdentity,
) -> None:
    _validate_inputs(admission, receipt, execution, request, worker)
    expected = _build_claim(admission, worker=worker, audit_event_id=claim.audit_event_id)
    if claim != expected:
        raise OperationRecoveryRetryClaimError("recovery_retry_claim_lineage_mismatch")
    row = store._operation_job_row(claim.job_id)
    if row is None:
        raise OperationRecoveryRetryClaimError("operation_job_not_found")
    job = store._decode_operation_job(row)
    if (
        job.get("state") != OperationJobState.ROLLING_BACK.value
        or job.get("state_version") != claim.to_state_version
        or job.get("mutation_may_have_occurred") is not True
        or job.get("recovery_required") is not False
        or job.get("last_audit_event_id") != claim.audit_event_id
    ):
        raise OperationRecoveryRetryClaimError("recovery_retry_claim_stale")
    evidence = job.get("evidence")
    if not isinstance(evidence, dict):
        raise OperationRecoveryRetryClaimError("operation_recovery_evidence_missing")
    if evidence.get("recovery_retry_admission") != admission.to_dict():
        raise OperationRecoveryRetryClaimError("recovery_retry_admission_evidence_mismatch")
    if evidence.get("recovery_retry_claim") != claim.to_dict():
        raise OperationRecoveryRetryClaimError("recovery_retry_claim_evidence_mismatch")
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
    if set(evidence) != expected_keys:
        raise OperationRecoveryRetryClaimError("operation_recovery_evidence_shape_mismatch")
    if evidence.get("rollback_execution_receipt") != execution.to_dict():
        raise OperationRecoveryRetryClaimError("rollback_execution_evidence_mismatch")
    if evidence.get("rollback_verification_receipt") != receipt.to_dict():
        raise OperationRecoveryRetryClaimError("rollback_verification_evidence_mismatch")
    _validate_recovery_lineage(
        job,
        recovery_sha256=claim.recovery_sha256,
        receipt=receipt,
    )


def _decode_claim(row: sqlite3.Row) -> OperationRecoveryRetryClaim:
    value = json.loads(row["claim_json"])
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    if digest != row["claim_sha256"]:
        raise OperationRecoveryRetryClaimError("recovery_retry_claim_integrity_mismatch")
    claim = OperationRecoveryRetryClaim(
        claim_id=value["claim_id"],
        admission_id=value["admission_id"],
        rollback_verification_receipt_id=value["rollback_verification_receipt_id"],
        rollback_execution_receipt_id=value["rollback_execution_receipt_id"],
        job_id=value["job_id"],
        action_id=value["action_id"],
        plan_id=value["plan_id"],
        plan_sha256=value["plan_sha256"],
        worker_id=value["worker_id"],
        target_node_id=value["target_node_id"],
        recovery_sha256=value["recovery_sha256"],
        retry_authorization_id=value["retry_authorization_id"],
        retry_correlation_id=value["retry_correlation_id"],
        retry_reason_sha256=value["retry_reason_sha256"],
        failed_audit_event_id=value["failed_audit_event_id"],
        from_state_version=value["from_state_version"],
        to_state_version=value["to_state_version"],
        audit_event_id=value["audit_event_id"],
    )
    if claim.to_dict() != value:
        raise OperationRecoveryRetryClaimError("recovery_retry_claim_shape_mismatch")
    for name in (
        "claim_id",
        "admission_id",
        "rollback_verification_receipt_id",
        "rollback_execution_receipt_id",
        "job_id",
        "action_id",
        "plan_id",
        "plan_sha256",
        "worker_id",
        "target_node_id",
        "recovery_sha256",
        "retry_authorization_id",
        "retry_correlation_id",
        "retry_reason_sha256",
        "failed_audit_event_id",
        "from_state_version",
        "to_state_version",
        "audit_event_id",
    ):
        if row[name] != getattr(claim, name):
            raise OperationRecoveryRetryClaimError(
                "recovery_retry_claim_identity_mismatch"
            )
    return claim
