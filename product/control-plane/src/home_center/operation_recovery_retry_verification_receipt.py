"""Fail-closed verification for one successful bounded recovery retry."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_commands import (
    ACTION_ID,
    ALLOWED_SERVICES,
    STATE_VALUE,
    SYSTEMCTL,
    OperationJobState,
)
from .operation_job_store import OperationJobPreconditionFailed
from .operation_recovery_retry_admission import (
    OperationRecoveryRetryAdmission,
    OperationRecoveryRetryRequest,
)
from .operation_recovery_retry_execution_receipt import (
    OperationRecoveryRetryExecutionReceipt,
    revalidate_operation_recovery_retry_execution_receipt,
)
from .operation_rollback_execution_receipt import OperationRollbackExecutionReceipt
from .operation_rollback_verification_receipt import OperationRollbackVerificationReceipt
from .operation_worker_handoff import OperationWorkerIdentity
from .util import canonical_json


SCHEMA = "home-center.operation-recovery-retry-verification-receipt.v1"


class OperationRecoveryRetryVerificationReceiptError(RuntimeError):
    """Recovery retry verification could not be accepted safely."""


class OperationRecoveryRetryVerificationStore(Protocol):
    def operation_job(self, job_id: str) -> dict[str, Any] | None: ...

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
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class OperationRecoveryRetryVerificationObservation:
    """Sanitized bounded systemd state observation; raw output is forbidden."""

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
            raise OperationRecoveryRetryVerificationReceiptError(
                "invalid_recovery_retry_verification_flags"
            )
        if (
            not isinstance(self.elapsed_ms, int)
            or isinstance(self.elapsed_ms, bool)
            or not 0 <= self.elapsed_ms <= 5_000
        ):
            raise OperationRecoveryRetryVerificationReceiptError(
                "invalid_recovery_retry_verification_elapsed_ms"
            )
        if self.exit_code is not None and (
            not isinstance(self.exit_code, int)
            or isinstance(self.exit_code, bool)
            or not -255 <= self.exit_code <= 255
        ):
            raise OperationRecoveryRetryVerificationReceiptError(
                "invalid_recovery_retry_verification_exit_code"
            )
        states = (
            self.load_state,
            self.active_state,
            self.sub_state,
            self.unit_file_state,
        )
        if not self.started:
            if self.timed_out or self.exit_code is not None or self.elapsed_ms != 0:
                raise OperationRecoveryRetryVerificationReceiptError(
                    "invalid_recovery_retry_verification_not_started"
                )
            if any(value is not None for value in states):
                raise OperationRecoveryRetryVerificationReceiptError(
                    "recovery_retry_verification_state_without_execution"
                )
            return
        if self.timed_out:
            if self.exit_code is not None or any(value is not None for value in states):
                raise OperationRecoveryRetryVerificationReceiptError(
                    "invalid_recovery_retry_verification_timeout"
                )
            return
        if self.exit_code is None:
            raise OperationRecoveryRetryVerificationReceiptError(
                "missing_recovery_retry_verification_exit_code"
            )
        if self.exit_code != 0:
            if any(value is not None for value in states):
                raise OperationRecoveryRetryVerificationReceiptError(
                    "state_from_failed_recovery_retry_verification"
                )
            return
        for value in states:
            if not isinstance(value, str) or not STATE_VALUE.fullmatch(value):
                raise OperationRecoveryRetryVerificationReceiptError(
                    "invalid_recovery_retry_service_state"
                )


@dataclass(frozen=True, slots=True)
class OperationRecoveryRetryVerificationReceipt:
    receipt_id: str
    recovery_retry_execution_receipt_id: str
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
    expected_active_state: str
    verification_sha256: str
    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int
    load_state: str | None
    active_state: str | None
    sub_state: str | None
    unit_file_state: str | None
    recovery_verified: bool
    recovery_required: bool
    next_state: str
    from_state_version: int
    to_state_version: int
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
            "recovery_retry_execution_receipt_id":
                self.recovery_retry_execution_receipt_id,
            "retry_claim_id": self.retry_claim_id,
            "admission_id": self.admission_id,
            "rollback_verification_receipt_id":
                self.rollback_verification_receipt_id,
            "rollback_execution_receipt_id": self.rollback_execution_receipt_id,
            "job_id": self.job_id,
            "action_id": self.action_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "worker_id": self.worker_id,
            "target_node_id": self.target_node_id,
            "recovery_sha256": self.recovery_sha256,
            "expected_active_state": self.expected_active_state,
            "verification_sha256": self.verification_sha256,
            "started": self.started,
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
            "elapsed_ms": self.elapsed_ms,
            "load_state": self.load_state,
            "active_state": self.active_state,
            "sub_state": self.sub_state,
            "unit_file_state": self.unit_file_state,
            "recovery_verified": self.recovery_verified,
            "recovery_required": self.recovery_required,
            "from_state": self.from_state,
            "next_state": self.next_state,
            "from_state_version": self.from_state_version,
            "to_state_version": self.to_state_version,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "production_mutation_enabled": False,
        }


class OperationRecoveryRetryVerificationReceiptCoordinator:
    """Close one successful retry from a bounded typed verification observation."""

    def __init__(self, store: OperationRecoveryRetryVerificationStore) -> None:
        if not hasattr(store, "operation_job") or not hasattr(
            store, "transition_operation_job"
        ):
            raise TypeError("store does not provide operation transition primitives")
        self._store = store

    def record(
        self,
        execution: OperationRecoveryRetryExecutionReceipt,
        admission: OperationRecoveryRetryAdmission,
        prior_verification: OperationRollbackVerificationReceipt,
        prior_execution: OperationRollbackExecutionReceipt,
        request: OperationRecoveryRetryRequest,
        *,
        worker: OperationWorkerIdentity,
        observation: OperationRecoveryRetryVerificationObservation,
    ) -> tuple[OperationRecoveryRetryVerificationReceipt, bool]:
        _validate_inputs(
            execution,
            admission,
            prior_verification,
            prior_execution,
            request,
            worker,
            observation,
        )
        job = self._store.operation_job(execution.job_id)
        if job is None:
            raise OperationRecoveryRetryVerificationReceiptError(
                "operation_job_not_found"
            )
        replay = _replay_receipt(
            job,
            execution,
            admission,
            prior_verification,
            prior_execution,
            observation,
        )
        if replay is not None:
            return replay, False

        revalidate_operation_recovery_retry_execution_receipt(
            self._store,
            execution,
            admission,
            prior_verification,
            prior_execution,
            request,
            worker=worker,
        )
        job = self._store.operation_job(execution.job_id)
        if job is None:
            raise OperationRecoveryRetryVerificationReceiptError(
                "operation_job_not_found"
            )
        verification_sha256 = _validate_pending_job(
            job,
            execution,
            admission,
            prior_verification,
            prior_execution,
        )
        receipt = _build_receipt(
            execution,
            verification_sha256,
            _expected_active_state(job, execution),
            observation,
        )
        evidence = dict(job["evidence"])
        evidence["recovery_retry_verification_receipt"] = receipt.to_dict()
        result = dict(job["result"]) if isinstance(job.get("result"), dict) else {}
        result["recovery_retry_verification"] = _result_value(receipt)
        recovery = _recovery_with_verification(job, execution, receipt)

        try:
            updated = self._store.transition_operation_job(
                execution.job_id,
                expected_state=OperationJobState.ROLLING_BACK,
                expected_state_version=execution.to_state_version,
                target_state=OperationJobState(receipt.next_state),
                mutation_may_have_occurred=True,
                result=result,
                evidence=evidence,
                recovery=recovery,
            )
        except OperationJobPreconditionFailed:
            current = self._store.operation_job(execution.job_id)
            if current is not None:
                replay = _replay_receipt(
                    current,
                    execution,
                    admission,
                    prior_verification,
                    prior_execution,
                    observation,
                )
                if replay is not None:
                    return replay, False
            raise OperationRecoveryRetryVerificationReceiptError(
                "operation_recovery_retry_verification_stale"
            ) from None

        _validate_final_job(
            updated,
            execution,
            admission,
            prior_verification,
            prior_execution,
            receipt,
        )
        return receipt, True


def revalidate_operation_recovery_retry_verification_receipt(
    store: OperationRecoveryRetryVerificationStore,
    receipt: OperationRecoveryRetryVerificationReceipt,
    execution: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
) -> None:
    """Fail closed before a consumer treats recovery retry as complete."""

    if not isinstance(receipt, OperationRecoveryRetryVerificationReceipt):
        raise TypeError(
            "receipt must be OperationRecoveryRetryVerificationReceipt"
        )
    _validate_lineage(
        receipt,
        execution,
        admission,
        prior_verification,
        prior_execution,
    )
    job = store.operation_job(receipt.job_id)
    if job is None:
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_job_not_found"
        )
    _validate_final_job(
        job,
        execution,
        admission,
        prior_verification,
        prior_execution,
        receipt,
    )


def _validate_inputs(
    execution: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
    request: OperationRecoveryRetryRequest,
    worker: OperationWorkerIdentity,
    observation: OperationRecoveryRetryVerificationObservation,
) -> None:
    if not isinstance(execution, OperationRecoveryRetryExecutionReceipt):
        raise TypeError(
            "execution must be OperationRecoveryRetryExecutionReceipt"
        )
    if not isinstance(admission, OperationRecoveryRetryAdmission):
        raise TypeError("admission must be OperationRecoveryRetryAdmission")
    if not isinstance(prior_verification, OperationRollbackVerificationReceipt):
        raise TypeError(
            "prior_verification must be OperationRollbackVerificationReceipt"
        )
    if not isinstance(prior_execution, OperationRollbackExecutionReceipt):
        raise TypeError(
            "prior_execution must be OperationRollbackExecutionReceipt"
        )
    if not isinstance(request, OperationRecoveryRetryRequest):
        raise TypeError("request must be OperationRecoveryRetryRequest")
    if not isinstance(worker, OperationWorkerIdentity):
        raise TypeError("worker must be OperationWorkerIdentity")
    if not isinstance(observation, OperationRecoveryRetryVerificationObservation):
        raise TypeError(
            "observation must be OperationRecoveryRetryVerificationObservation"
        )
    _validate_execution_receipt(execution, worker)


def _validate_execution_receipt(
    execution: OperationRecoveryRetryExecutionReceipt,
    worker: OperationWorkerIdentity,
) -> None:
    value = execution.to_dict()
    if execution.action_id != ACTION_ID:
        raise OperationRecoveryRetryVerificationReceiptError(
            "unsupported_operation_action"
        )
    if worker.worker_id != execution.worker_id or worker.node_id != execution.target_node_id:
        raise OperationRecoveryRetryVerificationReceiptError(
            "recovery_retry_verification_worker_identity_mismatch"
        )
    if (
        not execution.retry_succeeded
        or execution.recovery_required
        or not execution.verification_required
        or execution.next_state != OperationJobState.ROLLING_BACK.value
    ):
        raise OperationRecoveryRetryVerificationReceiptError(
            "recovery_retry_execution_not_verifiable"
        )
    for name in (
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "grants_execution_authority",
        "production_mutation_enabled",
    ):
        if value.get(name) is not False:
            raise OperationRecoveryRetryVerificationReceiptError(
                "unsafe_recovery_retry_execution_receipt"
            )


def _validate_pending_job(
    job: dict[str, Any],
    execution: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
) -> str:
    if job.get("state") != OperationJobState.ROLLING_BACK.value:
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_job_not_rolling_back"
        )
    if job.get("state_version") != execution.to_state_version:
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_job_state_stale"
        )
    if job.get("mutation_may_have_occurred") is not True:
        raise OperationRecoveryRetryVerificationReceiptError(
            "mutation_evidence_missing"
        )
    if job.get("recovery_required") is not False:
        raise OperationRecoveryRetryVerificationReceiptError(
            "recovery_already_required"
        )
    _validate_job_lineage(
        job,
        execution,
        admission,
        prior_verification,
        prior_execution,
        include_verification=False,
    )
    _validate_recovery_contract(job, execution, prior_verification)
    return _verification_sha256(job, execution)


def _validate_final_job(
    job: dict[str, Any],
    execution: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
    receipt: OperationRecoveryRetryVerificationReceipt,
) -> None:
    _validate_lineage(
        receipt,
        execution,
        admission,
        prior_verification,
        prior_execution,
    )
    if job.get("state") != receipt.next_state:
        raise OperationRecoveryRetryVerificationReceiptError(
            "final_state_mismatch"
        )
    if job.get("state_version") != receipt.to_state_version:
        raise OperationRecoveryRetryVerificationReceiptError(
            "final_state_version_mismatch"
        )
    if job.get("mutation_may_have_occurred") is not True:
        raise OperationRecoveryRetryVerificationReceiptError(
            "mutation_evidence_missing"
        )
    if job.get("recovery_required") is not receipt.recovery_required:
        raise OperationRecoveryRetryVerificationReceiptError(
            "recovery_state_mismatch"
        )
    _validate_job_lineage(
        job,
        execution,
        admission,
        prior_verification,
        prior_execution,
        include_verification=True,
        receipt=receipt,
    )
    _validate_recovery_contract(
        job,
        execution,
        prior_verification,
        receipt=receipt,
    )
    if _verification_sha256(job, execution) != receipt.verification_sha256:
        raise OperationRecoveryRetryVerificationReceiptError(
            "verification_contract_drift"
        )
    result = job.get("result")
    if not isinstance(result, dict) or result.get(
        "recovery_retry_verification"
    ) != _result_value(receipt):
        raise OperationRecoveryRetryVerificationReceiptError(
            "verification_result_mismatch"
        )
    audit_event_id = job.get("last_audit_event_id")
    if not isinstance(audit_event_id, str) or not audit_event_id:
        raise OperationRecoveryRetryVerificationReceiptError(
            "transition_audit_missing"
        )


def _validate_job_lineage(
    job: dict[str, Any],
    execution: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
    *,
    include_verification: bool,
    receipt: OperationRecoveryRetryVerificationReceipt | None = None,
) -> None:
    for name in (
        "job_id",
        "action_id",
        "plan_id",
        "plan_sha256",
        "target_node_id",
    ):
        if job.get(name) != getattr(execution, name):
            raise OperationRecoveryRetryVerificationReceiptError(
                f"operation_job_{name}_mismatch"
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
    if include_verification:
        expected_keys.add("recovery_retry_verification_receipt")
    if not isinstance(evidence, dict) or set(evidence) != expected_keys:
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_evidence_shape_mismatch"
        )
    exact = {
        "rollback_execution_receipt": prior_execution.to_dict(),
        "rollback_verification_receipt": prior_verification.to_dict(),
        "recovery_retry_admission": admission.to_dict(),
        "recovery_retry_execution_receipt": execution.to_dict(),
    }
    for name, value in exact.items():
        if evidence.get(name) != value:
            raise OperationRecoveryRetryVerificationReceiptError(
                f"{name}_evidence_mismatch"
            )
    claim = evidence.get("recovery_retry_claim")
    if (
        not isinstance(claim, dict)
        or claim.get("claim_id") != execution.retry_claim_id
        or claim.get("admission_id") != execution.admission_id
        or claim.get("job_id") != execution.job_id
        or claim.get("plan_id") != execution.plan_id
        or claim.get("plan_sha256") != execution.plan_sha256
        or claim.get("worker_id") != execution.worker_id
        or claim.get("target_node_id") != execution.target_node_id
        or claim.get("recovery_sha256") != execution.recovery_sha256
    ):
        raise OperationRecoveryRetryVerificationReceiptError(
            "recovery_retry_claim_evidence_mismatch"
        )
    for name in (
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "execution_authorized",
        "production_mutation_enabled",
    ):
        if claim.get(name) is not False:
            raise OperationRecoveryRetryVerificationReceiptError(
                "unsafe_recovery_retry_claim_evidence"
            )
    if include_verification:
        assert receipt is not None
        if evidence.get(
            "recovery_retry_verification_receipt"
        ) != receipt.to_dict():
            raise OperationRecoveryRetryVerificationReceiptError(
                "recovery_retry_verification_evidence_mismatch"
            )


def _validate_recovery_contract(
    job: dict[str, Any],
    execution: OperationRecoveryRetryExecutionReceipt,
    prior_verification: OperationRollbackVerificationReceipt,
    *,
    receipt: OperationRecoveryRetryVerificationReceipt | None = None,
) -> None:
    recovery = job.get("recovery")
    if not isinstance(recovery, dict):
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_recovery_missing"
        )
    base = dict(recovery)
    verification = base.pop("verification", None)
    if receipt is None:
        expected_verification = {
            "receipt_id": prior_verification.receipt_id,
            "recovery_verified": False,
            "recovery_required": True,
        }
    else:
        expected_verification = {
            "receipt_id": receipt.receipt_id,
            "recovery_verified": receipt.recovery_verified,
            "recovery_required": receipt.recovery_required,
        }
    if verification != expected_verification:
        raise OperationRecoveryRetryVerificationReceiptError(
            "recovery_verification_evidence_mismatch"
        )
    plan = job.get("plan")
    if not isinstance(plan, dict) or plan.get("recovery") != base:
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_plan_recovery_mismatch"
        )
    if (
        hashlib.sha256(canonical_json(base).encode("utf-8")).hexdigest()
        != execution.recovery_sha256
    ):
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_recovery_integrity_mismatch"
        )


def _expected_active_state(
    job: dict[str, Any],
    execution: OperationRecoveryRetryExecutionReceipt,
) -> str:
    recovery = job.get("plan", {}).get("recovery")
    if not isinstance(recovery, dict):
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_recovery_contract_missing"
        )
    expected = recovery.get("expected_active_state")
    if expected not in {"active", "inactive"}:
        raise OperationRecoveryRetryVerificationReceiptError(
            "invalid_expected_active_state"
        )
    if (
        recovery.get("strategy") != "restore-observed-active-state"
        or recovery.get("verification_required") is not True
        or recovery.get("timeout_seconds") != 15
    ):
        raise OperationRecoveryRetryVerificationReceiptError(
            "unsafe_operation_recovery_contract"
        )
    verb = "start" if expected == "active" else "stop"
    if recovery.get("argv") != [SYSTEMCTL, verb, job.get("service")]:
        raise OperationRecoveryRetryVerificationReceiptError(
            "unsafe_operation_recovery_argv"
        )
    if job.get("service") not in ALLOWED_SERVICES:
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_service_not_allowlisted"
        )
    if (
        hashlib.sha256(canonical_json(recovery).encode("utf-8")).hexdigest()
        != execution.recovery_sha256
    ):
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_recovery_integrity_mismatch"
        )
    return expected


def _verification_sha256(
    job: dict[str, Any],
    execution: OperationRecoveryRetryExecutionReceipt,
) -> str:
    plan = job.get("plan")
    if not isinstance(plan, dict):
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_plan_missing"
        )
    if (
        hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()
        != execution.plan_sha256
    ):
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_plan_integrity_mismatch"
        )
    expected_active_state = _expected_active_state(job, execution)
    argv = [
        SYSTEMCTL,
        "show",
        job["service"],
        "--property=LoadState",
        "--property=ActiveState",
        "--property=SubState",
        "--property=UnitFileState",
        "--no-pager",
    ]
    verification = plan.get("verification")
    if (
        not isinstance(verification, dict)
        or verification.get("argv") != argv
        or verification.get("timeout_seconds") != 5
    ):
        raise OperationRecoveryRetryVerificationReceiptError(
            "verification_contract_mismatch"
        )
    material = {
        "argv": argv,
        "timeout_seconds": 5,
        "expected_active_state": expected_active_state,
    }
    return hashlib.sha256(
        canonical_json(material).encode("utf-8")
    ).hexdigest()


def _build_receipt(
    execution: OperationRecoveryRetryExecutionReceipt,
    verification_sha256: str,
    expected_active_state: str,
    observation: OperationRecoveryRetryVerificationObservation,
) -> OperationRecoveryRetryVerificationReceipt:
    verified = (
        observation.started
        and not observation.timed_out
        and observation.exit_code == 0
        and observation.load_state == "loaded"
        and observation.active_state == expected_active_state
    )
    next_state = (
        OperationJobState.ROLLED_BACK
        if verified
        else OperationJobState.FAILED
    )
    identity = {
        "recovery_retry_execution_receipt_id": execution.receipt_id,
        "retry_claim_id": execution.retry_claim_id,
        "admission_id": execution.admission_id,
        "verification_sha256": verification_sha256,
        "expected_active_state": expected_active_state,
        "observation": {
            "started": observation.started,
            "timed_out": observation.timed_out,
            "exit_code": observation.exit_code,
            "elapsed_ms": observation.elapsed_ms,
            "load_state": observation.load_state,
            "active_state": observation.active_state,
            "sub_state": observation.sub_state,
            "unit_file_state": observation.unit_file_state,
        },
        "recovery_verified": verified,
        "recovery_required": not verified,
        "from_state_version": execution.to_state_version,
        "to_state_version": execution.to_state_version + 1,
        "next_state": next_state.value,
    }
    digest = hashlib.sha256(
        canonical_json(identity).encode("utf-8")
    ).hexdigest()
    return OperationRecoveryRetryVerificationReceipt(
        receipt_id=f"oprecoveryverify-{digest[:24]}",
        recovery_retry_execution_receipt_id=execution.receipt_id,
        retry_claim_id=execution.retry_claim_id,
        admission_id=execution.admission_id,
        rollback_verification_receipt_id=execution.rollback_verification_receipt_id,
        rollback_execution_receipt_id=execution.rollback_execution_receipt_id,
        job_id=execution.job_id,
        action_id=execution.action_id,
        plan_id=execution.plan_id,
        plan_sha256=execution.plan_sha256,
        worker_id=execution.worker_id,
        target_node_id=execution.target_node_id,
        recovery_sha256=execution.recovery_sha256,
        expected_active_state=expected_active_state,
        verification_sha256=verification_sha256,
        started=observation.started,
        timed_out=observation.timed_out,
        exit_code=observation.exit_code,
        elapsed_ms=observation.elapsed_ms,
        load_state=observation.load_state,
        active_state=observation.active_state,
        sub_state=observation.sub_state,
        unit_file_state=observation.unit_file_state,
        recovery_verified=verified,
        recovery_required=not verified,
        next_state=next_state.value,
        from_state_version=execution.to_state_version,
        to_state_version=execution.to_state_version + 1,
    )


def _replay_receipt(
    job: dict[str, Any],
    execution: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
    observation: OperationRecoveryRetryVerificationObservation,
) -> OperationRecoveryRetryVerificationReceipt | None:
    if job.get("state") not in {
        OperationJobState.ROLLED_BACK.value,
        OperationJobState.FAILED.value,
    }:
        return None
    if job.get("state_version") != execution.to_state_version + 1:
        return None
    evidence = job.get("evidence")
    if not isinstance(evidence, dict):
        return None
    value = evidence.get("recovery_retry_verification_receipt")
    if not isinstance(value, dict):
        return None
    receipt = _receipt_from_dict(value)
    candidate = _build_receipt(
        execution,
        _verification_sha256(job, execution),
        _expected_active_state(job, execution),
        observation,
    )
    if receipt != candidate:
        raise OperationRecoveryRetryVerificationReceiptError(
            "recovery_retry_verification_conflict"
        )
    _validate_final_job(
        job,
        execution,
        admission,
        prior_verification,
        prior_execution,
        receipt,
    )
    return receipt


def _receipt_from_dict(
    value: dict[str, Any],
) -> OperationRecoveryRetryVerificationReceipt:
    fixed = {
        "schema",
        "from_state",
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "grants_execution_authority",
        "production_mutation_enabled",
    }
    expected = (
        set(OperationRecoveryRetryVerificationReceipt.__dataclass_fields__)
        - fixed
    )
    if set(value) != expected | fixed:
        raise OperationRecoveryRetryVerificationReceiptError(
            "recovery_retry_verification_shape_mismatch"
        )
    receipt = OperationRecoveryRetryVerificationReceipt(
        **{name: value[name] for name in expected}
    )
    if receipt.to_dict() != value:
        raise OperationRecoveryRetryVerificationReceiptError(
            "recovery_retry_verification_shape_mismatch"
        )
    return receipt


def _validate_lineage(
    receipt: OperationRecoveryRetryVerificationReceipt,
    execution: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
) -> None:
    if (
        execution.admission_id != admission.admission_id
        or execution.rollback_verification_receipt_id
        != prior_verification.receipt_id
        or execution.rollback_execution_receipt_id != prior_execution.receipt_id
    ):
        raise OperationRecoveryRetryVerificationReceiptError(
            "recovery_retry_verification_upstream_lineage_mismatch"
        )
    expected = {
        "recovery_retry_execution_receipt_id": execution.receipt_id,
        "retry_claim_id": execution.retry_claim_id,
        "admission_id": admission.admission_id,
        "rollback_verification_receipt_id": prior_verification.receipt_id,
        "rollback_execution_receipt_id": prior_execution.receipt_id,
        "job_id": execution.job_id,
        "action_id": execution.action_id,
        "plan_id": execution.plan_id,
        "plan_sha256": execution.plan_sha256,
        "worker_id": execution.worker_id,
        "target_node_id": execution.target_node_id,
        "recovery_sha256": execution.recovery_sha256,
        "from_state_version": execution.to_state_version,
        "to_state_version": execution.to_state_version + 1,
    }
    for name, value in expected.items():
        if getattr(receipt, name) != value:
            raise OperationRecoveryRetryVerificationReceiptError(
                f"recovery_retry_verification_{name}_mismatch"
            )
    if receipt.expected_active_state not in {"active", "inactive"}:
        raise OperationRecoveryRetryVerificationReceiptError(
            "invalid_expected_active_state"
        )
    if (
        not isinstance(receipt.recovery_verified, bool)
        or not isinstance(receipt.recovery_required, bool)
        or receipt.recovery_required == receipt.recovery_verified
    ):
        raise OperationRecoveryRetryVerificationReceiptError(
            "invalid_recovery_retry_verification_result"
        )
    expected_state = (
        OperationJobState.ROLLED_BACK.value
        if receipt.recovery_verified
        else OperationJobState.FAILED.value
    )
    if receipt.next_state != expected_state:
        raise OperationRecoveryRetryVerificationReceiptError(
            "invalid_recovery_retry_verification_state"
        )
    for name in (
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "grants_execution_authority",
        "production_mutation_enabled",
    ):
        if receipt.to_dict().get(name) is not False:
            raise OperationRecoveryRetryVerificationReceiptError(
                "unsafe_recovery_retry_verification_receipt"
            )


def _recovery_with_verification(
    job: dict[str, Any],
    execution: OperationRecoveryRetryExecutionReceipt,
    receipt: OperationRecoveryRetryVerificationReceipt,
) -> dict[str, Any]:
    recovery = job.get("recovery")
    if not isinstance(recovery, dict):
        raise OperationRecoveryRetryVerificationReceiptError(
            "operation_recovery_missing"
        )
    value = dict(recovery)
    value["verification"] = {
        "receipt_id": receipt.receipt_id,
        "recovery_verified": receipt.recovery_verified,
        "recovery_required": receipt.recovery_required,
    }
    return value


def _result_value(
    receipt: OperationRecoveryRetryVerificationReceipt,
) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "started": receipt.started,
        "timed_out": receipt.timed_out,
        "exit_code": receipt.exit_code,
        "elapsed_ms": receipt.elapsed_ms,
        "load_state": receipt.load_state,
        "active_state": receipt.active_state,
        "sub_state": receipt.sub_state,
        "unit_file_state": receipt.unit_file_state,
        "expected_active_state": receipt.expected_active_state,
        "recovery_verified": receipt.recovery_verified,
        "recovery_required": receipt.recovery_required,
        "next_state": receipt.next_state,
    }
