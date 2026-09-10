"""Job-derived, fail-closed entry point for recovery retry terminal reconciliation."""

from __future__ import annotations

import types
from dataclasses import fields
from typing import Any, TypeVar, Union, get_args, get_origin, get_type_hints

from .operation_recovery_retry_admission import OperationRecoveryRetryAdmission
from .operation_recovery_retry_completion_reconciliation import (
    OperationRecoveryRetryCompletionReconciliation,
    OperationRecoveryRetryCompletionReconciliationStore,
    assess_operation_recovery_retry_verification_completion,
)
from .operation_recovery_retry_execution_receipt import (
    OperationRecoveryRetryExecutionReceipt,
)
from .operation_recovery_retry_verification_receipt import (
    SCHEMA as VERIFICATION_RECEIPT_SCHEMA,
    OperationRecoveryRetryVerificationReceipt,
)
from .operation_rollback_execution_receipt import OperationRollbackExecutionReceipt
from .operation_rollback_verification_receipt import OperationRollbackVerificationReceipt
from .util import canonical_json


class OperationRecoveryRetryTerminalReconciliationError(RuntimeError):
    """Durable terminal evidence could not be reconstructed safely."""


_RECEIPT_FIXED_VALUES = {
    "schema": VERIFICATION_RECEIPT_SCHEMA,
    "from_state": "rolling_back",
    "contains_command_material": False,
    "accepts_caller_argv": False,
    "accepts_shell": False,
    "grants_execution_authority": False,
    "production_mutation_enabled": False,
}

_RECEIPT_INIT_FIELDS = (
    "receipt_id",
    "recovery_retry_execution_receipt_id",
    "retry_claim_id",
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
    "expected_active_state",
    "verification_sha256",
    "started",
    "timed_out",
    "exit_code",
    "elapsed_ms",
    "load_state",
    "active_state",
    "sub_state",
    "unit_file_state",
    "recovery_verified",
    "recovery_required",
    "next_state",
    "from_state_version",
    "to_state_version",
)
_RECEIPT_KEYS = frozenset(_RECEIPT_INIT_FIELDS) | frozenset(_RECEIPT_FIXED_VALUES)
_STRING_FIELDS = (
    "receipt_id",
    "recovery_retry_execution_receipt_id",
    "retry_claim_id",
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
    "expected_active_state",
    "verification_sha256",
    "next_state",
)
_OPTIONAL_STRING_FIELDS = (
    "load_state",
    "active_state",
    "sub_state",
    "unit_file_state",
)
_REQUIRED_EVIDENCE_KEYS = frozenset(
    {
        "worker_claim",
        "execution_receipt",
        "verification_receipt",
        "rollback_claim",
        "rollback_execution_receipt",
        "rollback_verification_receipt",
        "recovery_retry_admission",
        "recovery_retry_claim",
        "recovery_retry_execution_receipt",
        "recovery_retry_verification_receipt",
    }
)

_T = TypeVar("_T")


def assess_operation_recovery_retry_completion_from_job(
    store: OperationRecoveryRetryCompletionReconciliationStore,
    job_id: str,
) -> OperationRecoveryRetryCompletionReconciliation:
    """Reconcile one terminal job using only its durable evidence lineage."""

    if not isinstance(job_id, str) or not job_id:
        raise OperationRecoveryRetryTerminalReconciliationError("invalid_job_id")
    if not hasattr(store, "operation_job"):
        raise TypeError("store does not provide operation_job")

    job = store.operation_job(job_id)
    if job is None:
        raise OperationRecoveryRetryTerminalReconciliationError(
            "operation_job_missing"
        )
    receipt, execution, admission, prior_verification, prior_execution = (
        _lineage_from_terminal_job(job, job_id)
    )
    return assess_operation_recovery_retry_verification_completion(
        store,
        receipt,
        execution,
        admission,
        prior_verification,
        prior_execution,
    )


def _lineage_from_terminal_job(
    job: dict[str, Any],
    job_id: str,
) -> tuple[
    OperationRecoveryRetryVerificationReceipt,
    OperationRecoveryRetryExecutionReceipt,
    OperationRecoveryRetryAdmission,
    OperationRollbackVerificationReceipt,
    OperationRollbackExecutionReceipt,
]:
    if not isinstance(job, dict) or job.get("job_id") != job_id:
        raise OperationRecoveryRetryTerminalReconciliationError(
            "operation_job_identity_mismatch"
        )
    if job.get("state") not in {"rolled_back", "failed"}:
        raise OperationRecoveryRetryTerminalReconciliationError(
            "operation_job_not_terminal"
        )
    evidence = job.get("evidence")
    if not isinstance(evidence, dict):
        raise OperationRecoveryRetryTerminalReconciliationError(
            "operation_evidence_missing"
        )
    if set(evidence) != _REQUIRED_EVIDENCE_KEYS:
        raise OperationRecoveryRetryTerminalReconciliationError(
            "operation_evidence_shape_mismatch"
        )

    receipt = _receipt_from_terminal_job(job, job_id)
    execution = _typed_evidence(
        evidence,
        "recovery_retry_execution_receipt",
        OperationRecoveryRetryExecutionReceipt,
    )
    admission = _typed_evidence(
        evidence,
        "recovery_retry_admission",
        OperationRecoveryRetryAdmission,
    )
    prior_verification = _typed_evidence(
        evidence,
        "rollback_verification_receipt",
        OperationRollbackVerificationReceipt,
    )
    prior_execution = _typed_evidence(
        evidence,
        "rollback_execution_receipt",
        OperationRollbackExecutionReceipt,
    )
    _validate_terminal_lineage(
        job,
        receipt,
        execution,
        admission,
        prior_verification,
        prior_execution,
    )
    return (
        receipt,
        execution,
        admission,
        prior_verification,
        prior_execution,
    )


def _typed_evidence(
    evidence: dict[str, Any],
    key: str,
    expected_type: type[_T],
) -> _T:
    raw = evidence.get(key)
    if not isinstance(raw, dict):
        raise OperationRecoveryRetryTerminalReconciliationError(
            f"{key}_missing"
        )

    init_fields = tuple(field.name for field in fields(expected_type) if field.init)
    type_hints = get_type_hints(expected_type)
    try:
        values = {name: raw[name] for name in init_fields}
    except KeyError as exc:
        raise OperationRecoveryRetryTerminalReconciliationError(
            f"{key}_shape_mismatch"
        ) from exc

    for name, value in values.items():
        annotation = type_hints.get(name, Any)
        if not _value_matches_type(value, annotation):
            raise OperationRecoveryRetryTerminalReconciliationError(
                f"{key}_type_mismatch"
            )

    try:
        candidate = expected_type(**values)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise OperationRecoveryRetryTerminalReconciliationError(
            f"{key}_invalid"
        ) from exc

    to_dict = getattr(candidate, "to_dict", None)
    if not callable(to_dict):
        raise TypeError(f"{expected_type.__name__} does not provide to_dict")
    try:
        rebuilt = to_dict()
        if canonical_json(rebuilt) != canonical_json(raw):
            raise OperationRecoveryRetryTerminalReconciliationError(
                f"{key}_roundtrip_mismatch"
            )
    except OperationRecoveryRetryTerminalReconciliationError:
        raise
    except (TypeError, ValueError) as exc:
        raise OperationRecoveryRetryTerminalReconciliationError(
            f"{key}_invalid"
        ) from exc
    return candidate


def _value_matches_type(value: Any, annotation: Any) -> bool:
    if annotation is Any:
        return True
    if annotation is bool:
        return isinstance(value, bool)
    if annotation is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if annotation is str:
        return isinstance(value, str)
    if annotation is type(None):
        return value is None

    origin = get_origin(annotation)
    if origin in {types.UnionType, Union}:
        return any(_value_matches_type(value, item) for item in get_args(annotation))
    return True


def _validate_terminal_lineage(
    job: dict[str, Any],
    receipt: OperationRecoveryRetryVerificationReceipt,
    execution: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
) -> None:
    for candidate in (execution, admission, prior_verification, prior_execution):
        for name in (
            "job_id",
            "action_id",
            "plan_id",
            "plan_sha256",
            "target_node_id",
        ):
            if getattr(candidate, name, None) != job.get(name):
                raise OperationRecoveryRetryTerminalReconciliationError(
                    "durable_terminal_lineage_mismatch"
                )

    if (
        receipt.recovery_retry_execution_receipt_id != execution.receipt_id
        or receipt.retry_claim_id != execution.retry_claim_id
        or receipt.admission_id != admission.admission_id
        or execution.admission_id != admission.admission_id
        or receipt.rollback_verification_receipt_id != prior_verification.receipt_id
        or execution.rollback_verification_receipt_id
        != prior_verification.receipt_id
        or admission.rollback_verification_receipt_id
        != prior_verification.receipt_id
        or receipt.rollback_execution_receipt_id != prior_execution.receipt_id
        or execution.rollback_execution_receipt_id != prior_execution.receipt_id
        or admission.rollback_execution_receipt_id != prior_execution.receipt_id
        or prior_verification.rollback_execution_receipt_id
        != prior_execution.receipt_id
        or receipt.worker_id != execution.worker_id
        or receipt.recovery_sha256 != execution.recovery_sha256
        or receipt.recovery_sha256 != admission.recovery_sha256
        or receipt.recovery_sha256 != prior_verification.recovery_sha256
        or receipt.recovery_sha256 != prior_execution.recovery_sha256
        or receipt.from_state_version != execution.to_state_version
    ):
        raise OperationRecoveryRetryTerminalReconciliationError(
            "durable_terminal_lineage_mismatch"
        )


def _receipt_from_terminal_job(
    job: dict[str, Any],
    job_id: str,
) -> OperationRecoveryRetryVerificationReceipt:
    if not isinstance(job, dict) or job.get("job_id") != job_id:
        raise OperationRecoveryRetryTerminalReconciliationError(
            "operation_job_identity_mismatch"
        )
    if job.get("state") not in {"rolled_back", "failed"}:
        raise OperationRecoveryRetryTerminalReconciliationError(
            "operation_job_not_terminal"
        )

    evidence = job.get("evidence")
    if not isinstance(evidence, dict):
        raise OperationRecoveryRetryTerminalReconciliationError(
            "operation_evidence_missing"
        )
    raw = evidence.get("recovery_retry_verification_receipt")
    if not isinstance(raw, dict):
        raise OperationRecoveryRetryTerminalReconciliationError(
            "recovery_retry_verification_receipt_missing"
        )
    if set(raw) != _RECEIPT_KEYS:
        raise OperationRecoveryRetryTerminalReconciliationError(
            "recovery_retry_verification_receipt_shape_mismatch"
        )
    for name, expected in _RECEIPT_FIXED_VALUES.items():
        if raw.get(name) is not expected and raw.get(name) != expected:
            raise OperationRecoveryRetryTerminalReconciliationError(
                "unsafe_recovery_retry_verification_receipt"
            )
    for name in _STRING_FIELDS:
        if not isinstance(raw.get(name), str) or not raw[name]:
            raise OperationRecoveryRetryTerminalReconciliationError(
                "invalid_recovery_retry_verification_receipt_types"
            )
    for name in _OPTIONAL_STRING_FIELDS:
        value = raw.get(name)
        if value is not None and (not isinstance(value, str) or not value):
            raise OperationRecoveryRetryTerminalReconciliationError(
                "invalid_recovery_retry_verification_receipt_types"
            )
    for name in ("started", "timed_out", "recovery_verified", "recovery_required"):
        if not isinstance(raw.get(name), bool):
            raise OperationRecoveryRetryTerminalReconciliationError(
                "invalid_recovery_retry_verification_receipt_types"
            )
    for name in ("elapsed_ms", "from_state_version", "to_state_version"):
        if not isinstance(raw.get(name), int) or isinstance(raw.get(name), bool):
            raise OperationRecoveryRetryTerminalReconciliationError(
                "invalid_recovery_retry_verification_receipt_types"
            )
    exit_code = raw.get("exit_code")
    if exit_code is not None and (
        not isinstance(exit_code, int) or isinstance(exit_code, bool)
    ):
        raise OperationRecoveryRetryTerminalReconciliationError(
            "invalid_recovery_retry_verification_receipt_types"
        )

    if (
        raw["job_id"] != job_id
        or raw["action_id"] != job.get("action_id")
        or raw["plan_id"] != job.get("plan_id")
        or raw["plan_sha256"] != job.get("plan_sha256")
        or raw["target_node_id"] != job.get("target_node_id")
        or raw["next_state"] != job.get("state")
        or raw["to_state_version"] != job.get("state_version")
    ):
        raise OperationRecoveryRetryTerminalReconciliationError(
            "recovery_retry_verification_receipt_not_current"
        )

    values = {name: raw[name] for name in _RECEIPT_INIT_FIELDS}
    receipt = OperationRecoveryRetryVerificationReceipt(**values)
    if canonical_json(receipt.to_dict()) != canonical_json(raw):
        raise OperationRecoveryRetryTerminalReconciliationError(
            "recovery_retry_verification_receipt_roundtrip_mismatch"
        )
    return receipt
