"""Job-derived, fail-closed entry point for recovery retry terminal reconciliation."""

from __future__ import annotations

from typing import Any

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


def assess_operation_recovery_retry_completion_from_job(
    store: OperationRecoveryRetryCompletionReconciliationStore,
    job_id: str,
    execution: OperationRecoveryRetryExecutionReceipt,
    admission: OperationRecoveryRetryAdmission,
    prior_verification: OperationRollbackVerificationReceipt,
    prior_execution: OperationRollbackExecutionReceipt,
) -> OperationRecoveryRetryCompletionReconciliation:
    """Reconcile one terminal job using only its durable verification receipt."""

    if not isinstance(job_id, str) or not job_id:
        raise OperationRecoveryRetryTerminalReconciliationError("invalid_job_id")
    if not hasattr(store, "operation_job"):
        raise TypeError("store does not provide operation_job")

    job = store.operation_job(job_id)
    if job is None:
        raise OperationRecoveryRetryTerminalReconciliationError(
            "operation_job_missing"
        )
    receipt = _receipt_from_terminal_job(job, job_id)
    return assess_operation_recovery_retry_verification_completion(
        store,
        receipt,
        execution,
        admission,
        prior_verification,
        prior_execution,
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
    if receipt.to_dict() != raw:
        raise OperationRecoveryRetryTerminalReconciliationError(
            "recovery_retry_verification_receipt_roundtrip_mismatch"
        )
    return receipt
