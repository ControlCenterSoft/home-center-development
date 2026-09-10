from __future__ import annotations

import inspect
import unittest
from unittest.mock import patch

from home_center.operation_recovery_retry_admission import (
    OperationRecoveryRetryAdmission,
)
from home_center.operation_recovery_retry_execution_receipt import (
    OperationRecoveryRetryExecutionReceipt,
)
from home_center.operation_recovery_retry_terminal_reconciliation import (
    OperationRecoveryRetryTerminalReconciliationError,
    assess_operation_recovery_retry_completion_from_job,
)
from home_center.operation_recovery_retry_verification_receipt import (
    OperationRecoveryRetryVerificationReceipt,
)
from home_center.operation_rollback_execution_receipt import (
    OperationRollbackExecutionReceipt,
)
from home_center.operation_rollback_verification_receipt import (
    OperationRollbackVerificationReceipt,
)


class FakeStore:
    def __init__(self, job: dict | None) -> None:
        self.job = job

    def operation_job(self, job_id: str):
        if self.job is None or self.job.get("job_id") != job_id:
            return None
        return self.job


class TerminalJobDerivedReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        job_id = "opjob-" + "1" * 24
        plan_id = "opplan-" + "2" * 24
        plan_sha256 = "3" * 64
        recovery_sha256 = "4" * 64
        target_node_id = "home-node-a"
        action_id = "service.restart"

        self.prior_execution = OperationRollbackExecutionReceipt(
            receipt_id="oprollbackexec-" + "f" * 24,
            rollback_claim_id="oprollback-" + "6" * 24,
            verification_receipt_id="opverify-" + "7" * 24,
            execution_receipt_id="opreceipt-" + "8" * 24,
            job_id=job_id,
            action_id=action_id,
            plan_id=plan_id,
            plan_sha256=plan_sha256,
            worker_id="worker-original",
            target_node_id=target_node_id,
            recovery_sha256=recovery_sha256,
            recovery_strategy="restore-observed-active-state",
            expected_active_state="active",
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=100,
            rollback_succeeded=True,
            recovery_required=False,
            next_state="rolling_back",
            from_state_version=2,
            to_state_version=3,
            verification_required=True,
            audit_event_id="audit-rollback-execution",
        )
        self.prior_verification = OperationRollbackVerificationReceipt(
            receipt_id="oprollbackverify-" + "e" * 24,
            rollback_execution_receipt_id=self.prior_execution.receipt_id,
            rollback_claim_id=self.prior_execution.rollback_claim_id,
            verification_receipt_id=self.prior_execution.verification_receipt_id,
            execution_receipt_id=self.prior_execution.execution_receipt_id,
            job_id=job_id,
            action_id=action_id,
            plan_id=plan_id,
            plan_sha256=plan_sha256,
            worker_id=self.prior_execution.worker_id,
            target_node_id=target_node_id,
            recovery_sha256=recovery_sha256,
            expected_active_state="active",
            verification_sha256="9" * 64,
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=75,
            load_state="loaded",
            active_state="inactive",
            sub_state="dead",
            unit_file_state="enabled",
            recovery_verified=False,
            recovery_required=True,
            next_state="failed",
            from_state_version=3,
            to_state_version=4,
        )
        self.admission = OperationRecoveryRetryAdmission(
            admission_id="oprecoveryretryadmission-" + "d" * 24,
            rollback_verification_receipt_id=self.prior_verification.receipt_id,
            rollback_execution_receipt_id=self.prior_execution.receipt_id,
            job_id=job_id,
            action_id=action_id,
            plan_id=plan_id,
            plan_sha256=plan_sha256,
            target_node_id=target_node_id,
            recovery_sha256=recovery_sha256,
            failed_state_version=4,
            failed_audit_event_id="audit-failed",
            retry_authorization_id="opauth-" + "a" * 24,
            retry_correlation_id="retry-correlation-0001",
            retry_reason_sha256="b" * 64,
        )
        self.execution = OperationRecoveryRetryExecutionReceipt(
            receipt_id="oprecoveryretryexec-" + "b" * 24,
            retry_claim_id="oprecoveryretryclaim-" + "c" * 24,
            admission_id=self.admission.admission_id,
            rollback_verification_receipt_id=self.prior_verification.receipt_id,
            rollback_execution_receipt_id=self.prior_execution.receipt_id,
            job_id=job_id,
            action_id=action_id,
            plan_id=plan_id,
            plan_sha256=plan_sha256,
            worker_id="worker-retry-a",
            target_node_id=target_node_id,
            recovery_sha256=recovery_sha256,
            command_sha256="6" * 64,
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=120,
            retry_succeeded=True,
            recovery_required=False,
            next_state="rolling_back",
            from_state_version=6,
            to_state_version=7,
            verification_required=True,
            audit_event_id="audit-recovery-retry-execution",
        )
        self.receipt = OperationRecoveryRetryVerificationReceipt(
            receipt_id="oprecoveryverify-" + "a" * 24,
            recovery_retry_execution_receipt_id=self.execution.receipt_id,
            retry_claim_id=self.execution.retry_claim_id,
            admission_id=self.admission.admission_id,
            rollback_verification_receipt_id=self.prior_verification.receipt_id,
            rollback_execution_receipt_id=self.prior_execution.receipt_id,
            job_id=job_id,
            action_id=action_id,
            plan_id=plan_id,
            plan_sha256=plan_sha256,
            worker_id=self.execution.worker_id,
            target_node_id=target_node_id,
            recovery_sha256=recovery_sha256,
            expected_active_state="active",
            verification_sha256="5" * 64,
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=45,
            load_state="loaded",
            active_state="active",
            sub_state="running",
            unit_file_state="enabled",
            recovery_verified=True,
            recovery_required=False,
            next_state="rolled_back",
            from_state_version=self.execution.to_state_version,
            to_state_version=self.execution.to_state_version + 1,
        )
        self.job = {
            "job_id": job_id,
            "action_id": action_id,
            "state": self.receipt.next_state,
            "state_version": self.receipt.to_state_version,
            "plan_id": plan_id,
            "plan_sha256": plan_sha256,
            "target_node_id": target_node_id,
            "evidence": {
                "worker_claim": {"kind": "prior-worker-claim"},
                "execution_receipt": {"kind": "prior-execution"},
                "verification_receipt": {"kind": "prior-verification"},
                "rollback_claim": {"kind": "prior-rollback-claim"},
                "rollback_execution_receipt": self.prior_execution.to_dict(),
                "rollback_verification_receipt": self.prior_verification.to_dict(),
                "recovery_retry_admission": self.admission.to_dict(),
                "recovery_retry_claim": {
                    "claim_id": self.execution.retry_claim_id,
                    "admission_id": self.admission.admission_id,
                    "job_id": job_id,
                    "plan_id": plan_id,
                    "plan_sha256": plan_sha256,
                    "worker_id": self.execution.worker_id,
                    "target_node_id": target_node_id,
                    "recovery_sha256": recovery_sha256,
                    "contains_command_material": False,
                    "accepts_caller_argv": False,
                    "accepts_shell": False,
                    "execution_authorized": False,
                    "production_mutation_enabled": False,
                },
                "recovery_retry_execution_receipt": self.execution.to_dict(),
                "recovery_retry_verification_receipt": self.receipt.to_dict(),
            },
        }
        self.store = FakeStore(self.job)

    def _call(self):
        with patch(
            "home_center.operation_recovery_retry_terminal_reconciliation."
            "assess_operation_recovery_retry_verification_completion"
        ) as delegate:
            sentinel = object()
            delegate.return_value = sentinel
            result = assess_operation_recovery_retry_completion_from_job(
                self.store,
                self.receipt.job_id,
            )
            return result, delegate

    def test_entry_point_has_no_caller_selected_lineage_arguments(self):
        parameters = tuple(
            inspect.signature(
                assess_operation_recovery_retry_completion_from_job
            ).parameters
        )
        self.assertEqual(("store", "job_id"), parameters)

    def test_exact_job_lineage_is_reconstructed_and_delegated(self):
        result, delegate = self._call()

        self.assertIs(result, delegate.return_value)
        args = delegate.call_args.args
        self.assertEqual(self.receipt, args[1])
        self.assertEqual(self.execution, args[2])
        self.assertEqual(self.admission, args[3])
        self.assertEqual(self.prior_verification, args[4])
        self.assertEqual(self.prior_execution, args[5])

    def test_missing_job_fails_closed(self):
        self.store.job = None
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "operation_job_missing",
        ):
            self._call()

    def test_nonterminal_job_fails_closed(self):
        self.job["state"] = "rolling_back"
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "operation_job_not_terminal",
        ):
            self._call()

    def test_missing_terminal_lineage_evidence_fails_closed(self):
        del self.job["evidence"]["recovery_retry_admission"]
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "operation_evidence_shape_mismatch",
        ):
            self._call()

    def test_extra_terminal_evidence_fails_closed(self):
        self.job["evidence"]["caller_selected_command"] = "/bin/sh"
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "operation_evidence_shape_mismatch",
        ):
            self._call()

    def test_extra_verification_receipt_field_fails_closed(self):
        raw = self.job["evidence"]["recovery_retry_verification_receipt"]
        raw["caller_selected_command"] = "/bin/sh"
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "shape_mismatch",
        ):
            self._call()

    def test_upstream_roundtrip_tamper_fails_closed(self):
        raw = self.job["evidence"]["recovery_retry_admission"]
        raw["caller_selected_command"] = "/bin/sh"
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "recovery_retry_admission_roundtrip_mismatch",
        ):
            self._call()

    def test_boolean_integer_confusion_fails_closed(self):
        raw = self.job["evidence"]["recovery_retry_admission"]
        raw["failed_state_version"] = True
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "recovery_retry_admission_type_mismatch",
        ):
            self._call()

    def test_terminal_state_version_drift_fails_closed(self):
        self.job["state_version"] += 1
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "verification_receipt_not_current",
        ):
            self._call()

    def test_job_lineage_drift_fails_closed(self):
        self.job["plan_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "verification_receipt_not_current",
        ):
            self._call()

    def test_cross_lineage_execution_is_rejected_before_delegate(self):
        raw = self.job["evidence"]["recovery_retry_execution_receipt"]
        raw["receipt_id"] = "oprecoveryretryexec-" + "0" * 24
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "durable_terminal_lineage_mismatch",
        ):
            self._call()


if __name__ == "__main__":
    unittest.main()
