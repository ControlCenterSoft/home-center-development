from __future__ import annotations

import unittest
from unittest.mock import patch

from home_center.operation_recovery_retry_terminal_reconciliation import (
    OperationRecoveryRetryTerminalReconciliationError,
    assess_operation_recovery_retry_completion_from_job,
)
from home_center.operation_recovery_retry_verification_receipt import (
    OperationRecoveryRetryVerificationReceipt,
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
        self.receipt = OperationRecoveryRetryVerificationReceipt(
            receipt_id="oprecoveryverify-" + "a" * 24,
            recovery_retry_execution_receipt_id="oprecoveryretryexec-" + "b" * 24,
            retry_claim_id="oprecoveryretryclaim-" + "c" * 24,
            admission_id="oprecoveryretryadmission-" + "d" * 24,
            rollback_verification_receipt_id="oprollbackverify-" + "e" * 24,
            rollback_execution_receipt_id="oprollbackexec-" + "f" * 24,
            job_id="opjob-" + "1" * 24,
            action_id="service.restart",
            plan_id="opplan-" + "2" * 24,
            plan_sha256="3" * 64,
            worker_id="worker-a",
            target_node_id="home-node-a",
            recovery_sha256="4" * 64,
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
            from_state_version=7,
            to_state_version=8,
        )
        self.job = {
            "job_id": self.receipt.job_id,
            "action_id": self.receipt.action_id,
            "state": self.receipt.next_state,
            "state_version": self.receipt.to_state_version,
            "plan_id": self.receipt.plan_id,
            "plan_sha256": self.receipt.plan_sha256,
            "target_node_id": self.receipt.target_node_id,
            "evidence": {
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
                object(),
                object(),
                object(),
                object(),
            )
            return result, delegate

    def test_exact_job_evidence_is_reconstructed_and_delegated(self):
        result, delegate = self._call()

        self.assertIs(result, delegate.return_value)
        derived = delegate.call_args.args[1]
        self.assertEqual(self.receipt, derived)
        self.assertEqual(self.receipt.to_dict(), derived.to_dict())

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

    def test_missing_verification_evidence_fails_closed(self):
        self.job["evidence"] = {}
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "verification_receipt_missing",
        ):
            self._call()

    def test_extra_receipt_field_fails_closed(self):
        raw = self.job["evidence"]["recovery_retry_verification_receipt"]
        raw["caller_selected_command"] = "/bin/sh"
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "shape_mismatch",
        ):
            self._call()

    def test_authority_tamper_fails_closed(self):
        raw = self.job["evidence"]["recovery_retry_verification_receipt"]
        raw["grants_execution_authority"] = True
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "unsafe_recovery_retry_verification_receipt",
        ):
            self._call()

    def test_boolean_integer_confusion_fails_closed(self):
        raw = self.job["evidence"]["recovery_retry_verification_receipt"]
        raw["elapsed_ms"] = True
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "invalid_recovery_retry_verification_receipt_types",
        ):
            self._call()

    def test_terminal_state_version_drift_fails_closed(self):
        self.job["state_version"] = 9
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "verification_receipt_not_current",
        ):
            self._call()

    def test_job_lineage_drift_fails_closed(self):
        self.job["plan_sha256"] = "9" * 64
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalReconciliationError,
            "verification_receipt_not_current",
        ):
            self._call()


if __name__ == "__main__":
    unittest.main()
