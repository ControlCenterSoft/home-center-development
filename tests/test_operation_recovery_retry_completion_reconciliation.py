from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace
from unittest.mock import patch

from home_center.operation_recovery_retry_completion_reconciliation import (
    OperationRecoveryRetryCompletionReconciliationError,
    assess_operation_recovery_retry_verification_completion,
)
from home_center.operation_recovery_retry_verification_receipt import (
    OperationRecoveryRetryVerificationReceipt,
    OperationRecoveryRetryVerificationReceiptError,
)
from home_center.util import canonical_json


class FakeStore:
    def __init__(self, job: dict, journal: dict) -> None:
        self.job = job
        self.journal = journal
        self.audit_valid = True
        self.journal_error = False

    def operation_job(self, job_id: str):
        if self.job is None or self.job.get("job_id") != job_id:
            return None
        return self.job

    def operation_recovery_retry_completion_journal(self, receipt_id: str):
        if self.journal_error:
            raise RuntimeError("journal integrity mismatch")
        if self.journal is None or self.journal.get("receipt_id") != receipt_id:
            return None
        return self.journal

    def verify_audit_chain(self):
        if not self.audit_valid:
            raise RuntimeError("invalid audit chain")
        return "f" * 64


class CompletionReconciliationTests(unittest.TestCase):
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
            "state": "rolled_back",
            "state_version": 8,
            "plan_id": self.receipt.plan_id,
            "request_sha256": "6" * 64,
            "plan_sha256": self.receipt.plan_sha256,
            "target_node_id": self.receipt.target_node_id,
            "service": "home-center.service",
            "correlation_id": "correlation-001",
            "result": {
                "recovery_retry_verification": {
                    "receipt_id": self.receipt.receipt_id
                }
            },
            "evidence": {
                "recovery_retry_verification_receipt": self.receipt.to_dict()
            },
            "recovery": {
                "verification": {
                    "receipt_id": self.receipt.receipt_id,
                    "recovery_verified": True,
                    "recovery_required": False,
                }
            },
            "mutation_may_have_occurred": True,
            "recovery_required": False,
            "last_audit_event_id": "audit-completion-001",
        }
        self.event = {
            "seq": 10,
            "event_id": "audit-completion-001",
            "occurred_at": "2026-09-10T10:00:00+00:00",
            "actor": "admin",
            "action": "operation.job.transition",
            "target": "home-node-a:home-center.service",
            "outcome": "rolled_back",
            "correlation_id": "correlation-001",
            "details": {
                "job_id": self.receipt.job_id,
                "plan_id": self.receipt.plan_id,
                "request_sha256": "6" * 64,
                "plan_sha256": self.receipt.plan_sha256,
                "from_state": "rolling_back",
                "to_state": "rolled_back",
                "from_state_version": 7,
                "to_state_version": 8,
                "mutation_may_have_occurred": True,
                "recovery_required": False,
            },
            "previous_hash": "7" * 64,
            "entry_hash": "8" * 64,
        }
        receipt_sha256 = hashlib.sha256(
            canonical_json(self.receipt.to_dict()).encode("utf-8")
        ).hexdigest()
        self.journal = {
            "schema": "home-center.operation-recovery-retry-completion-journal.v1",
            "journal_id": f"oprecoveryjournal-{receipt_sha256[:24]}",
            "receipt_id": self.receipt.receipt_id,
            "receipt_sha256": receipt_sha256,
            "job_id": self.receipt.job_id,
            "plan_id": self.receipt.plan_id,
            "plan_sha256": self.receipt.plan_sha256,
            "from_state": "rolling_back",
            "to_state": "rolled_back",
            "from_state_version": 7,
            "to_state_version": 8,
            "audit_event_id": self.event["event_id"],
            "audit_entry_hash": self.event["entry_hash"],
            "audit_event": self.event,
            "created_at": "2026-09-10T10:00:00+00:00",
            "atomic_with_job_transition": True,
            "single_use": True,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "retry_authorized": False,
            "rollback_authorized": False,
            "production_mutation_enabled": False,
        }
        self.store = FakeStore(self.job, self.journal)

    def _assess(self):
        with patch(
            "home_center.operation_recovery_retry_completion_reconciliation."
            "revalidate_operation_recovery_retry_verification_receipt"
        ):
            return assess_operation_recovery_retry_verification_completion(
                self.store,
                self.receipt,
                object(),
                object(),
                object(),
                object(),
            )

    def test_exact_journal_completion_is_confirmed_without_authority(self):
        first = self._assess()
        second = self._assess()

        self.assertEqual(first, second)
        self.assertEqual("confirmed", first.completion_status)
        self.assertEqual("confirmed", first.reason)
        self.assertTrue(first.exact_completion_confirmed)
        self.assertFalse(first.reconciliation_required)
        self.assertIsNotNone(first.audit_event_sha256)
        self.assertFalse(first.contains_command_material)
        self.assertFalse(first.accepts_caller_argv)
        self.assertFalse(first.accepts_shell)
        self.assertFalse(first.grants_execution_authority)
        self.assertFalse(first.retry_authorized)
        self.assertFalse(first.rollback_authorized)
        self.assertFalse(first.production_mutation_enabled)

    def test_missing_job_requires_reconciliation(self):
        self.store.job = None
        result = self._assess()
        self.assertEqual("operation_job_missing", result.reason)
        self.assertTrue(result.reconciliation_required)
        self.assertFalse(result.retry_authorized)

    def test_state_drift_requires_reconciliation_before_revalidation(self):
        self.job["state_version"] = 9
        result = self._assess()
        self.assertEqual("completion_state_not_current", result.reason)
        self.assertFalse(result.exact_completion_confirmed)

    def test_verification_evidence_drift_requires_reconciliation(self):
        with patch(
            "home_center.operation_recovery_retry_completion_reconciliation."
            "revalidate_operation_recovery_retry_verification_receipt",
            side_effect=OperationRecoveryRetryVerificationReceiptError("drift"),
        ):
            result = assess_operation_recovery_retry_verification_completion(
                self.store,
                self.receipt,
                object(),
                object(),
                object(),
                object(),
            )
        self.assertEqual("verification_evidence_not_current", result.reason)
        self.assertFalse(result.retry_authorized)

    def test_invalid_audit_chain_requires_reconciliation(self):
        self.store.audit_valid = False
        result = self._assess()
        self.assertEqual("audit_chain_invalid", result.reason)
        self.assertFalse(result.exact_completion_confirmed)

    def test_missing_completion_journal_requires_reconciliation(self):
        self.store.journal = None
        result = self._assess()
        self.assertEqual("transition_audit_missing", result.reason)
        self.assertFalse(result.exact_completion_confirmed)

    def test_corrupt_completion_journal_requires_reconciliation(self):
        self.store.journal_error = True
        result = self._assess()
        self.assertEqual("transition_audit_not_current", result.reason)
        self.assertFalse(result.exact_completion_confirmed)

    def test_journal_receipt_digest_drift_requires_reconciliation(self):
        self.journal["receipt_sha256"] = "0" * 64
        result = self._assess()
        self.assertEqual("transition_audit_not_current", result.reason)
        self.assertIsNone(result.audit_event_sha256)

    def test_journal_state_version_drift_requires_reconciliation(self):
        self.journal["to_state_version"] = 9
        result = self._assess()
        self.assertEqual("transition_audit_not_current", result.reason)

    def test_journal_audit_binding_drift_requires_reconciliation(self):
        self.journal["audit_entry_hash"] = "9" * 64
        result = self._assess()
        self.assertEqual("transition_audit_not_current", result.reason)

    def test_transition_audit_drift_requires_reconciliation(self):
        self.event["details"] = dict(self.event["details"])
        self.event["details"]["to_state_version"] = 9
        result = self._assess()
        self.assertEqual("transition_audit_not_current", result.reason)
        self.assertIsNone(result.audit_event_sha256)

    def test_completion_change_during_reconciliation_fails_closed(self):
        original = self.store.operation_job
        calls = 0

        def drifting(job_id: str):
            nonlocal calls
            calls += 1
            value = original(job_id)
            if calls >= 2 and value is not None:
                changed = dict(value)
                changed["result"] = {"changed": True}
                return changed
            return value

        self.store.operation_job = drifting  # type: ignore[method-assign]
        result = self._assess()
        self.assertEqual("completion_changed_during_reconciliation", result.reason)
        self.assertTrue(result.reconciliation_required)

    def test_unsafe_or_inconsistent_receipt_is_rejected(self):
        with self.assertRaisesRegex(
            OperationRecoveryRetryCompletionReconciliationError,
            "completion_version",
        ):
            assess_operation_recovery_retry_verification_completion(
                self.store,
                replace(self.receipt, to_state_version=10),
                object(),
                object(),
                object(),
                object(),
            )


if __name__ == "__main__":
    unittest.main()
