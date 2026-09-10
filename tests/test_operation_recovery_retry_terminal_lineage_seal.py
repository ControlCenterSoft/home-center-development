from __future__ import annotations

import copy
import hashlib
import unittest

from home_center.operation_recovery_retry_completion_reconciliation import (
    OperationRecoveryRetryCompletionReconciliation,
)
from home_center.operation_recovery_retry_terminal_lineage_seal import (
    OperationRecoveryRetryTerminalLineageSealError,
    seal_operation_recovery_retry_terminal_lineage,
)
from home_center.util import canonical_json


class FakeStore:
    def __init__(self, job: dict, journal: dict) -> None:
        self.job = job
        self.journal = journal
        self.job_reads = 0
        self.journal_reads = 0
        self.job_on_second_read: dict | None = None
        self.journal_on_second_read: dict | None = None

    def operation_job(self, job_id: str):
        self.job_reads += 1
        if self.job_reads > 1 and self.job_on_second_read is not None:
            return copy.deepcopy(self.job_on_second_read)
        if self.job.get("job_id") != job_id:
            return None
        return copy.deepcopy(self.job)

    def operation_recovery_retry_completion_journal(self, receipt_id: str):
        self.journal_reads += 1
        if self.journal_reads > 1 and self.journal_on_second_read is not None:
            return copy.deepcopy(self.journal_on_second_read)
        if self.journal.get("receipt_id") != receipt_id:
            return None
        return copy.deepcopy(self.journal)


def sha256(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class TerminalLineageSealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.receipt = {
            "schema": "home-center.operation-recovery-retry-verification-receipt.v1",
            "receipt_id": "oprecoveryverify-" + "a" * 24,
            "job_id": "opjob-" + "1" * 24,
            "action_id": "service.restart",
            "plan_id": "opplan-" + "2" * 24,
            "plan_sha256": "3" * 64,
            "target_node_id": "home-node-a",
            "from_state": "rolling_back",
            "next_state": "rolled_back",
            "from_state_version": 7,
            "to_state_version": 8,
            "recovery_verified": True,
            "recovery_required": False,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "production_mutation_enabled": False,
        }
        self.evidence = {
            "worker_claim": {"kind": "worker"},
            "execution_receipt": {"kind": "execution"},
            "verification_receipt": {"kind": "verification"},
            "rollback_claim": {"kind": "rollback-claim"},
            "rollback_execution_receipt": {"kind": "rollback-execution"},
            "rollback_verification_receipt": {"kind": "rollback-verification"},
            "recovery_retry_admission": {"kind": "retry-admission"},
            "recovery_retry_claim": {"kind": "retry-claim"},
            "recovery_retry_execution_receipt": {"kind": "retry-execution"},
            "recovery_retry_verification_receipt": self.receipt,
        }
        self.event = {
            "event_id": "audit-terminal",
            "entry_hash": "4" * 64,
            "previous_hash": "5" * 64,
            "action": "operation.job.transition",
            "outcome": "rolled_back",
        }
        self.job = {
            "job_id": self.receipt["job_id"],
            "action_id": self.receipt["action_id"],
            "state": "rolled_back",
            "state_version": 8,
            "plan_id": self.receipt["plan_id"],
            "request_sha256": "6" * 64,
            "plan_sha256": self.receipt["plan_sha256"],
            "target_node_id": self.receipt["target_node_id"],
            "service": "home-center",
            "correlation_id": "correlation-1",
            "result": {"ok": True},
            "evidence": self.evidence,
            "recovery": {"required": False},
            "mutation_may_have_occurred": True,
            "recovery_required": False,
            "last_audit_event_id": self.event["event_id"],
        }
        receipt_sha256 = sha256(self.receipt)
        audit_event_sha256 = sha256(self.event)
        self.journal = {
            "schema": "home-center.operation-recovery-retry-completion-journal.v1",
            "journal_id": f"oprecoveryjournal-{receipt_sha256[:24]}",
            "receipt_id": self.receipt["receipt_id"],
            "receipt_sha256": receipt_sha256,
            "job_id": self.receipt["job_id"],
            "plan_id": self.receipt["plan_id"],
            "plan_sha256": self.receipt["plan_sha256"],
            "from_state": "rolling_back",
            "to_state": "rolled_back",
            "from_state_version": 7,
            "to_state_version": 8,
            "audit_event_id": self.event["event_id"],
            "audit_entry_hash": self.event["entry_hash"],
            "audit_event": self.event,
            "created_at": "2026-09-10T16:00:00Z",
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
        self.checkpoint = OperationRecoveryRetryCompletionReconciliation(
            checkpoint_id="oprecoveryreconcile-" + "b" * 24,
            receipt_id=self.receipt["receipt_id"],
            receipt_sha256=receipt_sha256,
            recovery_retry_execution_receipt_id="oprecoveryretryexec-" + "c" * 24,
            job_id=self.receipt["job_id"],
            plan_id=self.receipt["plan_id"],
            plan_sha256=self.receipt["plan_sha256"],
            target_node_id=self.receipt["target_node_id"],
            audit_event_id=self.event["event_id"],
            audit_event_sha256=audit_event_sha256,
            observed_state="rolled_back",
            observed_state_version=8,
            claimed_recovery_verified=True,
            claimed_recovery_required=False,
            completion_status="confirmed",
            reason="confirmed",
            exact_completion_confirmed=True,
            reconciliation_required=False,
        )
        self.store = FakeStore(self.job, self.journal)

    def _seal(self):
        return seal_operation_recovery_retry_terminal_lineage(
            self.store,
            self.checkpoint,
        )

    def test_exact_terminal_lineage_is_sealed_deterministically(self):
        values = []
        for _ in range(100):
            self.store.job_reads = 0
            self.store.journal_reads = 0
            values.append(self._seal().to_dict())
        first = values[0]
        self.assertTrue(all(value == first for value in values))
        self.assertTrue(first["immutable_evidence_only"])
        for name in (
            "contains_command_material",
            "accepts_caller_argv",
            "accepts_shell",
            "grants_execution_authority",
            "retry_authorized",
            "rollback_authorized",
            "production_mutation_enabled",
        ):
            self.assertFalse(first[name])

    def test_extra_terminal_evidence_is_rejected(self):
        self.job["evidence"]["caller_selected_command"] = "/bin/sh"
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "terminal_evidence_shape_mismatch",
        ):
            self._seal()

    def test_terminal_receipt_tamper_is_rejected(self):
        self.job["evidence"]["recovery_retry_verification_receipt"][
            "target_node_id"
        ] = "other-node"
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "terminal_receipt_digest_mismatch",
        ):
            self._seal()

    def test_journal_authority_tamper_is_rejected(self):
        self.journal["retry_authorized"] = True
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "unsafe_completion_journal",
        ):
            self._seal()

    def test_journal_receipt_digest_tamper_is_rejected(self):
        self.journal["receipt_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "completion_journal_lineage_mismatch",
        ):
            self._seal()

    def test_audit_event_digest_tamper_is_rejected(self):
        self.journal["audit_event"]["outcome"] = "failed"
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "completion_audit_digest_mismatch",
        ):
            self._seal()

    def test_job_change_during_seal_is_rejected(self):
        changed = copy.deepcopy(self.job)
        changed["recovery_required"] = True
        self.store.job_on_second_read = changed
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "terminal_lineage_changed_during_seal",
        ):
            self._seal()

    def test_journal_change_during_seal_is_rejected(self):
        changed = copy.deepcopy(self.journal)
        changed["audit_entry_hash"] = "0" * 64
        self.store.journal_on_second_read = changed
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "terminal_lineage_changed_during_seal",
        ):
            self._seal()

    def test_boolean_state_version_is_rejected(self):
        self.job["state_version"] = True
        self.checkpoint = self._checkpoint_with(observed_state_version=True)
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "terminal_job_lineage_mismatch",
        ):
            self._seal()

    def test_missing_job_is_rejected(self):
        self.store.job["job_id"] = "other-job"
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "terminal_job_missing",
        ):
            self._seal()

    def test_missing_journal_is_rejected(self):
        self.store.journal["receipt_id"] = "other-receipt"
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "completion_journal_missing",
        ):
            self._seal()

    def _checkpoint_with(self, **changes):
        values = {
            "checkpoint_id": self.checkpoint.checkpoint_id,
            "receipt_id": self.checkpoint.receipt_id,
            "receipt_sha256": self.checkpoint.receipt_sha256,
            "recovery_retry_execution_receipt_id": (
                self.checkpoint.recovery_retry_execution_receipt_id
            ),
            "job_id": self.checkpoint.job_id,
            "plan_id": self.checkpoint.plan_id,
            "plan_sha256": self.checkpoint.plan_sha256,
            "target_node_id": self.checkpoint.target_node_id,
            "audit_event_id": self.checkpoint.audit_event_id,
            "audit_event_sha256": self.checkpoint.audit_event_sha256,
            "observed_state": self.checkpoint.observed_state,
            "observed_state_version": self.checkpoint.observed_state_version,
            "claimed_recovery_verified": self.checkpoint.claimed_recovery_verified,
            "claimed_recovery_required": self.checkpoint.claimed_recovery_required,
            "completion_status": self.checkpoint.completion_status,
            "reason": self.checkpoint.reason,
            "exact_completion_confirmed": self.checkpoint.exact_completion_confirmed,
            "reconciliation_required": self.checkpoint.reconciliation_required,
        }
        values.update(changes)
        return OperationRecoveryRetryCompletionReconciliation(**values)

    def test_reconciliation_required_checkpoint_is_rejected(self):
        self.checkpoint = self._checkpoint_with(
            completion_status="reconcile",
            reason="transition_audit_missing",
            exact_completion_confirmed=False,
            reconciliation_required=True,
        )
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageSealError,
            "terminal_completion_not_confirmed",
        ):
            self._seal()


if __name__ == "__main__":
    unittest.main()
