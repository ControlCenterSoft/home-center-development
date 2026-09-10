from __future__ import annotations

import copy
import hashlib
import unittest

from home_center.operation_recovery_retry_terminal_lineage_revalidation import (
    OperationRecoveryRetryTerminalLineageRevalidationError,
    revalidate_operation_recovery_retry_terminal_lineage,
)
from home_center.operation_recovery_retry_terminal_lineage_seal import (
    OperationRecoveryRetryTerminalLineageSeal,
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
        self.missing_job = False
        self.missing_journal = False

    def operation_job(self, job_id: str):
        self.job_reads += 1
        if self.missing_job or self.job.get("job_id") != job_id:
            return None
        if self.job_reads > 1 and self.job_on_second_read is not None:
            return copy.deepcopy(self.job_on_second_read)
        return copy.deepcopy(self.job)

    def operation_recovery_retry_completion_journal(self, receipt_id: str):
        self.journal_reads += 1
        if self.missing_journal or self.journal.get("receipt_id") != receipt_id:
            return None
        if self.journal_reads > 1 and self.journal_on_second_read is not None:
            return copy.deepcopy(self.journal_on_second_read)
        return copy.deepcopy(self.journal)


def sha256(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def job_material(job: dict) -> dict:
    return {
        "job_id": job.get("job_id"),
        "action_id": job.get("action_id"),
        "state": job.get("state"),
        "state_version": job.get("state_version"),
        "plan_id": job.get("plan_id"),
        "request_sha256": job.get("request_sha256"),
        "plan_sha256": job.get("plan_sha256"),
        "target_node_id": job.get("target_node_id"),
        "service": job.get("service"),
        "correlation_id": job.get("correlation_id"),
        "result": job.get("result"),
        "evidence": job.get("evidence"),
        "recovery": job.get("recovery"),
        "mutation_may_have_occurred": job.get("mutation_may_have_occurred"),
        "recovery_required": job.get("recovery_required"),
        "last_audit_event_id": job.get("last_audit_event_id"),
    }


def journal_material(journal: dict) -> dict:
    return {key: value for key, value in journal.items() if key != "created_at"}


class TerminalLineageRevalidationTests(unittest.TestCase):
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
        self.seal = self._make_seal()
        self.store = FakeStore(self.job, self.journal)

    def _make_seal(self) -> OperationRecoveryRetryTerminalLineageSeal:
        values = {
            "checkpoint_id": "oprecoveryreconcile-" + "b" * 24,
            "checkpoint_sha256": "c" * 64,
            "receipt_id": self.receipt["receipt_id"],
            "receipt_sha256": sha256(self.receipt),
            "job_id": self.job["job_id"],
            "job_state": self.job["state"],
            "job_state_version": self.job["state_version"],
            "plan_id": self.job["plan_id"],
            "plan_sha256": self.job["plan_sha256"],
            "target_node_id": self.job["target_node_id"],
            "terminal_evidence_sha256": sha256(self.evidence),
            "job_completion_sha256": sha256(job_material(self.job)),
            "completion_journal_id": self.journal["journal_id"],
            "completion_journal_sha256": sha256(journal_material(self.journal)),
            "audit_event_id": self.event["event_id"],
            "audit_event_sha256": sha256(self.event),
            "immutable_evidence_only": True,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "retry_authorized": False,
            "rollback_authorized": False,
            "production_mutation_enabled": False,
        }
        lineage_sha256 = sha256(values)
        return OperationRecoveryRetryTerminalLineageSeal(
            seal_id=f"oprecoveryseal-{lineage_sha256[:24]}",
            checkpoint_id=values["checkpoint_id"],
            checkpoint_sha256=values["checkpoint_sha256"],
            receipt_id=values["receipt_id"],
            receipt_sha256=values["receipt_sha256"],
            job_id=values["job_id"],
            job_state=values["job_state"],
            job_state_version=values["job_state_version"],
            plan_id=values["plan_id"],
            plan_sha256=values["plan_sha256"],
            target_node_id=values["target_node_id"],
            terminal_evidence_sha256=values["terminal_evidence_sha256"],
            job_completion_sha256=values["job_completion_sha256"],
            completion_journal_id=values["completion_journal_id"],
            completion_journal_sha256=values["completion_journal_sha256"],
            audit_event_id=values["audit_event_id"],
            audit_event_sha256=values["audit_event_sha256"],
            lineage_sha256=lineage_sha256,
        )

    def _revalidate(self):
        return revalidate_operation_recovery_retry_terminal_lineage(
            self.store,
            self.seal,
        )

    def test_exact_seal_is_current_and_deterministic(self):
        values = []
        for _ in range(100):
            self.store.job_reads = 0
            self.store.journal_reads = 0
            values.append(self._revalidate().to_dict())
        first = values[0]
        self.assertTrue(all(value == first for value in values))
        self.assertEqual(first["status"], "current")
        self.assertTrue(first["exact_seal_current"])
        self.assertFalse(first["fresh_decision_required"])
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

    def test_advanced_job_with_intact_old_journal_is_superseded(self):
        self.job["state_version"] = 9
        result = self._revalidate()
        self.assertEqual(result.status, "superseded")
        self.assertEqual(result.reason, "durable_job_revision_advanced_after_seal")
        self.assertTrue(result.fresh_decision_required)
        self.assertFalse(result.retry_authorized)

    def test_same_revision_job_drift_is_ambiguous(self):
        self.job["result"] = {"ok": False}
        result = self._revalidate()
        self.assertEqual(result.status, "ambiguous")
        self.assertEqual(result.reason, "sealed_terminal_digest_mismatch")
        self.assertTrue(result.fresh_decision_required)

    def test_journal_authority_tamper_is_ambiguous(self):
        self.journal["retry_authorized"] = True
        result = self._revalidate()
        self.assertEqual(result.status, "ambiguous")
        self.assertEqual(result.reason, "durable_terminal_material_unsafe")
        self.assertFalse(result.grants_execution_authority)

    def test_missing_material_is_ambiguous(self):
        self.store.missing_journal = True
        result = self._revalidate()
        self.assertEqual(result.status, "ambiguous")
        self.assertEqual(result.reason, "durable_terminal_material_unavailable")

    def test_change_during_revalidation_is_ambiguous(self):
        changed = copy.deepcopy(self.job)
        changed["recovery_required"] = True
        self.store.job_on_second_read = changed
        result = self._revalidate()
        self.assertEqual(result.status, "ambiguous")
        self.assertEqual(
            result.reason,
            "durable_lineage_changed_during_revalidation",
        )

    def test_caller_selected_shell_evidence_is_ambiguous(self):
        self.job["evidence"]["caller_selected_command"] = "/bin/sh"
        result = self._revalidate()
        self.assertEqual(result.status, "ambiguous")
        self.assertFalse(result.retry_authorized)
        self.assertFalse(result.rollback_authorized)

    def test_tampered_seal_identity_is_rejected(self):
        object.__setattr__(self.seal, "lineage_sha256", "0" * 64)
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageRevalidationError,
            "terminal_seal_identity_mismatch",
        ):
            self._revalidate()

    def test_tampered_seal_authority_is_rejected(self):
        object.__setattr__(self.seal, "retry_authorized", True)
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalLineageRevalidationError,
            "unsafe_terminal_seal",
        ):
            self._revalidate()

    def test_boolean_job_revision_is_ambiguous(self):
        self.job["state_version"] = True
        result = self._revalidate()
        self.assertEqual(result.status, "ambiguous")
        self.assertEqual(result.reason, "durable_job_revision_invalid")


if __name__ == "__main__":
    unittest.main()
