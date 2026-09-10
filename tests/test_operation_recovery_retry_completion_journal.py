from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from home_center.operation_commands import (
    ACTION_ID,
    SYSTEMCTL,
    OperationCommandError,
    OperationCommandPlan,
    OperationCommandRequest,
    OperationJobState,
)
from home_center.operation_job_store import OperationJobStateStore


class RecoveryRetryCompletionJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = OperationJobStateStore(
            Path(self.tempdir.name) / "state.db",
            b"journal-test-audit-key",
            "cluster-test",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.tempdir.cleanup()

    def _prepare_rolling_back(self, suffix: str = "a"):
        request = OperationCommandRequest(
            authorization_id="opauth-" + suffix * 24,
            idempotency_key=f"recovery-{suffix * 8}",
            target_node_id=f"node-{suffix}",
            service="home-center.service",
            reason="targeted recovery journal test",
            correlation_id=f"correlation-{suffix * 8}",
        )
        plan = OperationCommandPlan(
            plan_id="opcmd-" + suffix * 24,
            request_sha256=suffix * 64,
            request=request,
            snapshot_sha256=("f" if suffix != "f" else "e") * 64,
            restart_argv=(SYSTEMCTL, "restart", request.service),
            verify_argv=(SYSTEMCTL, "show", request.service),
            rollback_argv=(SYSTEMCTL, "start", request.service),
            rollback_expected_active_state="active",
        )
        job, created = self.store.create_operation_job(plan=plan, actor="admin")
        self.assertTrue(created)
        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.PREPARED,
            expected_state_version=1,
            target_state=OperationJobState.RUNNING,
        )
        return self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.RUNNING,
            expected_state_version=2,
            target_state=OperationJobState.ROLLING_BACK,
            mutation_may_have_occurred=True,
        )

    @staticmethod
    def _receipt(job: dict, receipt_id: str, *, verified: bool = True) -> dict:
        return {
            "schema": "home-center.operation-recovery-retry-verification-receipt.v1",
            "receipt_id": receipt_id,
            "recovery_retry_execution_receipt_id": "oprecoveryretryexec-" + "b" * 24,
            "retry_claim_id": "oprecoveryretryclaim-" + "c" * 24,
            "admission_id": "oprecoveryretryadmission-" + "d" * 24,
            "rollback_verification_receipt_id": "oprollbackverify-" + "e" * 24,
            "rollback_execution_receipt_id": "oprollbackexec-" + "f" * 24,
            "job_id": job["job_id"],
            "action_id": ACTION_ID,
            "plan_id": job["plan_id"],
            "plan_sha256": job["plan_sha256"],
            "worker_id": "worker-a",
            "target_node_id": job["target_node_id"],
            "recovery_sha256": "4" * 64,
            "expected_active_state": "active",
            "verification_sha256": "5" * 64,
            "started": True,
            "timed_out": False,
            "exit_code": 0,
            "elapsed_ms": 10,
            "load_state": "loaded",
            "active_state": "active",
            "sub_state": "running",
            "unit_file_state": "enabled",
            "recovery_verified": verified,
            "recovery_required": not verified,
            "from_state": "rolling_back",
            "next_state": "rolled_back" if verified else "failed",
            "from_state_version": 3,
            "to_state_version": 4,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "production_mutation_enabled": False,
        }

    def test_completion_journal_is_atomic_exact_and_non_authoritative(self):
        job = self._prepare_rolling_back()
        receipt = self._receipt(job, "oprecoveryverify-" + "1" * 24)
        final = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.ROLLING_BACK,
            expected_state_version=3,
            target_state=OperationJobState.ROLLED_BACK,
            mutation_may_have_occurred=True,
            evidence={"recovery_retry_verification_receipt": receipt},
            recovery={"verification": {"recovery_verified": True}},
        )

        journal = self.store.operation_recovery_retry_completion_journal(
            receipt["receipt_id"]
        )
        self.assertIsNotNone(journal)
        assert journal is not None
        self.assertEqual(final["last_audit_event_id"], journal["audit_event_id"])
        self.assertEqual(final["plan_id"], journal["plan_id"])
        self.assertEqual(3, journal["from_state_version"])
        self.assertEqual(4, journal["to_state_version"])
        self.assertEqual("rolled_back", journal["to_state"])
        self.assertEqual(
            journal["audit_entry_hash"], journal["audit_event"]["entry_hash"]
        )
        self.assertTrue(journal["atomic_with_job_transition"])
        self.assertTrue(journal["single_use"])
        self.assertFalse(journal["contains_command_material"])
        self.assertFalse(journal["accepts_caller_argv"])
        self.assertFalse(journal["accepts_shell"])
        self.assertFalse(journal["grants_execution_authority"])
        self.assertFalse(journal["retry_authorized"])
        self.assertFalse(journal["rollback_authorized"])
        self.assertFalse(journal["production_mutation_enabled"])
        self.store.verify_audit_chain()

    def test_failed_recovery_is_journaled_with_recovery_required(self):
        job = self._prepare_rolling_back("b")
        receipt = self._receipt(
            job, "oprecoveryverify-" + "2" * 24, verified=False
        )
        final = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.ROLLING_BACK,
            expected_state_version=3,
            target_state=OperationJobState.FAILED,
            mutation_may_have_occurred=True,
            evidence={"recovery_retry_verification_receipt": receipt},
            recovery={"verification": {"recovery_required": True}},
        )
        journal = self.store.operation_recovery_retry_completion_journal(
            receipt["receipt_id"]
        )
        self.assertEqual("failed", final["state"])
        self.assertTrue(final["recovery_required"])
        assert journal is not None
        self.assertEqual("failed", journal["to_state"])

    def test_tampered_receipt_fails_before_transition_or_audit_append(self):
        job = self._prepare_rolling_back("c")
        receipt = self._receipt(job, "oprecoveryverify-" + "3" * 24)
        receipt["plan_sha256"] = "0" * 64
        before = len(self.store._connection.execute("SELECT * FROM audit").fetchall())

        with self.assertRaisesRegex(
            OperationCommandError, "completion_lineage_mismatch"
        ):
            self.store.transition_operation_job(
                job["job_id"],
                expected_state=OperationJobState.ROLLING_BACK,
                expected_state_version=3,
                target_state=OperationJobState.ROLLED_BACK,
                mutation_may_have_occurred=True,
                evidence={"recovery_retry_verification_receipt": receipt},
                recovery={"verification": {"recovery_verified": True}},
            )

        current = self.store.operation_job(job["job_id"])
        self.assertEqual("rolling_back", current["state"])
        self.assertEqual(3, current["state_version"])
        after = len(self.store._connection.execute("SELECT * FROM audit").fetchall())
        self.assertEqual(before, after)

    def test_journal_uniqueness_rolls_back_entire_conflicting_completion(self):
        receipt_id = "oprecoveryverify-" + "4" * 24
        first = self._prepare_rolling_back("d")
        first_receipt = self._receipt(first, receipt_id)
        self.store.transition_operation_job(
            first["job_id"],
            expected_state=OperationJobState.ROLLING_BACK,
            expected_state_version=3,
            target_state=OperationJobState.ROLLED_BACK,
            mutation_may_have_occurred=True,
            evidence={"recovery_retry_verification_receipt": first_receipt},
            recovery={"verification": {"recovery_verified": True}},
        )

        second = self._prepare_rolling_back("e")
        second_receipt = self._receipt(second, receipt_id)
        before = len(self.store._connection.execute("SELECT * FROM audit").fetchall())
        with self.assertRaises(Exception):
            self.store.transition_operation_job(
                second["job_id"],
                expected_state=OperationJobState.ROLLING_BACK,
                expected_state_version=3,
                target_state=OperationJobState.ROLLED_BACK,
                mutation_may_have_occurred=True,
                evidence={"recovery_retry_verification_receipt": second_receipt},
                recovery={"verification": {"recovery_verified": True}},
            )
        current = self.store.operation_job(second["job_id"])
        self.assertEqual("rolling_back", current["state"])
        self.assertEqual(3, current["state_version"])
        after = len(self.store._connection.execute("SELECT * FROM audit").fetchall())
        self.assertEqual(before, after)

    def test_ordinary_rollback_completion_does_not_forge_retry_journal(self):
        job = self._prepare_rolling_back("f")
        final = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.ROLLING_BACK,
            expected_state_version=3,
            target_state=OperationJobState.ROLLED_BACK,
            mutation_may_have_occurred=True,
            recovery={"verification": {"recovery_verified": True}},
        )
        self.assertEqual("rolled_back", final["state"])
        count = self.store._connection.execute(
            "SELECT COUNT(*) FROM operation_recovery_retry_completion_journal"
        ).fetchone()[0]
        self.assertEqual(0, count)


if __name__ == "__main__":
    unittest.main()
