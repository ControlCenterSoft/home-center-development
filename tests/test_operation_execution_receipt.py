from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from home_center.operation_commands import (
    OperationCommandAdmission,
    OperationCommandRequest,
    ServiceStateSnapshot,
)
from home_center.operation_execution_receipt import (
    OperationExecutionObservation,
    OperationExecutionReceiptCoordinator,
    OperationExecutionReceiptError,
)
from home_center.operation_job_store import OperationJobStateStore
from home_center.operation_worker_claim import OperationWorkerClaimCoordinator
from home_center.operation_worker_handoff import (
    OperationWorkerIdentity,
    prepare_operation_worker_handoff,
)


class OperationExecutionReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.store = OperationJobStateStore(self.path, b"a" * 32, "home-test")
        self.claims = OperationWorkerClaimCoordinator(self.store)
        self.receipts = OperationExecutionReceiptCoordinator(self.store)
        self.worker = OperationWorkerIdentity(
            worker_id="worker-001",
            node_id="home-node-a",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _claimed_job(self):
        request = OperationCommandRequest(
            authorization_id="opauth-0123456789abcdef01234567",
            idempotency_key="restart-execution-receipt-001",
            target_node_id="home-node-a",
            service="home-center.service",
            reason="bounded supervised service restart",
            correlation_id="correlation-execution-receipt-001",
        )
        snapshot = ServiceStateSnapshot(
            target_node_id=request.target_node_id,
            service=request.service,
            load_state="loaded",
            active_state="active",
            sub_state="running",
            unit_file_state="enabled",
        )
        plan = OperationCommandAdmission().prepare(snapshot, request)
        job, created = self.store.create_operation_job(plan=plan, actor="admin")
        self.assertTrue(created)
        handoff = prepare_operation_worker_handoff(
            self.store,
            job_id=job["job_id"],
            expected_state_version=job["state_version"],
            worker=self.worker,
        )
        claim, created = self.claims.claim(handoff, worker=self.worker)
        self.assertTrue(created)
        return job, claim

    def test_success_receipt_moves_running_to_verifying_without_command_material(self) -> None:
        job, claim = self._claimed_job()
        receipt, created = self.receipts.record(
            claim.claim_id,
            worker=self.worker,
            observation=OperationExecutionObservation(
                started=True,
                timed_out=False,
                exit_code=0,
                elapsed_ms=225,
            ),
        )

        self.assertTrue(created)
        self.assertEqual(job["job_id"], receipt.job_id)
        self.assertEqual("running", receipt.from_state)
        self.assertEqual("verifying", receipt.next_state)
        self.assertEqual(2, receipt.from_state_version)
        self.assertEqual(3, receipt.to_state_version)
        self.assertTrue(receipt.mutation_may_have_occurred)
        value = receipt.to_dict()
        self.assertFalse(value["contains_command_material"])
        self.assertFalse(value["accepts_caller_argv"])
        self.assertFalse(value["accepts_shell"])
        self.assertFalse(value["grants_execution_authority"])
        self.assertFalse(value["production_mutation_enabled"])
        self.assertNotIn("argv", value)
        self.assertNotIn("stdout", value)
        self.assertNotIn("stderr", value)

        persisted = self.store.operation_job(job["job_id"])
        self.assertEqual("verifying", persisted["state"])
        self.assertEqual(3, persisted["state_version"])
        self.assertTrue(persisted["mutation_may_have_occurred"])
        self.assertEqual(claim.to_dict(), persisted["evidence"]["worker_claim"])
        self.assertEqual(value, persisted["evidence"]["execution_receipt"])
        self.store.verify_audit_chain()

    def test_nonzero_exit_requires_rollback(self) -> None:
        _, claim = self._claimed_job()
        receipt, _ = self.receipts.record(
            claim.claim_id,
            worker=self.worker,
            observation=OperationExecutionObservation(
                started=True,
                timed_out=False,
                exit_code=1,
                elapsed_ms=180,
            ),
        )
        persisted = self.store.operation_job(claim.job_id)
        self.assertEqual("rolling_back", receipt.next_state)
        self.assertTrue(receipt.mutation_may_have_occurred)
        self.assertEqual("rolling_back", persisted["state"])

    def test_timeout_requires_rollback(self) -> None:
        _, claim = self._claimed_job()
        receipt, _ = self.receipts.record(
            claim.claim_id,
            worker=self.worker,
            observation=OperationExecutionObservation(
                started=True,
                timed_out=True,
                exit_code=None,
                elapsed_ms=15_000,
            ),
        )
        self.assertEqual("rolling_back", receipt.next_state)
        self.assertTrue(receipt.mutation_may_have_occurred)

    def test_definite_start_failure_may_fail_without_rollback(self) -> None:
        _, claim = self._claimed_job()
        receipt, _ = self.receipts.record(
            claim.claim_id,
            worker=self.worker,
            observation=OperationExecutionObservation(
                started=False,
                timed_out=False,
                exit_code=None,
                elapsed_ms=0,
            ),
        )
        persisted = self.store.operation_job(claim.job_id)
        self.assertEqual("failed", receipt.next_state)
        self.assertFalse(receipt.mutation_may_have_occurred)
        self.assertEqual("failed", persisted["state"])
        self.assertFalse(persisted["mutation_may_have_occurred"])

    def test_exact_replay_is_idempotent_after_state_transition(self) -> None:
        _, claim = self._claimed_job()
        observation = OperationExecutionObservation(
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=100,
        )
        first, created = self.receipts.record(
            claim.claim_id,
            worker=self.worker,
            observation=observation,
        )
        self.assertTrue(created)
        before = len(self.store.audit_events())

        second, created = self.receipts.record(
            claim.claim_id,
            worker=self.worker,
            observation=observation,
        )

        self.assertFalse(created)
        self.assertEqual(first, second)
        self.assertEqual(before, len(self.store.audit_events()))

    def test_conflicting_replay_is_rejected(self) -> None:
        _, claim = self._claimed_job()
        self.receipts.record(
            claim.claim_id,
            worker=self.worker,
            observation=OperationExecutionObservation(True, False, 0, 100),
        )
        with self.assertRaisesRegex(
            OperationExecutionReceiptError,
            "operation_execution_receipt_conflict",
        ):
            self.receipts.record(
                claim.claim_id,
                worker=self.worker,
                observation=OperationExecutionObservation(True, False, 1, 100),
            )

    def test_wrong_worker_is_rejected_without_transition(self) -> None:
        _, claim = self._claimed_job()
        before = len(self.store.audit_events())
        wrong = OperationWorkerIdentity(worker_id="worker-002", node_id="home-node-a")
        with self.assertRaisesRegex(
            OperationExecutionReceiptError,
            "operation_worker_identity_mismatch",
        ):
            self.receipts.record(
                claim.claim_id,
                worker=wrong,
                observation=OperationExecutionObservation(True, False, 0, 100),
            )
        persisted = self.store.operation_job(claim.job_id)
        self.assertEqual("running", persisted["state"])
        self.assertEqual(2, persisted["state_version"])
        self.assertEqual(before, len(self.store.audit_events()))

    def test_stale_job_version_is_rejected_without_receipt(self) -> None:
        _, claim = self._claimed_job()
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE operation_job_metadata SET state_version=3 WHERE job_id=?",
                (claim.job_id,),
            )
        with self.assertRaisesRegex(
            OperationExecutionReceiptError,
            "operation_job_state_stale",
        ):
            self.receipts.record(
                claim.claim_id,
                worker=self.worker,
                observation=OperationExecutionObservation(True, False, 0, 100),
            )
        count = self.store._connection.execute(
            "SELECT COUNT(*) FROM operation_execution_receipts"
        ).fetchone()[0]
        self.assertEqual(0, count)

    def test_tampered_claim_is_detected_before_receipt(self) -> None:
        _, claim = self._claimed_job()
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE operation_worker_claims SET claim_sha256=? WHERE claim_id=?",
                ("0" * 64, claim.claim_id),
            )
        with self.assertRaisesRegex(
            OperationExecutionReceiptError,
            "operation_execution_receipt_rejected",
        ):
            self.receipts.record(
                claim.claim_id,
                worker=self.worker,
                observation=OperationExecutionObservation(True, False, 0, 100),
            )

    def test_invalid_observation_shape_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            OperationExecutionReceiptError,
            "invalid_not_started_observation",
        ):
            OperationExecutionObservation(False, False, 1, 0)
        with self.assertRaisesRegex(
            OperationExecutionReceiptError,
            "timeout_with_exit_code",
        ):
            OperationExecutionObservation(True, True, 1, 100)


if __name__ == "__main__":
    unittest.main()
