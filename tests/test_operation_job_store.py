from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from home_center.operation_commands import (
    OperationCommandAdmission,
    OperationCommandError,
    OperationCommandRequest,
    OperationJobState,
    ServiceStateSnapshot,
)
from home_center.operation_job_store import (
    OperationJobPreconditionFailed,
    OperationJobStateStore,
)
from home_center.store import IdempotencyConflict


class OperationJobStateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.store = OperationJobStateStore(self.path, b"a" * 32, "home-test")

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def plan(self, **overrides: str):
        request = OperationCommandRequest(
            authorization_id=overrides.pop(
                "authorization_id", "opauth-0123456789abcdef01234567"
            ),
            idempotency_key=overrides.pop(
                "idempotency_key", "restart-operation-001"
            ),
            target_node_id=overrides.pop("target_node_id", "home-node-a"),
            service=overrides.pop("service", "home-center.service"),
            reason=overrides.pop("reason", "recover supervised service"),
            correlation_id=overrides.pop("correlation_id", "correlation-001"),
        )
        snapshot = ServiceStateSnapshot(
            target_node_id=request.target_node_id,
            service=request.service,
            load_state="loaded",
            active_state=overrides.pop("active_state", "active"),
            sub_state="running",
            unit_file_state="enabled",
        )
        self.assertFalse(overrides)
        return OperationCommandAdmission().prepare(snapshot, request)

    def test_create_is_durable_idempotent_and_audit_bound(self) -> None:
        plan = self.plan()
        created, changed = self.store.create_operation_job(plan=plan, actor="admin")
        self.assertTrue(changed)
        self.assertEqual("prepared", created["state"])
        self.assertEqual(1, created["state_version"])
        self.assertFalse(created["mutation_may_have_occurred"])
        self.assertFalse(created["recovery_required"])
        self.assertEqual(plan.plan_id, created["plan_id"])
        self.assertEqual(plan.request_sha256, created["request_sha256"])
        self.assertEqual(plan.snapshot_sha256, created["snapshot_sha256"])
        self.assertEqual(
            created["last_audit_event_id"],
            self.store.audit_events(limit=1)[0]["event_id"],
        )
        self.store.verify_audit_chain()

        self.store.close()
        self.store = OperationJobStateStore(self.path, b"a" * 32, "home-test")
        replay, changed = self.store.create_operation_job(plan=plan, actor="admin")
        self.assertFalse(changed)
        self.assertEqual(created["job_id"], replay["job_id"])
        self.assertEqual(created["plan_sha256"], replay["plan_sha256"])

    def test_idempotency_key_cannot_bind_different_request(self) -> None:
        first = self.plan()
        self.store.create_operation_job(plan=first, actor="admin")
        second = self.plan(reason="different justified operation")
        with self.assertRaises(IdempotencyConflict):
            self.store.create_operation_job(plan=second, actor="admin")

    def test_success_path_uses_exact_state_version_cas(self) -> None:
        job, _ = self.store.create_operation_job(plan=self.plan(), actor="admin")
        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.PREPARED,
            expected_state_version=1,
            target_state=OperationJobState.RUNNING,
        )
        self.assertEqual(2, job["state_version"])

        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.RUNNING,
            expected_state_version=2,
            target_state=OperationJobState.VERIFYING,
            mutation_may_have_occurred=True,
            evidence={"execution_receipt_sha256": "1" * 64},
        )
        self.assertTrue(job["mutation_may_have_occurred"])
        self.assertEqual(3, job["state_version"])

        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.VERIFYING,
            expected_state_version=3,
            target_state=OperationJobState.SUCCEEDED,
            evidence={"verification_sha256": "2" * 64},
        )
        self.assertEqual("succeeded", job["state"])
        self.assertEqual(4, job["state_version"])
        self.assertFalse(job["recovery_required"])
        self.store.verify_audit_chain()

    def test_stale_state_version_is_rejected_without_audit_append(self) -> None:
        job, _ = self.store.create_operation_job(plan=self.plan(), actor="admin")
        before = len(self.store.audit_events())
        self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.PREPARED,
            expected_state_version=1,
            target_state=OperationJobState.RUNNING,
        )
        after_first = len(self.store.audit_events())
        self.assertEqual(before + 1, after_first)

        with self.assertRaises(OperationJobPreconditionFailed):
            self.store.transition_operation_job(
                job["job_id"],
                expected_state=OperationJobState.PREPARED,
                expected_state_version=1,
                target_state=OperationJobState.RUNNING,
            )
        self.assertEqual(after_first, len(self.store.audit_events()))

    def test_possible_mutation_requires_rollback_and_recovery_evidence(self) -> None:
        job, _ = self.store.create_operation_job(plan=self.plan(), actor="admin")
        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.PREPARED,
            expected_state_version=1,
            target_state=OperationJobState.RUNNING,
        )
        with self.assertRaisesRegex(OperationCommandError, "rollback_required"):
            self.store.transition_operation_job(
                job["job_id"],
                expected_state=OperationJobState.RUNNING,
                expected_state_version=2,
                target_state=OperationJobState.FAILED,
                mutation_may_have_occurred=True,
            )

        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.RUNNING,
            expected_state_version=2,
            target_state=OperationJobState.ROLLING_BACK,
            mutation_may_have_occurred=True,
        )
        with self.assertRaisesRegex(
            OperationCommandError, "recovery_evidence_required"
        ):
            self.store.transition_operation_job(
                job["job_id"],
                expected_state=OperationJobState.ROLLING_BACK,
                expected_state_version=3,
                target_state=OperationJobState.ROLLED_BACK,
            )

        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.ROLLING_BACK,
            expected_state_version=3,
            target_state=OperationJobState.ROLLED_BACK,
            recovery={"rollback_verified": True, "active_state": "active"},
        )
        self.assertEqual("rolled_back", job["state"])
        self.assertFalse(job["recovery_required"])

    def test_failed_rollback_sets_recovery_required(self) -> None:
        job, _ = self.store.create_operation_job(plan=self.plan(), actor="admin")
        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.PREPARED,
            expected_state_version=1,
            target_state=OperationJobState.RUNNING,
        )
        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.RUNNING,
            expected_state_version=2,
            target_state=OperationJobState.ROLLING_BACK,
            mutation_may_have_occurred=True,
        )
        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.ROLLING_BACK,
            expected_state_version=3,
            target_state=OperationJobState.FAILED,
            recovery={"rollback_verified": False, "error": "verification_failed"},
        )
        self.assertEqual("failed", job["state"])
        self.assertTrue(job["recovery_required"])

    def test_pre_mutation_failure_is_terminal_without_recovery_requirement(self) -> None:
        job, _ = self.store.create_operation_job(plan=self.plan(), actor="admin")
        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.PREPARED,
            expected_state_version=1,
            target_state=OperationJobState.FAILED,
            result={"error": "worker_unavailable"},
        )
        self.assertEqual("failed", job["state"])
        self.assertFalse(job["mutation_may_have_occurred"])
        self.assertFalse(job["recovery_required"])

    def test_verification_cannot_claim_success_without_mutation_evidence(self) -> None:
        job, _ = self.store.create_operation_job(plan=self.plan(), actor="admin")
        job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.PREPARED,
            expected_state_version=1,
            target_state=OperationJobState.RUNNING,
        )
        with self.assertRaisesRegex(
            OperationCommandError, "mutation_evidence_required"
        ):
            self.store.transition_operation_job(
                job["job_id"],
                expected_state=OperationJobState.RUNNING,
                expected_state_version=2,
                target_state=OperationJobState.VERIFYING,
            )

    def test_persisted_plan_tamper_is_detected(self) -> None:
        job, _ = self.store.create_operation_job(plan=self.plan(), actor="admin")
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE operation_job_metadata SET plan_json=? WHERE job_id=?",
                ('{"tampered":true}', job["job_id"]),
            )
        with self.assertRaisesRegex(RuntimeError, "plan integrity mismatch"):
            self.store.operation_job(job["job_id"])


if __name__ == "__main__":
    unittest.main()
