from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.operation_commands import (
    OperationCommandAdmission,
    OperationCommandRequest,
    ServiceStateSnapshot,
)
from home_center.operation_job_store import OperationJobStateStore
from home_center.operation_worker_claim import (
    OperationWorkerClaimCoordinator,
    OperationWorkerClaimError,
)
from home_center.operation_worker_handoff import (
    OperationWorkerIdentity,
    prepare_operation_worker_handoff,
)


class OperationWorkerClaimTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.store = OperationJobStateStore(self.path, b"a" * 32, "home-test")
        self.coordinator = OperationWorkerClaimCoordinator(self.store)
        self.worker = OperationWorkerIdentity(
            worker_id="worker-001",
            node_id="home-node-a",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _job_and_handoff(self):
        request = OperationCommandRequest(
            authorization_id="opauth-0123456789abcdef01234567",
            idempotency_key="restart-operation-claim-001",
            target_node_id="home-node-a",
            service="home-center.service",
            reason="bounded supervised service restart",
            correlation_id="correlation-claim-001",
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
        return job, handoff

    def test_claim_is_cas_bound_bounded_and_audited(self) -> None:
        job, handoff = self._job_and_handoff()
        claim, created = self.coordinator.claim(handoff, worker=self.worker)

        self.assertTrue(created)
        self.assertEqual(job["job_id"], claim.job_id)
        self.assertEqual(1, claim.from_state_version)
        self.assertEqual(2, claim.to_state_version)
        value = claim.to_dict()
        self.assertFalse(value["contains_command_material"])
        self.assertFalse(value["accepts_caller_argv"])
        self.assertFalse(value["accepts_shell"])
        self.assertFalse(value["execution_authorized"])
        self.assertFalse(value["production_mutation_enabled"])
        self.assertNotIn("argv", value)
        self.assertNotIn("execution", value)

        persisted = self.store.operation_job(job["job_id"])
        self.assertIsNotNone(persisted)
        self.assertEqual("running", persisted["state"])
        self.assertEqual(2, persisted["state_version"])
        self.assertEqual(value, persisted["evidence"]["worker_claim"])
        self.assertEqual(claim.audit_event_id, persisted["last_audit_event_id"])

        audit = self.store.audit_events(limit=1)[0]
        self.assertEqual("worker-001", audit["actor"])
        self.assertEqual("operation.worker.claim", audit["action"])
        self.assertEqual(handoff.handoff_id, audit["details"]["handoff_id"])
        self.assertEqual(handoff.plan_sha256, audit["details"]["plan_sha256"])
        self.store.verify_audit_chain()

    def test_exact_replay_is_idempotent_without_second_transition_or_audit(self) -> None:
        _, handoff = self._job_and_handoff()
        first, created = self.coordinator.claim(handoff, worker=self.worker)
        self.assertTrue(created)
        before = len(self.store.audit_events())

        second, created = self.coordinator.claim(handoff, worker=self.worker)

        self.assertFalse(created)
        self.assertEqual(first, second)
        self.assertEqual(before, len(self.store.audit_events()))
        persisted = self.store.operation_job(handoff.job_id)
        self.assertEqual("running", persisted["state"])
        self.assertEqual(2, persisted["state_version"])

    def test_wrong_worker_is_rejected_without_state_or_audit_change(self) -> None:
        job, handoff = self._job_and_handoff()
        before = len(self.store.audit_events())
        wrong = OperationWorkerIdentity(worker_id="worker-002", node_id="home-node-a")

        with self.assertRaisesRegex(
            OperationWorkerClaimError,
            "operation_worker_identity_mismatch",
        ):
            self.coordinator.claim(handoff, worker=wrong)

        persisted = self.store.operation_job(job["job_id"])
        self.assertEqual("prepared", persisted["state"])
        self.assertEqual(1, persisted["state_version"])
        self.assertEqual(before, len(self.store.audit_events()))

    def test_stale_state_version_is_rejected_without_partial_claim(self) -> None:
        job, handoff = self._job_and_handoff()
        before = len(self.store.audit_events())
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE operation_job_metadata SET state_version=2 WHERE job_id=?",
                (job["job_id"],),
            )

        with self.assertRaisesRegex(
            OperationWorkerClaimError,
            "operation_job_state_stale",
        ):
            self.coordinator.claim(handoff, worker=self.worker)

        persisted = self.store.operation_job(job["job_id"])
        self.assertEqual("prepared", persisted["state"])
        self.assertEqual(2, persisted["state_version"])
        self.assertEqual(before, len(self.store.audit_events()))
        row = self.store._connection.execute(
            "SELECT COUNT(*) FROM operation_worker_claims"
        ).fetchone()
        self.assertEqual(0, row[0])

    def test_tampered_handoff_is_rejected_before_running_transition(self) -> None:
        job, handoff = self._job_and_handoff()
        before = len(self.store.audit_events())
        tampered = replace(handoff, plan_sha256="0" * 64)

        with self.assertRaisesRegex(
            OperationWorkerClaimError,
            "operation_worker_handoff_stale",
        ):
            self.coordinator.claim(tampered, worker=self.worker)

        persisted = self.store.operation_job(job["job_id"])
        self.assertEqual("prepared", persisted["state"])
        self.assertEqual(before, len(self.store.audit_events()))

    def test_recovery_or_possible_mutation_blocks_claim(self) -> None:
        job, handoff = self._job_and_handoff()
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                """UPDATE operation_job_metadata
                SET recovery_required=1 WHERE job_id=?""",
                (job["job_id"],),
            )
        with self.assertRaisesRegex(
            OperationWorkerClaimError,
            "operation_job_recovery_required",
        ):
            self.coordinator.claim(handoff, worker=self.worker)

    def test_unexpected_prepared_evidence_blocks_claim(self) -> None:
        job, handoff = self._job_and_handoff()
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE jobs SET evidence_json=? WHERE job_id=?",
                ('{"unexpected":true}', job["job_id"]),
            )
        with self.assertRaisesRegex(
            OperationWorkerClaimError,
            "operation_job_unexpected_evidence",
        ):
            self.coordinator.claim(handoff, worker=self.worker)

    def test_durable_claim_tamper_is_detected_on_replay(self) -> None:
        _, handoff = self._job_and_handoff()
        self.coordinator.claim(handoff, worker=self.worker)
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                """UPDATE operation_worker_claims SET claim_sha256=?
                WHERE handoff_id=?""",
                ("0" * 64, handoff.handoff_id),
            )

        with self.assertRaisesRegex(
            OperationWorkerClaimError,
            "operation_worker_claim_integrity_mismatch",
        ):
            self.coordinator.claim(handoff, worker=self.worker)


if __name__ == "__main__":
    unittest.main()
