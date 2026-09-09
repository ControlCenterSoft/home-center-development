from __future__ import annotations

import hashlib
import unittest

from home_center.operation_worker_handoff import (
    OperationWorkerHandoffError,
    OperationWorkerIdentity,
    prepare_operation_worker_handoff,
    revalidate_operation_worker_handoff,
)
from home_center.util import canonical_json


class FakeStore:
    def __init__(self, job: dict[str, object] | None) -> None:
        self.job = job

    def operation_job(self, job_id: str) -> dict[str, object] | None:
        del job_id
        return self.job


class OperationWorkerHandoffTests(unittest.TestCase):
    def _job(self) -> dict[str, object]:
        plan = {
            "schema": "home-center.operation-command-plan.v1",
            "plan_id": "opcmd-" + "a" * 24,
            "request_sha256": "b" * 64,
            "action_id": "service.restart.v1",
            "authorization_id": "opauth-" + "c" * 24,
            "idempotency_key": "restart:home-center:0001",
            "target_node_id": "node-001",
            "service": "home-center.service",
            "snapshot_sha256": "d" * 64,
            "execution": {
                "executable": "/usr/bin/systemctl",
                "argv": ["/usr/bin/systemctl", "restart", "home-center.service"],
                "timeout_seconds": 15,
                "shell": False,
            },
            "verification": {
                "argv": ["/usr/bin/systemctl", "show", "home-center.service"],
                "timeout_seconds": 5,
                "required_active_state": "active",
            },
            "recovery": {
                "strategy": "restore-observed-active-state",
                "argv": ["/usr/bin/systemctl", "start", "home-center.service"],
                "timeout_seconds": 15,
                "expected_active_state": "active",
                "verification_required": True,
            },
            "audit": {
                "required": True,
                "correlation_id": "correlation-001",
                "reason": "bounded maintenance restart",
            },
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }
        return {
            "schema": "home-center.operation-job-record.v1",
            "job_id": "opjob-" + "e" * 24,
            "action_id": plan["action_id"],
            "state": "prepared",
            "state_version": 1,
            "plan_id": plan["plan_id"],
            "request_sha256": plan["request_sha256"],
            "plan_sha256": hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest(),
            "snapshot_sha256": plan["snapshot_sha256"],
            "authorization_id": plan["authorization_id"],
            "target_node_id": plan["target_node_id"],
            "mutation_may_have_occurred": False,
            "recovery_required": False,
            "plan": plan,
        }

    def _worker(self) -> OperationWorkerIdentity:
        return OperationWorkerIdentity(worker_id="worker-001", node_id="node-001")

    def test_handoff_is_deterministic_and_contains_no_command_material(self) -> None:
        store = FakeStore(self._job())
        first = prepare_operation_worker_handoff(
            store,
            job_id="opjob-" + "e" * 24,
            expected_state_version=1,
            worker=self._worker(),
        )
        second = prepare_operation_worker_handoff(
            store,
            job_id="opjob-" + "e" * 24,
            expected_state_version=1,
            worker=self._worker(),
        )

        self.assertEqual(first, second)
        value = first.to_dict()
        self.assertFalse(value["contains_command_material"])
        self.assertFalse(value["accepts_caller_argv"])
        self.assertFalse(value["accepts_shell"])
        self.assertFalse(value["direct_execution"])
        self.assertFalse(value["production_mutation_enabled"])
        self.assertNotIn("plan", value)
        self.assertNotIn("execution", value)
        self.assertNotIn("argv", value)
        self.assertNotIn("verification", value)
        self.assertNotIn("recovery", value)

    def test_handoff_binds_exact_plan_authorization_and_cas_version(self) -> None:
        job = self._job()
        handoff = prepare_operation_worker_handoff(
            FakeStore(job),
            job_id=job["job_id"],
            expected_state_version=1,
            worker=self._worker(),
        )
        self.assertEqual(handoff.plan_id, job["plan_id"])
        self.assertEqual(handoff.plan_sha256, job["plan_sha256"])
        self.assertEqual(handoff.authorization_id, job["authorization_id"])
        self.assertEqual(handoff.expected_state_version, 1)
        self.assertTrue(handoff.revalidate_before_execution)
        self.assertTrue(handoff.audit_required)

    def test_handoff_rejects_stale_state_version(self) -> None:
        with self.assertRaisesRegex(OperationWorkerHandoffError, "operation_job_state_stale"):
            prepare_operation_worker_handoff(
                FakeStore(self._job()),
                job_id="opjob-" + "e" * 24,
                expected_state_version=2,
                worker=self._worker(),
            )

    def test_handoff_rejects_non_prepared_or_recovery_job(self) -> None:
        running = self._job()
        running["state"] = "running"
        with self.assertRaisesRegex(OperationWorkerHandoffError, "operation_job_not_prepared"):
            prepare_operation_worker_handoff(
                FakeStore(running),
                job_id=running["job_id"],
                expected_state_version=1,
                worker=self._worker(),
            )

        recovery = self._job()
        recovery["recovery_required"] = True
        with self.assertRaisesRegex(OperationWorkerHandoffError, "operation_recovery_required"):
            prepare_operation_worker_handoff(
                FakeStore(recovery),
                job_id=recovery["job_id"],
                expected_state_version=1,
                worker=self._worker(),
            )

    def test_handoff_rejects_wrong_worker_node(self) -> None:
        worker = OperationWorkerIdentity(worker_id="worker-002", node_id="node-002")
        with self.assertRaisesRegex(OperationWorkerHandoffError, "worker_target_mismatch"):
            prepare_operation_worker_handoff(
                FakeStore(self._job()),
                job_id="opjob-" + "e" * 24,
                expected_state_version=1,
                worker=worker,
            )

    def test_handoff_rejects_tampered_plan_or_privilege_flags(self) -> None:
        tampered = self._job()
        tampered["plan"]["target_node_id"] = "node-002"
        with self.assertRaisesRegex(
            OperationWorkerHandoffError, "operation_plan_integrity_mismatch"
        ):
            prepare_operation_worker_handoff(
                FakeStore(tampered),
                job_id=tampered["job_id"],
                expected_state_version=1,
                worker=self._worker(),
            )

        unsafe = self._job()
        unsafe["plan"]["execution_authorized"] = True
        unsafe["plan_sha256"] = hashlib.sha256(
            canonical_json(unsafe["plan"]).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(OperationWorkerHandoffError, "unsafe_operation_plan"):
            prepare_operation_worker_handoff(
                FakeStore(unsafe),
                job_id=unsafe["job_id"],
                expected_state_version=1,
                worker=self._worker(),
            )

    def test_revalidation_rejects_head_movement_in_durable_job(self) -> None:
        job = self._job()
        store = FakeStore(job)
        handoff = prepare_operation_worker_handoff(
            store,
            job_id=job["job_id"],
            expected_state_version=1,
            worker=self._worker(),
        )
        job["state"] = "running"
        job["state_version"] = 2
        with self.assertRaisesRegex(OperationWorkerHandoffError, "operation_job_not_prepared"):
            revalidate_operation_worker_handoff(store, handoff)

    def test_revalidation_rejects_identity_drift(self) -> None:
        job = self._job()
        store = FakeStore(job)
        handoff = prepare_operation_worker_handoff(
            store,
            job_id=job["job_id"],
            expected_state_version=1,
            worker=self._worker(),
        )
        job["authorization_id"] = "opauth-" + "f" * 24
        with self.assertRaisesRegex(
            OperationWorkerHandoffError,
            "operation_plan_authorization_id_mismatch",
        ):
            revalidate_operation_worker_handoff(store, handoff)


if __name__ == "__main__":
    unittest.main()
