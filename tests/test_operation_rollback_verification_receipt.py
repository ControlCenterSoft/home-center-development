from __future__ import annotations

import copy
import hashlib
import unittest

from home_center.operation_commands import ACTION_ID, SYSTEMCTL, OperationJobState
from home_center.operation_job_store import OperationJobPreconditionFailed
from home_center.operation_rollback_execution_receipt import OperationRollbackExecutionReceipt
from home_center.operation_rollback_verification_receipt import (
    OperationRollbackVerificationObservation,
    OperationRollbackVerificationReceiptCoordinator,
    OperationRollbackVerificationReceiptError,
    revalidate_operation_rollback_verification_receipt,
)
from home_center.operation_worker_handoff import OperationWorkerIdentity
from home_center.util import canonical_json


class _Store:
    def __init__(self, job: dict[str, object]) -> None:
        self.job = copy.deepcopy(job)
        self.transitions = 0
        self.force_stale = False

    def operation_job(self, job_id: str) -> dict[str, object] | None:
        if self.job["job_id"] != job_id:
            return None
        return copy.deepcopy(self.job)

    def transition_operation_job(
        self,
        job_id: str,
        *,
        expected_state: OperationJobState,
        expected_state_version: int,
        target_state: OperationJobState,
        mutation_may_have_occurred: bool = False,
        result: dict[str, object] | None = None,
        evidence: dict[str, object] | None = None,
        recovery: dict[str, object] | None = None,
    ) -> dict[str, object]:
        if self.force_stale:
            raise OperationJobPreconditionFailed(job_id)
        if (
            self.job["state"] != expected_state.value
            or self.job["state_version"] != expected_state_version
        ):
            raise OperationJobPreconditionFailed(job_id)
        self.transitions += 1
        self.job["state"] = target_state.value
        self.job["state_version"] = expected_state_version + 1
        self.job["mutation_may_have_occurred"] = mutation_may_have_occurred
        self.job["recovery_required"] = target_state == OperationJobState.FAILED
        if result is not None:
            self.job["result"] = copy.deepcopy(result)
        if evidence is not None:
            self.job["evidence"] = copy.deepcopy(evidence)
        if recovery is not None:
            self.job["recovery"] = copy.deepcopy(recovery)
        self.job["last_audit_event_id"] = f"audit-transition-{self.transitions}"
        return copy.deepcopy(self.job)


class OperationRollbackVerificationReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.worker = OperationWorkerIdentity("worker-001", "home-node-a")
        self.execution, job = self._fixture("active")
        self.store = _Store(job)
        self.coordinator = OperationRollbackVerificationReceiptCoordinator(self.store)

    def _fixture(
        self,
        expected_active_state: str,
    ) -> tuple[OperationRollbackExecutionReceipt, dict[str, object]]:
        recovery_verb = "start" if expected_active_state == "active" else "stop"
        recovery = {
            "strategy": "restore-observed-active-state",
            "argv": [SYSTEMCTL, recovery_verb, "home-center.service"],
            "timeout_seconds": 15,
            "expected_active_state": expected_active_state,
            "verification_required": True,
        }
        plan = {
            "schema": "home-center.operation-command-plan.v1",
            "plan_id": "opcmd-" + "d" * 24,
            "request_sha256": "1" * 64,
            "action_id": ACTION_ID,
            "authorization_id": "opauth-" + "2" * 24,
            "idempotency_key": "operation-restart-001",
            "target_node_id": self.worker.node_id,
            "service": "home-center.service",
            "snapshot_sha256": "3" * 64,
            "execution": {
                "executable": SYSTEMCTL,
                "argv": [SYSTEMCTL, "restart", "home-center.service"],
                "timeout_seconds": 15,
                "shell": False,
            },
            "verification": {
                "argv": [
                    SYSTEMCTL,
                    "show",
                    "home-center.service",
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=SubState",
                    "--property=UnitFileState",
                    "--no-pager",
                ],
                "timeout_seconds": 5,
                "required_active_state": "active",
            },
            "recovery": recovery,
            "audit": {
                "required": True,
                "correlation_id": "correlation-rollback-verify-001",
                "reason": "bounded rollback verification receipt test",
            },
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }
        plan_sha256 = hashlib.sha256(canonical_json(plan).encode()).hexdigest()
        recovery_sha256 = hashlib.sha256(canonical_json(recovery).encode()).hexdigest()
        execution = OperationRollbackExecutionReceipt(
            receipt_id="oprollbackexec-" + "a" * 24,
            rollback_claim_id="oprollback-" + "b" * 24,
            verification_receipt_id="opverify-" + "c" * 24,
            execution_receipt_id="opreceipt-" + "e" * 24,
            job_id="opjob-" + "f" * 24,
            action_id=ACTION_ID,
            plan_id=plan["plan_id"],
            plan_sha256=plan_sha256,
            worker_id=self.worker.worker_id,
            target_node_id=self.worker.node_id,
            recovery_sha256=recovery_sha256,
            recovery_strategy="restore-observed-active-state",
            expected_active_state=expected_active_state,
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=100,
            rollback_succeeded=True,
            recovery_required=False,
            next_state="rolling_back",
            from_state_version=5,
            to_state_version=6,
            verification_required=True,
            audit_event_id="audit-rollback-execution",
        )
        worker_claim = {
            "claim_id": "opclaim-" + "1" * 24,
            "job_id": execution.job_id,
            "action_id": execution.action_id,
            "plan_id": execution.plan_id,
            "plan_sha256": execution.plan_sha256,
            "worker_id": execution.worker_id,
            "target_node_id": execution.target_node_id,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }
        original_execution = {
            "receipt_id": execution.execution_receipt_id,
            "claim_id": worker_claim["claim_id"],
            "job_id": execution.job_id,
            "action_id": execution.action_id,
            "plan_id": execution.plan_id,
            "plan_sha256": execution.plan_sha256,
            "worker_id": execution.worker_id,
            "target_node_id": execution.target_node_id,
            "started": True,
            "timed_out": False,
            "exit_code": 0,
            "mutation_may_have_occurred": True,
            "next_state": "verifying",
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "production_mutation_enabled": False,
        }
        verification = {
            "receipt_id": execution.verification_receipt_id,
            "execution_receipt_id": execution.execution_receipt_id,
            "job_id": execution.job_id,
            "action_id": execution.action_id,
            "plan_id": execution.plan_id,
            "plan_sha256": execution.plan_sha256,
            "worker_id": execution.worker_id,
            "target_node_id": execution.target_node_id,
            "verified": False,
            "next_state": "rolling_back",
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "production_mutation_enabled": False,
        }
        rollback_claim = {
            "claim_id": execution.rollback_claim_id,
            "verification_receipt_id": execution.verification_receipt_id,
            "execution_receipt_id": execution.execution_receipt_id,
            "job_id": execution.job_id,
            "action_id": execution.action_id,
            "plan_id": execution.plan_id,
            "plan_sha256": execution.plan_sha256,
            "worker_id": execution.worker_id,
            "target_node_id": execution.target_node_id,
            "recovery_sha256": execution.recovery_sha256,
            "recovery_strategy": execution.recovery_strategy,
            "expected_active_state": execution.expected_active_state,
            "state": "rolling_back",
            "to_state_version": 5,
            "verification_required": True,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }
        evidence = {
            "worker_claim": worker_claim,
            "execution_receipt": original_execution,
            "verification_receipt": verification,
            "rollback_claim": rollback_claim,
            "rollback_execution_receipt": execution.to_dict(),
        }
        job = {
            "job_id": execution.job_id,
            "action_id": execution.action_id,
            "state": "rolling_back",
            "state_version": 6,
            "plan_id": execution.plan_id,
            "plan_sha256": execution.plan_sha256,
            "target_node_id": execution.target_node_id,
            "service": "home-center.service",
            "plan": plan,
            "result": {"rollback_execution": {"receipt_id": execution.receipt_id}},
            "evidence": evidence,
            "recovery": recovery,
            "mutation_may_have_occurred": True,
            "recovery_required": False,
            "last_audit_event_id": execution.audit_event_id,
        }
        return execution, job

    @staticmethod
    def _observation(active_state: str = "active") -> OperationRollbackVerificationObservation:
        return OperationRollbackVerificationObservation(
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=75,
            load_state="loaded",
            active_state=active_state,
            sub_state="running" if active_state == "active" else "dead",
            unit_file_state="enabled",
        )

    def test_matching_state_closes_recovery(self) -> None:
        receipt, created = self.coordinator.record(
            self.execution,
            worker=self.worker,
            observation=self._observation(),
        )
        self.assertTrue(created)
        self.assertTrue(receipt.recovery_verified)
        self.assertFalse(receipt.recovery_required)
        self.assertEqual("rolled_back", receipt.next_state)
        self.assertEqual(7, receipt.to_state_version)
        self.assertEqual(1, self.store.transitions)
        value = receipt.to_dict()
        self.assertNotIn("argv", value)
        self.assertFalse(value["accepts_shell"])
        self.assertFalse(value["grants_execution_authority"])
        revalidate_operation_rollback_verification_receipt(
            self.store, receipt, self.execution
        )

    def test_expected_inactive_is_supported(self) -> None:
        execution, job = self._fixture("inactive")
        store = _Store(job)
        coordinator = OperationRollbackVerificationReceiptCoordinator(store)
        receipt, _ = coordinator.record(
            execution,
            worker=self.worker,
            observation=self._observation("inactive"),
        )
        self.assertEqual("rolled_back", receipt.next_state)
        self.assertTrue(receipt.recovery_verified)

    def test_state_mismatch_fails_closed(self) -> None:
        receipt, _ = self.coordinator.record(
            self.execution,
            worker=self.worker,
            observation=self._observation("inactive"),
        )
        self.assertEqual("failed", receipt.next_state)
        self.assertTrue(receipt.recovery_required)
        self.assertTrue(self.store.job["recovery_required"])

    def test_timeout_nonzero_and_not_started_fail_closed(self) -> None:
        observations = (
            OperationRollbackVerificationObservation(True, True, None, 5_000),
            OperationRollbackVerificationObservation(True, False, 1, 25),
            OperationRollbackVerificationObservation(False, False, None, 0),
        )
        for observation in observations:
            with self.subTest(observation=observation):
                execution, job = self._fixture("active")
                store = _Store(job)
                receipt, _ = OperationRollbackVerificationReceiptCoordinator(store).record(
                    execution,
                    worker=self.worker,
                    observation=observation,
                )
                self.assertEqual("failed", receipt.next_state)
                self.assertTrue(receipt.recovery_required)

    def test_exact_replay_is_idempotent(self) -> None:
        observation = self._observation()
        first, created = self.coordinator.record(
            self.execution, worker=self.worker, observation=observation
        )
        self.assertTrue(created)
        second, created = self.coordinator.record(
            self.execution, worker=self.worker, observation=observation
        )
        self.assertFalse(created)
        self.assertEqual(first, second)
        self.assertEqual(1, self.store.transitions)

    def test_conflicting_replay_is_rejected(self) -> None:
        self.coordinator.record(
            self.execution, worker=self.worker, observation=self._observation()
        )
        with self.assertRaisesRegex(
            OperationRollbackVerificationReceiptError,
            "rollback_verification_conflict",
        ):
            self.coordinator.record(
                self.execution,
                worker=self.worker,
                observation=self._observation("inactive"),
            )

    def test_wrong_worker_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            OperationRollbackVerificationReceiptError,
            "operation_worker_identity_mismatch",
        ):
            self.coordinator.record(
                self.execution,
                worker=OperationWorkerIdentity("worker-002", self.worker.node_id),
                observation=self._observation(),
            )

    def test_stale_state_version_is_rejected(self) -> None:
        self.store.job["state_version"] = 7
        with self.assertRaisesRegex(
            OperationRollbackVerificationReceiptError,
            "operation_job_state_stale",
        ):
            self.coordinator.record(
                self.execution, worker=self.worker, observation=self._observation()
            )

    def test_cas_race_fails_closed(self) -> None:
        self.store.force_stale = True
        with self.assertRaisesRegex(
            OperationRollbackVerificationReceiptError,
            "operation_rollback_verification_stale",
        ):
            self.coordinator.record(
                self.execution, worker=self.worker, observation=self._observation()
            )

    def test_plan_verification_drift_is_rejected(self) -> None:
        self.store.job["plan"]["verification"]["timeout_seconds"] = 10
        with self.assertRaisesRegex(
            OperationRollbackVerificationReceiptError,
            "operation_plan_integrity_mismatch",
        ):
            self.coordinator.record(
                self.execution, worker=self.worker, observation=self._observation()
            )

    def test_prior_evidence_drift_is_rejected(self) -> None:
        self.store.job["evidence"]["execution_receipt"]["target_node_id"] = "home-node-b"
        with self.assertRaisesRegex(
            OperationRollbackVerificationReceiptError,
            "execution_receipt_target_node_id_mismatch",
        ):
            self.coordinator.record(
                self.execution, worker=self.worker, observation=self._observation()
            )

    def test_unsafe_prior_evidence_is_rejected(self) -> None:
        self.store.job["evidence"]["rollback_claim"]["accepts_shell"] = True
        with self.assertRaisesRegex(
            OperationRollbackVerificationReceiptError,
            "unsafe_prior_evidence",
        ):
            self.coordinator.record(
                self.execution, worker=self.worker, observation=self._observation()
            )

    def test_revalidation_rejects_final_evidence_drift(self) -> None:
        receipt, _ = self.coordinator.record(
            self.execution, worker=self.worker, observation=self._observation()
        )
        self.store.job["evidence"].pop("rollback_verification_receipt")
        with self.assertRaisesRegex(
            OperationRollbackVerificationReceiptError,
            "operation_evidence_shape_mismatch",
        ):
            revalidate_operation_rollback_verification_receipt(
                self.store, receipt, self.execution
            )

    def test_invalid_observations_are_rejected(self) -> None:
        invalid = (
            dict(started=False, timed_out=True, exit_code=None, elapsed_ms=0),
            dict(started=False, timed_out=False, exit_code=0, elapsed_ms=0),
            dict(started=True, timed_out=False, exit_code=None, elapsed_ms=1),
            dict(started=True, timed_out=True, exit_code=1, elapsed_ms=1),
            dict(started=True, timed_out=True, exit_code=None, elapsed_ms=5_001),
            dict(
                started=True,
                timed_out=False,
                exit_code=1,
                elapsed_ms=1,
                active_state="active",
            ),
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(OperationRollbackVerificationReceiptError):
                    OperationRollbackVerificationObservation(**value)


if __name__ == "__main__":
    unittest.main()
