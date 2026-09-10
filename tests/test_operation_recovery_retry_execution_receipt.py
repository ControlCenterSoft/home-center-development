from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from home_center.operation_commands import (
    ACTION_ID,
    OperationCommandAdmission,
    OperationCommandRequest,
    OperationJobState,
    ServiceStateSnapshot,
)
from home_center.operation_job_store import OperationJobStateStore
from home_center.operation_recovery_retry_admission import (
    OperationRecoveryRetryAdmissionCoordinator,
    OperationRecoveryRetryRequest,
)
from home_center.operation_recovery_retry_claim import (
    OperationRecoveryRetryClaimCoordinator,
)
from home_center.operation_recovery_retry_execution_receipt import (
    OperationRecoveryRetryExecutionObservation,
    OperationRecoveryRetryExecutionReceiptCoordinator,
    OperationRecoveryRetryExecutionReceiptError,
    revalidate_operation_recovery_retry_execution_receipt,
)
from home_center.operation_rollback_execution_receipt import (
    OperationRollbackExecutionReceipt,
)
from home_center.operation_rollback_verification_receipt import (
    OperationRollbackVerificationReceipt,
)
from home_center.operation_worker_handoff import OperationWorkerIdentity
from home_center.util import canonical_json


class OperationRecoveryRetryExecutionReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.store = OperationJobStateStore(self.path, b"a" * 32, "home-test")
        self.worker = OperationWorkerIdentity("worker-retry-a", "home-node-a")
        self.request = OperationRecoveryRetryRequest(
            authorization_id="opauth-abcdefabcdefabcdefabcdef",
            correlation_id="correlation-recovery-retry-exec-001",
            reason="operator approved one bounded recovery retry",
        )
        command_request = OperationCommandRequest(
            authorization_id="opauth-0123456789abcdef01234567",
            idempotency_key="restart-operation-retry-exec-001",
            target_node_id="home-node-a",
            service="home-center.service",
            reason="recover supervised service",
            correlation_id="correlation-original-001",
        )
        snapshot = ServiceStateSnapshot(
            target_node_id=command_request.target_node_id,
            service=command_request.service,
            load_state="loaded",
            active_state="active",
            sub_state="running",
            unit_file_state="enabled",
        )
        plan = OperationCommandAdmission().prepare(snapshot, command_request)
        job, _ = self.store.create_operation_job(plan=plan, actor="admin")
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

        recovery_sha256 = hashlib.sha256(
            canonical_json(job["plan"]["recovery"]).encode("utf-8")
        ).hexdigest()
        self.prior_execution = OperationRollbackExecutionReceipt(
            receipt_id="oprollbackexec-" + "a" * 24,
            rollback_claim_id="oprollback-" + "b" * 24,
            verification_receipt_id="opverify-" + "c" * 24,
            execution_receipt_id="opreceipt-" + "d" * 24,
            job_id=job["job_id"],
            action_id=ACTION_ID,
            plan_id=job["plan_id"],
            plan_sha256=job["plan_sha256"],
            worker_id="worker-original",
            target_node_id=job["target_node_id"],
            recovery_sha256=recovery_sha256,
            recovery_strategy="restore-observed-active-state",
            expected_active_state="active",
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=100,
            rollback_succeeded=True,
            recovery_required=False,
            next_state="rolling_back",
            from_state_version=2,
            to_state_version=3,
            verification_required=True,
            audit_event_id="audit-rollback-execution",
        )
        self.prior_verification = OperationRollbackVerificationReceipt(
            receipt_id="oprollbackverify-" + "e" * 24,
            rollback_execution_receipt_id=self.prior_execution.receipt_id,
            rollback_claim_id=self.prior_execution.rollback_claim_id,
            verification_receipt_id=self.prior_execution.verification_receipt_id,
            execution_receipt_id=self.prior_execution.execution_receipt_id,
            job_id=self.prior_execution.job_id,
            action_id=self.prior_execution.action_id,
            plan_id=self.prior_execution.plan_id,
            plan_sha256=self.prior_execution.plan_sha256,
            worker_id=self.prior_execution.worker_id,
            target_node_id=self.prior_execution.target_node_id,
            recovery_sha256=self.prior_execution.recovery_sha256,
            expected_active_state=self.prior_execution.expected_active_state,
            verification_sha256="f" * 64,
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=75,
            load_state="loaded",
            active_state="inactive",
            sub_state="dead",
            unit_file_state="enabled",
            recovery_verified=False,
            recovery_required=True,
            next_state="failed",
            from_state_version=3,
            to_state_version=4,
        )
        evidence = {
            "worker_claim": {"kind": "prior-worker-claim"},
            "execution_receipt": {"kind": "prior-execution"},
            "verification_receipt": {"kind": "prior-verification"},
            "rollback_claim": {"kind": "prior-rollback-claim"},
            "rollback_execution_receipt": self.prior_execution.to_dict(),
            "rollback_verification_receipt": self.prior_verification.to_dict(),
        }
        recovery = dict(job["plan"]["recovery"])
        recovery["verification"] = {
            "receipt_id": self.prior_verification.receipt_id,
            "recovery_verified": False,
            "recovery_required": True,
        }
        self.failed_job = self.store.transition_operation_job(
            job["job_id"],
            expected_state=OperationJobState.ROLLING_BACK,
            expected_state_version=3,
            target_state=OperationJobState.FAILED,
            mutation_may_have_occurred=True,
            evidence=evidence,
            recovery=recovery,
        )
        with patch(
            "home_center.operation_recovery_retry_admission."
            "revalidate_operation_rollback_verification_receipt"
        ):
            self.admission = OperationRecoveryRetryAdmissionCoordinator(
                self.store
            ).prepare(
                self.prior_verification,
                self.prior_execution,
                self.request,
            )
            self.claim, _ = OperationRecoveryRetryClaimCoordinator(
                self.store
            ).claim(
                self.admission,
                self.prior_verification,
                self.prior_execution,
                self.request,
                worker=self.worker,
            )
        self.coordinator = OperationRecoveryRetryExecutionReceiptCoordinator(
            self.store
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _record(
        self,
        observation: OperationRecoveryRetryExecutionObservation,
        *,
        worker: OperationWorkerIdentity | None = None,
    ):
        active_worker = worker or self.worker
        with patch(
            "home_center.operation_recovery_retry_claim."
            "revalidate_operation_recovery_retry_admission"
        ):
            return self.coordinator.record(
                self.claim.claim_id,
                self.admission,
                self.prior_verification,
                self.prior_execution,
                self.request,
                worker=active_worker,
                observation=observation,
            )

    def test_success_records_single_use_sanitized_receipt_and_requires_verification(
        self,
    ) -> None:
        before_audit = len(self.store.audit_events())
        receipt, changed = self._record(
            OperationRecoveryRetryExecutionObservation(True, False, 0, 120)
        )

        self.assertTrue(changed)
        self.assertTrue(receipt.retry_succeeded)
        self.assertTrue(receipt.verification_required)
        self.assertFalse(receipt.recovery_required)
        self.assertEqual("rolling_back", receipt.next_state)
        self.assertEqual(self.claim.to_state_version, receipt.from_state_version)
        self.assertEqual(self.claim.to_state_version + 1, receipt.to_state_version)
        self.assertTrue(receipt.single_use)
        self.assertFalse(receipt.contains_command_material)
        self.assertFalse(receipt.accepts_caller_argv)
        self.assertFalse(receipt.accepts_shell)
        self.assertFalse(receipt.grants_execution_authority)
        self.assertFalse(receipt.production_mutation_enabled)
        self.assertNotIn("argv", receipt.to_dict())
        self.assertNotIn("executable", receipt.to_dict())

        current = self.store.operation_job(self.claim.job_id)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual("rolling_back", current["state"])
        self.assertEqual(receipt.to_state_version, current["state_version"])
        self.assertFalse(current["recovery_required"])
        self.assertEqual(receipt.audit_event_id, current["last_audit_event_id"])
        self.assertEqual(
            receipt.to_dict(),
            current["evidence"]["recovery_retry_execution_receipt"],
        )
        self.assertEqual(before_audit + 1, len(self.store.audit_events()))
        self.store.verify_audit_chain()

    def test_exact_replay_is_idempotent_without_second_audit(self) -> None:
        observation = OperationRecoveryRetryExecutionObservation(True, False, 0, 120)
        first, changed = self._record(observation)
        self.assertTrue(changed)
        audit_count = len(self.store.audit_events())

        second, changed = self._record(observation)
        self.assertFalse(changed)
        self.assertEqual(first, second)
        self.assertEqual(audit_count, len(self.store.audit_events()))

    def test_conflicting_replay_observation_is_rejected(self) -> None:
        self._record(OperationRecoveryRetryExecutionObservation(True, False, 0, 120))
        with self.assertRaisesRegex(
            OperationRecoveryRetryExecutionReceiptError,
            "recovery_retry_execution_receipt_conflict",
        ):
            self._record(
                OperationRecoveryRetryExecutionObservation(True, False, 1, 120)
            )

    def test_failed_retry_returns_to_failed_and_requires_recovery(self) -> None:
        receipt, changed = self._record(
            OperationRecoveryRetryExecutionObservation(True, False, 1, 90)
        )
        self.assertTrue(changed)
        self.assertFalse(receipt.retry_succeeded)
        self.assertTrue(receipt.recovery_required)
        self.assertFalse(receipt.verification_required)
        self.assertEqual("failed", receipt.next_state)

        current = self.store.operation_job(self.claim.job_id)
        assert current is not None
        self.assertEqual("failed", current["state"])
        self.assertTrue(current["recovery_required"])

    def test_timeout_is_fail_closed_without_exit_code(self) -> None:
        receipt, _ = self._record(
            OperationRecoveryRetryExecutionObservation(True, True, None, 15_000)
        )
        self.assertEqual("failed", receipt.next_state)
        self.assertTrue(receipt.recovery_required)
        self.assertFalse(receipt.verification_required)

    def test_worker_rebind_is_rejected_before_receipt(self) -> None:
        other = OperationWorkerIdentity("worker-retry-b", "home-node-a")
        with self.assertRaisesRegex(
            OperationRecoveryRetryExecutionReceiptError,
            "recovery_retry_worker_identity_mismatch",
        ):
            self._record(
                OperationRecoveryRetryExecutionObservation(True, False, 0, 50),
                worker=other,
            )

    def test_recovery_contract_drift_is_rejected(self) -> None:
        current = self.store.operation_job(self.claim.job_id)
        assert current is not None
        recovery = dict(current["recovery"])
        recovery["timeout_seconds"] = 14
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE jobs SET recovery_json=? WHERE job_id=?",
                (canonical_json(recovery), self.claim.job_id),
            )
        with self.assertRaisesRegex(
            OperationRecoveryRetryExecutionReceiptError,
            "recovery_retry_execution_receipt_rejected",
        ):
            self._record(
                OperationRecoveryRetryExecutionObservation(True, False, 0, 50)
            )

    def test_claim_evidence_drift_is_rejected(self) -> None:
        current = self.store.operation_job(self.claim.job_id)
        assert current is not None
        evidence = dict(current["evidence"])
        evidence["recovery_retry_claim"] = {"tampered": True}
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE jobs SET evidence_json=? WHERE job_id=?",
                (canonical_json(evidence), self.claim.job_id),
            )
        with self.assertRaisesRegex(
            OperationRecoveryRetryExecutionReceiptError,
            "recovery_retry_execution_receipt_rejected",
        ):
            self._record(
                OperationRecoveryRetryExecutionObservation(True, False, 0, 50)
            )

    def test_persisted_receipt_tamper_fails_closed(self) -> None:
        receipt, _ = self._record(
            OperationRecoveryRetryExecutionObservation(True, False, 0, 120)
        )
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                """UPDATE operation_recovery_retry_execution_receipts
                SET receipt_json=? WHERE receipt_id=?""",
                ('{"tampered":true}', receipt.receipt_id),
            )
        with self.assertRaisesRegex(
            OperationRecoveryRetryExecutionReceiptError,
            "recovery_retry_execution_receipt_integrity_mismatch",
        ):
            self._record(
                OperationRecoveryRetryExecutionObservation(True, False, 0, 120)
            )

    def test_revalidation_rejects_post_receipt_lineage_drift(self) -> None:
        receipt, _ = self._record(
            OperationRecoveryRetryExecutionObservation(True, False, 0, 120)
        )
        revalidate_operation_recovery_retry_execution_receipt(
            self.store,
            receipt,
            self.admission,
            self.prior_verification,
            self.prior_execution,
            self.request,
            worker=self.worker,
        )

        current = self.store.operation_job(self.claim.job_id)
        assert current is not None
        evidence = dict(current["evidence"])
        evidence["recovery_retry_admission"] = replace(
            self.admission,
            failed_audit_event_id="different-audit-event",
        ).to_dict()
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE jobs SET evidence_json=? WHERE job_id=?",
                (canonical_json(evidence), self.claim.job_id),
            )
        with self.assertRaisesRegex(
            OperationRecoveryRetryExecutionReceiptError,
            "recovery_retry_admission_evidence_mismatch",
        ):
            revalidate_operation_recovery_retry_execution_receipt(
                self.store,
                receipt,
                self.admission,
                self.prior_verification,
                self.prior_execution,
                self.request,
                worker=self.worker,
            )

    def test_observation_rejects_unbounded_or_inconsistent_results(self) -> None:
        with self.assertRaisesRegex(
            OperationRecoveryRetryExecutionReceiptError,
            "invalid_recovery_retry_execution_elapsed_ms",
        ):
            OperationRecoveryRetryExecutionObservation(True, False, 0, 15_001)
        with self.assertRaisesRegex(
            OperationRecoveryRetryExecutionReceiptError,
            "recovery_retry_timeout_with_exit_code",
        ):
            OperationRecoveryRetryExecutionObservation(True, True, 1, 10)
        with self.assertRaisesRegex(
            OperationRecoveryRetryExecutionReceiptError,
            "invalid_recovery_retry_not_started_observation",
        ):
            OperationRecoveryRetryExecutionObservation(False, False, 0, 0)


if __name__ == "__main__":
    unittest.main()
