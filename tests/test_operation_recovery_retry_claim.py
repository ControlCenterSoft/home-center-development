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
    OperationRecoveryRetryClaimError,
    revalidate_operation_recovery_retry_claim,
)
from home_center.operation_rollback_execution_receipt import (
    OperationRollbackExecutionReceipt,
)
from home_center.operation_rollback_verification_receipt import (
    OperationRollbackVerificationReceipt,
)
from home_center.operation_worker_handoff import OperationWorkerIdentity
from home_center.util import canonical_json


class OperationRecoveryRetryClaimTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.store = OperationJobStateStore(self.path, b"a" * 32, "home-test")
        self.worker = OperationWorkerIdentity("worker-retry-a", "home-node-a")
        self.request = OperationRecoveryRetryRequest(
            authorization_id="opauth-abcdefabcdefabcdefabcdef",
            correlation_id="correlation-recovery-retry-claim-001",
            reason="operator approved one bounded recovery retry",
        )

        command_request = OperationCommandRequest(
            authorization_id="opauth-0123456789abcdef01234567",
            idempotency_key="restart-operation-retry-001",
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
        self.execution = OperationRollbackExecutionReceipt(
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
        self.receipt = OperationRollbackVerificationReceipt(
            receipt_id="oprollbackverify-" + "e" * 24,
            rollback_execution_receipt_id=self.execution.receipt_id,
            rollback_claim_id=self.execution.rollback_claim_id,
            verification_receipt_id=self.execution.verification_receipt_id,
            execution_receipt_id=self.execution.execution_receipt_id,
            job_id=self.execution.job_id,
            action_id=self.execution.action_id,
            plan_id=self.execution.plan_id,
            plan_sha256=self.execution.plan_sha256,
            worker_id=self.execution.worker_id,
            target_node_id=self.execution.target_node_id,
            recovery_sha256=self.execution.recovery_sha256,
            expected_active_state=self.execution.expected_active_state,
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
            "rollback_execution_receipt": self.execution.to_dict(),
            "rollback_verification_receipt": self.receipt.to_dict(),
        }
        recovery = dict(job["plan"]["recovery"])
        recovery["verification"] = {
            "receipt_id": self.receipt.receipt_id,
            "recovery_verified": False,
            "recovery_required": True,
        }
        self.job = self.store.transition_operation_job(
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
            ).prepare(self.receipt, self.execution, self.request)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _claim(self, *, worker: OperationWorkerIdentity | None = None):
        active_worker = worker or self.worker
        with patch(
            "home_center.operation_recovery_retry_admission."
            "revalidate_operation_rollback_verification_receipt"
        ):
            return OperationRecoveryRetryClaimCoordinator(self.store).claim(
                self.admission,
                self.receipt,
                self.execution,
                self.request,
                worker=active_worker,
            )

    def test_claim_reenters_failed_job_with_exact_cas_and_fresh_authorization(self) -> None:
        before_audit = len(self.store.audit_events())
        claim, changed = self._claim()

        self.assertTrue(changed)
        self.assertEqual(self.admission.admission_id, claim.admission_id)
        self.assertEqual(self.request.authorization_id, claim.retry_authorization_id)
        self.assertEqual(self.job["state_version"], claim.from_state_version)
        self.assertEqual(self.job["state_version"] + 1, claim.to_state_version)
        self.assertTrue(claim.single_use)
        self.assertFalse(claim.execution_authorized)
        self.assertFalse(claim.production_mutation_enabled)
        self.assertNotIn("argv", claim.to_dict())
        self.assertNotIn("executable", claim.to_dict())

        current = self.store.operation_job(self.job["job_id"])
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual("rolling_back", current["state"])
        self.assertEqual(claim.to_state_version, current["state_version"])
        self.assertTrue(current["mutation_may_have_occurred"])
        self.assertFalse(current["recovery_required"])
        self.assertEqual(claim.audit_event_id, current["last_audit_event_id"])
        self.assertEqual(
            self.admission.to_dict(),
            current["evidence"]["recovery_retry_admission"],
        )
        self.assertEqual(
            claim.to_dict(),
            current["evidence"]["recovery_retry_claim"],
        )
        self.assertEqual(before_audit + 1, len(self.store.audit_events()))
        self.store.verify_audit_chain()

    def test_exact_replay_is_idempotent_without_second_audit_append(self) -> None:
        first, changed = self._claim()
        self.assertTrue(changed)
        audit_count = len(self.store.audit_events())

        second, changed = self._claim()
        self.assertFalse(changed)
        self.assertEqual(first, second)
        self.assertEqual(audit_count, len(self.store.audit_events()))

    def test_claim_is_single_worker_and_cannot_be_rebound_on_replay(self) -> None:
        self._claim()
        other = OperationWorkerIdentity("worker-retry-b", "home-node-a")
        with self.assertRaisesRegex(
            OperationRecoveryRetryClaimError,
            "recovery_retry_claim_lineage_mismatch",
        ):
            self._claim(worker=other)

    def test_stale_failed_version_is_rejected_without_new_audit(self) -> None:
        stale = replace(
            self.admission,
            failed_state_version=self.admission.failed_state_version + 1,
        )
        before = len(self.store.audit_events())
        with patch(
            "home_center.operation_recovery_retry_claim."
            "revalidate_operation_recovery_retry_admission"
        ):
            with self.assertRaisesRegex(
                OperationRecoveryRetryClaimError,
                "operation_job_state_stale",
            ):
                OperationRecoveryRetryClaimCoordinator(self.store).claim(
                    stale,
                    self.receipt,
                    self.execution,
                    self.request,
                    worker=self.worker,
                )
        self.assertEqual(before, len(self.store.audit_events()))

    def test_failed_audit_lineage_drift_is_rejected(self) -> None:
        stale = replace(self.admission, failed_audit_event_id="different-audit-event")
        with patch(
            "home_center.operation_recovery_retry_claim."
            "revalidate_operation_recovery_retry_admission"
        ):
            with self.assertRaisesRegex(
                OperationRecoveryRetryClaimError,
                "operation_job_audit_stale",
            ):
                OperationRecoveryRetryClaimCoordinator(self.store).claim(
                    stale,
                    self.receipt,
                    self.execution,
                    self.request,
                    worker=self.worker,
                )

    def test_recovery_contract_drift_fails_closed(self) -> None:
        recovery = dict(self.job["recovery"])
        recovery["timeout_seconds"] = 999
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE jobs SET recovery_json=? WHERE job_id=?",
                (canonical_json(recovery), self.job["job_id"]),
            )
        with patch(
            "home_center.operation_recovery_retry_admission."
            "revalidate_operation_rollback_verification_receipt"
        ):
            with self.assertRaisesRegex(
                OperationRecoveryRetryClaimError,
                "operation_recovery_evidence_drift",
            ):
                OperationRecoveryRetryClaimCoordinator(self.store).claim(
                    self.admission,
                    self.receipt,
                    self.execution,
                    self.request,
                    worker=self.worker,
                )

    def test_target_node_mismatch_is_rejected_before_state_change(self) -> None:
        other_node = OperationWorkerIdentity("worker-retry-b", "home-node-b")
        with self.assertRaisesRegex(
            OperationRecoveryRetryClaimError,
            "operation_worker_target_mismatch",
        ):
            self._claim(worker=other_node)
        current = self.store.operation_job(self.job["job_id"])
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual("failed", current["state"])

    def test_tampered_persisted_claim_fails_closed(self) -> None:
        claim, _ = self._claim()
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                """UPDATE operation_recovery_retry_claims
                SET claim_json=? WHERE claim_id=?""",
                ('{"tampered":true}', claim.claim_id),
            )
        with self.assertRaisesRegex(
            OperationRecoveryRetryClaimError,
            "recovery_retry_claim_integrity_mismatch",
        ):
            self._claim()

    def test_explicit_revalidation_binds_current_job_and_claim_evidence(self) -> None:
        claim, _ = self._claim()
        revalidate_operation_recovery_retry_claim(
            self.store,
            claim,
            self.admission,
            self.receipt,
            self.execution,
            self.request,
            worker=self.worker,
        )

        current = self.store.operation_job(self.job["job_id"])
        assert current is not None
        evidence = dict(current["evidence"])
        evidence["recovery_retry_claim"] = {"tampered": True}
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE jobs SET evidence_json=? WHERE job_id=?",
                (canonical_json(evidence), self.job["job_id"]),
            )
        with self.assertRaisesRegex(
            OperationRecoveryRetryClaimError,
            "recovery_retry_claim_evidence_mismatch",
        ):
            revalidate_operation_recovery_retry_claim(
                self.store,
                claim,
                self.admission,
                self.receipt,
                self.execution,
                self.request,
                worker=self.worker,
            )


if __name__ == "__main__":
    unittest.main()
