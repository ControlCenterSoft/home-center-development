from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from home_center.operation_commands import ACTION_ID
from home_center.operation_recovery_retry_admission import (
    OperationRecoveryRetryAdmissionCoordinator,
    OperationRecoveryRetryAdmissionError,
    OperationRecoveryRetryRequest,
    revalidate_operation_recovery_retry_admission,
)
from home_center.operation_rollback_execution_receipt import (
    OperationRollbackExecutionReceipt,
)
from home_center.operation_rollback_verification_receipt import (
    OperationRollbackVerificationReceipt,
)


class _Store:
    def __init__(self, job: dict[str, object]) -> None:
        self.job = copy.deepcopy(job)

    def operation_job(self, job_id: str) -> dict[str, object] | None:
        if self.job["job_id"] != job_id:
            return None
        return copy.deepcopy(self.job)


class OperationRecoveryRetryAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.execution = OperationRollbackExecutionReceipt(
            receipt_id="oprollbackexec-" + "a" * 24,
            rollback_claim_id="oprollback-" + "b" * 24,
            verification_receipt_id="opverify-" + "c" * 24,
            execution_receipt_id="opreceipt-" + "d" * 24,
            job_id="opjob-" + "e" * 24,
            action_id=ACTION_ID,
            plan_id="opcmd-" + "f" * 24,
            plan_sha256="1" * 64,
            worker_id="worker-001",
            target_node_id="home-node-a",
            recovery_sha256="2" * 64,
            recovery_strategy="restore-observed-active-state",
            expected_active_state="active",
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
        self.receipt = OperationRollbackVerificationReceipt(
            receipt_id="oprollbackverify-" + "3" * 24,
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
            verification_sha256="4" * 64,
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
            from_state_version=6,
            to_state_version=7,
        )
        self.job = {
            "job_id": self.receipt.job_id,
            "action_id": self.receipt.action_id,
            "state": "failed",
            "state_version": 7,
            "plan_id": self.receipt.plan_id,
            "plan_sha256": self.receipt.plan_sha256,
            "target_node_id": self.receipt.target_node_id,
            "authorization_id": "opauth-" + "5" * 24,
            "mutation_may_have_occurred": True,
            "recovery_required": True,
            "last_audit_event_id": "audit-failed-verification",
        }
        self.store = _Store(self.job)
        self.request = OperationRecoveryRetryRequest(
            authorization_id="opauth-" + "6" * 24,
            correlation_id="correlation-recovery-retry-001",
            reason="operator approved one bounded recovery retry",
        )

    @patch(
        "home_center.operation_recovery_retry_admission."
        "revalidate_operation_rollback_verification_receipt"
    )
    def test_failed_verification_builds_deterministic_safe_admission(
        self, revalidate
    ) -> None:
        coordinator = OperationRecoveryRetryAdmissionCoordinator(self.store)
        first = coordinator.prepare(self.receipt, self.execution, self.request)
        second = coordinator.prepare(self.receipt, self.execution, self.request)

        self.assertEqual(first, second)
        self.assertEqual("failed", first.to_dict()["failed_state"])
        self.assertTrue(first.retry_eligible)
        self.assertTrue(first.requires_new_worker_claim)
        self.assertFalse(first.state_transition_authorized)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.production_mutation_enabled)
        self.assertNotIn("reason", first.to_dict())
        self.assertNotIn("argv", first.to_dict())
        self.assertEqual(2, revalidate.call_count)

    @patch(
        "home_center.operation_recovery_retry_admission."
        "revalidate_operation_rollback_verification_receipt"
    )
    def test_reused_initial_authorization_is_rejected(self, _revalidate) -> None:
        request = OperationRecoveryRetryRequest(
            authorization_id=self.job["authorization_id"],
            correlation_id=self.request.correlation_id,
            reason=self.request.reason,
        )
        with self.assertRaisesRegex(
            OperationRecoveryRetryAdmissionError,
            "fresh_retry_authorization_required",
        ):
            OperationRecoveryRetryAdmissionCoordinator(self.store).prepare(
                self.receipt, self.execution, request
            )

    @patch(
        "home_center.operation_recovery_retry_admission."
        "revalidate_operation_rollback_verification_receipt"
    )
    def test_nonfailed_or_recovered_receipt_is_rejected(self, _revalidate) -> None:
        recovered = copy.copy(self.receipt)
        object.__setattr__(recovered, "recovery_verified", True)
        object.__setattr__(recovered, "recovery_required", False)
        object.__setattr__(recovered, "next_state", "rolled_back")
        with self.assertRaisesRegex(
            OperationRecoveryRetryAdmissionError,
            "recovery_retry_requires_failed_verification",
        ):
            OperationRecoveryRetryAdmissionCoordinator(self.store).prepare(
                recovered, self.execution, self.request
            )

    @patch(
        "home_center.operation_recovery_retry_admission."
        "revalidate_operation_rollback_verification_receipt"
    )
    def test_state_version_and_audit_drift_fail_closed(self, _revalidate) -> None:
        admission = OperationRecoveryRetryAdmissionCoordinator(self.store).prepare(
            self.receipt, self.execution, self.request
        )
        self.store.job["state_version"] = 8
        with self.assertRaisesRegex(
            OperationRecoveryRetryAdmissionError,
            "operation_job_state_stale",
        ):
            revalidate_operation_recovery_retry_admission(
                self.store,
                admission,
                self.receipt,
                self.execution,
                self.request,
            )

        self.store.job["state_version"] = 7
        self.store.job["last_audit_event_id"] = "audit-failed-verification-new"
        with self.assertRaisesRegex(
            OperationRecoveryRetryAdmissionError,
            "recovery_retry_admission_stale",
        ):
            revalidate_operation_recovery_retry_admission(
                self.store,
                admission,
                self.receipt,
                self.execution,
                self.request,
            )

    @patch(
        "home_center.operation_recovery_retry_admission."
        "revalidate_operation_rollback_verification_receipt"
    )
    def test_job_lineage_and_recovery_flags_fail_closed(self, _revalidate) -> None:
        mutations = (
            ("recovery_required", False, "recovery_not_required"),
            ("mutation_may_have_occurred", False, "mutation_evidence_missing"),
            ("target_node_id", "home-node-b", "operation_job_target_node_id_mismatch"),
        )
        for key, value, error in mutations:
            with self.subTest(key=key):
                store = _Store(self.job)
                store.job[key] = value
                with self.assertRaisesRegex(OperationRecoveryRetryAdmissionError, error):
                    OperationRecoveryRetryAdmissionCoordinator(store).prepare(
                        self.receipt, self.execution, self.request
                    )

    @patch(
        "home_center.operation_recovery_retry_admission."
        "revalidate_operation_rollback_verification_receipt"
    )
    def test_changed_request_invalidates_admission(self, _revalidate) -> None:
        admission = OperationRecoveryRetryAdmissionCoordinator(self.store).prepare(
            self.receipt, self.execution, self.request
        )
        changed = OperationRecoveryRetryRequest(
            authorization_id="opauth-" + "7" * 24,
            correlation_id=self.request.correlation_id,
            reason=self.request.reason,
        )
        with self.assertRaisesRegex(
            OperationRecoveryRetryAdmissionError,
            "recovery_retry_admission_stale",
        ):
            revalidate_operation_recovery_retry_admission(
                self.store,
                admission,
                self.receipt,
                self.execution,
                changed,
            )

    def test_request_validation_is_bounded(self) -> None:
        invalid = (
            dict(
                authorization_id="invalid",
                correlation_id="correlation-retry-001",
                reason="valid reason",
            ),
            dict(
                authorization_id="opauth-" + "8" * 24,
                correlation_id="short",
                reason="valid reason",
            ),
            dict(
                authorization_id="opauth-" + "8" * 24,
                correlation_id="correlation-retry-001",
                reason="x",
            ),
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(OperationRecoveryRetryAdmissionError):
                    OperationRecoveryRetryRequest(**value)


if __name__ == "__main__":
    unittest.main()
