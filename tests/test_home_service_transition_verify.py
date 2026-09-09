from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from home_center.home_service_admission import HomeServiceExecutionAdmission
from home_center.home_service_execution_result import HomeServiceExecutionOutcome, record_execution_result
from home_center.home_service_operations import HomeServiceInstanceSnapshot, HomeServiceInstanceState
from home_center.home_service_state import HomeServiceInstanceStateStore, InstanceTransition
from home_center.home_service_state_transition import decide_state_transition, prepare_transition_commit
from home_center.home_service_transition_apply import (
    HomeServiceTransitionApplyReceipt,
    HomeServiceTransitionAuthorization,
    apply_transition_commit,
)
from home_center.home_service_transition_verify import (
    TransitionVerificationCode,
    TransitionVerificationStatus,
    verify_transition_apply,
)
from home_center.home_service_worker_claim import HomeServiceWorkerClaim
from home_center.home_services import HomeServiceCatalogError
from home_center.store import StateStore


class HomeServiceTransitionVerifyTests(unittest.TestCase):
    def _applied(self, instances: HomeServiceInstanceStateStore):
        created = instances.create(
            instance_id="instance-001",
            service_id="service-001",
            target_node_id="node-001",
        )
        snapshot = HomeServiceInstanceSnapshot(
            instance_id=str(created["instance_id"]),
            service_id=str(created["service_id"]),
            target_node_id=str(created["target_node_id"]),
            state=HomeServiceInstanceState(str(created["state"])),
            generation=int(created["generation"]),
            resource_version=str(created["resource_version"]),
        )
        admission = HomeServiceExecutionAdmission(
            admission_id="hsea-001",
            plan_id="hsop-001",
            plan_sha256="a" * 64,
            instance_id=snapshot.instance_id,
            operation="install",
            based_on_generation=snapshot.generation,
            based_on_resource_version=snapshot.resource_version,
            approval_id="approval-001",
            job_id="job-001",
            audit_correlation_id="audit-001",
            secret_references=(),
        )
        claim = HomeServiceWorkerClaim(
            claim_id="hswc-001",
            admission_id=admission.admission_id,
            plan_id=admission.plan_id,
            job_id=admission.job_id,
            worker_id="worker-001",
            node_id=snapshot.target_node_id,
            instance_id=snapshot.instance_id,
            operation=admission.operation,
            based_on_generation=snapshot.generation,
            based_on_resource_version=snapshot.resource_version,
        )
        result = record_execution_result(
            claim,
            outcome=HomeServiceExecutionOutcome.SUCCEEDED,
            target_state=HomeServiceInstanceState.INSTALLED,
            observed_generation=snapshot.generation,
            observed_resource_version=snapshot.resource_version,
            evidence_digest="evidence-001",
        )
        decision = decide_state_transition(result, claim, admission, snapshot)
        commit = prepare_transition_commit(decision)
        authorization = HomeServiceTransitionAuthorization(
            authorization_id="hsta-001",
            commit_id=commit.commit_id,
            decision_id=commit.decision_id,
            instance_id=commit.instance_id,
            expected_generation=commit.expected_generation,
            expected_resource_version=commit.expected_resource_version,
            allow_durable_commit=True,
            production_mutation_enabled=True,
        )
        return commit, apply_transition_commit(commit, authorization, instances)

    def test_exact_read_back_is_verified_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            commit, receipt = self._applied(instances)
            before = instances.get(commit.instance_id)

            verification = verify_transition_apply(receipt, instances)

            self.assertEqual(TransitionVerificationStatus.VERIFIED, verification.status)
            self.assertTrue(verification.verified)
            self.assertEqual((), verification.mismatch_codes)
            self.assertEqual(receipt.target_state, verification.observed_state)
            self.assertEqual(receipt.generation, verification.observed_generation)
            self.assertEqual(receipt.resource_version, verification.observed_resource_version)
            self.assertTrue(verification.evidence_record_only)
            self.assertFalse(verification.further_mutation_authorized)
            self.assertFalse(verification.production_mutation_enabled)
            self.assertEqual(before, instances.get(commit.instance_id))
            store.close()

    def test_later_state_change_is_reported_as_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            commit, receipt = self._applied(instances)
            current = instances.get(commit.instance_id)
            self.assertIsNotNone(current)
            instances.transition(
                InstanceTransition(
                    instance_id=commit.instance_id,
                    expected_generation=int(current["generation"]),
                    expected_resource_version=str(current["resource_version"]),
                    idempotency_key="manual-drift-001",
                    target_state=HomeServiceInstanceState.CONFIGURED,
                )
            )

            verification = verify_transition_apply(receipt, instances)

            self.assertEqual(TransitionVerificationStatus.DRIFTED, verification.status)
            self.assertFalse(verification.verified)
            self.assertEqual(
                (
                    TransitionVerificationCode.STATE_MISMATCH,
                    TransitionVerificationCode.GENERATION_MISMATCH,
                    TransitionVerificationCode.RESOURCE_VERSION_MISMATCH,
                ),
                verification.mismatch_codes,
            )
            self.assertFalse(verification.further_mutation_authorized)
            store.close()

    def test_ambiguous_receipt_is_rejected(self) -> None:
        unsafe = HomeServiceTransitionApplyReceipt(
            receipt_id="hstr-" + "a" * 24,
            authorization_id="hsta-001",
            commit_id="hstc-" + "b" * 24,
            decision_id="hstd-" + "c" * 24,
            instance_id="instance-001",
            target_state="installed",
            generation=2,
            resource_version="rv:instance:" + "d" * 24,
            applied=True,
            idempotent_replay=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            with self.assertRaisesRegex(HomeServiceCatalogError, "invalid_transition_apply_receipt"):
                verify_transition_apply(unsafe, instances)
            store.close()


if __name__ == "__main__":
    unittest.main()
