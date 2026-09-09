from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from home_center.home_service_admission import HomeServiceExecutionAdmission
from home_center.home_service_execution_result import HomeServiceExecutionOutcome, record_execution_result
from home_center.home_service_operations import HomeServiceInstanceSnapshot, HomeServiceInstanceState
from home_center.home_service_state import HomeServiceInstanceStateStore
from home_center.home_service_state_transition import decide_state_transition, prepare_transition_commit
from home_center.home_service_transition_apply import (
    HomeServiceTransitionAuthorization,
    apply_transition_commit,
)
from home_center.home_service_worker_claim import HomeServiceWorkerClaim
from home_center.home_services import HomeServiceCatalogError
from home_center.store import StateStore


class HomeServiceTransitionApplyTests(unittest.TestCase):
    def _prepared(self, instances: HomeServiceInstanceStateStore):
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
        return commit, authorization

    def test_authorized_commit_applies_exact_prepared_version_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            commit, authorization = self._prepared(instances)

            first = apply_transition_commit(commit, authorization, instances)
            current = instances.get(commit.instance_id)
            self.assertIsNotNone(current)
            self.assertTrue(first.applied)
            self.assertFalse(first.idempotent_replay)
            self.assertFalse(first.further_mutation_authorized)
            self.assertEqual(commit.target_state.value, current["state"])
            self.assertEqual(commit.next_generation, current["generation"])
            self.assertEqual(commit.next_resource_version, current["resource_version"])

            second = apply_transition_commit(commit, authorization, instances)
            self.assertEqual(first.receipt_id, second.receipt_id)
            self.assertFalse(second.applied)
            self.assertTrue(second.idempotent_replay)
            self.assertEqual(current, instances.get(commit.instance_id))
            store.close()

    def test_authorization_binding_mismatch_fails_before_state_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            commit, _ = self._prepared(instances)
            before = instances.get(commit.instance_id)
            mismatched = HomeServiceTransitionAuthorization(
                authorization_id="hsta-002",
                commit_id="hstc-other",
                decision_id=commit.decision_id,
                instance_id=commit.instance_id,
                expected_generation=commit.expected_generation,
                expected_resource_version=commit.expected_resource_version,
                allow_durable_commit=True,
                production_mutation_enabled=True,
            )

            with self.assertRaisesRegex(HomeServiceCatalogError, "transition_authorization_binding_mismatch"):
                apply_transition_commit(commit, mismatched, instances)
            self.assertEqual(before, instances.get(commit.instance_id))
            store.close()

    def test_authorization_must_explicitly_enable_mutation(self) -> None:
        with self.assertRaisesRegex(HomeServiceCatalogError, "durable_transition_not_authorized"):
            HomeServiceTransitionAuthorization(
                authorization_id="hsta-003",
                commit_id="hstc-001",
                decision_id="hstd-001",
                instance_id="instance-001",
                expected_generation=1,
                expected_resource_version="rv:instance:001",
                allow_durable_commit=False,
                production_mutation_enabled=False,
            )


if __name__ == "__main__":
    unittest.main()
