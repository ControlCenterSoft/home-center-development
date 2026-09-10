from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from home_center.home_service_admission import HomeServiceExecutionAdmission
from home_center.home_service_execution_result import HomeServiceExecutionOutcome, record_execution_result
from home_center.home_service_operations import HomeServiceInstanceSnapshot, HomeServiceInstanceState
from home_center.home_service_state import HomeServiceInstanceStateStore
from home_center.home_service_state_transition import decide_state_transition, prepare_transition_commit
from home_center.home_service_transition_apply import HomeServiceTransitionAuthorization
from home_center.home_service_transition_audit import (
    HomeServiceTransitionApplyContext,
    apply_transition_commit_audited,
)
from home_center.home_service_worker_claim import HomeServiceWorkerClaim
from home_center.home_services import HomeServiceCatalogError
from home_center.store import StateStore


class HomeServiceTransitionAuditTests(unittest.TestCase):
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

    def test_audited_apply_records_bound_intent_before_durable_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            commit, authorization = self._prepared(instances)
            context = HomeServiceTransitionApplyContext(
                actor="admin",
                reason="Apply verified home-service transition",
                correlation_id="transition-001",
            )

            applied = apply_transition_commit_audited(commit, authorization, instances, context)
            events = store.audit_events()
            self.assertEqual(1, len(events))
            event = events[0]
            self.assertEqual(applied.audit_event_id, event["event_id"])
            self.assertEqual("admin", event["actor"])
            self.assertEqual("home-service.transition.apply.requested", event["action"])
            self.assertEqual(commit.instance_id, event["target"])
            self.assertEqual("authorized", event["outcome"])
            self.assertEqual("transition-001", event["correlation_id"])
            self.assertEqual(authorization.authorization_id, event["details"]["authorization_id"])
            self.assertEqual(commit.commit_id, event["details"]["commit_id"])
            self.assertEqual(commit.next_generation, event["details"]["next_generation"])
            self.assertTrue(applied.receipt.applied)
            self.assertEqual(commit.next_resource_version, instances.get(commit.instance_id)["resource_version"])
            self.assertNotEqual("0" * 64, store.verify_audit_chain())
            store.close()

    def test_binding_mismatch_fails_before_audit_or_state_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            commit, authorization = self._prepared(instances)
            before = instances.get(commit.instance_id)
            mismatched = HomeServiceTransitionAuthorization(
                authorization_id="hsta-002",
                commit_id="hstc-other",
                decision_id=authorization.decision_id,
                instance_id=authorization.instance_id,
                expected_generation=authorization.expected_generation,
                expected_resource_version=authorization.expected_resource_version,
                allow_durable_commit=True,
                production_mutation_enabled=True,
            )
            context = HomeServiceTransitionApplyContext(
                actor="admin",
                reason="Rejected mismatch",
                correlation_id="transition-002",
            )

            with self.assertRaisesRegex(HomeServiceCatalogError, "transition_authorization_binding_mismatch"):
                apply_transition_commit_audited(commit, mismatched, instances, context)
            self.assertEqual([], store.audit_events())
            self.assertEqual(before, instances.get(commit.instance_id))
            store.close()

    def test_invalid_audit_context_is_rejected(self) -> None:
        with self.assertRaisesRegex(HomeServiceCatalogError, "invalid_transition_reason"):
            HomeServiceTransitionApplyContext(
                actor="admin",
                reason=" surrounding whitespace ",
                correlation_id="transition-003",
            )


if __name__ == "__main__":
    unittest.main()
