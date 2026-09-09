from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from home_center.home_service_admission import HomeServiceExecutionAdmission
from home_center.home_service_execution_result import (
    HomeServiceExecutionOutcome,
    record_execution_result,
)
from home_center.home_service_operations import HomeServiceInstanceSnapshot, HomeServiceInstanceState
from home_center.home_service_state import HomeServiceInstanceStateStore
from home_center.home_service_state_transition import (
    TransitionDecisionStatus,
    TransitionRejectionCode,
    decide_state_transition,
    prepare_transition_commit,
)
from home_center.home_service_worker_claim import HomeServiceWorkerClaim
from home_center.home_services import HomeServiceCatalogError
from home_center.store import StateStore


class HomeServiceStateTransitionTests(unittest.TestCase):
    def _chain(
        self,
        *,
        snapshot: HomeServiceInstanceSnapshot | None = None,
    ) -> tuple[
        HomeServiceInstanceSnapshot,
        HomeServiceExecutionAdmission,
        HomeServiceWorkerClaim,
        object,
    ]:
        snapshot = snapshot or HomeServiceInstanceSnapshot(
            instance_id="instance-001",
            service_id="service-001",
            target_node_id="node-001",
            state=HomeServiceInstanceState.PLANNED,
            generation=1,
            resource_version="rv:instance:001",
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
        return snapshot, admission, claim, result

    @staticmethod
    def _view(value: object, **overrides: object) -> SimpleNamespace:
        names = getattr(value, "__dataclass_fields__")
        fields = {name: getattr(value, name) for name in names}
        fields.update(overrides)
        return SimpleNamespace(**fields)

    def test_verified_evidence_does_not_change_durable_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
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
            snapshot, admission, claim, result = self._chain(snapshot=snapshot)

            before = instances.get(snapshot.instance_id)
            decision = decide_state_transition(result, claim, admission, snapshot)
            commit = prepare_transition_commit(decision)
            after = instances.get(snapshot.instance_id)

            self.assertEqual(before, after)
            self.assertEqual(TransitionDecisionStatus.ALLOWED, decision.status)
            self.assertTrue(decision.transition_allowed)
            self.assertFalse(result.state_transition_authorized)
            self.assertFalse(commit.committed)
            self.assertFalse(commit.production_mutation_enabled)
            store.close()

    def test_allowed_decision_and_commit_are_deterministic_and_idempotent(self) -> None:
        snapshot, admission, claim, result = self._chain()

        first_decision = decide_state_transition(result, claim, admission, snapshot)
        second_decision = decide_state_transition(result, claim, admission, snapshot)
        first_commit = prepare_transition_commit(first_decision)
        second_commit = prepare_transition_commit(second_decision)

        self.assertEqual(first_decision, second_decision)
        self.assertEqual(first_commit, second_commit)
        self.assertTrue(first_commit.idempotent)
        self.assertTrue(first_commit.compare_and_swap_required)
        self.assertEqual(2, first_commit.next_generation)
        self.assertEqual(first_commit.idempotency_key, second_commit.idempotency_key)

    def test_failed_or_unverified_evidence_is_rejected(self) -> None:
        snapshot, admission, claim, result = self._chain()
        cases = (
            (
                self._view(result, verified=False),
                TransitionRejectionCode.EVIDENCE_NOT_VERIFIED,
            ),
            (
                self._view(result, outcome=HomeServiceExecutionOutcome.FAILED),
                TransitionRejectionCode.EXECUTION_NOT_SUCCEEDED,
            ),
            (
                self._view(result, state_transition_authorized=True),
                TransitionRejectionCode.UNSAFE_EVIDENCE_BOUNDARY,
            ),
        )
        for evidence, code in cases:
            with self.subTest(code=code):
                decision = decide_state_transition(evidence, claim, admission, snapshot)
                self.assertEqual(TransitionDecisionStatus.REJECTED, decision.status)
                self.assertIn(code, decision.rejection_codes)
                self.assertFalse(decision.transition_allowed)
                with self.assertRaisesRegex(HomeServiceCatalogError, "transition_not_allowed"):
                    prepare_transition_commit(decision)

    def test_every_identity_and_cas_binding_fails_closed(self) -> None:
        snapshot, admission, claim, result = self._chain()
        cases = (
            (
                self._view(result, claim_id="hswc-other"),
                claim,
                admission,
                snapshot,
                TransitionRejectionCode.CLAIM_BINDING_MISMATCH,
            ),
            (
                result,
                self._view(claim, admission_id="hsea-other"),
                admission,
                snapshot,
                TransitionRejectionCode.ADMISSION_BINDING_MISMATCH,
            ),
            (
                self._view(result, job_id="job-other"),
                claim,
                admission,
                snapshot,
                TransitionRejectionCode.JOB_BINDING_MISMATCH,
            ),
            (
                self._view(result, plan_id="hsop-other"),
                claim,
                admission,
                snapshot,
                TransitionRejectionCode.PLAN_BINDING_MISMATCH,
            ),
            (
                self._view(result, worker_id="worker-other"),
                claim,
                admission,
                snapshot,
                TransitionRejectionCode.WORKER_BINDING_MISMATCH,
            ),
            (
                self._view(result, instance_id="instance-other"),
                claim,
                admission,
                snapshot,
                TransitionRejectionCode.INSTANCE_BINDING_MISMATCH,
            ),
            (
                result,
                self._view(claim, node_id="node-other"),
                admission,
                snapshot,
                TransitionRejectionCode.NODE_BINDING_MISMATCH,
            ),
            (
                self._view(result, observed_generation=2),
                claim,
                admission,
                snapshot,
                TransitionRejectionCode.GENERATION_BINDING_MISMATCH,
            ),
            (
                self._view(result, observed_resource_version="rv:instance:other"),
                claim,
                admission,
                snapshot,
                TransitionRejectionCode.RESOURCE_VERSION_BINDING_MISMATCH,
            ),
        )
        for evidence, claim_view, admission_view, current, code in cases:
            with self.subTest(code=code):
                decision = decide_state_transition(evidence, claim_view, admission_view, current)
                self.assertEqual(TransitionDecisionStatus.REJECTED, decision.status)
                self.assertIn(code, decision.rejection_codes)

    def test_target_state_must_match_admitted_operation(self) -> None:
        snapshot, admission, claim, result = self._chain()
        evidence = self._view(result, target_state=HomeServiceInstanceState.READY)
        decision = decide_state_transition(evidence, claim, admission, snapshot)
        self.assertIn(TransitionRejectionCode.TARGET_STATE_MISMATCH, decision.rejection_codes)

    def test_unsafe_claim_and_admission_flags_are_rejected(self) -> None:
        snapshot, admission, claim, result = self._chain()
        cases = (
            (
                self._view(claim, production_mutation_enabled=True),
                admission,
                TransitionRejectionCode.UNSAFE_WORKER_CLAIM,
            ),
            (
                claim,
                self._view(admission, direct_execution=True),
                TransitionRejectionCode.UNSAFE_EXECUTION_ADMISSION,
            ),
        )
        for claim_view, admission_view, code in cases:
            with self.subTest(code=code):
                decision = decide_state_transition(result, claim_view, admission_view, snapshot)
                self.assertIn(code, decision.rejection_codes)
                self.assertFalse(decision.transition_allowed)

    def test_contract_schemas_are_closed_and_non_mutating(self) -> None:
        root = Path("contracts/market")
        for filename in (
            "home-service-transition-decision.v1.schema.json",
            "home-service-transition-commit.v1.schema.json",
        ):
            with self.subTest(filename=filename):
                contract = json.loads((root / filename).read_text(encoding="utf-8"))
                self.assertIs(contract["additionalProperties"], False)
                self.assertIs(
                    contract["properties"]["production_mutation_enabled"]["const"],
                    False,
                )
                self.assertIn("production_mutation_enabled", contract["required"])

        snapshot, admission, claim, result = self._chain()
        decision = decide_state_transition(result, claim, admission, snapshot).to_dict()
        commit = prepare_transition_commit(
            decide_state_transition(result, claim, admission, snapshot)
        ).to_dict()
        decision_schema = json.loads(
            (root / "home-service-transition-decision.v1.schema.json").read_text(encoding="utf-8")
        )
        commit_schema = json.loads(
            (root / "home-service-transition-commit.v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(decision_schema["required"]), set(decision))
        self.assertEqual(set(commit_schema["required"]), set(commit))


if __name__ == "__main__":
    unittest.main()
