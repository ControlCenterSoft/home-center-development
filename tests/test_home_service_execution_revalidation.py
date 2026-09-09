from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.home_service_admission import (
    ApprovalEvidence,
    DurableJobBinding,
    admit_operation,
)
from home_center.home_service_execution_revalidation import (
    HomeServiceClaimTokenEvidence,
    HomeServiceExecutionJobSnapshot,
    HomeServiceExecutionJobState,
    execution_admission_sha256,
    revalidate_execution,
)
from home_center.home_service_operations import (
    HomeServiceInstanceSnapshot,
    HomeServiceInstanceState,
    HomeServiceOperation,
    HomeServiceOperationPlanner,
    HomeServiceOperationRequest,
)
from home_center.home_service_worker_claim import HomeServiceWorkerIdentity, claim_execution
from home_center.home_services import HomeServiceCatalogError


ROOT = Path(__file__).resolve().parents[1]


class HomeServiceExecutionRevalidationTests(unittest.TestCase):
    def _inputs(self):
        snapshot = HomeServiceInstanceSnapshot(
            instance_id="minecraft-main",
            service_id="minecraft-server",
            target_node_id="home-node-a",
            state=HomeServiceInstanceState.READY,
            generation=7,
            resource_version="rv:instance:7",
        )
        plan = HomeServiceOperationPlanner().plan(
            snapshot,
            HomeServiceOperationRequest(
                operation=HomeServiceOperation.UPDATE,
                expected_generation=7,
                expected_resource_version="rv:instance:7",
                idempotency_key="update-001",
            ),
        )
        admission = admit_operation(
            plan,
            snapshot,
            ApprovalEvidence(
                "approval-001",
                plan.plan_id,
                "local-admin",
                "Apply verified update",
            ),
            DurableJobBinding("job-001", plan.plan_id, "preflight"),
            audit_correlation_id="audit-001",
        )
        claim = claim_execution(
            admission,
            snapshot,
            HomeServiceWorkerIdentity("worker-001", "home-node-a"),
            job_state="preflight",
        )
        token = HomeServiceClaimTokenEvidence(claim.claim_id, "b" * 64)
        job = HomeServiceExecutionJobSnapshot(
            job_id=claim.job_id,
            state=HomeServiceExecutionJobState.QUEUED,
            admission_id=admission.admission_id,
            admission_sha256=execution_admission_sha256(admission),
            claim_id=claim.claim_id,
            claim_token_sha256=token.claim_token_sha256,
        )
        return snapshot, admission, claim, job, token

    def test_revalidation_is_deterministic_and_non_mutating(self) -> None:
        snapshot, admission, claim, job, token = self._inputs()
        first = revalidate_execution(admission, claim, snapshot, job, token)
        second = revalidate_execution(admission, claim, snapshot, job, token)

        self.assertEqual(first, second)
        value = first.to_dict()
        self.assertTrue(value["revalidated"])
        self.assertTrue(value["compare_and_swap_matched"])
        self.assertTrue(value["revalidation_record_only"])
        self.assertFalse(value["execution_authorized"])
        self.assertFalse(value["direct_execution"])
        self.assertFalse(value["production_mutation_enabled"])
        self.assertFalse(value["accepts_secret_values"])
        self.assertEqual("queued", value["observed_job_state"])
        self.assertRegex(value["revalidation_id"], r"^hsrv-[a-f0-9]{24}$")

    def test_stale_job_state_fails_closed(self) -> None:
        snapshot, admission, claim, job, token = self._inputs()
        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "invalid_job_state_for_revalidation",
        ):
            revalidate_execution(
                admission,
                claim,
                snapshot,
                replace(job, state=HomeServiceExecutionJobState.RUNNING),
                token,
            )

    def test_stale_claim_token_fails_closed(self) -> None:
        snapshot, admission, claim, job, _ = self._inputs()
        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "claim_token_precondition_failed",
        ):
            revalidate_execution(
                admission,
                claim,
                snapshot,
                job,
                HomeServiceClaimTokenEvidence(claim.claim_id, "c" * 64),
            )

    def test_stale_instance_generation_or_resource_version_fails_closed(self) -> None:
        snapshot, admission, claim, job, token = self._inputs()
        stale_values = (
            replace(snapshot, generation=8),
            replace(snapshot, resource_version="rv:instance:8"),
        )
        for stale in stale_values:
            with self.subTest(stale=stale), self.assertRaisesRegex(
                HomeServiceCatalogError,
                "execution_revalidation_precondition_failed",
            ):
                revalidate_execution(admission, claim, stale, job, token)

    def test_stale_admission_digest_fails_closed(self) -> None:
        snapshot, admission, claim, job, token = self._inputs()
        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "admission_digest_precondition_failed",
        ):
            revalidate_execution(
                admission,
                claim,
                snapshot,
                replace(job, admission_sha256="d" * 64),
                token,
            )

    def test_cross_bound_claim_fails_closed(self) -> None:
        snapshot, admission, claim, job, token = self._inputs()
        with self.assertRaisesRegex(HomeServiceCatalogError, "execution_binding_mismatch"):
            revalidate_execution(
                admission,
                replace(claim, job_id="job-002"),
                snapshot,
                job,
                token,
            )

    def test_contract_is_closed_and_has_no_command_endpoint_or_credential(self) -> None:
        contract = json.loads(
            (
                ROOT
                / "contracts/market/home-service-execution-revalidation.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertIs(contract["additionalProperties"], False)
        properties = contract["properties"]
        self.assertNotIn("command", properties)
        self.assertNotIn("shell", properties)
        self.assertNotIn("endpoint", properties)
        self.assertNotIn("credential", properties)
        self.assertNotIn("claim_token", properties)
        self.assertIn("claim_token_sha256", properties)
        self.assertIs(properties["execution_authorized"]["const"], False)
        self.assertIs(properties["production_mutation_enabled"]["const"], False)
        self.assertIs(properties["accepts_secret_values"]["const"], False)
        self.assertEqual(set(contract["required"]), set(properties))

    def test_malformed_digest_is_rejected(self) -> None:
        _, _, claim, _, _ = self._inputs()
        with self.assertRaisesRegex(HomeServiceCatalogError, "invalid_claim_token_digest"):
            HomeServiceClaimTokenEvidence(claim.claim_id, "not-a-digest")


if __name__ == "__main__":
    unittest.main()
