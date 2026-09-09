from __future__ import annotations

import unittest

from home_center.home_service_admission import HomeServiceExecutionAdmission
from home_center.home_service_operations import HomeServiceInstanceSnapshot, HomeServiceInstanceState
from home_center.home_service_worker_claim import (
    HomeServiceWorkerIdentity,
    claim_execution,
)
from home_center.home_services import HomeServiceCatalogError


class HomeServiceWorkerClaimTests(unittest.TestCase):
    def _admission(self) -> HomeServiceExecutionAdmission:
        return HomeServiceExecutionAdmission(
            admission_id="hsea-001",
            plan_id="hsop-001",
            plan_sha256="a" * 64,
            instance_id="instance-001",
            operation="install",
            based_on_generation=1,
            based_on_resource_version="rv-instance-001",
            approval_id="approval-001",
            job_id="job-001",
            audit_correlation_id="audit-001",
            secret_references=(),
        )

    def _snapshot(self, *, generation: int = 1, resource_version: str = "rv-instance-001") -> HomeServiceInstanceSnapshot:
        return HomeServiceInstanceSnapshot(
            instance_id="instance-001",
            service_id="service-001",
            target_node_id="node-001",
            state=HomeServiceInstanceState.PLANNED,
            generation=generation,
            resource_version=resource_version,
        )

    def test_claim_is_deterministic_and_stays_non_mutating(self) -> None:
        worker = HomeServiceWorkerIdentity(worker_id="worker-001", node_id="node-001")
        first = claim_execution(self._admission(), self._snapshot(), worker, job_state="preflight")
        second = claim_execution(self._admission(), self._snapshot(), worker, job_state="preflight")

        self.assertEqual(first.claim_id, second.claim_id)
        self.assertTrue(first.claimed)
        self.assertTrue(first.revalidate_before_execution)
        self.assertFalse(first.direct_execution)
        self.assertFalse(first.production_mutation_enabled)
        self.assertFalse(first.accepts_secret_values)

    def test_claim_rejects_stale_instance_state(self) -> None:
        worker = HomeServiceWorkerIdentity(worker_id="worker-001", node_id="node-001")
        with self.assertRaisesRegex(HomeServiceCatalogError, "worker_claim_precondition_failed"):
            claim_execution(
                self._admission(),
                self._snapshot(generation=2, resource_version="rv-instance-002"),
                worker,
                job_state="preflight",
            )

    def test_claim_rejects_worker_on_wrong_node(self) -> None:
        worker = HomeServiceWorkerIdentity(worker_id="worker-002", node_id="node-002")
        with self.assertRaisesRegex(HomeServiceCatalogError, "worker_target_mismatch"):
            claim_execution(self._admission(), self._snapshot(), worker, job_state="preflight")

    def test_claim_rejects_non_preflight_job(self) -> None:
        worker = HomeServiceWorkerIdentity(worker_id="worker-001", node_id="node-001")
        with self.assertRaisesRegex(HomeServiceCatalogError, "invalid_job_state_for_claim"):
            claim_execution(self._admission(), self._snapshot(), worker, job_state="running")


if __name__ == "__main__":
    unittest.main()
