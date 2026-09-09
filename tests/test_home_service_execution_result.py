from __future__ import annotations

import unittest
from types import SimpleNamespace

from home_center.home_service_execution_result import (
    HomeServiceExecutionOutcome,
    record_execution_result,
)
from home_center.home_service_operations import HomeServiceInstanceState
from home_center.home_services import HomeServiceCatalogError


class HomeServiceExecutionResultTests(unittest.TestCase):
    def _claim(self, **overrides: object) -> SimpleNamespace:
        values: dict[str, object] = {
            "claim_id": "hswc-001",
            "plan_id": "hsop-001",
            "job_id": "job-001",
            "worker_id": "worker-001",
            "instance_id": "instance-001",
            "based_on_generation": 1,
            "based_on_resource_version": "rv-instance-001",
            "claimed": True,
            "revalidate_before_execution": True,
            "direct_execution": False,
            "production_mutation_enabled": False,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_result_is_deterministic_and_inert(self) -> None:
        first = record_execution_result(
            self._claim(),
            outcome=HomeServiceExecutionOutcome.SUCCEEDED,
            target_state=HomeServiceInstanceState.INSTALLED,
            observed_generation=1,
            observed_resource_version="rv-instance-001",
            evidence_digest="evidence-001",
        )
        second = record_execution_result(
            self._claim(),
            outcome=HomeServiceExecutionOutcome.SUCCEEDED,
            target_state=HomeServiceInstanceState.INSTALLED,
            observed_generation=1,
            observed_resource_version="rv-instance-001",
            evidence_digest="evidence-001",
        )

        self.assertEqual(first.result_id, second.result_id)
        self.assertTrue(first.verified)
        self.assertFalse(first.state_transition_authorized)
        self.assertFalse(first.production_mutation_enabled)

    def test_result_rejects_stale_observation(self) -> None:
        with self.assertRaisesRegex(HomeServiceCatalogError, "execution_result_precondition_failed"):
            record_execution_result(
                self._claim(),
                outcome=HomeServiceExecutionOutcome.FAILED,
                target_state=HomeServiceInstanceState.DEGRADED,
                observed_generation=2,
                observed_resource_version="rv-instance-002",
                evidence_digest="evidence-002",
            )

    def test_result_rejects_unsafe_claim(self) -> None:
        with self.assertRaisesRegex(HomeServiceCatalogError, "unsafe_worker_claim"):
            record_execution_result(
                self._claim(production_mutation_enabled=True),
                outcome=HomeServiceExecutionOutcome.SUCCEEDED,
                target_state=HomeServiceInstanceState.INSTALLED,
                observed_generation=1,
                observed_resource_version="rv-instance-001",
                evidence_digest="evidence-003",
            )


if __name__ == "__main__":
    unittest.main()
