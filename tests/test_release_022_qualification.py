from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path

import home_center
from home_center.home_service_execution_result import HomeServiceExecutionResult
from home_center.home_service_worker_claim import HomeServiceWorkerClaim
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


class Release022QualificationTests(unittest.TestCase):
    def test_release_identity_is_consistent(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertGreaterEqual(tuple(int(part) for part in version.split(".")), (0, 22, 0))
        self.assertEqual(version, project["project"]["version"])
        self.assertEqual(version, home_center.__version__)
        release_notes = (ROOT / "docs/releases/0.22.0.md").read_text(encoding="utf-8")
        self.assertIn("# Home Center 0.22.0", release_notes)
        self.assertIn("cannot authorize that transition", release_notes)

    def test_release_artifact_contains_worker_handoff_runtime(self) -> None:
        self.assertIn("home_center/home_service_worker_claim.py", REQUIRED_MEMBERS)
        self.assertIn("home_center/home_service_execution_revalidation.py", REQUIRED_MEMBERS)
        self.assertIn("home_center/home_service_execution_result.py", REQUIRED_MEMBERS)
        self.assertIn("home_center/home_service_state_transition.py", REQUIRED_MEMBERS)

    def test_execution_revalidation_contract_is_closed_and_inert(self) -> None:
        contract = json.loads(
            (ROOT / "contracts/market/home-service-execution-revalidation.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIs(contract["additionalProperties"], False)
        properties = contract["properties"]
        self.assertEqual("queued", properties["observed_job_state"]["const"])
        self.assertIs(properties["compare_and_swap_matched"]["const"], True)
        self.assertIs(properties["execution_authorized"]["const"], False)
        self.assertIs(properties["direct_execution"]["const"], False)
        self.assertIs(properties["production_mutation_enabled"]["const"], False)
        self.assertIs(properties["accepts_secret_values"]["const"], False)

    def test_state_transition_contracts_are_closed_and_non_mutating(self) -> None:
        decision = json.loads(
            (ROOT / "contracts/market/home-service-transition-decision.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        commit = json.loads(
            (ROOT / "contracts/market/home-service-transition-commit.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIs(decision["additionalProperties"], False)
        self.assertIs(commit["additionalProperties"], False)
        self.assertIs(decision["properties"]["durable_commit_required"]["const"], True)
        self.assertIs(decision["properties"]["evidence_record_only"]["const"], True)
        self.assertIs(decision["properties"]["production_mutation_enabled"]["const"], False)
        self.assertIs(commit["properties"]["committed"]["const"], False)
        self.assertIs(commit["properties"]["production_mutation_enabled"]["const"], False)

    def test_claim_and_result_types_lock_non_mutating_boundary(self) -> None:
        claim = HomeServiceWorkerClaim(
            claim_id="claim-001",
            admission_id="admission-001",
            plan_id="plan-001",
            job_id="job-001",
            worker_id="worker-001",
            node_id="node-001",
            instance_id="instance-001",
            operation="install",
            based_on_generation=1,
            based_on_resource_version="rv-001",
        )
        self.assertTrue(claim.revalidate_before_execution)
        self.assertFalse(claim.direct_execution)
        self.assertFalse(claim.production_mutation_enabled)
        self.assertFalse(claim.accepts_secret_values)

        result = HomeServiceExecutionResult.__dataclass_fields__
        self.assertFalse(result["state_transition_authorized"].default)
        self.assertFalse(result["production_mutation_enabled"].default)


if __name__ == "__main__":
    unittest.main()
