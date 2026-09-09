from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


class Release021QualificationTests(unittest.TestCase):
    def test_release_identity_is_consistent(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual("0.21.0", version)
        self.assertEqual(version, project["project"]["version"])
        self.assertEqual(version, home_center.__version__)
        self.assertIn("# Home Center 0.21.0", (ROOT / "docs/releases/0.21.0.md").read_text(encoding="utf-8"))

    def test_release_artifact_contains_state_and_admission_runtime(self) -> None:
        self.assertIn("home_center/home_service_state.py", REQUIRED_MEMBERS)
        self.assertIn("home_center/home_service_admission.py", REQUIRED_MEMBERS)

    def test_admission_contract_is_closed_and_cannot_execute_directly(self) -> None:
        contract = json.loads((ROOT / "contracts/market/home-service-execution-admission.v1.schema.json").read_text(encoding="utf-8"))
        self.assertIs(contract["additionalProperties"], False)
        properties = contract["properties"]
        self.assertIs(properties["worker_claim_authorized"]["const"], True)
        self.assertIs(properties["revalidate_before_claim"]["const"], True)
        self.assertIs(properties["direct_execution"]["const"], False)
        self.assertIs(properties["production_mutation_enabled"]["const"], False)
        self.assertIs(properties["accepts_secret_values"]["const"], False)


if __name__ == "__main__":
    unittest.main()
