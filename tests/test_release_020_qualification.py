from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


class Release020QualificationTests(unittest.TestCase):
    def test_release_identity_is_consistent(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertGreaterEqual(tuple(map(int, version.split("."))), (0, 20, 0))
        self.assertEqual(version, project["project"]["version"])
        self.assertEqual(version, home_center.__version__)
        self.assertIn(
            "# Home Center 0.20.0",
            (ROOT / "docs/releases/0.20.0.md").read_text(encoding="utf-8"),
        )

    def test_release_artifact_contains_operation_runtime(self) -> None:
        self.assertIn("home_center/home_service_operations.py", REQUIRED_MEMBERS)

    def test_operation_contract_is_closed_secret_free_and_non_authoritative(self) -> None:
        contract = json.loads(
            (
                ROOT / "contracts/market/home-service-operation-plan.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertIs(contract["additionalProperties"], False)
        properties = contract["properties"]
        self.assertIs(properties["approval_required"]["const"], True)
        self.assertIs(properties["durable_job_required"]["const"], True)
        self.assertIs(properties["audit_required"]["const"], True)
        self.assertIs(properties["execution_authorized"]["const"], False)
        self.assertIs(properties["production_mutation_enabled"]["const"], False)
        self.assertIs(properties["accepts_secret_values"]["const"], False)
        self.assertNotIn("secret_values", properties)


if __name__ == "__main__":
    unittest.main()
