from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


class Release024QualificationTests(unittest.TestCase):
    def test_release_identity_is_consistent(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual("0.24.0", version)
        self.assertEqual(version, project["project"]["version"])
        self.assertEqual(version, home_center.__version__)
        notes = (ROOT / "docs/releases/0.24.0.md").read_text(encoding="utf-8")
        self.assertIn("# Home Center 0.24.0", notes)
        self.assertIn("Status: development qualification candidate.", notes)
        self.assertIn("read-back verification", notes)
        self.assertIn("## Audited apply boundary", notes)

    def test_release_artifact_requires_apply_audit_and_verification_runtime(self) -> None:
        self.assertIn("home_center/home_service_transition_apply.py", REQUIRED_MEMBERS)
        self.assertIn("home_center/home_service_transition_audit.py", REQUIRED_MEMBERS)
        self.assertIn("home_center/home_service_transition_verify.py", REQUIRED_MEMBERS)

    def test_verification_contract_is_closed_and_non_mutating(self) -> None:
        contract = json.loads(
            (ROOT / "contracts/market/home-service-transition-verification.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIs(contract["additionalProperties"], False)
        properties = contract["properties"]
        self.assertEqual("home-center.home-service-transition-verification.v1", properties["schema"]["const"])
        self.assertIs(properties["evidence_record_only"]["const"], True)
        self.assertIs(properties["further_mutation_authorized"]["const"], False)
        self.assertIs(properties["production_mutation_enabled"]["const"], False)
        self.assertEqual({"verified", "drifted"}, set(properties["status"]["enum"]))


if __name__ == "__main__":
    unittest.main()
