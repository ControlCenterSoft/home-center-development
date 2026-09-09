from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


class Release026QualificationTests(unittest.TestCase):
    def test_release_identity_is_consistent(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual("0.26.0", version)
        self.assertEqual(version, project["project"]["version"])
        self.assertEqual(version, home_center.__version__)
        notes = (ROOT / "docs/releases/0.26.0.md").read_text(encoding="utf-8")
        self.assertIn("# Home Center 0.26.0", notes)
        self.assertIn("Status: development qualification candidate.", notes)
        self.assertIn("## Household/Intent planning", notes)

    def test_release_artifact_requires_household_runtime(self) -> None:
        self.assertIn("home_center/household.py", REQUIRED_MEMBERS)
        self.assertIn("home_center/household_intent.py", REQUIRED_MEMBERS)
        self.assertIn("home_center/home_service_transition_completion.py", REQUIRED_MEMBERS)

    def test_household_contracts_are_closed(self) -> None:
        for name in (
            "household.v1.schema.json",
            "household-effective-policy.v1.schema.json",
            "household-intent-plan.v1.schema.json",
        ):
            contract = json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))
            self.assertIs(contract["additionalProperties"], False)

    def test_policy_and_intent_contracts_forbid_direct_mutation(self) -> None:
        policy = json.loads(
            (ROOT / "contracts/household/household-effective-policy.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIs(policy["properties"]["external_publication_allowed"]["const"], False)
        self.assertIs(policy["properties"]["production_mutation_enabled"]["const"], False)

        plan = json.loads(
            (ROOT / "contracts/household/household-intent-plan.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIs(plan["properties"]["confirmation_required"]["const"], True)
        self.assertIs(plan["properties"]["mutation_authorized"]["const"], False)
        self.assertIs(plan["properties"]["production_mutation_enabled"]["const"], False)


if __name__ == "__main__":
    unittest.main()
