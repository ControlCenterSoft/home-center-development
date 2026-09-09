from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path

import home_center
from home_center.home_services import BUILTIN_HOME_SERVICES, REQUIRED_LIFECYCLE
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


class Release019QualificationTests(unittest.TestCase):
    def test_release_identity_is_consistent(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual("0.19.0", version)
        self.assertEqual(version, project["project"]["version"])
        self.assertEqual(version, home_center.__version__)
        self.assertIn(
            "# Home Center 0.19.0",
            (ROOT / "docs/releases/0.19.0.md").read_text(encoding="utf-8"),
        )

    def test_release_artifact_contains_home_service_runtime(self) -> None:
        self.assertIn("home_center/home_services.py", REQUIRED_MEMBERS)

    def test_home_service_contracts_are_closed_and_non_authoritative(self) -> None:
        for name in (
            "home-service-profile.v1.schema.json",
            "home-service-deployment-plan.v1.schema.json",
        ):
            contract = json.loads((ROOT / "contracts/market" / name).read_text(encoding="utf-8"))
            with self.subTest(contract=name):
                self.assertIs(contract["additionalProperties"], False)
                self.assertIs(
                    contract["properties"]["production_mutation_enabled"]["const"],
                    False,
                )

    def test_catalog_has_complete_lifecycle_for_every_service(self) -> None:
        self.assertEqual(6, len(BUILTIN_HOME_SERVICES.profiles))
        self.assertTrue(
            all(profile.lifecycle == REQUIRED_LIFECYCLE for profile in BUILTIN_HOME_SERVICES.profiles)
        )


if __name__ == "__main__":
    unittest.main()
