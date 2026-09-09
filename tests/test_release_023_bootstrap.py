from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

import home_center


ROOT = Path(__file__).resolve().parents[1]


class Release023BootstrapTests(unittest.TestCase):
    def test_release_identity_is_consistent(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertGreaterEqual(tuple(int(part) for part in version.split(".")), (0, 23, 0))
        self.assertEqual(version, project["project"]["version"])
        self.assertEqual(version, home_center.__version__)

    def test_development_candidate_is_present(self) -> None:
        notes = (ROOT / "docs/releases/0.23.0.md").read_text(encoding="utf-8")
        self.assertIn("# Home Center 0.23.0", notes)
        self.assertIn("Status: development qualification candidate.", notes)
        self.assertIn("## Durable transition authorization", notes)
        self.assertIn("Home Center 0.22.0 admission", notes)
        self.assertIn("does not by itself authorize an official release", notes)

    def test_previous_release_guarantees_remain_documented(self) -> None:
        previous = (ROOT / "docs/releases/0.22.0.md").read_text(encoding="utf-8")
        self.assertIn("# Home Center 0.22.0", previous)
        self.assertIn("cannot authorize that transition", previous)


if __name__ == "__main__":
    unittest.main()
