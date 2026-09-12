from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_release_058_exact_candidate_identity() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == "0.58.0"
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == "0.58.0"
    runtime_init = (ROOT / "product/control-plane/src/home_center/__init__.py").read_text(encoding="utf-8")
    assert '__version__ = "0.58.0"' in runtime_init
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    assert '<small id="version">0.58.0</small>' in html


def test_release_058_candidate_claims_are_bounded() -> None:
    notes = (ROOT / "docs/releases/0.58.0.md").read_text(encoding="utf-8")
    assert "Status: release candidate." in notes
    assert "`single-node-core`" in notes
    assert "multi-node HA / automatic failover" in notes
    assert "concrete production provider execution" in notes
    assert "commercial launch clearance" in notes
    assert "enrollment_completed=false" in notes
    assert "post_condition_verified=false" in notes
    assert "managed_state_change_authorized=false" in notes
    assert "PUBLIC STABLE promotion remain separate" in notes
