from __future__ import annotations

import tomllib
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_050_identity_is_cumulative() -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert tuple(int(part) for part in version.split(".")) >= (0, 50, 0)
    assert project["project"]["version"] == version
    assert home_center.__version__ == version


def test_release_050_notes_and_contract_are_present() -> None:
    notes = (ROOT / "docs/releases/0.50.0.md").read_text(encoding="utf-8")
    contract = ROOT / "contracts/modules/module-home-service-compatibility-state.v1.schema.json"
    assert "# Home Center 0.50.0" in notes
    assert "deterministic read-only state projection" in notes
    assert contract.is_file()


def test_release_050_wheel_keeps_049_and_adds_state_projection() -> None:
    required = {
        "home_center/household_member_change.py",
        "home_center/household_runtime.py",
        "home_center/module_home_service_multi_compatibility.py",
        "home_center/module_home_service_multi_compatibility_revalidation.py",
        "home_center/module_home_service_compatibility_state.py",
    }
    assert required <= REQUIRED_MEMBERS


def test_release_050_is_cumulative_over_confirmed_cozy_family_flow() -> None:
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    javascript = (ROOT / "product/web/static/app.js").read_text(encoding="utf-8")
    api = (ROOT / "product/control-plane/src/home_center/api_v2.py").read_text(encoding="utf-8")
    assert 'id="member-plan-form"' in html
    assert 'id="member-confirm-card"' in html
    assert "/api/v1/household/members/plan" in javascript
    assert "/api/v1/household/members/confirm" in javascript
    assert '"/api/v1/household/members/plan"' in api
    assert '"/api/v1/household/members/confirm"' in api
