from __future__ import annotations

import tomllib
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_049_identity_is_exact_and_documented() -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    notes = (ROOT / "docs/releases/0.49.0.md").read_text(encoding="utf-8")

    assert version == "0.49.0"
    assert project["project"]["version"] == version
    assert home_center.__version__ == version
    assert "# Home Center 0.49.0" in notes
    assert "Aggregate module compatibility revalidation" in notes
    assert "Confirmed Household member changes" in notes
    assert "plan member → review name/role/base generation → explicit confirm" in notes


def test_release_049_wheel_requires_both_parallel_runtime_boundaries() -> None:
    required = {
        "home_center/module_home_service_multi_compatibility.py",
        "home_center/module_home_service_multi_compatibility_revalidation.py",
        "home_center/household_member_change.py",
        "home_center/household_runtime.py",
        "home_center/household_store.py",
    }
    assert required <= REQUIRED_MEMBERS


def test_release_049_household_api_requires_separate_plan_and_confirm() -> None:
    api = (
        ROOT / "product/control-plane/src/home_center/api_v2.py"
    ).read_text(encoding="utf-8")
    runtime = (
        ROOT / "product/control-plane/src/home_center/household_runtime.py"
    ).read_text(encoding="utf-8")

    assert '"/api/v1/household/members/plan"' in api
    assert '"/api/v1/household/members/confirm"' in api
    assert "plan_member" in runtime
    assert "confirm_member" in runtime
    assert "confirmed" in runtime
    assert "household_member_change_stale" in runtime


def test_release_049_cozy_ui_has_explicit_confirmation_surface() -> None:
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    javascript = (ROOT / "product/web/static/app.js").read_text(encoding="utf-8")

    assert 'id="add-person-form"' in html
    assert 'id="member-confirm-card"' in html
    assert "Родитель" in html
    assert "Ребёнок" in html
    assert "Гость" in html
    assert "/api/v1/household/members/plan" in javascript
    assert "/api/v1/household/members/confirm" in javascript
    assert "confirmed: true" in javascript
