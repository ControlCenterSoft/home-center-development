from __future__ import annotations

import tomllib
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_050_identity_is_exact() -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert version == "0.50.0"
    assert project["project"]["version"] == version
    assert home_center.__version__ == version


def test_release_050_notes_and_contract_are_present() -> None:
    notes = (ROOT / "docs/releases/0.50.0.md").read_text(encoding="utf-8")
    contract = ROOT / "contracts/modules/module-home-service-compatibility-state.v1.schema.json"
    assert "# Home Center 0.50.0" in notes
    assert "read-only" in notes
    assert "не Public Stable" in notes
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


def test_release_050_keeps_stable_only_update_channel() -> None:
    updater = (ROOT / "deploy/scripts/home-center-auto-update.sh").read_text(encoding="utf-8")
    installer = (ROOT / "deploy/scripts/install-home-center-auto-update.sh").read_text(encoding="utf-8")
    assert "home-center-stable/releases?per_page=30" in updater
    assert "home-center-stable/releases/download/" in updater
    assert "home-center-development/releases" not in updater
    assert "home-center-stable/releases?per_page=30" in installer
    assert "home-center-development/releases" not in installer
