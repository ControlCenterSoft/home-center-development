from __future__ import annotations

import tomllib
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def test_release_051_boundary_is_preserved_in_later_releases() -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    notes = (ROOT / "docs/releases/0.51.0.md").read_text(encoding="utf-8")
    assert _version_tuple(version) >= (0, 51, 0)
    assert project["project"]["version"] == version
    assert home_center.__version__ == version
    assert "# Home Center 0.51.0" in notes
    assert "management_required=true" in notes
    assert "managed=false" in notes


def test_release_051_wheel_requires_device_change_runtime() -> None:
    required = {
        "home_center/household_device_change.py",
        "home_center/household_device_runtime.py",
        "home_center/household_member_change.py",
        "home_center/module_home_service_compatibility_state.py",
    }
    assert required <= REQUIRED_MEMBERS


def test_release_051_api_has_separate_device_plan_and_confirm() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v2.py").read_text(encoding="utf-8")
    runtime = (ROOT / "product/control-plane/src/home_center/runtime.py").read_text(encoding="utf-8")
    assert '"/api/v1/household/devices/plan"' in api
    assert '"/api/v1/household/devices/confirm"' in api
    assert "self.runtime.household_devices.plan_device_add" in api
    assert "self.runtime.household_devices.confirm_device_add" in api
    assert "HouseholdDeviceRuntimeService" in runtime
    assert "self.household_devices = HouseholdDeviceRuntimeService(self.store)" in runtime


def test_release_051_cozy_ui_exposes_device_registration_without_management_claim() -> None:
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    javascript = (ROOT / "product/web/static/device-registration.js").read_text(encoding="utf-8")
    assert 'src="/static/device-registration.js"' in html
    assert "Добавить устройство" in javascript
    assert "/api/v1/household/devices/plan" in javascript
    assert "/api/v1/household/devices/confirm" in javascript
    assert "confirmed: true" in javascript
    assert "управление устройством требуется" in javascript
    assert "ещё не выполнено" in javascript


def test_release_051_device_contract_forbids_false_managed_and_provider_authority() -> None:
    source = (ROOT / "product/control-plane/src/home_center/household_device_change.py").read_text(encoding="utf-8")
    assert "managed_after_registration: bool = field(default=False" in source
    assert "policy_application_authorized: bool = field(default=False" in source
    assert "provider_execution_authorized: bool = field(default=False" in source
    assert "household_device_false_managed_claim" in source
