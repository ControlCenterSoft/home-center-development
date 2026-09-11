from __future__ import annotations

import tomllib
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def test_release_052_boundary_is_preserved_in_later_releases() -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    notes = (ROOT / "docs/releases/0.52.0.md").read_text(encoding="utf-8")
    assert _version_tuple(version) >= (0, 52, 0)
    assert project["project"]["version"] == version
    assert home_center.__version__ == version
    assert "# Home Center 0.52.0" in notes
    assert "provider_selected=false" in notes
    assert "provider_execution_authorized=false" in notes
    assert "managed" in notes


def test_release_052_wheel_requires_management_planning_runtime() -> None:
    required = {
        "home_center/household_device_change.py",
        "home_center/household_device_runtime.py",
        "home_center/household_device_management.py",
        "home_center/household_device_management_runtime.py",
        "home_center/household_member_change.py",
    }
    assert required <= REQUIRED_MEMBERS


def test_release_052_api_and_runtime_expose_planning_only_boundary() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v2.py").read_text(encoding="utf-8")
    runtime = (ROOT / "product/control-plane/src/home_center/runtime.py").read_text(encoding="utf-8")
    assert '"/api/v1/household/devices/management/plan"' in api
    assert "self.runtime.household_device_management.plan" in api
    assert "HouseholdDeviceManagementRuntimeService" in runtime
    assert "self.household_device_management = HouseholdDeviceManagementRuntimeService(self.store)" in runtime
    assert "/management/confirm" not in api


def test_release_052_cozy_ui_requires_explicit_management_check() -> None:
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    javascript = (ROOT / "product/web/static/device-management-plan.js").read_text(encoding="utf-8")
    assert 'src="/static/device-management-plan.js"' in html
    assert "Проверить необходимость" in javascript
    assert "/api/v1/household/devices/management/plan" in javascript
    assert "provider_selected !== false" in javascript
    assert "provider_execution_authorized !== false" in javascript
    assert "policy_application_authorized !== false" in javascript
    assert "ничего не установлено и не применено" in javascript


def test_release_052_contract_never_authorizes_provider_or_policy_application() -> None:
    source = (ROOT / "product/control-plane/src/home_center/household_device_management.py").read_text(encoding="utf-8")
    assert "provider_selected: bool = field(default=False" in source
    assert "provider_execution_authorized: bool = field(default=False" in source
    assert "policy_application_authorized: bool = field(default=False" in source
    assert "infrastructure_mutation_authorized: bool = field(default=False" in source
    assert "external_publication_authorized: bool = field(default=False" in source
    assert 'action_type="household.device.management.enroll"' in source
    assert "provider_resolution_required=True" in source
    assert "confirmation_required=True" in source


def test_release_052_is_cumulative_over_confirmed_family_and_device_flows() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v2.py").read_text(encoding="utf-8")
    assert '"/api/v1/household/members/plan"' in api
    assert '"/api/v1/household/members/confirm"' in api
    assert '"/api/v1/household/devices/plan"' in api
    assert '"/api/v1/household/devices/confirm"' in api
