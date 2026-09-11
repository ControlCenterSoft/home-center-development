from __future__ import annotations

import tomllib
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_053_identity_is_exact_and_documented() -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    notes = (ROOT / "docs/releases/0.53.0.md").read_text(encoding="utf-8")
    assert version == "0.53.0"
    assert project["project"]["version"] == version
    assert home_center.__version__ == version
    assert "# Home Center 0.53.0" in notes
    assert "confirmed-for-provider-resolution" in notes
    assert "managed=false" in notes
    assert "provider_execution_authorized=false" in notes


def test_release_053_wheel_requires_enrollment_runtime() -> None:
    required = {
        "home_center/household_device_enrollment.py",
        "home_center/household_device_enrollment_runtime.py",
        "home_center/household_device_management.py",
        "home_center/household_device_management_runtime.py",
        "home_center/household_device_runtime.py",
        "home_center/household_member_change.py",
    }
    assert required <= REQUIRED_MEMBERS


def test_release_053_api_exposes_separate_enrollment_plan_and_confirm() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v2.py").read_text(encoding="utf-8")
    runtime = (ROOT / "product/control-plane/src/home_center/runtime.py").read_text(encoding="utf-8")
    assert '"/api/v1/household/devices/enrollment/plan"' in api
    assert '"/api/v1/household/devices/enrollment/confirm"' in api
    assert "self.runtime.household_device_enrollment.plan" in api
    assert "self.runtime.household_device_enrollment.confirm" in api
    assert "HouseholdDeviceEnrollmentRuntimeService" in runtime
    assert "self.household_device_enrollment = HouseholdDeviceEnrollmentRuntimeService(self.store)" in runtime


def test_release_053_contract_forbids_execution_and_managed_state_change() -> None:
    source = (ROOT / "product/control-plane/src/home_center/household_device_enrollment.py").read_text(encoding="utf-8")
    assert "confirmation_required: bool = field(default=True" in source
    assert "provider_resolution_required: bool = field(default=True" in source
    assert "provider_selected: bool = field(default=False" in source
    assert "provider_execution_authorized: bool = field(default=False" in source
    assert "policy_application_authorized: bool = field(default=False" in source
    assert "managed_state_change_authorized: bool = field(default=False" in source
    assert "infrastructure_mutation_authorized: bool = field(default=False" in source
    assert "external_publication_authorized: bool = field(default=False" in source
    runtime = (ROOT / "product/control-plane/src/home_center/household_device_enrollment_runtime.py").read_text(encoding="utf-8")
    assert "self.store.set_meta(HOUSEHOLD_STATE_KEY" not in runtime


def test_release_053_cozy_ui_requires_two_explicit_enrollment_actions() -> None:
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    management = (ROOT / "product/web/static/device-management-plan.js").read_text(encoding="utf-8")
    enrollment = (ROOT / "product/web/static/device-enrollment.js").read_text(encoding="utf-8")
    assert 'src="/static/device-enrollment.js"' in html
    assert "homecenter:device-management-plan" in management
    assert "Подготовить подключение" in enrollment
    assert "Подтвердить переход к настройке" in enrollment
    assert "/api/v1/household/devices/enrollment/plan" in enrollment
    assert "/api/v1/household/devices/enrollment/confirm" in enrollment
    assert "confirmed: true" in enrollment
    assert "provider_selected === false" in enrollment
    assert "managed_state_change_authorized === false" in enrollment
    assert "Управление ещё не включено" in enrollment


def test_release_053_preserves_previous_cozy_family_device_boundaries() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v2.py").read_text(encoding="utf-8")
    assert '"/api/v1/household/members/plan"' in api
    assert '"/api/v1/household/members/confirm"' in api
    assert '"/api/v1/household/devices/plan"' in api
    assert '"/api/v1/household/devices/confirm"' in api
    assert '"/api/v1/household/devices/management/plan"' in api
