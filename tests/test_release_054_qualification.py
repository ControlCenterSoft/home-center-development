from __future__ import annotations

import tomllib
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def test_release_054_boundary_is_preserved_in_later_releases() -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    notes = (ROOT / "docs/releases/0.54.0.md").read_text(encoding="utf-8")
    assert _version_tuple(version) >= (0, 54, 0)
    assert project["project"]["version"] == version
    assert home_center.__version__ == version
    assert "# Home Center 0.54.0" in notes
    assert "single-candidate" in notes
    assert "choice-required" in notes
    assert "provider_execution_authorized=false" in notes


def test_release_054_wheel_contains_provider_resolution_runtime() -> None:
    assert {
        "home_center/device_management_provider.py",
        "home_center/device_management_provider_runtime.py",
        "home_center/household_device_enrollment.py",
        "home_center/household_device_enrollment_runtime.py",
    } <= REQUIRED_MEMBERS


def test_release_054_api_is_read_only_and_separate_from_enrollment_confirmation() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v2.py").read_text(encoding="utf-8")
    runtime = (ROOT / "product/control-plane/src/home_center/runtime.py").read_text(encoding="utf-8")
    source = (ROOT / "product/control-plane/src/home_center/device_management_provider.py").read_text(encoding="utf-8")
    provider_runtime = (ROOT / "product/control-plane/src/home_center/device_management_provider_runtime.py").read_text(encoding="utf-8")
    assert '"/api/v1/household/devices/enrollment/provider-resolution/plan"' in api
    assert "self.runtime.device_management_providers.plan" in api
    assert "DeviceManagementProviderRuntimeService" in runtime
    assert "provider_selection_required: bool = field(default=True" in source
    assert "selected_provider_id: None = field(default=None" in source
    assert "provider_execution_authorized: bool = field(default=False" in source
    assert "policy_application_authorized: bool = field(default=False" in source
    assert "managed_state_change_authorized: bool = field(default=False" in source
    assert "infrastructure_mutation_authorized: bool = field(default=False" in source
    assert "external_publication_authorized: bool = field(default=False" in source
    assert "self.store.set_meta(HOUSEHOLD_STATE_KEY" not in provider_runtime


def test_release_054_cozy_ui_preserves_provider_resolution_boundary() -> None:
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    enrollment = (ROOT / "product/web/static/device-enrollment.js").read_text(encoding="utf-8")
    resolution = (ROOT / "product/web/static/device-provider-resolution.js").read_text(encoding="utf-8")
    assert 'src="/static/device-provider-resolution.js"' in html
    assert "homecenter:device-enrollment-confirmed" in enrollment
    assert "/api/v1/household/devices/enrollment/provider-resolution/plan" in resolution
    assert "provider_selection_required === true" in resolution
    assert "selected_provider_id === null" in resolution
    assert "provider_execution_authorized === false" in resolution
    assert "platform_verified === false" in resolution
    assert "Найден один доступный способ. Он ещё не выбран" in resolution


def test_release_054_preserves_confirmation_gated_053_boundary() -> None:
    enrollment = (ROOT / "product/control-plane/src/home_center/household_device_enrollment.py").read_text(encoding="utf-8")
    provider_runtime = (ROOT / "product/control-plane/src/home_center/device_management_provider_runtime.py").read_text(encoding="utf-8")
    assert "confirmation_required: bool = field(default=True" in enrollment
    assert 'envelope.get("status") != "confirmed"' in provider_runtime
    assert 'receipt.get("outcome") != "confirmed-for-provider-resolution"' in provider_runtime
    assert 'receipt.get("provider_selected") is not False' in provider_runtime
    assert 'receipt.get("provider_execution_authorized") is not False' in provider_runtime
