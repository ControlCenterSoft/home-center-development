from __future__ import annotations

from pathlib import Path

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_054_provider_runtime_is_required_in_artifact() -> None:
    assert {
        "home_center/device_management_provider.py",
        "home_center/device_management_provider_runtime.py",
        "home_center/household_device_enrollment.py",
        "home_center/household_device_enrollment_runtime.py",
    } <= REQUIRED_MEMBERS


def test_release_054_api_is_planning_only() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v2.py").read_text(encoding="utf-8")
    runtime = (ROOT / "product/control-plane/src/home_center/runtime.py").read_text(encoding="utf-8")
    provider_runtime = (
        ROOT / "product/control-plane/src/home_center/device_management_provider_runtime.py"
    ).read_text(encoding="utf-8")

    assert '"/api/v1/household/devices/enrollment/provider-resolution/plan"' in api
    assert "self.runtime.device_management_providers.plan" in api
    assert "DeviceManagementProviderRuntimeService" in runtime
    assert "self.device_management_providers = DeviceManagementProviderRuntimeService(self.store)" in runtime
    assert 'set(request) != {"schema", "enrollment_proposal_id", "device_platform"}' in provider_runtime
    assert "selected_provider_id" not in provider_runtime.split("def plan(", 1)[1].split("raw_catalog", 1)[0]
    assert "credential" not in provider_runtime.lower()


def test_release_054_contract_is_non_authorizing() -> None:
    source = (
        ROOT / "product/control-plane/src/home_center/device_management_provider.py"
    ).read_text(encoding="utf-8")
    runtime = (
        ROOT / "product/control-plane/src/home_center/device_management_provider_runtime.py"
    ).read_text(encoding="utf-8")

    assert "provider_selection_required: bool = field(default=True" in source
    assert "selected_provider_id: None = field(default=None" in source
    assert "provider_execution_authorized: bool = field(default=False" in source
    assert "policy_application_authorized: bool = field(default=False" in source
    assert "managed_state_change_authorized: bool = field(default=False" in source
    assert "infrastructure_mutation_authorized: bool = field(default=False" in source
    assert "external_publication_authorized: bool = field(default=False" in source
    assert "self.store.set_meta(PROVIDER_CATALOG_STATE_KEY" not in runtime
    assert "self.store.set_meta(HOUSEHOLD_STATE_KEY" not in runtime


def test_release_054_cozy_ui_is_loaded_and_fail_closed() -> None:
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    enrollment = (ROOT / "product/web/static/device-enrollment.js").read_text(encoding="utf-8")
    provider = (ROOT / "product/web/static/device-provider-resolution.js").read_text(encoding="utf-8")

    assert 'src="/static/device-provider-resolution.js"' in html
    assert "homecenter:device-enrollment-confirmed" in enrollment
    assert "homecenter:device-enrollment-confirmed" in provider
    assert "/api/v1/household/devices/enrollment/provider-resolution/plan" in provider
    assert "platform_verified === false" in provider
    assert "provider_selection_required === true" in provider
    assert "selected_provider_id === null" in provider
    assert "provider_execution_authorized === false" in provider
    assert "policy_application_authorized === false" in provider
    assert "managed_state_change_authorized === false" in provider
    assert "infrastructure_mutation_authorized === false" in provider
    assert "external_publication_authorized === false" in provider
    assert "candidate?.execution_authorized === false" in provider


def test_release_054_notes_state_exact_safety_boundary() -> None:
    notes = (ROOT / "docs/releases/0.54.0.md").read_text(encoding="utf-8")
    assert "Status: source package prepared for qualification." in notes
    assert "platform_claim_source=user" in notes
    assert "platform_verified=false" in notes
    assert "provider_selection_required=true" in notes
    assert "selected_provider_id=null" in notes
    assert "provider_execution_authorized=false" in notes
    assert "Persistent migration Household-state не требуется" in notes
