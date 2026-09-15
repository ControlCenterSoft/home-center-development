from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANAGEMENT = ROOT / "product" / "web" / "static" / "device-management-plan.js"


def _source() -> str:
    return MANAGEMENT.read_text(encoding="utf-8")


def test_device_management_plan_requests_are_serialized() -> None:
    source = _source()

    assert "let managementPlanInFlight = false;" in source
    assert "if (managementPlanInFlight) return;" in source
    assert "setManagementPlanBusy(button, true);" in source
    assert "setManagementPlanBusy(button, false);" in source


def test_device_management_card_owns_busy_state_and_controls() -> None:
    source = _source()

    assert "card.setAttribute('aria-busy', 'false');" in source
    assert "card.setAttribute('aria-busy', busy ? 'true' : 'false');" in source
    assert "document.querySelectorAll('#device-management-list button')" in source
    assert "control.disabled = busy;" in source
    assert "button.textContent = 'Проверяем…';" in source
    assert "button.dataset.managementIdleLabel" in source


def test_device_list_is_not_rerendered_during_management_plan() -> None:
    source = _source()

    assert "$('#workspace-view')?.hidden || managementPlanInFlight" in source
    assert "void syncDevices();" in source


def test_management_plan_keeps_planning_only_authority_boundary() -> None:
    source = _source()

    assert "data?.provider_selected !== false" in source
    assert "data?.provider_execution_authorized !== false" in source
    assert "data?.policy_application_authorized !== false" in source
    assert "data?.infrastructure_mutation_authorized !== false" in source
    assert "data?.external_publication_authorized !== false" in source
    assert "homecenter:device-management-plan" in source
