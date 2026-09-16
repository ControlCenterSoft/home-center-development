from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "product" / "web" / "static" / "device-management-plan.js"


def test_device_management_plan_serializes_ui_operations() -> None:
    ui = UI.read_text(encoding="utf-8")
    assert "let managementPlanInFlight = false" in ui
    assert "if (managementPlanInFlight) return" in ui
    assert "card.setAttribute('aria-busy', busy ? 'true' : 'false')" in ui
    assert "card.querySelectorAll('button')" in ui
    assert "button.textContent = 'Проверяем…'" in ui
    assert "button.textContent = originalText" in ui


def test_device_management_plan_does_not_rerender_while_request_owns_surface() -> None:
    ui = UI.read_text(encoding="utf-8")
    assert "$('#workspace-view')?.hidden || managementPlanInFlight" in ui
    assert "if (managementPlanInFlight) return;\n      const household" in ui
    assert "if (!managementPlanInFlight) card.hidden = true" in ui


def test_device_management_plan_keeps_planning_only_boundary() -> None:
    ui = UI.read_text(encoding="utf-8")
    assert "/api/v1/household/devices/management/plan" in ui
    assert "provider_selected !== false" in ui
    assert "provider_execution_authorized !== false" in ui
    assert "policy_application_authorized !== false" in ui
    assert "infrastructure_mutation_authorized !== false" in ui
    assert "external_publication_authorized !== false" in ui
    assert "homecenter:device-management-plan" in ui
