from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "product" / "web" / "static" / "device-management-plan.js"


def test_device_management_ui_serializes_plan_requests() -> None:
    javascript = SCRIPT.read_text(encoding="utf-8")

    assert "let planningDeviceId = null;" in javascript
    assert "if (planningDeviceId !== null) return;" in javascript
    assert "planningDeviceId = deviceId;" in javascript
    assert "planningDeviceId = null;" in javascript
    assert "planningDeviceId !== null) return;" in javascript


def test_device_management_ui_exposes_and_restores_busy_state() -> None:
    javascript = SCRIPT.read_text(encoding="utf-8")

    assert "card.setAttribute('aria-busy', 'false')" in javascript
    assert "function setPlanningBusy(active, selectedButton = null)" in javascript
    assert "card.setAttribute('aria-busy', String(active))" in javascript
    assert "document.querySelectorAll('[data-device-management-plan]')" in javascript
    assert "button.disabled = active;" in javascript
    assert "active ? 'Проверяем…' : 'Проверить необходимость'" in javascript
    assert "button.dataset.deviceManagementPlan = device.device_id;" in javascript


def test_device_management_ui_keeps_planning_only_safety_boundary() -> None:
    javascript = SCRIPT.read_text(encoding="utf-8")

    assert "/api/v1/household/devices/management/plan" in javascript
    assert "provider_selected !== false" in javascript
    assert "provider_execution_authorized !== false" in javascript
    assert "policy_application_authorized !== false" in javascript
    assert "infrastructure_mutation_authorized !== false" in javascript
    assert "external_publication_authorized !== false" in javascript
    assert "homecenter:device-management-plan" in javascript
    assert "/management/confirm" not in javascript
