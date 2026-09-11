from __future__ import annotations

import json
from pathlib import Path

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_056_selection_runtime_is_required_in_artifact() -> None:
    assert {
        "home_center/device_management_provider.py",
        "home_center/device_management_provider_runtime.py",
        "home_center/device_management_provider_selection.py",
        "home_center/device_management_provider_selection_runtime.py",
    } <= REQUIRED_MEMBERS


def test_release_056_api_has_plan_and_confirm_but_no_execution_endpoint() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v2.py").read_text(encoding="utf-8")
    assert '"/api/v1/household/devices/enrollment/provider-selection/plan"' in api
    assert '"/api/v1/household/devices/enrollment/provider-selection/confirm"' in api
    assert "/provider-selection/execute" not in api
    assert "/provider-execution" not in api
    assert "device_management_provider_selection.plan" in api
    assert "device_management_provider_selection.confirm" in api


def test_release_056_request_shape_does_not_accept_credentials_or_execution_flags() -> None:
    runtime = (
        ROOT / "product/control-plane/src/home_center/device_management_provider_selection_runtime.py"
    ).read_text(encoding="utf-8")
    selection = (
        ROOT / "product/control-plane/src/home_center/device_management_provider_selection.py"
    ).read_text(encoding="utf-8")

    plan_shape = runtime.split("if set(request) != {", 1)[1].split("}", 1)[0]
    assert '"resolution_plan_id"' in plan_shape
    assert '"enrollment_proposal_id"' in plan_shape
    assert '"device_platform"' in plan_shape
    assert '"provider_id"' in plan_shape
    assert "credential" not in plan_shape.lower()
    assert "token" not in plan_shape.lower()
    assert "execution" not in plan_shape.lower()
    assert "credential_access_authorized: bool = field(default=False" in selection
    assert "enrollment_authorized: bool = field(default=False" in selection
    assert "provider_execution_authorized: bool = field(default=False" in selection


def test_release_056_contracts_are_closed_and_non_authorizing() -> None:
    proposal = json.loads(
        (
            ROOT
            / "contracts/devices/device-management-provider-selection-proposal.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    confirmation = json.loads(
        (
            ROOT
            / "contracts/devices/device-management-provider-selection-confirmation.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    assert proposal["additionalProperties"] is False
    assert confirmation["additionalProperties"] is False
    assert proposal["properties"]["provider_selected"] == {"const": False}
    assert confirmation["properties"]["provider_selected"] == {"const": True}
    for schema in (proposal, confirmation):
        for field in (
            "provider_execution_authorized",
            "credential_access_authorized",
            "enrollment_authorized",
            "policy_application_authorized",
            "managed_state_change_authorized",
            "infrastructure_mutation_authorized",
            "external_publication_authorized",
        ):
            assert schema["properties"][field] == {"const": False}


def test_release_056_cozy_ui_requires_separate_confirmation_and_keeps_execution_closed() -> None:
    ui = (ROOT / "product/web/static/device-provider-resolution.js").read_text(encoding="utf-8")
    assert "/provider-selection/plan" in ui
    assert "/provider-selection/confirm" in ui
    assert "Подтвердить выбор" in ui
    assert "provider_selected === false" in ui
    assert "provider_selected === true" in ui
    assert "credential_access_authorized === false" in ui
    assert "enrollment_authorized === false" in ui
    assert "provider_execution_authorized === false" in ui
    assert "credentials не передаются" in ui.lower()


def test_release_056_notes_do_not_claim_provider_execution() -> None:
    notes = (ROOT / "docs/releases/0.56.0.md").read_text(encoding="utf-8")
    assert "Status: source package prepared for qualification." in notes
    assert "Выполнение выбранного провайдера в 0.56 отсутствует." in notes
    assert "credential_access_authorized=false" in notes
    assert "provider_execution_authorized=false" in notes
