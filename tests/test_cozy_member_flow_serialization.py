from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MEMBER = ROOT / "product" / "web" / "static" / "member-change.js"


def _member_source() -> str:
    return MEMBER.read_text(encoding="utf-8")


def test_member_plan_and_confirm_share_one_serial_operation_owner() -> None:
    source = _member_source()

    assert "let activeMemberOperation = 0;" in source
    assert "function beginMemberOperation()" in source
    assert "function ownsMemberOperation(operationId)" in source
    assert "function finishMemberOperation(operationId)" in source
    assert source.count("const operationId = beginMemberOperation();") >= 2
    assert source.count("if (!ownsMemberOperation(operationId)) return;") >= 2
    assert source.count("finishMemberOperation(operationId);") >= 2


def test_member_flow_busy_state_disables_competing_actions() -> None:
    source = _member_source()

    assert "function setMemberFlowBusy(busy)" in source
    assert "planForm.setAttribute('aria-busy', 'true');" in source
    assert "confirmCard.setAttribute('aria-busy', 'true');" in source
    assert "Array.from(planForm.elements).forEach((control) =>" in source
    assert "confirmButton.disabled = busy;" in source
    assert "cancelButton.disabled = busy;" in source
    assert "if (activeMemberOperation !== 0) return;" in source


def test_navigation_invalidates_local_member_ui_without_changing_server_contract() -> None:
    source = _member_source()

    assert "function resetMemberFlowForNavigation()" in source
    assert "activeMemberOperation = 0;" in source
    assert "refreshButton.addEventListener('click', resetMemberFlowForNavigation);" in source
    assert "logoutButton.addEventListener('click', resetMemberFlowForNavigation);" in source
    assert "'/api/v1/household/members/plan'" in source
    assert "'/api/v1/household/members/confirm'" in source
    assert "confirmed: true" in source
    assert "household_member_change_stale" in source
    assert "credentials: 'same-origin'" in source
    assert "Изменение отменено. Данные семьи не менялись." in source
