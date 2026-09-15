from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MEMBER = ROOT / "product" / "web" / "static" / "member-change.js"


def _member_source() -> str:
    return MEMBER.read_text(encoding="utf-8")


def test_member_plan_and_confirm_share_one_operation_lock() -> None:
    member = _member_source()

    assert "let memberOperation = null;" in member
    assert "if (memberOperation !== null) return false;" in member
    assert "beginMemberOperation('plan')" in member
    assert "beginMemberOperation('confirm')" in member
    assert "endMemberOperation('plan')" in member
    assert "endMemberOperation('confirm')" in member


def test_member_operation_exposes_busy_state_and_disables_all_plan_controls() -> None:
    member = _member_source()

    assert "planForm.setAttribute('aria-busy', busy ? 'true' : 'false');" in member
    assert "confirmationCard.setAttribute('aria-busy', busy ? 'true' : 'false');" in member
    assert "Array.from(planForm.elements).forEach((control) =>" in member
    assert "control.disabled = busy;" in member
    assert "confirmButton.disabled = busy || memberConfirmSubmitted || !proposalReady;" in member
    assert "cancelButton.disabled = busy || memberConfirmSubmitted || !proposalReady;" in member


def test_cancel_cannot_claim_no_change_after_confirm_submission() -> None:
    member = _member_source()

    submitted = member.index("memberConfirmSubmitted = true;")
    confirm_request = member.index("'/api/v1/household/members/confirm'", submitted)
    assert submitted < confirm_request
    assert "if (memberOperation !== null || memberConfirmSubmitted || !pendingMemberProposal?.proposal_id) return;" in member
    assert "Изменение отменено. Данные семьи не менялись." in member
    assert "pendingMemberProposal = null;" in member
    assert "Не удалось подтвердить результат изменения. Обновите состояние семьи перед новой попыткой." in member


def test_refresh_and_logout_only_invalidate_local_confirmation_state() -> None:
    member = _member_source()

    assert "refreshButton.addEventListener('click', invalidateMemberConfirmation)" in member
    assert "logoutButton.addEventListener('click', invalidateMemberConfirmation)" in member
    invalidate_body = member.split("function invalidateMemberConfirmation() {", 1)[1].split("\n  }", 1)[0]
    assert "memberRequest(" not in invalidate_body
    assert "Данные семьи не менялись" not in invalidate_body
