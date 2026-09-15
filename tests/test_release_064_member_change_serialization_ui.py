from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "product" / "web" / "static" / "index.html"
MEMBER = ROOT / "product" / "web" / "static" / "member-change.js"


def test_member_plan_and_confirm_operations_are_serialized() -> None:
    member = MEMBER.read_text(encoding="utf-8")

    assert "let memberOperationInFlight = false;" in member
    assert "function setMemberOperationBusy(busy)" in member
    assert "planForm.setAttribute('aria-busy', busy ? 'true' : 'false');" in member
    assert "confirmCard.setAttribute('aria-busy', busy ? 'true' : 'false');" in member
    assert "planForm.querySelectorAll('input, select, button')" in member
    assert "confirmButton.disabled = busy;" in member
    assert "cancelButton.disabled = busy;" in member
    assert member.count("setMemberOperationBusy(true);") == 2
    assert member.count("setMemberOperationBusy(false);") == 2

    plan_start = member.index("planForm.addEventListener('submit'")
    cancel_start = member.index("cancelButton.addEventListener('click'")
    confirm_start = member.index("confirmButton.addEventListener('click'")
    plan_block = member[plan_start:cancel_start]
    cancel_block = member[cancel_start:confirm_start]
    confirm_block = member[confirm_start:]

    assert "if (memberOperationInFlight) return;" in plan_block
    assert "if (memberOperationInFlight) return;" in cancel_block
    assert "if (memberOperationInFlight || !pendingMemberProposal?.proposal_id) return;" in confirm_block


def test_cancel_cannot_claim_no_change_after_confirm_has_started() -> None:
    member = MEMBER.read_text(encoding="utf-8")
    cancel_start = member.index("cancelButton.addEventListener('click'")
    confirm_start = member.index("confirmButton.addEventListener('click'")
    cancel_block = member[cancel_start:confirm_start]

    guard_at = cancel_block.index("if (memberOperationInFlight) return;")
    claim_at = cancel_block.index("Изменение отменено. Данные семьи не менялись.")
    assert guard_at < claim_at


def test_member_flow_preserves_authority_and_local_invalidation_boundaries() -> None:
    member = MEMBER.read_text(encoding="utf-8")
    index = INDEX.read_text(encoding="utf-8")

    assert 'id="member-plan-form"' in index
    assert 'id="member-confirm-card"' in index
    assert "credentials: 'same-origin'" in member
    assert "household_member_change_stale" in member
    assert "confirmed: true" in member
    assert "refreshButton.addEventListener('click', clearMemberConfirmation)" in member
    assert "logoutButton.addEventListener('click', clearMemberConfirmation)" in member
    assert "focusConfirmAfterBusy" in member
    assert "setMemberOperationBusy(false);\n      if (focusConfirmAfterBusy) confirmButton.focus();" in member
    assert "innerHTML" not in member
