from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MEMBER = ROOT / "product" / "web" / "static" / "member-change.js"


def _member_source() -> str:
    return MEMBER.read_text(encoding="utf-8")


def test_member_plan_and_confirm_are_serialized() -> None:
    source = _member_source()

    assert "let memberOperationInFlight = false;" in source
    assert "function setMemberOperationBusy(busy)" in source
    assert "if (memberOperationInFlight) return;" in source
    assert "if (memberOperationInFlight || !pendingMemberProposal?.proposal_id) return;" in source
    assert "setMemberOperationBusy(true);" in source
    assert source.count("setMemberOperationBusy(false);") == 2


def test_member_busy_state_owns_all_plan_and_confirmation_controls() -> None:
    source = _member_source()

    assert "planForm.setAttribute('aria-busy', busy ? 'true' : 'false');" in source
    assert "confirmCard.setAttribute('aria-busy', busy ? 'true' : 'false');" in source
    assert "planForm.querySelectorAll('input, select, button')" in source
    assert "confirmButton.disabled = busy;" in source
    assert "cancelButton.disabled = busy;" in source


def test_cancel_cannot_claim_no_change_during_inflight_confirm() -> None:
    source = _member_source()
    cancel_handler = source.split("cancelButton.addEventListener('click', () => {", 1)[1].split("});", 1)[0]

    assert "if (memberOperationInFlight) return;" in cancel_handler
    assert "Изменение отменено. Данные семьи не менялись." in cancel_handler
    assert cancel_handler.index("if (memberOperationInFlight) return;") < cancel_handler.index("Данные семьи не менялись")


def test_refresh_and_logout_only_invalidate_local_pending_state() -> None:
    source = _member_source()

    assert "refreshButton.addEventListener('click', clearMemberConfirmation)" in source
    assert "logoutButton.addEventListener('click', clearMemberConfirmation)" in source
    assert "AbortController" not in source
    assert "abort()" not in source
