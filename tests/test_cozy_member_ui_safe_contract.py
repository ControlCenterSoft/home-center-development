from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "product" / "web" / "static" / "index.html"
APP = ROOT / "product" / "web" / "static" / "app.js"
MEMBER = ROOT / "product" / "web" / "static" / "member-change.js"


def test_member_change_ui_is_explicit_confirmation_flow() -> None:
    index = INDEX.read_text(encoding="utf-8")
    member = MEMBER.read_text(encoding="utf-8")
    assert 'id="member-plan-form"' in index
    assert 'id="member-confirm-card"' in index
    assert 'id="member-confirm-button"' in index
    assert 'id="member-cancel-button"' in index
    assert '/static/member-change.js' in index
    assert '/api/v1/household/members/plan' in member
    assert '/api/v1/household/members/confirm' in member
    assert 'confirmed: true' in member
    assert 'household_member_change_stale' in member
    assert 'credentials: \'same-origin\'' in member
    assert 'innerHTML' not in member


def test_member_change_ui_serializes_plan_and_confirm_operations() -> None:
    member = MEMBER.read_text(encoding="utf-8")
    assert "let memberOperationInFlight = false" in member
    assert "let memberConfirmationSubmitted = false" in member
    assert "if (memberOperationInFlight) return" in member
    assert "if (memberOperationInFlight || !pendingMemberProposal?.proposal_id) return" in member
    assert "planForm.setAttribute('aria-busy', busy ? 'true' : 'false')" in member
    assert "confirmCard.setAttribute('aria-busy', busy ? 'true' : 'false')" in member
    assert "planForm.querySelectorAll('input, select, button')" in member
    assert "memberConfirmationSubmitted = true" in member
    assert "Подтверждение уже было отправлено. Обновите состояние семьи, чтобы проверить результат." in member
    assert "Подтверждение было отправлено, но результат не получен." in member
    assert "clearMemberConfirmation({resetSubmitted: true})" in member


def test_member_ui_preserves_current_main_accessibility_and_fail_closed_node_state() -> None:
    app = APP.read_text(encoding="utf-8")
    index = INDEX.read_text(encoding="utf-8")
    assert "const HEALTHY_NODE_STATES" in app
    assert "classifyNode" in app
    assert ".tabIndex" in app
    assert "aria-selected" in app
    assert 'aria-labelledby="cozy-tab-family"' in index
    assert 'aria-live="polite"' in index
    assert 'id="version"' in index
