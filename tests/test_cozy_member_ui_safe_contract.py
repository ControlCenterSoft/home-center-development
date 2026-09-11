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
