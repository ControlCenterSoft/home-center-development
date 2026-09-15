from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "product" / "web" / "static"


def _index() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def _focus_helper() -> str:
    return (STATIC / "auth-focus.js").read_text(encoding="utf-8")


def test_auth_focus_helper_loads_after_main_ui_script() -> None:
    html = _index()

    app = html.index('src="/static/app.js"')
    focus = html.index('src="/static/auth-focus.js"')
    tablist = html.index('src="/static/tablist-keyboard.js"')
    assert app < focus < tablist


def test_auth_focus_handoff_covers_login_and_password_change_views() -> None:
    source = _focus_helper()

    assert "['login-view', 'password']" in source
    assert "['password-view', 'current-password']" in source
    assert "new MutationObserver(focusVisibleAuthView)" in source
    assert "attributeFilter: ['hidden']" in source
    assert "view.contains(document.activeElement)" in source
    assert "target.focus()" in source


def test_auth_focus_handoff_is_browser_local_and_non_authorizing() -> None:
    source = _focus_helper()

    assert "fetch(" not in source
    assert "XMLHttpRequest" not in source
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    assert "method:" not in source
