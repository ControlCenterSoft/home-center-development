from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "product" / "web" / "static"


def test_tablist_keyboard_helper_is_loaded_after_core_ui() -> None:
    index = (STATIC / "index.html").read_text(encoding="utf-8")

    app = index.index('<script src="/static/app.js"></script>')
    helper = index.index('<script src="/static/tablist-keyboard.js"></script>')

    assert helper > app


def test_tablist_keyboard_helper_covers_both_aria_tablists() -> None:
    source = (STATIC / "tablist-keyboard.js").read_text(encoding="utf-8")

    assert "#mode-switch [role=\"tab\"]" in source
    assert ".cozy-nav [role=\"tab\"]" in source
    assert "event.key !== HOME && event.key !== END" in source
    assert "event.preventDefault()" in source
    assert "tabs[0]" in source
    assert "tabs[tabs.length - 1]" in source
    assert "target.click()" in source
    assert "target.focus()" in source


def test_tablist_keyboard_helper_is_navigation_only() -> None:
    source = (STATIC / "tablist-keyboard.js").read_text(encoding="utf-8")

    forbidden = (
        "fetch(",
        "XMLHttpRequest",
        "method: 'POST'",
        'method: "POST"',
        "localStorage.setItem",
        "sessionStorage.setItem",
    )
    assert not any(token in source for token in forbidden)
