from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "product" / "web" / "static" / "app.css"


def _css() -> str:
    return CSS.read_text(encoding="utf-8")


def test_forced_colors_preserves_keyboard_focus_and_selected_tabs() -> None:
    css = _css()

    assert "@media(forced-colors:active)" in css
    assert "outline:3px solid Highlight" in css
    assert ".mode-button.active,.cozy-nav-button.active" in css
    assert "outline:2px solid Highlight" in css
    assert "font-weight:900" in css


def test_forced_colors_does_not_rely_only_on_custom_status_colors() -> None:
    css = _css()

    assert ".status-badge,.state-pill,.service-state,.attention-item{border:1px solid CanvasText}" in css
    assert ".attention-item.good{border-style:double}" in css
    assert ".attention-item.warn{border-style:dashed}" in css
    assert ".attention-dot{background:CanvasText}" in css
