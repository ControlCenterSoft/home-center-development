from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "product" / "web" / "static" / "app.css"


def _css() -> str:
    return CSS.read_text(encoding="utf-8")


def test_shell_respects_top_and_horizontal_safe_areas() -> None:
    css = _css()

    assert "padding:max(14px,env(safe-area-inset-top)) max(24px,env(safe-area-inset-right)) 14px max(24px,env(safe-area-inset-left))" in css
    assert "padding:28px max(24px,env(safe-area-inset-right)) 56px max(24px,env(safe-area-inset-left))" in css
    assert "padding:max(12px,env(safe-area-inset-top)) max(16px,env(safe-area-inset-right)) 12px max(16px,env(safe-area-inset-left))" in css
    assert "padding:22px max(16px,env(safe-area-inset-right)) 92px max(16px,env(safe-area-inset-left))" in css


def test_mobile_cozy_navigation_stays_inside_display_cutouts() -> None:
    css = _css()

    assert "left:max(12px,env(safe-area-inset-left))" in css
    assert "right:max(12px,env(safe-area-inset-right))" in css
    assert "bottom:max(12px,env(safe-area-inset-bottom))" in css
