from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "product" / "web" / "static"


def test_cozy_and_full_modes_are_present() -> None:
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert 'id="mode-cozy"' in html
    assert 'id="mode-full"' in html
    assert 'id="cozy-view"' in html
    assert 'id="full-view"' in html
    assert "Уютный" in html
    assert "Полный" in html


def test_cozy_mode_is_safe_default_and_persistent() -> None:
    javascript = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "home-center.interface-mode" in javascript
    assert "return 'cozy'" in javascript
    assert "localStorage.setItem" in javascript
    assert "normalized = mode === 'full' ? 'full' : 'cozy'" in javascript


def test_switch_is_presentation_only() -> None:
    javascript = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "data-mode" in javascript
    assert "setMode(button.dataset.mode)" in javascript
    assert "fetch('/api/v1/infrastructure'" in javascript
    assert "method: 'POST'" not in javascript
    assert 'method: "POST"' not in javascript


def test_mobile_first_breakpoints_exist() -> None:
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert "@media(max-width:800px)" in css
    assert "@media(max-width:460px)" in css
    assert ".cozy-summary" in css
