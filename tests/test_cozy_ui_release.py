from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "product" / "web" / "static"


def test_cozy_and_full_modes_are_present() -> None:
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert 'id="mode-cozy"' in html
    assert 'id="mode-full"' in html
    assert 'id="cozy-view"' in html
    assert 'id="full-view"' in html
    assert 'href="/static/app.css"' in html
    assert 'src="/static/app.js"' in html
    assert "Уютный" in html
    assert "Полный" in html


def test_cozy_mode_is_safe_default_and_persistent() -> None:
    javascript = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "home-center.interface-mode" in javascript
    assert "return 'cozy'" in javascript
    assert "localStorage.setItem" in javascript
    assert "normalized = mode === 'full' ? 'full' : 'cozy'" in javascript


def test_complete_cozy_menu_is_present_and_persistent() -> None:
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    javascript = (STATIC / "app.js").read_text(encoding="utf-8")

    for section, panel, label in [
        ("home", "cozy-home", "Домой"),
        ("family", "cozy-family", "Семья"),
        ("house", "cozy-house", "Мой дом"),
    ]:
        assert f'data-cozy-section="{section}"' in html
        assert f'id="{panel}"' in html
        assert label in html

    assert "home-center.cozy-section" in javascript
    assert "VALID_SECTIONS" in javascript
    assert "setCozySection" in javascript


def test_cozy_ui_uses_existing_read_model_without_mutation_calls() -> None:
    javascript = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "fetch('/api/v1/infrastructure'" in javascript
    assert "method: 'POST'" not in javascript
    assert 'method: "POST"' not in javascript
    assert "HOME_SERVICE_CATALOG" in javascript
    assert "renderFamily" in javascript
    assert "renderHomeServices" in javascript


def test_mobile_first_navigation_breakpoints_exist() -> None:
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert "@media(max-width:900px)" in css
    assert "@media(max-width:800px)" in css
    assert "@media(max-width:460px)" in css
    assert ".cozy-nav" in css
    assert "position:fixed" in css
    assert ".home-service-grid" in css
    assert ".family-grid" in css
