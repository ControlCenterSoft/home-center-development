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


def test_authentication_and_forced_password_change_are_back_in_ui() -> None:
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    javascript = (STATIC / "app.js").read_text(encoding="utf-8")
    assert 'id="login-view"' in html
    assert 'id="password-view"' in html
    assert 'id="login-form"' in html
    assert 'id="password-form"' in html
    assert "/api/v1/session" in javascript
    assert "/api/v1/auth/local-admin/password/change" in javascript
    assert "password_change_required" in javascript
    assert "credentials: 'same-origin'" in javascript


def test_cozy_mode_is_safe_default_and_persistent() -> None:
    javascript = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "home-center.interface-mode" in javascript
    assert "? 'full' : 'cozy'" in javascript
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


def test_household_bootstrap_is_wired_but_provider_mutation_is_not() -> None:
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    javascript = (STATIC / "app.js").read_text(encoding="utf-8")
    assert 'id="household-bootstrap-form"' in html
    assert "/api/v1/household" in javascript
    assert "/api/v1/household/bootstrap" in javascript
    assert "home-center.household-bootstrap.v1" in javascript
    assert "/api/v1/desired-state" not in javascript
    assert "/api/v1/actions/" not in javascript
    assert "HOME_SERVICE_CATALOG" in javascript
    assert "renderFamily" in javascript
    assert "renderHomeServices" in javascript


def test_mobile_first_navigation_breakpoints_exist() -> None:
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert "@media(max-width:900px)" in css
    assert "@media(max-width:800px)" in css
    assert "@media(max-width:520px)" in css
    assert ".cozy-nav" in css
    assert "position:fixed" in css
    assert ".home-service-grid" in css
    assert ".family-grid" in css
    assert ".setup-card" in css
