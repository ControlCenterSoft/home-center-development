from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "product" / "web" / "static"
INDEX = STATIC / "index.html"
ACCESSIBILITY = STATIC / "accessibility.css"


def test_keyboard_skip_link_precedes_shell_and_targets_main_landmark() -> None:
    html = INDEX.read_text(encoding="utf-8")
    skip_link = '<a class="skip-link" href="#main-content">Перейти к основному содержимому</a>'

    assert '/static/accessibility.css' in html
    assert skip_link in html
    assert html.index(skip_link) < html.index('<div class="app-shell">')
    assert '<main id="main-content" tabindex="-1">' in html


def test_skip_link_is_hidden_until_keyboard_focus_and_respects_display_cutouts() -> None:
    css = ACCESSIBILITY.read_text(encoding="utf-8")

    assert ".skip-link{" in css
    assert "safe-area-inset-top" in css
    assert "safe-area-inset-left" in css
    assert "transform:translateY(calc(-100% - 24px))" in css
    assert ".skip-link:focus-visible{" in css
    assert "transform:translateY(0)" in css
