from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "product" / "web" / "static"
API = ROOT / "product" / "control-plane" / "src" / "home_center" / "api.py"
PACKAGE_INIT = ROOT / "product" / "control-plane" / "src" / "home_center" / "__init__.py"
PYPROJECT = ROOT / "pyproject.toml"
VERSION = ROOT / "VERSION"
RELEASE_NOTES = ROOT / "docs" / "releases" / "0.49.0.md"


class CozyUiReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = (STATIC / "index.html").read_text(encoding="utf-8")
        self.javascript = (STATIC / "app.js").read_text(encoding="utf-8")
        self.css = (STATIC / "app.css").read_text(encoding="utf-8")
        self.api = API.read_text(encoding="utf-8")

    def test_release_identity_is_aligned_for_official_release(self) -> None:
        self.assertEqual(VERSION.read_text(encoding="utf-8").strip(), "0.49.0")
        self.assertIn('__version__ = "0.49.0"', PACKAGE_INIT.read_text(encoding="utf-8"))
        self.assertIn('version = "0.49.0"', PYPROJECT.read_text(encoding="utf-8"))
        release_notes = RELEASE_NOTES.read_text(encoding="utf-8")
        self.assertIn("# Home Center 0.49.0", release_notes)
        self.assertIn("Status: official release.", release_notes)
        self.assertNotIn("qualification candidate", release_notes.lower())
        self.assertNotIn("development candidate", release_notes.lower())
        self.assertIn("## Security and commercial boundary", release_notes)
        self.assertIn("## Release qualification", release_notes)

    def test_cozy_and_full_modes_are_present_with_tab_semantics(self) -> None:
        for marker in (
            'id="mode-cozy"',
            'id="mode-full"',
            'id="cozy-view"',
            'id="full-view"',
            'role="tablist"',
            'role="tabpanel"',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.html)
        self.assertIn('aria-selected="true">Уютный</button>', self.html)
        self.assertIn('aria-selected="false" tabindex="-1">Полный</button>', self.html)
        self.assertIn("Уютный", self.html)
        self.assertIn("Полный", self.html)

    def test_authentication_and_forced_password_change_are_in_ui(self) -> None:
        for marker in ('id="login-view"', 'id="password-view"', 'id="login-form"', 'id="password-form"'):
            self.assertIn(marker, self.html)
        self.assertIn("/api/v1/session", self.javascript)
        self.assertIn("/api/v1/auth/local-admin/password/change", self.javascript)
        self.assertIn("password_change_required", self.javascript)
        self.assertIn("credentials: 'same-origin'", self.javascript)

    def test_cozy_mode_is_safe_default_and_persistent(self) -> None:
        self.assertIn("home-center.interface-mode", self.javascript)
        self.assertIn("return saved === 'full' ? 'full' : 'cozy'", self.javascript)
        self.assertIn("localStorage.setItem", self.javascript)
        self.assertIn("normalized = mode === 'full' ? 'full' : 'cozy'", self.javascript)

    def test_complete_cozy_navigation_is_present_persistent_and_keyboard_accessible(self) -> None:
        for section, panel, label in (
            ("home", "cozy-home", "Домой"),
            ("family", "cozy-family", "Семья"),
            ("house", "cozy-house", "Мой дом"),
        ):
            with self.subTest(section=section):
                self.assertIn(f'data-cozy-section="{section}"', self.html)
                self.assertIn(f'id="{panel}"', self.html)
                self.assertIn(label, self.html)
        self.assertIn("home-center.cozy-section", self.javascript)
        self.assertIn("VALID_SECTIONS", self.javascript)
        self.assertIn("setCozySection", self.javascript)
        self.assertIn("ArrowLeft", self.javascript)
        self.assertIn("ArrowRight", self.javascript)

    def test_household_bootstrap_is_wired_without_infrastructure_mutation(self) -> None:
        self.assertIn('id="household-bootstrap-form"', self.html)
        self.assertIn("/api/v1/household", self.javascript)
        self.assertIn("/api/v1/household/bootstrap", self.javascript)
        self.assertIn("home-center.household-bootstrap.v1", self.javascript)
        self.assertNotIn("/api/v1/desired-state", self.javascript)
        self.assertNotIn("/api/v1/actions/", self.javascript)
        self.assertIn("HOME_SERVICE_CATALOG", self.javascript)
        self.assertIn("renderFamily", self.javascript)
        self.assertIn("renderHomeServices", self.javascript)

    def test_static_asset_links_match_server_route(self) -> None:
        self.assertIn('href="/static/app.css"', self.html)
        self.assertIn('src="/static/app.js"', self.html)
        self.assertIn('path.startswith("/static/")', self.api)
        self.assertIn('path.removeprefix("/static/")', self.api)

    def test_unknown_node_state_is_not_treated_as_healthy(self) -> None:
        self.assertIn("if (!raw) return 'unknown'", self.javascript)
        self.assertIn("classifyNode(node) !== 'healthy'", self.javascript)
        self.assertIn("не подтверждены как здоровые", self.javascript)

    def test_mobile_and_reduced_motion_boundaries_exist(self) -> None:
        self.assertIn("@media(max-width:900px)", self.css)
        self.assertIn("@media(max-width:800px)", self.css)
        self.assertIn("@media(max-width:460px)", self.css)
        self.assertIn("min-height:44px", self.css)
        self.assertIn("position:fixed", self.css)
        self.assertIn("prefers-reduced-motion", self.css)
        self.assertIn(".setup-card", self.css)


if __name__ == "__main__":
    unittest.main()
