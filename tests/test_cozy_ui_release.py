from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "product" / "web" / "static"
API = ROOT / "product" / "control-plane" / "src" / "home_center" / "api.py"
PACKAGE_INIT = ROOT / "product" / "control-plane" / "src" / "home_center" / "__init__.py"
PYPROJECT = ROOT / "pyproject.toml"
VERSION = ROOT / "VERSION"
RELEASE_NOTES = ROOT / "docs" / "releases" / "0.47.0.md"


class CozyUiReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = (STATIC / "index.html").read_text(encoding="utf-8")
        self.javascript = (STATIC / "app.js").read_text(encoding="utf-8")
        self.css = (STATIC / "app.css").read_text(encoding="utf-8")
        self.api = API.read_text(encoding="utf-8")

    def test_release_identity_is_aligned_for_qualification(self) -> None:
        self.assertEqual(VERSION.read_text(encoding="utf-8").strip(), "0.47.0")
        self.assertIn('__version__ = "0.47.0"', PACKAGE_INIT.read_text(encoding="utf-8"))
        self.assertIn('version = "0.47.0"', PYPROJECT.read_text(encoding="utf-8"))
        release_notes = RELEASE_NOTES.read_text(encoding="utf-8")
        self.assertIn("# Home Center 0.47.0", release_notes)
        self.assertIn("Status: development candidate.", release_notes)

    def test_cozy_and_full_modes_are_present(self) -> None:
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
        self.assertIn("Уютный", self.html)
        self.assertIn("Полный", self.html)

    def test_cozy_mode_is_the_visible_safe_default(self) -> None:
        self.assertIn('aria-selected="true">Уютный</button>', self.html)
        self.assertIn('aria-selected="false">Полный</button>', self.html)
        self.assertIn('id="cozy-view" class="view cozy-view"', self.html)
        self.assertIn('id="full-view" class="view" role="tabpanel" aria-labelledby="mode-full full-title" hidden', self.html)
        self.assertIn("home-center.interface-mode", self.javascript)
        self.assertIn("return 'cozy'", self.javascript)

    def test_complete_cozy_navigation_is_present_and_persistent(self) -> None:
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
        self.assertIn("localStorage.setItem", self.javascript)

    def test_static_asset_links_match_server_route(self) -> None:
        self.assertIn('href="/static/app.css"', self.html)
        self.assertIn('src="/static/app.js"', self.html)
        self.assertIn('path.startswith("/static/")', self.api)
        self.assertIn('path.removeprefix("/static/")', self.api)

    def test_cozy_ui_stays_read_only_and_capability_driven(self) -> None:
        self.assertIn("fetch('/api/v1/infrastructure'", self.javascript)
        self.assertIn("cache: 'no-store'", self.javascript)
        for method in (
            "method: 'POST'",
            'method: "POST"',
            "method: 'PUT'",
            'method: "PUT"',
            "method: 'PATCH'",
            'method: "PATCH"',
            "method: 'DELETE'",
            'method: "DELETE"',
        ):
            with self.subTest(method=method):
                self.assertNotIn(method, self.javascript)
        self.assertIn("HOME_SERVICE_CATALOG", self.javascript)
        self.assertIn("renderFamily", self.javascript)
        self.assertIn("renderHomeServices", self.javascript)
        self.assertIn("capabilityMatches", self.javascript)

    def test_unknown_node_state_is_not_treated_as_healthy(self) -> None:
        self.assertIn("if (!raw) return 'unknown'", self.javascript)
        self.assertIn("classifyNode(node) !== 'healthy'", self.javascript)
        self.assertIn("не подтверждены как здоровые", self.javascript)

    def test_keyboard_and_mobile_boundaries_exist(self) -> None:
        self.assertIn("ArrowLeft", self.javascript)
        self.assertIn("ArrowRight", self.javascript)
        self.assertIn("@media(max-width:900px)", self.css)
        self.assertIn("@media(max-width:800px)", self.css)
        self.assertIn("@media(max-width:460px)", self.css)
        self.assertIn("min-height:44px", self.css)
        self.assertIn("position:fixed", self.css)
        self.assertIn("prefers-reduced-motion", self.css)


if __name__ == "__main__":
    unittest.main()
