from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "product" / "web" / "static"
API = ROOT / "product" / "control-plane" / "src" / "home_center" / "api.py"


class CozyUiReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = (STATIC / "index.html").read_text(encoding="utf-8")
        self.javascript = (STATIC / "app.js").read_text(encoding="utf-8")
        self.css = (STATIC / "app.css").read_text(encoding="utf-8")
        self.api = API.read_text(encoding="utf-8")

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

    def test_static_asset_links_match_server_route(self) -> None:
        self.assertIn('href="/static/app.css"', self.html)
        self.assertIn('src="/static/app.js"', self.html)
        self.assertIn('path.startswith("/static/")', self.api)
        self.assertIn('path.removeprefix("/static/")', self.api)

    def test_cozy_mode_is_safe_default_and_browser_local(self) -> None:
        self.assertIn("home-center.interface-mode", self.javascript)
        self.assertIn("return 'cozy'", self.javascript)
        self.assertIn("localStorage.setItem", self.javascript)
        self.assertIn("mode === 'full' ? 'full' : 'cozy'", self.javascript)

    def test_mode_switch_has_no_mutation_request(self) -> None:
        self.assertIn("setMode(button.dataset.mode)", self.javascript)
        self.assertIn("fetch('/api/v1/infrastructure'", self.javascript)
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

    def test_unknown_node_state_is_not_treated_as_healthy(self) -> None:
        self.assertIn("if (!raw) return 'unknown'", self.javascript)
        self.assertIn("classifyNode(node) !== 'healthy'", self.javascript)
        self.assertIn("не подтверждены как здоровые", self.javascript)

    def test_mobile_first_and_keyboard_boundaries_exist(self) -> None:
        self.assertIn("@media(max-width:800px)", self.css)
        self.assertIn("@media(max-width:460px)", self.css)
        self.assertIn("min-height:44px", self.css)
        self.assertIn("ArrowLeft", self.javascript)
        self.assertIn("ArrowRight", self.javascript)


if __name__ == "__main__":
    unittest.main()
