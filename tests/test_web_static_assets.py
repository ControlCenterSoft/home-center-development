from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "product" / "web" / "static"


class WebStaticAssetQualificationTests(unittest.TestCase):
    def test_index_uses_canonical_static_routes(self) -> None:
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="/static/app.css"', html)
        self.assertIn('src="/static/app.js"', html)
        self.assertNotIn('href="app.css"', html)
        self.assertNotIn('src="app.js"', html)
        self.assertNotIn(">development<", html)

    def test_login_and_first_password_change_are_reachable_from_web_ui(self) -> None:
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        script = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="login-form"', html)
        self.assertIn('id="password-form"', html)
        self.assertIn('"/api/v1/session"', script)
        self.assertIn('"/api/v1/auth/local-admin/password/change"', script)
        self.assertIn('"/api/v1/infrastructure"', script)

    def test_static_assets_are_non_empty(self) -> None:
        for name in ("index.html", "app.css", "app.js"):
            self.assertGreater((STATIC / name).stat().st_size, 512, name)


if __name__ == "__main__":
    unittest.main()
