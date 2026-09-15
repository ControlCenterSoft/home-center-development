from __future__ import annotations

from pathlib import Path
import re
import tomllib

import pytest

ROOT = Path(__file__).resolve().parents[1]
RELEASE = "0.64.0"


def _version() -> str:
    return (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def _require_064_line() -> None:
    if _version() != RELEASE:
        pytest.skip("0.64-only exact source identity regression")


def test_064_exact_identity_matches_package_runtime_and_ui() -> None:
    _require_064_line()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    runtime = (ROOT / "product/control-plane/src/home_center/__init__.py").read_text(encoding="utf-8")
    index = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")

    assert pyproject["project"]["version"] == RELEASE
    assert re.search(r'^__version__ = "0\.64\.0"$', runtime, re.MULTILINE)
    assert '<small id="version">0.64.0</small>' in index


def test_064_release_notes_bind_development_identity_to_stable_baseline() -> None:
    _require_064_line()
    notes = (ROOT / "docs/releases/0.64.0.md").read_text(encoding="utf-8")

    assert notes.startswith("# Home Center 0.64.0\n\nStatus: development\n")
    assert "Authoritative Public Stable baseline for this work is Home Center 0.63.0." in notes
    assert "DEVELOPMENT_NO_PUBLISH" in notes
    assert "Status: official release." in notes


def test_publisher_derives_notes_and_tag_from_version_and_fails_closed_for_development() -> None:
    _require_064_line()
    workflow = (ROOT / ".github/workflows/publish-release.yml").read_text(encoding="utf-8")

    assert 'version="$(tr -d \'[:space:]\' < VERSION)"' in workflow
    assert 'notes="docs/releases/${version}.md"' in workflow
    assert 'echo "tag=v$version" >> "$GITHUB_OUTPUT"' in workflow
    assert "grep -Eq '^Status: official release\\.?$' \"$notes\"" in workflow
    assert "RELEASE_AUTHORIZATION=DEVELOPMENT_NO_PUBLISH" in workflow
    assert "RELEASE_STATE=DEVELOPMENT_NO_PUBLISH" in workflow
    assert "0.64.0" not in workflow
