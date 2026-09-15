from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.64.0"
STABLE_BASELINE = "0.63.0"
CURRENT_VERSION = (ROOT / "VERSION").read_text(encoding="ascii").strip()

pytestmark = pytest.mark.skipif(
    CURRENT_VERSION != VERSION,
    reason="exact 0.64.0 identity assertions are scoped to the 0.64 release line",
)


def test_064_exact_source_identity_is_consistent() -> None:
    project = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    runtime_init = (
        ROOT / "product/control-plane/src/home_center/__init__.py"
    ).read_text(encoding="utf-8")
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")

    assert CURRENT_VERSION == VERSION
    assert project["version"] == VERSION
    assert f'__version__ = "{VERSION}"' in runtime_init
    assert f'<small id="version">{VERSION}</small>' in html


def test_064_release_notes_bind_same_identity_and_stable_baseline() -> None:
    notes = (ROOT / f"docs/releases/{VERSION}.md").read_text(encoding="utf-8")

    assert notes.startswith(f"# Home Center {VERSION}\n\nStatus: development\n")
    assert f"Home Center {STABLE_BASELINE}" in notes
    assert (
        "`VERSION`, Python package metadata, runtime `__version__` and the web UI "
        f"identify the current source line as {VERSION}."
    ) in notes
    assert "Status: official release." in notes
    assert "DEVELOPMENT_NO_PUBLISH" in notes


def test_064_publisher_derives_identity_from_version_file() -> None:
    workflow = (
        ROOT / ".github/workflows/publish-release.yml"
    ).read_text(encoding="utf-8")

    assert "< VERSION" in workflow
    assert 'notes="docs/releases/${version}.md"' in workflow
    assert 'echo "tag=v$version"' in workflow
    assert "^Status: official release" in workflow
    assert "DEVELOPMENT_NO_PUBLISH" in workflow
    assert "steps.release.outputs.publishable == 'true'" in workflow


def test_064_development_identity_does_not_authorize_publication() -> None:
    notes = (ROOT / f"docs/releases/{VERSION}.md").read_text(encoding="utf-8")
    status = next(
        line.strip() for line in notes.splitlines() if line.startswith("Status:")
    )

    assert status == "Status: development"
    assert status != "Status: official release."
