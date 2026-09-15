from __future__ import annotations

import tomllib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_INIT = ROOT / "product" / "control-plane" / "src" / "home_center" / "__init__.py"
WEB_INDEX = ROOT / "product" / "web" / "static" / "index.html"
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish-release.yml"


def _current_version() -> str:
    return (ROOT / "VERSION").read_text(encoding="ascii").strip()


def _require_064(version: str) -> None:
    if not version.startswith("0.64."):
        pytest.skip("0.64 identity contract is release-line scoped")


def test_064_source_identity_is_bound_across_runtime_ui_and_release_notes() -> None:
    version = _current_version()
    _require_064(version)

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    runtime_init = RUNTIME_INIT.read_text(encoding="utf-8")
    html = WEB_INDEX.read_text(encoding="utf-8")
    notes_path = ROOT / "docs" / "releases" / f"{version}.md"
    notes = notes_path.read_text(encoding="utf-8")

    assert project["version"] == version
    assert f'__version__ = "{version}"' in runtime_init
    assert f'<small id="version">{version}</small>' in html
    assert notes.startswith(f"# Home Center {version}\n")
    assert "Authoritative Public Stable baseline for this work is Home Center 0.63.0." in notes


def test_064_publisher_derives_tag_and_notes_from_version_and_fails_closed_for_development() -> None:
    version = _current_version()
    _require_064(version)

    notes = (ROOT / "docs" / "releases" / f"{version}.md").read_text(encoding="utf-8")
    workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    status = next(line.strip() for line in notes.splitlines() if line.startswith("Status:"))

    assert 'version="$(tr -d \'[:space:]\' < VERSION)"' in workflow
    assert 'notes="docs/releases/${version}.md"' in workflow
    assert 'echo "tag=v$version" >> "$GITHUB_OUTPUT"' in workflow
    assert "grep -Eq '^Status: official release\\.?$' \"$notes\"" in workflow
    assert "publishable=false" in workflow
    assert "DEVELOPMENT_NO_PUBLISH" in workflow
    assert "0.64.0" not in workflow

    if status == "Status: development":
        assert "this document does not authorize a tag, GitHub Release, deployment artifact or Public Stable promotion" in notes
    else:
        assert status in {"Status: official release", "Status: official release."}
