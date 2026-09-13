from __future__ import annotations

import tomllib
from pathlib import Path

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.60.0"
BASE_SHA = "1b54a0e72ca8fead4527946f95498dde41ee553f"


def test_release_060_exact_identity_is_consistent() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == VERSION
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == VERSION
    runtime_init = (ROOT / "product/control-plane/src/home_center/__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{VERSION}"' in runtime_init
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    assert f'<small id="version">{VERSION}</small>' in html


def test_release_060_notes_are_official_bounded_and_truthful() -> None:
    notes = (ROOT / "docs/releases/0.60.0.md").read_text(encoding="utf-8")
    assert notes.startswith("# Home Center 0.60.0\n\nStatus: official release.")
    assert "`single-node-core`" in notes
    assert "Provider command acceptance также не является enforcement success" in notes
    assert "Concrete production adapter должен проходить отдельную exact-bound qualification" in notes
    assert "Multi-node HA / automatic failover" in notes
    assert "commercial launch clearance" in notes
    assert "0.59.0 → 0.60.0" in notes


def test_release_060_parental_runtime_is_required_in_reproducible_wheel() -> None:
    assert {
        "home_center/parental_internet_policy.py",
        "home_center/parental_internet_policy_adapter.py",
        "home_center/parental_internet_policy_api.py",
        "home_center/parental_internet_policy_change_api.py",
        "home_center/parental_internet_policy_reconciliation.py",
        "home_center/parental_internet_policy_runtime.py",
        "home_center/parental_internet_policy_validation.py",
        "home_center/parental_internet_verified_base.py",
    } <= REQUIRED_MEMBERS


def test_release_060_upgrade_drills_bind_exact_public_stable_without_source_rewrite() -> None:
    for name in (
        "test_release_060_hosted_upgrade_drill.py",
        "test_release_060_hosted_systemd_upgrade.py",
    ):
        source = (ROOT / "tests" / name).read_text(encoding="utf-8")
        assert f'BASE_SHA = "{BASE_SHA}"' in source
        assert 'BASELINE_VERSION = "0.59.0"' in source
        assert 'CANDIDATE_VERSION = "0.60.0"' in source
        assert "SOURCE_VERSION" not in source
        assert "replace(source_marker" not in source


def test_release_060_ci_derives_deployment_candidate_from_exact_version() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert 'version="$(tr -d \'[:space:]\' < VERSION)"' in workflow
    assert "HC_VERSION=$version" in workflow
    assert 'artifact="home-center-${HC_VERSION}-linux-amd64.tar.gz"' in workflow
