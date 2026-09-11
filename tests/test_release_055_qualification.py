from __future__ import annotations

import tomllib
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_055_identity_is_exact_and_documented() -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    notes = (ROOT / "docs/releases/0.55.0.md").read_text(encoding="utf-8")
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    assert version == "0.55.0"
    assert project["project"]["version"] == version
    assert home_center.__version__ == version
    assert '<small id="version">0.55.0</small>' in html
    assert "# Home Center 0.55.0" in notes
    assert "read-only" in notes
    assert "production_mutation_enabled=false" in notes
    assert "external_publication_authorized=false" in notes


def test_release_055_wheel_contains_compatibility_state_index_runtime() -> None:
    assert "home_center/module_home_service_compatibility_state_index.py" in REQUIRED_MEMBERS


def test_release_055_contract_keeps_all_authority_closed() -> None:
    source = (ROOT / "product/control-plane/src/home_center/module_home_service_compatibility_state_index.py").read_text(encoding="utf-8")
    schema = (ROOT / "contracts/modules/module-home-service-compatibility-state-index.v1.schema.json").read_text(encoding="utf-8")
    assert "admission_authorized" in source
    assert "installation_authorized" in source
    assert "execution_authorized" in source
    assert "production_mutation_enabled" in source
    assert "external_publication_authorized" in source
    assert '"const": false' in schema


def test_release_055_empty_is_not_compatible_and_stale_is_fail_closed() -> None:
    source = (ROOT / "product/control-plane/src/home_center/module_home_service_compatibility_state_index.py").read_text(encoding="utf-8")
    assert 'summary_status = "empty"' in source
    assert 'summary_status = "stale"' in source
    assert 'summary_status = "blocked"' in source
    assert source.index('summary_status = "stale"') < source.index('summary_status = "blocked"')
