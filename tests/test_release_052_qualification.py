from __future__ import annotations

import tomllib
from pathlib import Path

import home_center
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_052_identity_is_exact_and_documented() -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    notes = (ROOT / "docs/releases/0.52.0.md").read_text(encoding="utf-8")
    assert version == "0.52.0"
    assert project["project"]["version"] == version
    assert home_center.__version__ == version
    assert "# Home Center 0.52.0" in notes
    assert "required" in notes
    assert "satisfied" in notes
    assert "optional" in notes
    assert "provider_selected=false" in notes


def test_release_052_wheel_requires_management_status_runtime() -> None:
    required = {
        "home_center/api_v3.py",
        "home_center/household_device_management.py",
        "home_center/household_device_change.py",
        "home_center/household_device_runtime.py",
    }
    assert required <= REQUIRED_MEMBERS


def test_release_052_api_is_authenticated_read_only_and_provider_free() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v3.py").read_text(encoding="utf-8")
    management = (
        ROOT / "product/control-plane/src/home_center/household_device_management.py"
    ).read_text(encoding="utf-8")
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(encoding="utf-8")
    assert '"/api/v1/household/devices/management"' in api
    assert "self._require_actor(correlation_id)" in api
    assert "RuntimeRequestHandlerV3" in server
    assert 'SATISFIED = "satisfied"' in management
    assert 'REQUIRED = "required"' in management
    assert 'OPTIONAL = "optional"' in management
    assert "provider_selected: bool = field(default=False" in management
    assert "policy_application_authorized: bool = field(default=False" in management
    assert "provider_execution_authorized: bool = field(default=False" in management
    assert "infrastructure_mutation_authorized: bool = field(default=False" in management
    assert "external_publication_authorized: bool = field(default=False" in management
