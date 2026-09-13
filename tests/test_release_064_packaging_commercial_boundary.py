from __future__ import annotations

import ast
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "product/control-plane/src/home_center"
FOUNDATION_MODULES = (
    "safe_auto_repair.py",
    "safe_auto_repair_history.py",
)


def _absolute_import_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def test_064_foundation_has_no_third_party_runtime_dependency() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert not project.get("dependencies"), "0.64 foundation must not silently add a runtime dependency"

    for module in FOUNDATION_MODULES:
        roots = _absolute_import_roots(RUNTIME / module)
        unexpected = sorted(root for root in roots if root not in sys.stdlib_module_names and root != "home_center")
        assert unexpected == [], f"{module} added non-stdlib absolute imports: {unexpected}"


def test_064_foundation_modules_are_present_in_the_exact_ci_wheel() -> None:
    wheels = sorted((ROOT / "dist/first").glob("*.whl"))
    if not wheels:
        pytest.skip("exact CI wheel is not present in this test invocation")
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
    for module in FOUNDATION_MODULES:
        assert f"home_center/{module}" in names


def test_064_release_boundary_keeps_commercial_provider_and_ha_claims_closed() -> None:
    notes = (ROOT / "docs/releases/0.64.0.md").read_text(encoding="utf-8")
    assert "Authoritative Public Stable baseline for this work is Home Center 0.63.0." in notes
    assert "adds no third-party runtime dependency" in notes
    assert "no remote-service client dependency" in notes
    assert "does not claim provider qualification, HA capability or commercial-launch/legal clearance" in notes
    assert "eligible_for_auto_repair=true` is evidence only" in notes
    assert "does not grant execution authority" in notes


def test_064_foundation_source_contains_no_remote_client_or_secret_value_import() -> None:
    forbidden_import_roots = {
        "boto3",
        "botocore",
        "google",
        "httpx",
        "requests",
        "urllib3",
        "paramiko",
        "openai",
    }
    for module in FOUNDATION_MODULES:
        roots = _absolute_import_roots(RUNTIME / module)
        assert roots.isdisjoint(forbidden_import_roots)

        source = (RUNTIME / module).read_text(encoding="utf-8").lower()
        for forbidden in (
            "password_value",
            "credential_value",
            "private_key_value",
            "api_key_value",
            "bearer_token_value",
        ):
            assert forbidden not in source
