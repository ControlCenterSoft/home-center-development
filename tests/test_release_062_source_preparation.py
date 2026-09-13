from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.62.1"
BASELINE_VERSION = "0.61.2"


def _contract(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def _semver_tuple(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def test_062_release_identity_remains_consistent_in_later_release_trains() -> None:
    current = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    assert _semver_tuple(current) >= _semver_tuple(VERSION)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == current
    runtime_init = (ROOT / "product/control-plane/src/home_center/__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{current}"' in runtime_init
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    assert f'<small id="version">{current}</small>' in html


def test_062_release_notes_are_official_bounded_and_truthful() -> None:
    notes = (ROOT / "docs/releases/0.62.1.md").read_text(encoding="utf-8")
    assert notes.startswith("# Home Center 0.62.1\n\nStatus: official release.")
    assert "Release profile: `single-node-core`." in notes
    assert "provider execution" in notes.lower()
    assert "disabled/fail-closed/unclaimed" in notes
    assert "multi-node HA/automatic failover" in notes
    assert "commercial-launch clearance" in notes
    assert f"{BASELINE_VERSION} → {VERSION} → {BASELINE_VERSION}" in notes
    assert "reconciled ancestry" in notes


def test_062_role_identity_runtime_source_is_present() -> None:
    for relative in (
        "product/control-plane/src/home_center/role_identity_provisioning.py",
        "product/control-plane/src/home_center/role_identity_provisioning_runtime_safe.py",
        "product/control-plane/src/home_center/role_identity_provider_qualification.py",
        "product/control-plane/src/home_center/role_identity_binding_transition.py",
        "product/control-plane/src/home_center/role_identity_binding_api_runtime.py",
        "product/control-plane/src/home_center/api_v9.py",
    ):
        assert (ROOT / relative).is_file()


def test_062_provider_contract_is_closed_and_non_authorizing() -> None:
    provider = _contract("role-identity-provider-capability.v1.schema.json")
    assert provider["additionalProperties"] is False
    props = provider["properties"]
    assert props["emergency_admin_isolated"] == {"const": True}
    assert props["arbitrary_privilege_grant_supported"] == {"const": False}
    assert props["execution_authorized"] == {"const": False}


def test_062_plan_contract_requires_confirmation_and_preserves_emergency_admin() -> None:
    plan = _contract("role-identity-provisioning-plan.v1.schema.json")
    assert plan["additionalProperties"] is False
    props = plan["properties"]
    assert props["confirmation_required"] == {"const": True}
    assert props["account_absence_preflight_required"] == {"const": True}
    assert props["post_condition_verification_required"] == {"const": True}
    assert props["credential_material_authorized"] == {"const": False}
    assert props["emergency_admin_mutation_authorized"] == {"const": False}
    assert props["arbitrary_privilege_grant_authorized"] == {"const": False}
    assert props["execution_authorized"] == {"const": False}
    assert props["infrastructure_mutation_authorized"] == {"const": False}
    assert props["external_publication_authorized"] == {"const": False}


def test_062_api_bind_contract_cannot_accept_provider_receipt() -> None:
    bind = _contract("role-identity-provisioning-api-bind-request.v1.schema.json")
    assert bind["additionalProperties"] is False
    assert set(bind["required"]) == {"schema", "plan_id", "execution_job_id", "confirmed"}
    assert bind["properties"]["confirmed"] == {"const": True}
    assert "execution_receipt" not in bind["properties"]
    assert "provider_evidence" not in json.dumps(bind, sort_keys=True)


def test_062_architecture_rejects_privilege_equivalence() -> None:
    architecture = (ROOT / "docs/architecture/0.62-role-identity-provisioning-foundation.md").read_text(
        encoding="utf-8"
    )
    assert "does **not** automatically imply operating-system administrator" in architecture
    assert "secret references rather than credential values" in architecture
