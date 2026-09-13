from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _contract(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def test_062_source_preparation_does_not_preempt_release_identity() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == "0.61.0"
    notes = (ROOT / "docs/releases/0.62.0.md").read_text(encoding="utf-8")
    assert "not Release Candidate and not Public Stable" in notes
    assert "Current Public Stable remains 0.61.0" in notes


def test_062_role_identity_runtime_source_is_present() -> None:
    assert (ROOT / "product/control-plane/src/home_center/role_identity_provisioning.py").is_file()


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


def test_062_architecture_rejects_privilege_equivalence() -> None:
    architecture = (ROOT / "docs/architecture/0.62-role-identity-provisioning-foundation.md").read_text(
        encoding="utf-8"
    )
    assert "does **not** automatically imply operating-system administrator" in architecture
    assert "secret references rather than credential values" in architecture
