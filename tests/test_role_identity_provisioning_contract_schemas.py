from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, effective_policy
from home_center.household_store import HouseholdStore
from home_center.role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
    StorageMode,
    build_role_identity_provisioning_plan,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts" / "household"
DIGEST = "a" * 64


def _schema(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def _objects():
    household = Household(
        household_id="home",
        members=(FamilyMember("member-parent", "Parent", HouseholdRole.PARENT),),
        devices=(),
    )
    store = HouseholdStore()
    store.create(household)
    snapshot = store.read("home")
    policy = effective_policy(snapshot.household, "member-parent")
    provider = IdentityProviderCapability(
        provider_id="local-provider",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        supported_roles=(HouseholdRole.PARENT,),
        account_create_supported=True,
        portable_home_supported=False,
        portable_profile_supported=False,
        secret_reference_supported=True,
        evidence_sha256=DIGEST,
    )
    plan = build_role_identity_provisioning_plan(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        member_id="member-parent",
        account_name="pavel.user",
        home_directory_mode=StorageMode.LOCAL,
        profile_mode=StorageMode.LOCAL,
    )
    return provider, plan


def test_role_identity_schemas_are_valid_and_closed() -> None:
    provider_schema = _schema("role-identity-provider-capability.v1.schema.json")
    plan_schema = _schema("role-identity-provisioning-plan.v1.schema.json")
    jsonschema.Draft202012Validator.check_schema(provider_schema)
    jsonschema.Draft202012Validator.check_schema(plan_schema)
    assert provider_schema["additionalProperties"] is False
    assert plan_schema["additionalProperties"] is False


def test_exact_provider_and_plan_validate_against_public_contracts() -> None:
    provider, plan = _objects()
    jsonschema.Draft202012Validator(
        _schema("role-identity-provider-capability.v1.schema.json")
    ).validate(provider.to_dict())
    jsonschema.Draft202012Validator(
        _schema("role-identity-provisioning-plan.v1.schema.json")
    ).validate(plan.to_dict())


def test_provider_schema_rejects_execution_authority() -> None:
    provider, _plan = _objects()
    raw = provider.to_dict()
    raw["execution_authorized"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            _schema("role-identity-provider-capability.v1.schema.json")
        ).validate(raw)


def test_plan_schema_rejects_emergency_admin_or_execution_authority() -> None:
    _provider, plan = _objects()
    schema = _schema("role-identity-provisioning-plan.v1.schema.json")

    raw = plan.to_dict()
    raw["emergency_admin_mutation_authorized"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(raw)

    raw = plan.to_dict()
    raw["execution_authorized"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(raw)
