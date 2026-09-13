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
from home_center.role_identity_provisioning_confirmation import (
    build_account_preflight_evidence,
    confirm_role_identity_provisioning,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts" / "household"
DIGEST = "a" * 64


def _schema(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def _objects():
    household = Household(
        household_id="home",
        members=(FamilyMember("member-child", "Child", HouseholdRole.CHILD),),
        devices=(),
    )
    store = HouseholdStore()
    store.create(household)
    snapshot = store.read("home")
    policy = effective_policy(snapshot.household, "member-child")
    provider = IdentityProviderCapability(
        provider_id="directory-provider",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.DIRECTORY,
        supported_roles=(HouseholdRole.CHILD,),
        account_create_supported=True,
        portable_home_supported=True,
        portable_profile_supported=True,
        secret_reference_supported=True,
        evidence_sha256=DIGEST,
    )
    plan = build_role_identity_provisioning_plan(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        member_id="member-child",
        account_name="child.user",
        home_directory_mode=StorageMode.PORTABLE,
        profile_mode=StorageMode.PORTABLE,
    )
    preflight = build_account_preflight_evidence(
        plan=plan,
        observed_state="absent",
        observed_at="2026-09-13T03:50:00Z",
    )
    receipt = confirm_role_identity_provisioning(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        plan=plan,
        preflight=preflight,
        confirmed=True,
        now="2026-09-13T03:51:00Z",
    )
    return plan, preflight, receipt


def test_confirmation_schemas_are_valid_and_closed() -> None:
    for name in (
        "role-identity-account-preflight.v1.schema.json",
        "role-identity-provisioning-confirm-request.v1.schema.json",
        "role-identity-provisioning-confirm-receipt.v1.schema.json",
    ):
        schema = _schema(name)
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False


def test_preflight_and_receipt_validate_against_public_contracts() -> None:
    _plan, preflight, receipt = _objects()
    jsonschema.Draft202012Validator(
        _schema("role-identity-account-preflight.v1.schema.json")
    ).validate(preflight.to_dict())
    jsonschema.Draft202012Validator(
        _schema("role-identity-provisioning-confirm-receipt.v1.schema.json")
    ).validate(receipt.to_dict())


def test_preflight_schema_rejects_execution_or_credential_observation() -> None:
    _plan, preflight, _receipt = _objects()
    schema = _schema("role-identity-account-preflight.v1.schema.json")

    raw = preflight.to_dict()
    raw["execution_authorized"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(raw)

    raw = preflight.to_dict()
    raw["credential_material_observed"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(raw)


def test_confirmation_receipt_schema_rejects_all_mutation_authority() -> None:
    _plan, _preflight, receipt = _objects()
    schema = _schema("role-identity-provisioning-confirm-receipt.v1.schema.json")

    for field in (
        "provider_execution_authorized",
        "credential_material_authorized",
        "emergency_admin_mutation_authorized",
        "arbitrary_privilege_grant_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        raw = receipt.to_dict()
        raw[field] = True
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(raw)
