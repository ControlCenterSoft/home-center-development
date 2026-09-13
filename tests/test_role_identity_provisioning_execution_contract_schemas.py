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
from home_center.role_identity_provisioning_execution import (
    RoleIdentityProviderCreateResult,
    build_identity_provider_create_request,
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
    confirmation = confirm_role_identity_provisioning(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        plan=plan,
        preflight=preflight,
        confirmed=True,
        now="2026-09-13T03:51:00Z",
    )
    request = build_identity_provider_create_request(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        plan=plan,
        confirmation=confirmation,
        job_id="identity-job-1",
        credential_references=[
            {"name": "provider-bind", "reference": "secret://providers/directory/bind"}
        ],
        deadline_at="2026-09-13T04:00:00Z",
    )
    result = RoleIdentityProviderCreateResult(provider_operation_id="operation-1")
    return request, result


def test_identity_execution_schemas_are_valid_and_closed() -> None:
    for name in (
        "role-identity-provider-create-request.v1.schema.json",
        "role-identity-provider-create-result.v1.schema.json",
    ):
        schema = _schema(name)
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False


def test_exact_provider_request_and_result_validate_against_contracts() -> None:
    request, result = _objects()
    jsonschema.Draft202012Validator(
        _schema("role-identity-provider-create-request.v1.schema.json")
    ).validate(request.to_dict())
    jsonschema.Draft202012Validator(
        _schema("role-identity-provider-create-result.v1.schema.json")
    ).validate(result.to_dict())


def test_provider_request_schema_rejects_credential_value_or_broad_authority() -> None:
    request, _result = _objects()
    schema = _schema("role-identity-provider-create-request.v1.schema.json")

    raw = request.to_dict()
    raw["credential_references"][0]["reference"] = "password-value"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(raw)

    raw = request.to_dict()
    raw["emergency_admin_mutation_authorized"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(raw)

    raw = request.to_dict()
    raw["infrastructure_mutation_authorized"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(raw)


def test_provider_result_schema_rejects_false_success() -> None:
    _request, result = _objects()
    schema = _schema("role-identity-provider-create-result.v1.schema.json")

    for field in (
        "account_creation_verified",
        "home_directory_verified",
        "profile_verified",
        "post_condition_verified",
        "credential_material_returned",
    ):
        raw = result.to_dict()
        raw[field] = True
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(raw)
