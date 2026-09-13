from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import HouseholdRole
from home_center.role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
    RoleIdentityProvisioningPlan,
    StorageMode,
)
from home_center.role_identity_provisioning_execution import (
    IdentityProvisioningExecutionError,
    RoleIdentityProvisioningAdapterResult,
    adapter_result_from_dict,
    build_identity_execution_request,
    execution_request_from_dict,
)

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64


def _provider(*, evidence: str = DIGEST, secret_refs: bool = True) -> IdentityProviderCapability:
    return IdentityProviderCapability(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        supported_roles=(HouseholdRole.PARENT, HouseholdRole.CHILD),
        account_create_supported=True,
        portable_home_supported=False,
        portable_profile_supported=False,
        secret_reference_supported=secret_refs,
        evidence_sha256=evidence,
    )


def _plan(*, evidence: str = DIGEST) -> RoleIdentityProvisioningPlan:
    return RoleIdentityProvisioningPlan(
        plan_id="hcidp-" + "b" * 24,
        household_id="household-1",
        member_id="member-1",
        role=HouseholdRole.CHILD,
        household_snapshot_id="snapshot-1",
        household_resource_version="rv-1",
        household_generation=4,
        policy_id="policy-1",
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=evidence,
        account_name="artemiy",
        home_directory_mode=StorageMode.LOCAL,
        profile_mode=StorageMode.LOCAL,
    )


def _request_dict() -> dict[str, object]:
    request = build_identity_execution_request(
        plan=_plan(),
        provider=_provider(),
        job_id="job-identity-1",
        credential_references=[
            {"name": "initial-password", "reference": "secret://identity/artemiy/initial"}
        ],
        confirmed=True,
    )
    return request.to_dict()


def test_execution_requires_explicit_confirmation_and_exact_provider_binding() -> None:
    with pytest.raises(IdentityProvisioningExecutionError, match="identity_execution_confirmation_required"):
        build_identity_execution_request(
            plan=_plan(),
            provider=_provider(),
            job_id="job-identity-1",
            credential_references=[],
            confirmed=False,
        )

    with pytest.raises(IdentityProvisioningExecutionError, match="identity_execution_provider_binding_mismatch"):
        build_identity_execution_request(
            plan=_plan(),
            provider=_provider(evidence="c" * 64),
            job_id="job-identity-1",
            credential_references=[],
            confirmed=True,
        )


def test_execution_accepts_only_secret_references_and_never_authorizes_secret_values() -> None:
    request = _request_dict()
    assert request["provider_execution_authorized"] is True
    assert request["credential_value_access_authorized"] is False
    assert request["emergency_admin_mutation_authorized"] is False
    assert request["arbitrary_privilege_grant_authorized"] is False
    assert request["unrelated_account_mutation_authorized"] is False
    assert request["post_condition_verification_required"] is True
    assert request["external_publication_authorized"] is False
    assert request["credential_references"] == [
        {"name": "initial-password", "reference": "secret://identity/artemiy/initial"}
    ]

    with pytest.raises(IdentityProvisioningExecutionError, match="identity_secret_reference_invalid"):
        build_identity_execution_request(
            plan=_plan(),
            provider=_provider(),
            job_id="job-identity-1",
            credential_references=[{"name": "initial-password", "reference": "PlaintextPassword"}],
            confirmed=True,
        )

    with pytest.raises(IdentityProvisioningExecutionError, match="identity_provider_secret_reference_unsupported"):
        build_identity_execution_request(
            plan=_plan(),
            provider=_provider(secret_refs=False),
            job_id="job-identity-1",
            credential_references=[
                {"name": "initial-password", "reference": "secret://identity/artemiy/initial"}
            ],
            confirmed=True,
        )


def test_transport_request_is_closed_and_rejects_authority_escalation() -> None:
    payload = _request_dict()
    assert execution_request_from_dict(payload).to_dict() == payload

    escalated = dict(payload)
    escalated["emergency_admin_mutation_authorized"] = True
    with pytest.raises(IdentityProvisioningExecutionError, match="identity_execution_request_rejected"):
        execution_request_from_dict(escalated)

    unknown = dict(payload)
    unknown["password"] = "do-not-accept"
    with pytest.raises(IdentityProvisioningExecutionError, match="identity_execution_request_rejected"):
        execution_request_from_dict(unknown)


def test_provider_acceptance_is_never_account_creation_success() -> None:
    result = RoleIdentityProvisioningAdapterResult(
        provider_operation_id="provider-op-1",
        account_name="artemiy",
    ).to_dict()
    parsed = adapter_result_from_dict(result)
    assert parsed.to_dict() == result
    assert result["state"] == "accepted"
    assert result["account_created_verified"] is False
    assert result["home_directory_verified"] is False
    assert result["profile_verified"] is False
    assert result["post_condition_verified"] is False

    false_success = dict(result)
    false_success["account_created_verified"] = True
    with pytest.raises(IdentityProvisioningExecutionError, match="identity_adapter_result_rejected"):
        adapter_result_from_dict(false_success)


def test_execution_request_and_result_validate_against_closed_public_contracts() -> None:
    request_schema = json.loads(
        (ROOT / "contracts/household/role-identity-provisioning-execution-request.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    result_schema = json.loads(
        (ROOT / "contracts/household/role-identity-provisioning-adapter-result.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(request_schema).validate(_request_dict())
    jsonschema.Draft202012Validator(result_schema).validate(
        RoleIdentityProvisioningAdapterResult(
            provider_operation_id="provider-op-1",
            account_name="artemiy",
        ).to_dict()
    )
