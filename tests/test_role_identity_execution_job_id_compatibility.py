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
    build_identity_execution_request,
    execution_request_from_dict,
)

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64


def _provider() -> IdentityProviderCapability:
    return IdentityProviderCapability(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        supported_roles=(HouseholdRole.CHILD,),
        account_create_supported=True,
        portable_home_supported=False,
        portable_profile_supported=False,
        secret_reference_supported=True,
        evidence_sha256=DIGEST,
    )


def _plan() -> RoleIdentityProvisioningPlan:
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
        provider_evidence_sha256=DIGEST,
        account_name="artemiy",
        home_directory_mode=StorageMode.LOCAL,
        profile_mode=StorageMode.LOCAL,
    )


def test_execution_request_accepts_durable_state_store_uuid_job_id() -> None:
    job_id = "7f0ac7e6-33b8-44af-8f36-a35fa3d54691"
    request = build_identity_execution_request(
        plan=_plan(),
        provider=_provider(),
        job_id=job_id,
        credential_references=[],
        confirmed=True,
    )
    assert request.job_id == job_id
    assert execution_request_from_dict(request.to_dict()) == request

    schema = json.loads(
        (ROOT / "contracts/household/role-identity-provisioning-execution-request.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(request.to_dict())


def test_execution_request_rejects_unbounded_or_delimiter_job_id() -> None:
    for value in ("", " bad", "job/with/slash", "x" * 129):
        with pytest.raises(
            IdentityProvisioningExecutionError,
            match="identity_execution_job_id_invalid",
        ):
            build_identity_execution_request(
                plan=_plan(),
                provider=_provider(),
                job_id=value,
                credential_references=[],
                confirmed=True,
            )
