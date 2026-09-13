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
from home_center.role_identity_provisioning_execution import RoleIdentityProvisioningAdapterResult
from home_center.role_identity_provisioning_verification import (
    AccountReadbackState,
    IdentityProvisioningReadbackObservation,
    IdentityProvisioningVerificationError,
    ResourceReadbackState,
    observation_from_dict,
    verify_identity_provisioning,
)

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_DIGEST = "a" * 64
ACCOUNT_DIGEST = "b" * 64
OBSERVATION_DIGEST = "c" * 64


def _provider(*, digest: str = PROVIDER_DIGEST) -> IdentityProviderCapability:
    return IdentityProviderCapability(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        supported_roles=(HouseholdRole.PARENT, HouseholdRole.CHILD),
        account_create_supported=True,
        portable_home_supported=False,
        portable_profile_supported=False,
        secret_reference_supported=True,
        evidence_sha256=digest,
    )


def _plan(*, digest: str = PROVIDER_DIGEST) -> RoleIdentityProvisioningPlan:
    return RoleIdentityProvisioningPlan(
        plan_id="hcidp-" + "d" * 24,
        household_id="household-1",
        member_id="member-1",
        role=HouseholdRole.CHILD,
        household_snapshot_id="snapshot-1",
        household_resource_version="rv-1",
        household_generation=6,
        policy_id="policy-1",
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=digest,
        account_name="artemiy",
        home_directory_mode=StorageMode.LOCAL,
        profile_mode=StorageMode.LOCAL,
    )


def _accepted(*, operation: str = "provider-op-1", account: str = "artemiy") -> RoleIdentityProvisioningAdapterResult:
    return RoleIdentityProvisioningAdapterResult(provider_operation_id=operation, account_name=account)


def _observation(
    *,
    account_state: AccountReadbackState = AccountReadbackState.PRESENT,
    home_state: ResourceReadbackState = ResourceReadbackState.READY,
    profile_state: ResourceReadbackState = ResourceReadbackState.READY,
    operation: str = "provider-op-1",
    account: str = "artemiy",
    provider_digest: str = PROVIDER_DIGEST,
    observed_at: str = "2026-09-13T03:55:00Z",
    valid_until: str = "2026-09-13T04:25:00Z",
) -> IdentityProvisioningReadbackObservation:
    return IdentityProvisioningReadbackObservation(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=provider_digest,
        provider_operation_id=operation,
        account_name=account,
        account_state=account_state,
        account_identity_sha256=ACCOUNT_DIGEST if account_state is AccountReadbackState.PRESENT else None,
        home_directory_state=home_state,
        profile_state=profile_state,
        observed_at=observed_at,
        valid_until=valid_until,
        evidence_sha256=OBSERVATION_DIGEST,
    )


def test_exact_fresh_readback_is_verified_without_granting_mutation_authority() -> None:
    result = verify_identity_provisioning(
        plan=_plan(),
        provider=_provider(),
        accepted=_accepted(),
        observation=_observation(),
        now="2026-09-13T04:00:00Z",
    )
    assert result.verified is True
    assert result.account_created_verified is True
    assert result.home_directory_verified is True
    assert result.profile_verified is True
    assert result.blockers == ()
    payload = result.to_dict()
    assert payload["durable_state_change_authorized"] is False
    assert payload["privilege_grant_authorized"] is False
    assert payload["external_publication_authorized"] is False


@pytest.mark.parametrize(
    ("account_state", "home_state", "profile_state", "expected"),
    [
        (AccountReadbackState.ABSENT, ResourceReadbackState.READY, ResourceReadbackState.READY, "account_absent_after_provider_acceptance"),
        (AccountReadbackState.CONFLICT, ResourceReadbackState.READY, ResourceReadbackState.READY, "account_identity_conflict"),
        (AccountReadbackState.UNKNOWN, ResourceReadbackState.READY, ResourceReadbackState.READY, "account_state_unknown"),
        (AccountReadbackState.PRESENT, ResourceReadbackState.MISSING, ResourceReadbackState.READY, "home_directory_missing"),
        (AccountReadbackState.PRESENT, ResourceReadbackState.UNKNOWN, ResourceReadbackState.READY, "home_directory_unknown"),
        (AccountReadbackState.PRESENT, ResourceReadbackState.READY, ResourceReadbackState.MISSING, "profile_missing"),
        (AccountReadbackState.PRESENT, ResourceReadbackState.READY, ResourceReadbackState.UNKNOWN, "profile_unknown"),
    ],
)
def test_incomplete_or_ambiguous_readback_never_becomes_false_success(
    account_state: AccountReadbackState,
    home_state: ResourceReadbackState,
    profile_state: ResourceReadbackState,
    expected: str,
) -> None:
    result = verify_identity_provisioning(
        plan=_plan(),
        provider=_provider(),
        accepted=_accepted(),
        observation=_observation(
            account_state=account_state,
            home_state=home_state,
            profile_state=profile_state,
        ),
        now="2026-09-13T04:00:00Z",
    )
    assert result.verified is False
    assert result.account_created_verified is False
    assert result.home_directory_verified is False
    assert result.profile_verified is False
    assert expected in result.blockers


def test_stale_or_future_observation_fails_closed() -> None:
    expired = verify_identity_provisioning(
        plan=_plan(),
        provider=_provider(),
        accepted=_accepted(),
        observation=_observation(valid_until="2026-09-13T03:59:59Z"),
        now="2026-09-13T04:00:00Z",
    )
    assert expired.verified is False
    assert expired.blockers == ("observation_expired",)

    future = verify_identity_provisioning(
        plan=_plan(),
        provider=_provider(),
        accepted=_accepted(),
        observation=_observation(observed_at="2026-09-13T04:01:00Z", valid_until="2026-09-13T04:25:00Z"),
        now="2026-09-13T04:00:00Z",
    )
    assert future.verified is False
    assert future.blockers == ("observation_from_future",)


def test_provider_acceptance_and_observation_must_bind_exact_plan_and_operation() -> None:
    with pytest.raises(IdentityProvisioningVerificationError, match="identity_verification_provider_binding_mismatch"):
        verify_identity_provisioning(
            plan=_plan(), provider=_provider(digest="e" * 64), accepted=_accepted(), observation=_observation(), now="2026-09-13T04:00:00Z"
        )

    with pytest.raises(IdentityProvisioningVerificationError, match="identity_verification_acceptance_binding_mismatch"):
        verify_identity_provisioning(
            plan=_plan(), provider=_provider(), accepted=_accepted(account="kirill"), observation=_observation(), now="2026-09-13T04:00:00Z"
        )

    with pytest.raises(IdentityProvisioningVerificationError, match="identity_verification_observation_binding_mismatch"):
        verify_identity_provisioning(
            plan=_plan(), provider=_provider(), accepted=_accepted(), observation=_observation(operation="another-op"), now="2026-09-13T04:00:00Z"
        )


def test_readback_transport_is_closed_read_only_and_secret_free() -> None:
    payload = _observation().to_dict()
    assert observation_from_dict(payload).to_dict() == payload

    escalated = dict(payload)
    escalated["privilege_grant_authorized"] = True
    with pytest.raises(IdentityProvisioningVerificationError, match="identity_verification_observation_rejected"):
        observation_from_dict(escalated)

    unknown = dict(payload)
    unknown["provider_payload"] = {"password": "never accepted"}
    with pytest.raises(IdentityProvisioningVerificationError, match="identity_verification_observation_rejected"):
        observation_from_dict(unknown)


def test_readback_and_verification_match_closed_public_schemas() -> None:
    observation_schema = json.loads(
        (ROOT / "contracts/household/role-identity-provisioning-readback-observation.v1.schema.json").read_text(encoding="utf-8")
    )
    verification_schema = json.loads(
        (ROOT / "contracts/household/role-identity-provisioning-verification.v1.schema.json").read_text(encoding="utf-8")
    )
    observation = _observation().to_dict()
    result = verify_identity_provisioning(
        plan=_plan(), provider=_provider(), accepted=_accepted(), observation=_observation(), now="2026-09-13T04:00:00Z"
    ).to_dict()
    jsonschema.Draft202012Validator(observation_schema).validate(observation)
    jsonschema.Draft202012Validator(verification_schema).validate(result)
