from __future__ import annotations

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
from home_center.role_identity_provisioning_post_condition import (
    IdentityProvisioningPostConditionError,
    build_identity_readback_observation,
    readback_observation_from_dict,
    verify_identity_provisioning_post_condition,
)

DIGEST = "a" * 64


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


def test_provider_acceptance_requires_separate_readback_before_verified_success() -> None:
    request, result = _objects()
    assert result.post_condition_verified is False
    assert result.account_creation_verified is False

    observation = build_identity_readback_observation(
        request=request,
        result=result,
        account_state="present",
        home_directory_state="ready",
        profile_state="ready",
        observed_at="2026-09-13T03:52:00Z",
    )
    verification = verify_identity_provisioning_post_condition(
        request=request,
        result=result,
        observation=observation,
        now="2026-09-13T03:53:00Z",
    )

    assert verification.account_creation_verified is True
    assert verification.home_directory_verified is True
    assert verification.profile_verified is True
    assert verification.post_condition_verified is True
    assert verification.credential_material_returned is False
    assert verification.emergency_admin_mutation_authorized is False
    assert verification.arbitrary_privilege_grant_authorized is False
    assert verification.infrastructure_mutation_authorized is False
    assert verification.external_publication_authorized is False


def test_missing_or_unknown_postconditions_fail_closed() -> None:
    request, result = _objects()
    cases = (
        ("absent", "ready", "ready", "identity_account_creation_not_verified"),
        ("unknown", "ready", "ready", "identity_account_creation_not_verified"),
        ("present", "missing", "ready", "identity_home_directory_not_verified"),
        ("present", "unknown", "ready", "identity_home_directory_not_verified"),
        ("present", "ready", "missing", "identity_profile_not_verified"),
        ("present", "ready", "unknown", "identity_profile_not_verified"),
    )
    for account_state, home_state, profile_state, code in cases:
        observation = build_identity_readback_observation(
            request=request,
            result=result,
            account_state=account_state,
            home_directory_state=home_state,
            profile_state=profile_state,
            observed_at="2026-09-13T03:52:00Z",
        )
        with pytest.raises(IdentityProvisioningPostConditionError, match=code):
            verify_identity_provisioning_post_condition(
                request=request,
                result=result,
                observation=observation,
                now="2026-09-13T03:53:00Z",
            )


def test_readback_is_content_addressed_and_strictly_reconstructed() -> None:
    request, result = _objects()
    observation = build_identity_readback_observation(
        request=request,
        result=result,
        account_state="present",
        home_directory_state="ready",
        profile_state="ready",
        observed_at="2026-09-13T03:52:00Z",
    )
    assert readback_observation_from_dict(observation.to_dict()) == observation

    raw = observation.to_dict()
    raw["execution_authorized"] = True
    with pytest.raises(
        IdentityProvisioningPostConditionError,
        match="identity_readback_observation_rejected",
    ):
        readback_observation_from_dict(raw)

    raw = observation.to_dict()
    raw["observed_at"] = "2026-09-13T03:52:01Z"
    with pytest.raises(
        IdentityProvisioningPostConditionError,
        match="identity_readback_observation_rejected",
    ):
        readback_observation_from_dict(raw)


def test_stale_future_or_cross_operation_readback_is_rejected() -> None:
    request, result = _objects()
    observation = build_identity_readback_observation(
        request=request,
        result=result,
        account_state="present",
        home_directory_state="ready",
        profile_state="ready",
        observed_at="2026-09-13T03:52:00Z",
    )

    with pytest.raises(IdentityProvisioningPostConditionError, match="identity_readback_stale"):
        verify_identity_provisioning_post_condition(
            request=request,
            result=result,
            observation=observation,
            now="2026-09-13T03:58:00Z",
        )

    with pytest.raises(IdentityProvisioningPostConditionError, match="identity_readback_stale"):
        verify_identity_provisioning_post_condition(
            request=request,
            result=result,
            observation=observation,
            now="2026-09-13T03:51:59Z",
        )

    raw = observation.to_dict()
    raw["provider_operation_id"] = "other-operation"
    raw["observation_id"] = "hcidobs-" + "0" * 24
    with pytest.raises(IdentityProvisioningPostConditionError):
        verify_identity_provisioning_post_condition(
            request=request,
            result=result,
            observation=raw,
            now="2026-09-13T03:53:00Z",
        )
