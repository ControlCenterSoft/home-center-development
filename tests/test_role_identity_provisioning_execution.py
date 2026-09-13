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
    IdentityProvisioningExecutionError,
    RoleIdentityProviderCreateResult,
    build_identity_provider_create_request,
    normalize_identity_credential_references,
    provider_create_result_from_dict,
)

DIGEST = "a" * 64


def _objects(*, secret_refs: bool = True):
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
        secret_reference_supported=secret_refs,
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
    return snapshot, policy, provider, plan, confirmation


def test_provider_request_is_exact_bound_and_secret_reference_only() -> None:
    snapshot, policy, provider, plan, confirmation = _objects()
    request = build_identity_provider_create_request(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        plan=plan,
        confirmation=confirmation,
        job_id="identity-job-1",
        credential_references=[
            {"name": "bootstrap-password", "reference": "secret://household/member-child/bootstrap"},
            {"name": "provider-bind", "reference": "secret://providers/directory/bind"},
        ],
        deadline_at="2026-09-13T04:00:00Z",
    )

    assert request.plan_id == plan.plan_id
    assert request.confirmation_receipt_id == confirmation.receipt_id
    assert request.provider_id == provider.provider_id
    assert request.identity_account_creation_authorized is True
    assert request.provider_execution_authorized is True
    assert request.credential_value_access_authorized is False
    assert request.emergency_admin_mutation_authorized is False
    assert request.arbitrary_privilege_grant_authorized is False
    assert request.infrastructure_mutation_authorized is False
    assert request.external_publication_authorized is False
    assert request.post_condition_verification_required is True
    assert [item.name for item in request.credential_references] == [
        "bootstrap-password",
        "provider-bind",
    ]
    assert all(item.reference.startswith("secret://") for item in request.credential_references)


def test_raw_secret_material_and_path_traversal_are_rejected() -> None:
    for value in (
        [{"name": "password", "reference": "plain-text-secret"}],
        [{"name": "password", "reference": "secret://household/../root"}],
    ):
        with pytest.raises(IdentityProvisioningExecutionError):
            normalize_identity_credential_references(value)


def test_duplicate_credential_names_are_rejected() -> None:
    with pytest.raises(
        IdentityProvisioningExecutionError,
        match="identity_credential_reference_invalid",
    ):
        normalize_identity_credential_references(
            [
                {"name": "provider-bind", "reference": "secret://a/bind"},
                {"name": "provider-bind", "reference": "secret://b/bind"},
            ]
        )


def test_provider_without_secret_reference_support_fails_closed() -> None:
    snapshot, policy, provider, plan, confirmation = _objects(secret_refs=False)
    with pytest.raises(
        IdentityProvisioningExecutionError,
        match="identity_provider_secret_reference_unsupported",
    ):
        build_identity_provider_create_request(
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


def test_confirmation_binding_mismatch_is_rejected() -> None:
    snapshot, policy, provider, plan, confirmation = _objects()
    other_snapshot, other_policy, other_provider, other_plan, other_confirmation = _objects()
    assert other_plan.plan_id == plan.plan_id

    tampered = other_confirmation.to_dict()
    tampered["provider_evidence_sha256"] = "b" * 64
    with pytest.raises(
        IdentityProvisioningExecutionError,
        match="identity_confirmation_receipt_rejected",
    ):
        build_identity_provider_create_request(
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            plan=plan,
            confirmation=tampered,
            job_id="identity-job-1",
            credential_references=[],
            deadline_at="2026-09-13T04:00:00Z",
        )


def test_provider_drift_invalidates_execution_plan() -> None:
    snapshot, policy, _provider, plan, confirmation = _objects()
    changed_provider = IdentityProviderCapability(
        provider_id="directory-provider",
        provider_version="1.0.1",
        provider_kind=IdentityProviderKind.DIRECTORY,
        supported_roles=(HouseholdRole.CHILD,),
        account_create_supported=True,
        portable_home_supported=True,
        portable_profile_supported=True,
        secret_reference_supported=True,
        evidence_sha256="b" * 64,
    )
    with pytest.raises(
        IdentityProvisioningExecutionError,
        match="identity_execution_plan_stale",
    ):
        build_identity_provider_create_request(
            snapshot=snapshot,
            policy=policy,
            provider=changed_provider,
            plan=plan,
            confirmation=confirmation,
            job_id="identity-job-1",
            credential_references=[],
            deadline_at="2026-09-13T04:00:00Z",
        )


def test_provider_acceptance_never_claims_account_creation_success() -> None:
    result = RoleIdentityProviderCreateResult(provider_operation_id="operation-1")
    parsed = provider_create_result_from_dict(result.to_dict())
    assert parsed == result
    assert parsed.account_creation_verified is False
    assert parsed.home_directory_verified is False
    assert parsed.profile_verified is False
    assert parsed.post_condition_verified is False
    assert parsed.credential_material_returned is False

    raw = result.to_dict()
    raw["account_creation_verified"] = True
    with pytest.raises(
        IdentityProvisioningExecutionError,
        match="identity_provider_create_result_rejected",
    ):
        provider_create_result_from_dict(raw)
