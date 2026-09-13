from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, effective_policy
from home_center.household_store import HouseholdStore
from home_center.role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
    IdentityProvisioningError,
    StorageMode,
    build_role_identity_provisioning_plan,
    cozy_identity_plan_projection,
    full_identity_plan_projection,
    plan_from_dict,
    provider_capability_from_dict,
)

DIGEST = "a" * 64


def _snapshot(*, enabled: bool = True):
    household = Household(
        household_id="home",
        members=(
            FamilyMember(
                member_id="member-child",
                display_name="Child",
                role=HouseholdRole.CHILD,
                enabled=enabled,
            ),
            FamilyMember(
                member_id="member-parent",
                display_name="Parent",
                role=HouseholdRole.PARENT,
            ),
        ),
        devices=(),
    )
    store = HouseholdStore()
    store.create(household)
    return store.read("home")


def _provider(*, portable_home: bool = True, portable_profile: bool = True):
    return IdentityProviderCapability(
        provider_id="directory-provider",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.DIRECTORY,
        supported_roles=(HouseholdRole.PARENT, HouseholdRole.CHILD),
        account_create_supported=True,
        portable_home_supported=portable_home,
        portable_profile_supported=portable_profile,
        secret_reference_supported=True,
        evidence_sha256=DIGEST,
    )


def _plan(*, enabled: bool = True, account_name: str = "child.user"):
    snapshot = _snapshot(enabled=enabled)
    policy = effective_policy(snapshot.household, "member-child")
    return build_role_identity_provisioning_plan(
        snapshot=snapshot,
        policy=policy,
        provider=_provider(),
        member_id="member-child",
        account_name=account_name,
        home_directory_mode=StorageMode.PORTABLE,
        profile_mode=StorageMode.PORTABLE,
    )


def test_plan_is_exact_bound_and_does_not_grant_execution_authority() -> None:
    plan = _plan()
    snapshot = _snapshot()

    assert plan.household_id == "home"
    assert plan.member_id == "member-child"
    assert plan.role is HouseholdRole.CHILD
    assert plan.household_snapshot_id == snapshot.snapshot_id
    assert plan.household_resource_version == snapshot.resource_version
    assert plan.household_generation == snapshot.generation
    assert plan.provider_id == "directory-provider"
    assert plan.provider_evidence_sha256 == DIGEST
    assert plan.account_name == "child.user"
    assert plan.confirmation_required is True
    assert plan.account_absence_preflight_required is True
    assert plan.post_condition_verification_required is True
    assert plan.credential_material_authorized is False
    assert plan.emergency_admin_mutation_authorized is False
    assert plan.arbitrary_privilege_grant_authorized is False
    assert plan.execution_authorized is False
    assert plan.infrastructure_mutation_authorized is False
    assert plan.external_publication_authorized is False
    assert plan_from_dict(plan.to_dict()) == plan


def test_reserved_emergency_admin_names_are_rejected() -> None:
    for name in ("admin", "administrator", "root", "ADMIN"):
        with pytest.raises(IdentityProvisioningError, match="identity_account_name_invalid"):
            _plan(account_name=name)


def test_provider_evidence_cannot_claim_execution_or_emergency_admin_access() -> None:
    raw = _provider().to_dict()
    raw["execution_authorized"] = True
    with pytest.raises(IdentityProvisioningError, match="identity_provider_evidence_rejected"):
        provider_capability_from_dict(raw)

    raw = _provider().to_dict()
    raw["emergency_admin_isolated"] = False
    with pytest.raises(IdentityProvisioningError, match="identity_provider_evidence_rejected"):
        provider_capability_from_dict(raw)


def test_portable_modes_require_explicit_provider_capability() -> None:
    snapshot = _snapshot()
    policy = effective_policy(snapshot.household, "member-child")

    with pytest.raises(IdentityProvisioningError, match="identity_portable_home_unsupported"):
        build_role_identity_provisioning_plan(
            snapshot=snapshot,
            policy=policy,
            provider=_provider(portable_home=False),
            member_id="member-child",
            account_name="child.user",
            home_directory_mode=StorageMode.PORTABLE,
            profile_mode=StorageMode.LOCAL,
        )

    with pytest.raises(IdentityProvisioningError, match="identity_portable_profile_unsupported"):
        build_role_identity_provisioning_plan(
            snapshot=snapshot,
            policy=policy,
            provider=_provider(portable_profile=False),
            member_id="member-child",
            account_name="child.user",
            home_directory_mode=StorageMode.LOCAL,
            profile_mode=StorageMode.PORTABLE,
        )


def test_policy_must_bind_the_exact_household_member_and_role() -> None:
    snapshot = _snapshot()
    parent_policy = effective_policy(snapshot.household, "member-parent")
    with pytest.raises(IdentityProvisioningError, match="identity_policy_binding_mismatch"):
        build_role_identity_provisioning_plan(
            snapshot=snapshot,
            policy=parent_policy,
            provider=_provider(),
            member_id="member-child",
            account_name="child.user",
            home_directory_mode=StorageMode.LOCAL,
            profile_mode=StorageMode.LOCAL,
        )


def test_disabled_member_fails_closed() -> None:
    snapshot = _snapshot(enabled=False)
    policy = effective_policy(_snapshot().household, "member-child")
    with pytest.raises(IdentityProvisioningError, match="identity_member_disabled"):
        build_role_identity_provisioning_plan(
            snapshot=snapshot,
            policy=policy,
            provider=_provider(),
            member_id="member-child",
            account_name="child.user",
            home_directory_mode=StorageMode.LOCAL,
            profile_mode=StorageMode.LOCAL,
        )


def test_plan_identity_tampering_is_rejected() -> None:
    raw = _plan().to_dict()
    raw["account_name"] = "other.user"
    with pytest.raises(IdentityProvisioningError, match="identity_plan_rejected"):
        plan_from_dict(raw)

    raw = _plan().to_dict()
    raw["execution_authorized"] = True
    with pytest.raises(IdentityProvisioningError, match="identity_plan_rejected"):
        plan_from_dict(raw)


def test_ui_projections_do_not_claim_account_creation() -> None:
    plan = _plan()
    cozy = cozy_identity_plan_projection(plan)
    full = full_identity_plan_projection(plan)

    assert cozy["will_create_now"] is False
    assert cozy["confirmation_required"] is True
    assert cozy["emergency_admin_unchanged"] is True
    assert full["provider_execution_state"] == "not-authorized"
    assert full["credential_material_state"] == "not-authorized"
    assert full["emergency_admin_state"] == "independent-unchanged"
    assert full["post_condition_verification_required"] is True
