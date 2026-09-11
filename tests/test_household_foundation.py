from __future__ import annotations

import pytest

from home_center.home_services import HomeServiceCatalogError
from home_center.household import (
    FamilyMember,
    Household,
    HouseholdRole,
    InternetPolicy,
    ManagedDevice,
    effective_policy,
)
from home_center.household_intent import (
    HouseholdIntent,
    HouseholdIntentKind,
    plan_household_intent,
)


def household() -> Household:
    return Household(
        household_id="home-01",
        members=(
            FamilyMember(member_id="parent-01", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="child-01", display_name="Child", role=HouseholdRole.CHILD),
            FamilyMember(member_id="guest-01", display_name="Guest", role=HouseholdRole.GUEST),
        ),
        devices=(
            ManagedDevice(
                device_id="phone-01",
                member_id="child-01",
                display_name="Child phone",
                managed=True,
            ),
        ),
    )


def test_household_is_canonical_and_requires_parent() -> None:
    value = household()
    assert [member.member_id for member in value.members] == ["child-01", "guest-01", "parent-01"]
    assert value.devices[0].member_id == "child-01"

    with pytest.raises(HomeServiceCatalogError, match="household_parent_required"):
        Household(
            household_id="home-02",
            members=(FamilyMember(member_id="child-02", display_name="Child", role=HouseholdRole.CHILD),),
            devices=(),
        )


def test_household_rejects_duplicate_and_orphan_device_bindings() -> None:
    parent = FamilyMember(member_id="parent-01", display_name="Parent", role=HouseholdRole.PARENT)
    with pytest.raises(HomeServiceCatalogError, match="duplicate_household_member"):
        Household(household_id="home-01", members=(parent, parent), devices=())

    with pytest.raises(HomeServiceCatalogError, match="household_device_member_not_found"):
        Household(
            household_id="home-01",
            members=(parent,),
            devices=(
                ManagedDevice(
                    device_id="phone-02",
                    member_id="missing-01",
                    display_name="Unknown phone",
                    managed=True,
                ),
            ),
        )


def test_effective_policy_is_deterministic_and_safe_by_role() -> None:
    value = household()
    child = effective_policy(value, "child-01")
    again = effective_policy(value, "child-01")
    guest = effective_policy(value, "guest-01")
    parent = effective_policy(value, "parent-01")

    assert child.policy_id == again.policy_id
    assert child.internet_policy is InternetPolicy.FILTERED
    assert child.managed_device_required is True
    assert child.vpn_allowed is False
    assert child.administration_allowed is False
    assert child.external_publication_allowed is False
    assert child.production_mutation_enabled is False

    assert guest.internet_policy is InternetPolicy.GUEST
    assert guest.home_files_allowed is False
    assert guest.administration_allowed is False
    assert guest.external_publication_allowed is False

    assert parent.internet_policy is InternetPolicy.FULL
    assert parent.administration_allowed is True
    assert parent.external_publication_allowed is False


def test_member_onboarding_intent_is_parent_only_and_non_mutating() -> None:
    value = household()
    intent = HouseholdIntent(
        intent_id="intent-01",
        actor_member_id="parent-01",
        kind=HouseholdIntentKind.ONBOARD_MEMBER,
        target_id="child-02",
        requested_role=HouseholdRole.CHILD,
    )
    first = plan_household_intent(value, intent)
    second = plan_household_intent(value, intent)

    assert first.plan_id == second.plan_id
    assert [action.action_type for action in first.actions] == [
        "household.member.create",
        "household.policy.compose",
    ]
    assert first.confirmation_required is True
    assert first.mutation_authorized is False
    assert first.production_mutation_enabled is False
    assert all(action.requires_confirmation for action in first.actions)

    denied = HouseholdIntent(
        intent_id="intent-02",
        actor_member_id="child-01",
        kind=HouseholdIntentKind.ONBOARD_MEMBER,
        target_id="guest-02",
        requested_role=HouseholdRole.GUEST,
    )
    with pytest.raises(HomeServiceCatalogError, match="household_intent_not_authorized"):
        plan_household_intent(value, denied)


def test_device_enrollment_binds_exact_member_and_rejects_unknown_subject() -> None:
    value = household()
    intent = HouseholdIntent(
        intent_id="intent-03",
        actor_member_id="parent-01",
        kind=HouseholdIntentKind.ENROLL_DEVICE,
        target_id="tablet-01",
        subject_member_id="child-01",
    )
    plan = plan_household_intent(value, intent)
    assert all(action.subject_member_id == "child-01" for action in plan.actions)
    assert [action.action_type for action in plan.actions] == [
        "household.device.enroll",
        "household.device.apply-effective-policy",
    ]

    unknown = HouseholdIntent(
        intent_id="intent-04",
        actor_member_id="parent-01",
        kind=HouseholdIntentKind.ENROLL_DEVICE,
        target_id="tablet-02",
        subject_member_id="missing-01",
    )
    with pytest.raises(HomeServiceCatalogError, match="household_member_not_found"):
        plan_household_intent(value, unknown)


def test_device_intent_rejects_role_and_member_intent_rejects_subject() -> None:
    with pytest.raises(HomeServiceCatalogError, match="household_intent_role_not_allowed"):
        HouseholdIntent(
            intent_id="intent-05",
            actor_member_id="parent-01",
            kind=HouseholdIntentKind.ENROLL_DEVICE,
            target_id="tablet-03",
            requested_role=HouseholdRole.GUEST,
            subject_member_id="guest-01",
        )

    with pytest.raises(HomeServiceCatalogError, match="household_intent_subject_not_allowed"):
        HouseholdIntent(
            intent_id="intent-06",
            actor_member_id="parent-01",
            kind=HouseholdIntentKind.ONBOARD_MEMBER,
            target_id="child-03",
            requested_role=HouseholdRole.CHILD,
            subject_member_id="child-01",
        )
