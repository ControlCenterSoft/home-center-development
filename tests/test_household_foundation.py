from __future__ import annotations

import unittest

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


class HouseholdFoundationTests(unittest.TestCase):
    def test_household_is_canonical_and_requires_parent(self) -> None:
        value = household()
        self.assertEqual(
            ["child-01", "guest-01", "parent-01"],
            [member.member_id for member in value.members],
        )
        self.assertEqual("child-01", value.devices[0].member_id)

        with self.assertRaisesRegex(HomeServiceCatalogError, "household_parent_required"):
            Household(
                household_id="home-02",
                members=(
                    FamilyMember(
                        member_id="child-02",
                        display_name="Child",
                        role=HouseholdRole.CHILD,
                    ),
                ),
                devices=(),
            )

    def test_household_rejects_duplicate_and_orphan_device_bindings(self) -> None:
        parent = FamilyMember(
            member_id="parent-01",
            display_name="Parent",
            role=HouseholdRole.PARENT,
        )
        with self.assertRaisesRegex(HomeServiceCatalogError, "duplicate_household_member"):
            Household(household_id="home-01", members=(parent, parent), devices=())

        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "household_device_member_not_found",
        ):
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

    def test_effective_policy_is_deterministic_and_safe_by_role(self) -> None:
        value = household()
        child = effective_policy(value, "child-01")
        again = effective_policy(value, "child-01")
        guest = effective_policy(value, "guest-01")
        parent = effective_policy(value, "parent-01")

        self.assertEqual(child.policy_id, again.policy_id)
        self.assertIs(child.internet_policy, InternetPolicy.FILTERED)
        self.assertIs(child.managed_device_required, True)
        self.assertIs(child.vpn_allowed, False)
        self.assertIs(child.administration_allowed, False)
        self.assertIs(child.external_publication_allowed, False)
        self.assertIs(child.production_mutation_enabled, False)

        self.assertIs(guest.internet_policy, InternetPolicy.GUEST)
        self.assertIs(guest.home_files_allowed, False)
        self.assertIs(guest.administration_allowed, False)
        self.assertIs(guest.external_publication_allowed, False)

        self.assertIs(parent.internet_policy, InternetPolicy.FULL)
        self.assertIs(parent.administration_allowed, True)
        self.assertIs(parent.external_publication_allowed, False)

    def test_member_onboarding_intent_is_parent_only_and_non_mutating(self) -> None:
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

        self.assertEqual(first.plan_id, second.plan_id)
        self.assertEqual(
            ["household.member.create", "household.policy.compose"],
            [action.action_type for action in first.actions],
        )
        self.assertIs(first.confirmation_required, True)
        self.assertIs(first.mutation_authorized, False)
        self.assertIs(first.production_mutation_enabled, False)
        self.assertTrue(all(action.requires_confirmation for action in first.actions))

        denied = HouseholdIntent(
            intent_id="intent-02",
            actor_member_id="child-01",
            kind=HouseholdIntentKind.ONBOARD_MEMBER,
            target_id="guest-02",
            requested_role=HouseholdRole.GUEST,
        )
        with self.assertRaisesRegex(HomeServiceCatalogError, "household_intent_not_authorized"):
            plan_household_intent(value, denied)

    def test_device_enrollment_binds_exact_member_and_rejects_unknown_subject(self) -> None:
        value = household()
        intent = HouseholdIntent(
            intent_id="intent-03",
            actor_member_id="parent-01",
            kind=HouseholdIntentKind.ENROLL_DEVICE,
            target_id="tablet-01",
            subject_member_id="child-01",
        )
        plan = plan_household_intent(value, intent)
        self.assertTrue(all(action.subject_member_id == "child-01" for action in plan.actions))
        self.assertEqual(
            ["household.device.enroll", "household.device.apply-effective-policy"],
            [action.action_type for action in plan.actions],
        )

        unknown = HouseholdIntent(
            intent_id="intent-04",
            actor_member_id="parent-01",
            kind=HouseholdIntentKind.ENROLL_DEVICE,
            target_id="tablet-02",
            subject_member_id="missing-01",
        )
        with self.assertRaisesRegex(HomeServiceCatalogError, "household_member_not_found"):
            plan_household_intent(value, unknown)

    def test_device_intent_rejects_role_and_member_intent_rejects_subject(self) -> None:
        with self.assertRaisesRegex(HomeServiceCatalogError, "household_intent_role_not_allowed"):
            HouseholdIntent(
                intent_id="intent-05",
                actor_member_id="parent-01",
                kind=HouseholdIntentKind.ENROLL_DEVICE,
                target_id="tablet-03",
                requested_role=HouseholdRole.GUEST,
                subject_member_id="guest-01",
            )

        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "household_intent_subject_not_allowed",
        ):
            HouseholdIntent(
                intent_id="intent-06",
                actor_member_id="parent-01",
                kind=HouseholdIntentKind.ONBOARD_MEMBER,
                target_id="child-03",
                requested_role=HouseholdRole.CHILD,
                subject_member_id="child-01",
            )


if __name__ == "__main__":
    unittest.main()
