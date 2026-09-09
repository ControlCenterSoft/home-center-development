from __future__ import annotations

from home_center.household import HouseholdRole, InternetPolicy
from home_center.household_policy import policy_bundle_for_role


def test_policy_bundle_is_deterministic_and_non_mutating() -> None:
    first = policy_bundle_for_role(HouseholdRole.CHILD)
    second = policy_bundle_for_role(HouseholdRole.CHILD)

    assert first.bundle_id == second.bundle_id
    assert first.role is HouseholdRole.CHILD
    assert first.internet_policy is InternetPolicy.FILTERED
    assert first.managed_device_required is True
    assert first.vpn_allowed is False
    assert first.administration_allowed is False
    assert first.external_publication_allowed is False
    assert first.production_mutation_enabled is False


def test_guest_bundle_never_grants_parent_capabilities() -> None:
    guest = policy_bundle_for_role(HouseholdRole.GUEST)
    parent = policy_bundle_for_role(HouseholdRole.PARENT)

    assert guest.internet_policy is InternetPolicy.GUEST
    assert guest.home_files_allowed is False
    assert guest.smart_home_control_allowed is False
    assert guest.administration_allowed is False
    assert parent.administration_allowed is True
    assert parent.external_publication_allowed is False
