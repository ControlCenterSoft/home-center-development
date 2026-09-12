from __future__ import annotations

import pytest

from home_center.home_services import HomeServiceCatalogError
from home_center.household import (
    FamilyMember,
    Household,
    HouseholdRole,
    InternetPolicy,
    effective_policy,
)
from home_center.policy_composer import (
    PolicyBundle,
    compose_policy_bundle,
    compose_policy_bundles,
)


def household() -> Household:
    return Household(
        household_id="home-01",
        members=(
            FamilyMember(member_id="parent-01", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="child-01", display_name="Child", role=HouseholdRole.CHILD),
            FamilyMember(member_id="guest-01", display_name="Guest", role=HouseholdRole.GUEST),
        ),
        devices=(),
    )


def test_policy_bundle_composition_is_deterministic_and_restrictive() -> None:
    base = effective_policy(household(), "parent-01")
    internet = PolicyBundle(
        bundle_id="bundle-filtered",
        display_name="Filtered internet",
        internet_policy=InternetPolicy.FILTERED,
    )
    no_admin = PolicyBundle(
        bundle_id="bundle-no-admin",
        display_name="No administration",
        administration_allowed=False,
        vpn_allowed=False,
    )

    first = compose_policy_bundles(base, (internet, no_admin))
    second = compose_policy_bundles(base, (no_admin, internet))

    assert first.preview_id == second.preview_id
    assert first.effective_policy.policy_id == second.effective_policy.policy_id
    assert first.bundle_ids == ("bundle-filtered", "bundle-no-admin")
    assert first.effective_policy.internet_policy is InternetPolicy.FILTERED
    assert first.effective_policy.vpn_allowed is False
    assert first.effective_policy.administration_allowed is False
    assert first.effective_policy.external_publication_allowed is False
    assert first.effective_policy.production_mutation_enabled is False
    assert first.confirmation_required is True
    assert first.mutation_authorized is False
    assert {change.field for change in first.changes} == {
        "internet_policy",
        "vpn_allowed",
        "administration_allowed",
    }


def test_policy_bundle_can_require_management_but_not_weaken_it() -> None:
    parent = effective_policy(household(), "parent-01")
    require_managed = PolicyBundle(
        bundle_id="bundle-managed",
        display_name="Managed devices only",
        managed_device_required=True,
    )
    preview = compose_policy_bundle(parent, require_managed)
    assert preview.effective_policy.managed_device_required is True

    child = effective_policy(household(), "child-01")
    weaken = PolicyBundle(
        bundle_id="bundle-unmanaged",
        display_name="Allow unmanaged",
        managed_device_required=False,
    )
    with pytest.raises(HomeServiceCatalogError, match="policy_bundle_privilege_escalation"):
        compose_policy_bundle(child, weaken)


def test_policy_bundle_rejects_capability_and_internet_escalation() -> None:
    child = effective_policy(household(), "child-01")

    vpn = PolicyBundle(
        bundle_id="bundle-vpn",
        display_name="Enable VPN",
        vpn_allowed=True,
    )
    with pytest.raises(HomeServiceCatalogError, match="policy_bundle_privilege_escalation"):
        compose_policy_bundle(child, vpn)

    internet = PolicyBundle(
        bundle_id="bundle-full-internet",
        display_name="Full internet",
        internet_policy=InternetPolicy.FULL,
    )
    with pytest.raises(HomeServiceCatalogError, match="policy_bundle_privilege_escalation"):
        compose_policy_bundle(child, internet)


def test_policy_bundle_rejects_empty_or_duplicate_composition() -> None:
    base = effective_policy(household(), "parent-01")
    with pytest.raises(HomeServiceCatalogError, match="empty_policy_bundle"):
        PolicyBundle(bundle_id="bundle-empty", display_name="Empty")

    bundle = PolicyBundle(
        bundle_id="bundle-filtered",
        display_name="Filtered internet",
        internet_policy=InternetPolicy.FILTERED,
    )
    with pytest.raises(HomeServiceCatalogError, match="duplicate_policy_bundle"):
        compose_policy_bundles(base, (bundle, bundle))

    with pytest.raises(HomeServiceCatalogError, match="policy_bundle_required"):
        compose_policy_bundles(base, ())


def test_policy_preview_serialization_stays_non_mutating() -> None:
    base = effective_policy(household(), "guest-01")
    bundle = PolicyBundle(
        bundle_id="bundle-guest-managed",
        display_name="Guest managed device",
        managed_device_required=True,
    )
    preview = compose_policy_bundle(base, bundle).to_dict()

    assert preview["schema"] == "home-center.household-policy-composition-preview.v1"
    assert preview["confirmation_required"] is True
    assert preview["mutation_authorized"] is False
    assert preview["production_mutation_enabled"] is False
    assert preview["effective_policy"]["external_publication_allowed"] is False
    assert preview["effective_policy"]["production_mutation_enabled"] is False
