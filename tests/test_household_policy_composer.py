from __future__ import annotations

import pytest

from home_center.household import Household, FamilyMember, HouseholdRole, InternetPolicy, effective_policy
from home_center.household_policy_composer import (
    HouseholdPolicyComposerError,
    build_policy_bundle,
    compose_policy,
    policy_bundle_from_dict,
    technical_policy_projection,
)


def _household() -> Household:
    return Household(
        household_id="home",
        members=(
            FamilyMember(member_id="parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="child", display_name="Child", role=HouseholdRole.CHILD),
            FamilyMember(member_id="guest", display_name="Guest", role=HouseholdRole.GUEST),
        ),
        devices=(),
    )


def _child_bundle(**overrides):
    value = {
        "internet_policy": "filtered",
        "vpn_allowed": False,
        "managed_device_required": True,
        "home_files_allowed": True,
        "smart_home_control_allowed": False,
        "administration_allowed": False,
        "external_publication_allowed": False,
    }
    value.update(overrides)
    return value


def test_policy_bundle_can_only_tighten_role_and_is_deterministic() -> None:
    bundle = build_policy_bundle(
        role=HouseholdRole.CHILD,
        value=_child_bundle(internet_policy="guest", home_files_allowed=False),
    )
    same = policy_bundle_from_dict(bundle.to_dict())
    assert same == bundle
    assert bundle.internet_policy is InternetPolicy.GUEST
    assert bundle.home_files_allowed is False
    assert bundle.external_publication_allowed is False

    base = effective_policy(_household(), "child")
    policy = compose_policy(base=base, bundle=bundle)
    assert policy.policy_id.startswith("hcpol-")
    assert policy.internet_policy is InternetPolicy.GUEST
    assert policy.enforcement_verified is False
    assert policy.production_mutation_enabled is False
    assert policy.external_publication_allowed is False
    assert "ожида" not in policy.explanation_ru
    assert "внешняя публикация запрещена" in policy.explanation_ru
    technical = technical_policy_projection(policy)
    assert technical["enforcement_verified"] is False
    assert technical["external_publication_allowed"] is False


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"internet_policy": "full"}, "policy_bundle_internet_escalation_rejected"),
        ({"vpn_allowed": True}, "policy_bundle_capability_escalation_rejected"),
        ({"managed_device_required": False}, "policy_bundle_managed_device_relaxation_rejected"),
        ({"administration_allowed": True}, "policy_bundle_capability_escalation_rejected"),
        ({"external_publication_allowed": True}, "policy_bundle_external_publication_rejected"),
    ],
)
def test_child_policy_escalation_is_rejected(override: dict[str, object], code: str) -> None:
    with pytest.raises(HouseholdPolicyComposerError, match=code):
        build_policy_bundle(role=HouseholdRole.CHILD, value=_child_bundle(**override))


def test_parent_bundle_may_restrict_but_never_reenable_external_publication() -> None:
    bundle = build_policy_bundle(
        role=HouseholdRole.PARENT,
        value={
            "internet_policy": "filtered",
            "vpn_allowed": False,
            "managed_device_required": True,
            "home_files_allowed": False,
            "smart_home_control_allowed": False,
            "administration_allowed": False,
            "external_publication_allowed": False,
        },
    )
    policy = compose_policy(base=effective_policy(_household(), "parent"), bundle=bundle)
    assert policy.internet_policy is InternetPolicy.FILTERED
    assert policy.vpn_allowed is False
    assert policy.administration_allowed is False
    assert policy.external_publication_allowed is False
