from __future__ import annotations

import hashlib

from home_center.household import FamilyMember, Household, HouseholdRole, effective_policy
from home_center.household_policy_composer import build_policy_bundle, compose_policy
from home_center.parental_internet_policy import build_parental_internet_policy
from home_center.util import canonical_json

SHA = "a" * 64


def _composed(*, home_files_allowed: bool):
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="child", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )
    base = effective_policy(household, "child")
    bundle = build_policy_bundle(
        role=HouseholdRole.CHILD,
        value={
            "internet_policy": "filtered",
            "vpn_allowed": False,
            "managed_device_required": True,
            "home_files_allowed": home_files_allowed,
            "smart_home_control_allowed": False,
            "administration_allowed": False,
            "external_publication_allowed": False,
        },
    )
    return compose_policy(base=base, bundle=bundle)


def _parental(base):
    return build_parental_internet_policy(
        base=base,
        rule_source_id="family-filter",
        rule_source_version="2026.09.13",
        rule_source_sha256=SHA,
        allow_categories=("education",),
    )


def test_parental_policy_binds_full_sha256_of_exact_composed_policy() -> None:
    base = _composed(home_files_allowed=True)
    policy = _parental(base)
    expected = hashlib.sha256(canonical_json(base.to_dict()).encode()).hexdigest()
    assert policy.base_policy_id == base.policy_id
    assert policy.base_policy_sha256 == expected
    assert policy.to_dict()["subject_role"] == "child"
    assert policy.to_dict()["base_policy_sha256"] == expected


def test_parental_identity_changes_when_exact_base_policy_changes() -> None:
    first = _parental(_composed(home_files_allowed=True))
    second = _parental(_composed(home_files_allowed=False))
    assert first.base_policy_id != second.base_policy_id
    assert first.base_policy_sha256 != second.base_policy_sha256
    assert first.policy_id != second.policy_id
