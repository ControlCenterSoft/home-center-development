from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, effective_policy
from home_center.household_policy_composer import build_policy_bundle, compose_policy
from home_center.parental_internet_policy import ParentalInternetPolicyError, build_parental_internet_policy
from home_center.parental_internet_policy_validation import parental_internet_policy_from_dict

SHA = "a" * 64


def _base(*, home_files_allowed: bool = True):
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="child", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )
    role = effective_policy(household, "child")
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
    return compose_policy(base=role, bundle=bundle)


def _policy(base):
    return build_parental_internet_policy(
        base=base,
        rule_source_id="family-filter",
        rule_source_version="2026.09.13",
        rule_source_sha256=SHA,
        allow_domains=("school.example",),
        deny_categories=("adult",),
        allow_categories=("education",),
        daily_quota_minutes=180,
    )


def test_exact_policy_round_trip_rebuilds_against_exact_base() -> None:
    base = _base()
    policy = _policy(base)
    restored = parental_internet_policy_from_dict(value=policy.to_dict(), base=base)
    assert restored == policy


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("subject_role", "parent"),
        ("default_decision", "allow"),
        ("dns_policy_required", False),
        ("proxy_policy_required", False),
        ("enforcement_authorized", True),
        ("infrastructure_mutation_authorized", True),
        ("external_publication_authorized", True),
        ("base_policy_sha256", "b" * 64),
        ("rule_source_sha256", "b" * 64),
        ("daily_quota_minutes", 181),
    ],
)
def test_tampered_transport_policy_is_rejected(field, value) -> None:
    base = _base()
    raw = _policy(base).to_dict()
    raw[field] = value
    with pytest.raises(ParentalInternetPolicyError):
        parental_internet_policy_from_dict(value=raw, base=base)


def test_unknown_field_is_rejected_not_ignored() -> None:
    base = _base()
    raw = _policy(base).to_dict()
    raw["client_override"] = "allow"
    with pytest.raises(ParentalInternetPolicyError, match="parental_policy_transport_rejected"):
        parental_internet_policy_from_dict(value=raw, base=base)


def test_policy_from_another_exact_base_is_rejected() -> None:
    first_base = _base(home_files_allowed=True)
    second_base = _base(home_files_allowed=False)
    raw = _policy(first_base).to_dict()
    with pytest.raises(ParentalInternetPolicyError, match="parental_policy_transport_rejected"):
        parental_internet_policy_from_dict(value=raw, base=second_base)
