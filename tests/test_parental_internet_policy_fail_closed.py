from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, effective_policy
from home_center.household_policy_composer import build_policy_bundle, compose_policy
from home_center.parental_internet_policy import (
    AccessDecision,
    InternetAccessQuery,
    ParentalInternetPolicyError,
    build_parental_internet_policy,
    evaluate_parental_internet_policy,
)

SHA = "a" * 64


def _base():
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
            "home_files_allowed": True,
            "smart_home_control_allowed": False,
            "administration_allowed": False,
            "external_publication_allowed": False,
        },
    )
    return compose_policy(base=role, bundle=bundle)


def _policy(**overrides):
    values = {
        "base": _base(),
        "rule_source_id": "family-filter",
        "rule_source_version": "2026.09.13",
        "rule_source_sha256": SHA,
    }
    values.update(overrides)
    return build_parental_internet_policy(**values)


def _query(policy, **overrides):
    values = {
        "policy_id": policy.policy_id,
        "household_id": policy.household_id,
        "member_id": policy.member_id,
        "domain": "news.example",
        "category": "general",
        "weekday": 0,
        "minute_of_day": 600,
        "daily_used_minutes": 0,
        "weekly_used_minutes": 0,
        "continuous_used_minutes": 0,
        "rule_source_id": policy.rule_source_id,
        "rule_source_version": policy.rule_source_version,
        "rule_source_sha256": policy.rule_source_sha256,
    }
    values.update(overrides)
    return InternetAccessQuery(**values)


def test_empty_allow_lists_are_default_deny_not_allow_all() -> None:
    policy = _policy()
    decision = evaluate_parental_internet_policy(policy=policy, query=_query(policy))
    assert decision.decision is AccessDecision.DENY
    assert decision.reason == "category_not_allowed"


def test_known_category_requires_explicit_allow() -> None:
    policy = _policy(allow_categories=("education",))
    denied = evaluate_parental_internet_policy(policy=policy, query=_query(policy, category="general"))
    assert denied.decision is AccessDecision.DENY
    assert denied.reason == "category_not_allowed"
    allowed = evaluate_parental_internet_policy(policy=policy, query=_query(policy, category="education"))
    assert allowed.decision is AccessDecision.ALLOW
    assert allowed.reason == "category_allowed"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("rule_source_version", ["latest"], "parental_rule_source_version_invalid"),
        ("rule_source_sha256", {"sha": SHA}, "parental_rule_source_sha256_invalid"),
        ("schedule", ("bad-window",), "parental_schedule_invalid"),
        ("schedule", ({"weekday": 0, "start_minute": 10, "end_minute": 20, "extra": True},), "parental_schedule_invalid"),
    ],
)
def test_malformed_policy_inputs_fail_with_bounded_errors(field, value, code) -> None:
    with pytest.raises(ParentalInternetPolicyError, match=code):
        _policy(**{field: value})


def test_malformed_runtime_query_fails_closed_without_exception() -> None:
    policy = _policy(allow_categories=("general",))
    query = _query(policy, category={"spoof": "general"})
    decision = evaluate_parental_internet_policy(policy=policy, query=query)
    assert decision.decision is AccessDecision.DENY
    assert decision.reason == "query_invalid"
