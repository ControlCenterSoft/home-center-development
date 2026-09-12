from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, effective_policy
from home_center.household_policy_composer import build_policy_bundle, compose_policy
from home_center.parental_internet_policy import (
    AccessDecision,
    InternetAccessQuery,
    ParentalInternetPolicyError,
    ScheduleWindow,
    build_parental_internet_policy,
    evaluate_parental_internet_policy,
)

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 64


def _child_policy():
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
            "home_files_allowed": True,
            "smart_home_control_allowed": False,
            "administration_allowed": False,
            "external_publication_allowed": False,
        },
    )
    return compose_policy(base=base, bundle=bundle)


def _policy(**overrides):
    values = dict(
        base=_child_policy(),
        rule_source_id="family-filter",
        rule_source_version="2026.09.13",
        rule_source_sha256=SHA,
        allow_domains=("school.example",),
        deny_domains=("blocked.example",),
        allow_categories=("education", "general"),
        deny_categories=("adult", "gambling"),
        schedule=(ScheduleWindow(weekday=0, start_minute=480, end_minute=1200),),
        daily_quota_minutes=180,
        weekly_quota_minutes=900,
        continuous_session_minutes=60,
        break_minutes=15,
        grace_minutes=5,
        bonus_minutes=20,
    )
    values.update(overrides)
    return build_parental_internet_policy(**values)


def _query(policy, **overrides):
    values = dict(
        policy_id=policy.policy_id,
        household_id=policy.household_id,
        member_id=policy.member_id,
        domain="learn.example",
        category="education",
        weekday=0,
        minute_of_day=600,
        daily_used_minutes=0,
        weekly_used_minutes=0,
        continuous_used_minutes=0,
        rule_source_id=policy.rule_source_id,
        rule_source_version=policy.rule_source_version,
        rule_source_sha256=policy.rule_source_sha256,
    )
    values.update(overrides)
    return InternetAccessQuery(**values)


def test_policy_is_deterministic_closed_and_schema_valid() -> None:
    first = _policy(allow_domains=("SCHOOL.EXAMPLE.", "xn--e1afmkfd.xn--p1ai"))
    second = _policy(allow_domains=("xn--e1afmkfd.xn--p1ai", "school.example"))
    assert first == second
    assert first.to_dict()["default_decision"] == "deny"
    assert first.to_dict()["dns_policy_required"] is True
    assert first.to_dict()["proxy_policy_required"] is True
    assert first.to_dict()["enforcement_authorized"] is False
    assert first.to_dict()["infrastructure_mutation_authorized"] is False
    assert first.to_dict()["external_publication_authorized"] is False
    schema = json.loads((ROOT / "contracts/household/parental-internet-policy.v1.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(first.to_dict())


def test_parental_policy_requires_child_boundary() -> None:
    household = Household(
        household_id="home",
        members=(FamilyMember(member_id="parent", display_name="Parent", role=HouseholdRole.PARENT),),
        devices=(),
    )
    base = effective_policy(household, "parent")
    bundle = build_policy_bundle(
        role=HouseholdRole.PARENT,
        value={
            "internet_policy": "full", "vpn_allowed": True, "managed_device_required": False,
            "home_files_allowed": True, "smart_home_control_allowed": True,
            "administration_allowed": True, "external_publication_allowed": False,
        },
    )
    composed = compose_policy(base=base, bundle=bundle)
    with pytest.raises(ParentalInternetPolicyError, match="parental_policy_child_boundary_rejected"):
        build_parental_internet_policy(
            base=composed, rule_source_id="family-filter", rule_source_version="1", rule_source_sha256=SHA
        )


def test_stale_rule_source_and_unknown_classification_fail_closed() -> None:
    policy = _policy()
    stale = evaluate_parental_internet_policy(
        policy=policy,
        query=_query(policy, rule_source_sha256="b" * 64),
    )
    assert stale.decision is AccessDecision.DENY
    assert stale.reason == "rule_source_stale_or_mismatched"
    unknown = evaluate_parental_internet_policy(policy=policy, query=_query(policy, category=None))
    assert unknown.decision is AccessDecision.DENY
    assert unknown.reason == "classification_unknown"


def test_deny_schedule_and_quota_precede_allow_rules() -> None:
    policy = _policy(allow_domains=("school.example",), deny_domains=("ads.school.example",))
    denied = evaluate_parental_internet_policy(
        policy=policy, query=_query(policy, domain="x.ads.school.example")
    )
    assert denied.reason == "explicit_domain_deny"

    outside = evaluate_parental_internet_policy(
        policy=policy, query=_query(policy, domain="school.example", minute_of_day=300)
    )
    assert outside.reason == "outside_allowed_schedule"

    quota = evaluate_parental_internet_policy(
        policy=policy, query=_query(policy, domain="school.example", daily_used_minutes=200)
    )
    assert quota.reason == "daily_quota_exhausted"


def test_bonus_grace_and_required_break_have_bounded_semantics() -> None:
    policy = _policy()
    assert evaluate_parental_internet_policy(
        policy=policy, query=_query(policy, daily_used_minutes=199)
    ).decision is AccessDecision.ALLOW
    assert evaluate_parental_internet_policy(
        policy=policy, query=_query(policy, daily_used_minutes=200)
    ).reason == "daily_quota_exhausted"
    assert evaluate_parental_internet_policy(
        policy=policy, query=_query(policy, continuous_used_minutes=64)
    ).decision is AccessDecision.ALLOW
    limited = evaluate_parental_internet_policy(
        policy=policy, query=_query(policy, continuous_used_minutes=65)
    )
    assert limited.reason == "continuous_session_limit"
    assert limited.required_break_minutes == 15


def test_explicit_domain_allow_does_not_bypass_parental_limits() -> None:
    policy = _policy()
    allowed = evaluate_parental_internet_policy(
        policy=policy, query=_query(policy, domain="video.school.example", category=None)
    )
    assert allowed.decision is AccessDecision.ALLOW
    assert allowed.reason == "explicit_domain_allow"
    limited = evaluate_parental_internet_policy(
        policy=policy,
        query=_query(policy, domain="video.school.example", category=None, weekly_used_minutes=900),
    )
    assert limited.decision is AccessDecision.DENY
    assert limited.reason == "weekly_quota_exhausted"


def test_category_rules_are_fail_closed_and_decision_schema_is_closed() -> None:
    policy = _policy()
    denied = evaluate_parental_internet_policy(policy=policy, query=_query(policy, category="adult"))
    assert denied.reason == "category_deny"
    not_allowed = evaluate_parental_internet_policy(policy=policy, query=_query(policy, category="social"))
    assert not_allowed.reason == "category_not_allowed"
    allowed = evaluate_parental_internet_policy(policy=policy, query=_query(policy, category="education"))
    assert allowed.reason == "category_allowed"
    assert allowed.to_dict()["fail_closed"] is True
    assert allowed.to_dict()["enforcement_authorized"] is False
    schema = json.loads((ROOT / "contracts/household/parental-internet-decision.v1.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(allowed.to_dict())


def test_conflicts_and_ambiguous_schedule_are_rejected() -> None:
    with pytest.raises(ParentalInternetPolicyError, match="parental_rule_conflict"):
        _policy(allow_categories=("education",), deny_categories=("education",))
    with pytest.raises(ParentalInternetPolicyError, match="parental_schedule_overlap"):
        _policy(schedule=(ScheduleWindow(0, 480, 700), ScheduleWindow(0, 650, 900)))
    with pytest.raises(ParentalInternetPolicyError, match="parental_continuous_controls_without_limit"):
        _policy(continuous_session_minutes=None, break_minutes=15, grace_minutes=0)
