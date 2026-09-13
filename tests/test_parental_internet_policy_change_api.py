from __future__ import annotations

import hashlib

import pytest

from home_center.parental_internet_policy_change_api import (
    ParentalInternetPolicyChangeAPIError,
    cozy_parental_internet_desired_projection,
    full_parental_internet_desired_projection,
    parse_parental_internet_confirm_request,
    parse_parental_internet_plan_request,
)
from home_center.parental_internet_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    DESIRED_STATE_SCHEMA,
    PLAN_REQUEST_SCHEMA,
)
from home_center.util import canonical_json

SHA = "a" * 64


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _plan_request(**overrides):
    value = {
        "schema": PLAN_REQUEST_SCHEMA,
        "subject_member_id": "member-child",
        "rule_source_id": "family-filter",
        "rule_source_version": "2026.09.13",
        "rule_source_sha256": SHA,
        "allow_domains": ["school.example"],
        "deny_domains": ["blocked.example"],
        "allow_categories": ["education"],
        "deny_categories": ["adult"],
        "schedule": [{"weekday": 0, "start_minute": 480, "end_minute": 1200}],
        "daily_quota_minutes": 180,
        "weekly_quota_minutes": 900,
        "continuous_session_minutes": 60,
        "break_minutes": 15,
        "grace_minutes": 5,
        "bonus_minutes": 20,
        "reason": "  семейные правила  ",
    }
    value.update(overrides)
    return value


def _policy():
    return {
        "schema": "home-center.parental-internet-policy.v1",
        "policy_id": "hcip-" + "b" * 24,
        "household_id": "home",
        "member_id": "member-child",
        "subject_role": "child",
        "base_policy_id": "hcpol-" + "c" * 24,
        "base_policy_sha256": "d" * 64,
        "rule_source_id": "family-filter",
        "rule_source_version": "2026.09.13",
        "rule_source_sha256": SHA,
        "allow_domains": ["school.example"],
        "deny_domains": ["blocked.example"],
        "allow_categories": ["education"],
        "deny_categories": ["adult"],
        "schedule": [{"weekday": 0, "start_minute": 480, "end_minute": 1200}],
        "daily_quota_minutes": 180,
        "weekly_quota_minutes": 900,
        "continuous_session_minutes": 60,
        "break_minutes": 15,
        "grace_minutes": 5,
        "bonus_minutes": 20,
        "default_decision": "deny",
        "dns_policy_required": True,
        "proxy_policy_required": True,
        "enforcement_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _desired():
    policy = _policy()
    return {
        "schema": DESIRED_STATE_SCHEMA,
        "household_id": "home",
        "member_id": "member-child",
        "generation": 1,
        "plan_id": "hpip-" + "e" * 24,
        "verified_base_state_sha256": "f" * 64,
        "base_policy_id": policy["base_policy_id"],
        "base_policy_sha256": policy["base_policy_sha256"],
        "policy": policy,
        "policy_sha256": _digest(policy),
        "reason": "семейные правила",
        "enforcement_verified": False,
        "reconciliation_required": True,
        "dns_policy_applied": False,
        "proxy_policy_applied": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def test_plan_parser_is_closed_bounded_and_normalizes_reason() -> None:
    parsed = parse_parental_internet_plan_request(_plan_request())
    assert parsed["reason"] == "семейные правила"
    assert parsed["subject_member_id"] == "member-child"
    assert parsed["schedule"][0]["start_minute"] == 480
    with pytest.raises(ParentalInternetPolicyChangeAPIError):
        parse_parental_internet_plan_request({**_plan_request(), "client_role": "parent"})


@pytest.mark.parametrize(
    "override",
    [
        {"rule_source_sha256": "latest"},
        {"rule_source_version": "bad version"},
        {"daily_quota_minutes": 1441},
        {"weekly_quota_minutes": -1},
        {"continuous_session_minutes": 0},
        {"grace_minutes": 61},
        {"schedule": [{"weekday": 7, "start_minute": 1, "end_minute": 2}]},
        {"schedule": [{"weekday": 0, "start_minute": 20, "end_minute": 20}]},
        {"allow_domains": ["x" * 254]},
    ],
)
def test_plan_parser_rejects_malformed_or_unbounded_input(override) -> None:
    with pytest.raises(ParentalInternetPolicyChangeAPIError):
        parse_parental_internet_plan_request(_plan_request(**override))


def test_confirm_requires_exact_plan_id_and_explicit_true() -> None:
    value = {
        "schema": CONFIRM_REQUEST_SCHEMA,
        "plan_id": "hpip-" + "a" * 24,
        "confirmed": True,
    }
    assert parse_parental_internet_confirm_request(value) == value
    with pytest.raises(ParentalInternetPolicyChangeAPIError):
        parse_parental_internet_confirm_request({**value, "confirmed": False})
    with pytest.raises(ParentalInternetPolicyChangeAPIError):
        parse_parental_internet_confirm_request({**value, "plan_id": "latest"})


def test_cozy_desired_projection_is_truthful_and_non_enforcing() -> None:
    projection = cozy_parental_internet_desired_projection(_desired())
    assert projection["title"] == "Семейные правила сохранены"
    assert projection["status"] == "Ожидают применения и проверки"
    assert projection["enforcement_verified"] is False
    assert projection["dns_policy_applied"] is False
    assert projection["proxy_policy_applied"] is False
    assert projection["reconciliation_required"] is True


def test_full_desired_projection_preserves_exact_evidence_and_negative_authority() -> None:
    desired = _desired()
    projection = full_parental_internet_desired_projection(desired)
    assert projection["verified_base_state_sha256"] == desired["verified_base_state_sha256"]
    assert projection["base_policy_sha256"] == desired["base_policy_sha256"]
    assert projection["policy_sha256"] == desired["policy_sha256"]
    assert projection["policy"] == desired["policy"]
    assert projection["enforcement_verified"] is False
    assert projection["infrastructure_mutation_authorized"] is False
    assert projection["external_publication_authorized"] is False


def test_false_success_or_tampered_policy_is_rejected_before_projection() -> None:
    desired = _desired()
    desired["dns_policy_applied"] = True
    with pytest.raises(ParentalInternetPolicyChangeAPIError):
        cozy_parental_internet_desired_projection(desired)

    desired = _desired()
    desired["policy"]["daily_quota_minutes"] = 181
    with pytest.raises(ParentalInternetPolicyChangeAPIError):
        full_parental_internet_desired_projection(desired)
