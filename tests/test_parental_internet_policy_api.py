from __future__ import annotations

import pytest

from home_center.parental_internet_policy import AccessDecision, InternetPolicyDecision
from home_center.parental_internet_policy_api import (
    ParentalInternetPolicyAPIError,
    cozy_parental_internet_projection,
    full_parental_internet_projection,
    parse_parental_internet_query,
)

SHA = "a" * 64


def _query(**overrides):
    value = {
        "schema": "home-center.parental-internet-query.v1",
        "policy_id": "hcip-" + "b" * 24,
        "household_id": "home",
        "member_id": "child",
        "domain": "learn.example",
        "category": "education",
        "weekday": 0,
        "minute_of_day": 600,
        "daily_used_minutes": 20,
        "weekly_used_minutes": 100,
        "continuous_used_minutes": 15,
        "rule_source_id": "family-filter",
        "rule_source_version": "2026.09.13",
        "rule_source_sha256": SHA,
    }
    value.update(overrides)
    return value


def _decision(decision: AccessDecision, reason: str, required_break_minutes: int = 0):
    return InternetPolicyDecision(
        policy_id="hcip-" + "b" * 24,
        decision=decision,
        reason=reason,
        rule_source_id="family-filter",
        rule_source_version="2026.09.13",
        rule_source_sha256=SHA,
        required_break_minutes=required_break_minutes,
    )


def test_query_parser_is_closed_and_preserves_exact_usage_evidence() -> None:
    parsed = parse_parental_internet_query(_query())
    assert parsed.policy_id == "hcip-" + "b" * 24
    assert parsed.domain == "learn.example"
    assert parsed.category == "education"
    assert parsed.daily_used_minutes == 20
    assert parsed.weekly_used_minutes == 100
    assert parsed.continuous_used_minutes == 15
    assert parsed.rule_source_sha256 == SHA

    with pytest.raises(ParentalInternetPolicyAPIError, match="invalid_parental_internet_query"):
        parse_parental_internet_query({**_query(), "client_override": "allow"})


def test_query_parser_rejects_unbounded_or_malformed_fields() -> None:
    for override in (
        {"weekday": 7},
        {"minute_of_day": 1440},
        {"daily_used_minutes": -1},
        {"rule_source_sha256": "latest"},
        {"rule_source_version": "bad version"},
        {"policy_id": "latest"},
        {"category": "x" * 129},
        {"domain": ""},
    ):
        with pytest.raises(ParentalInternetPolicyAPIError, match="invalid_parental_internet_query"):
            parse_parental_internet_query(_query(**override))


def test_cozy_projection_explains_denial_without_false_enforcement_claim() -> None:
    projection = cozy_parental_internet_projection(
        _decision(AccessDecision.DENY, "daily_quota_exhausted")
    )
    assert projection["decision"] == "deny"
    assert projection["title"] == "Доступ запрещён правилами"
    assert "Дневной лимит" in projection["explanation"]
    assert projection["enforcement_verified"] is False
    assert projection["infrastructure_mutation_authorized"] is False
    assert projection["external_publication_authorized"] is False


def test_cozy_projection_explains_required_break() -> None:
    projection = cozy_parental_internet_projection(
        _decision(AccessDecision.DENY, "continuous_session_limit", required_break_minutes=15)
    )
    assert projection["decision"] == "deny"
    assert projection["required_break_minutes"] == 15
    assert "15 мин" in projection["explanation"]


def test_cozy_projection_accepts_only_known_allow_and_deny_reasons() -> None:
    allowed = cozy_parental_internet_projection(
        _decision(AccessDecision.ALLOW, "explicit_domain_allow")
    )
    assert allowed["decision"] == "allow"
    assert allowed["title"] == "Доступ разрешён правилами"

    with pytest.raises(ParentalInternetPolicyAPIError, match="invalid_parental_internet_decision"):
        cozy_parental_internet_projection(_decision(AccessDecision.ALLOW, "category_deny"))
    with pytest.raises(ParentalInternetPolicyAPIError, match="invalid_parental_internet_decision"):
        cozy_parental_internet_projection(_decision(AccessDecision.DENY, "unexpected_reason"))


def test_full_projection_keeps_exact_evidence_and_negative_authority() -> None:
    decision = _decision(AccessDecision.DENY, "rule_source_stale_or_mismatched")
    projection = full_parental_internet_projection(decision)
    assert projection["decision"] == decision.to_dict()
    assert projection["decision"]["rule_source_version"] == "2026.09.13"
    assert projection["decision"]["rule_source_sha256"] == SHA
    assert projection["enforcement_verified"] is False
    assert projection["infrastructure_mutation_authorized"] is False
    assert projection["external_publication_authorized"] is False
