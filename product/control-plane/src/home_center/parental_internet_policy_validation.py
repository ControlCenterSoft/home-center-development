"""Strict storage/transport validation for Home Center 0.60 parental policy."""
from __future__ import annotations

from .household_policy_composer import ComposedPolicy
from .parental_internet_policy import (
    POLICY_SCHEMA,
    ParentalInternetPolicy,
    ParentalInternetPolicyError,
    build_parental_internet_policy,
)


_EXPECTED = {
    "schema",
    "policy_id",
    "household_id",
    "member_id",
    "subject_role",
    "base_policy_id",
    "base_policy_sha256",
    "rule_source_id",
    "rule_source_version",
    "rule_source_sha256",
    "allow_domains",
    "deny_domains",
    "allow_categories",
    "deny_categories",
    "schedule",
    "daily_quota_minutes",
    "weekly_quota_minutes",
    "continuous_session_minutes",
    "break_minutes",
    "grace_minutes",
    "bonus_minutes",
    "default_decision",
    "dns_policy_required",
    "proxy_policy_required",
    "enforcement_authorized",
    "infrastructure_mutation_authorized",
    "external_publication_authorized",
}


def parental_internet_policy_from_dict(
    *, value: object, base: ComposedPolicy
) -> ParentalInternetPolicy:
    """Rebuild and compare a persisted policy against its exact 0.59 base."""

    if not isinstance(base, ComposedPolicy):
        raise TypeError("parental_base_policy_invalid")
    if not isinstance(value, dict) or set(value) != _EXPECTED:
        raise ParentalInternetPolicyError("parental_policy_transport_rejected")
    if (
        value.get("schema") != POLICY_SCHEMA
        or value.get("subject_role") != "child"
        or value.get("default_decision") != "deny"
        or value.get("dns_policy_required") is not True
        or value.get("proxy_policy_required") is not True
        or value.get("enforcement_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise ParentalInternetPolicyError("parental_policy_transport_rejected")
    try:
        rebuilt = build_parental_internet_policy(
            base=base,
            rule_source_id=value["rule_source_id"],
            rule_source_version=value["rule_source_version"],
            rule_source_sha256=value["rule_source_sha256"],
            allow_domains=value["allow_domains"],
            deny_domains=value["deny_domains"],
            allow_categories=value["allow_categories"],
            deny_categories=value["deny_categories"],
            schedule=value["schedule"],
            daily_quota_minutes=value["daily_quota_minutes"],
            weekly_quota_minutes=value["weekly_quota_minutes"],
            continuous_session_minutes=value["continuous_session_minutes"],
            break_minutes=value["break_minutes"],
            grace_minutes=value["grace_minutes"],
            bonus_minutes=value["bonus_minutes"],
        )
    except ParentalInternetPolicyError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ParentalInternetPolicyError("parental_policy_transport_rejected") from exc
    if rebuilt.to_dict() != value:
        raise ParentalInternetPolicyError("parental_policy_transport_rejected")
    return rebuilt
