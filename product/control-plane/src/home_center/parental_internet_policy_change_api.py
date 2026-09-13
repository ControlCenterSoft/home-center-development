"""Transport-neutral parent change API helpers for Home Center 0.60.

The helpers do not register routes and do not grant enforcement authority. HTTP wiring
must reuse Home Center authentication, same-origin/CSRF, scoped re-auth and idempotency
fences before calling the protected runtime.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .parental_internet_policy import POLICY_SCHEMA
from .parental_internet_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    DESIRED_STATE_SCHEMA,
    PLAN_REQUEST_SCHEMA,
)
from .util import canonical_json

COZY_DESIRED_SCHEMA = "home-center.cozy-parental-internet-policy-desired.v1"
FULL_DESIRED_SCHEMA = "home-center.full-parental-internet-policy-desired.v1"
_PLAN_ID = re.compile(r"hpip-[0-9a-f]{24}\Z")
_POLICY_ID = re.compile(r"hcip-[0-9a-f]{24}\Z")
_BASE_POLICY_ID = re.compile(r"hcpol-[0-9a-f]{24}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")

_RULE_FIELDS = {
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
}


class ParentalInternetPolicyChangeAPIError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _identifier(value: object, *, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(ch) < 33 for ch in value)
    ):
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")
    return value


def _optional_limit(value: object, maximum: int) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 1 <= value <= maximum:
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")
    return value


def _bounded_list(value: object, maximum: int, item_maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")
    for item in value:
        if not isinstance(item, str) or not item or len(item) > item_maximum:
            raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")
    return list(value)


def parse_parental_internet_plan_request(value: object) -> dict[str, Any]:
    required = {"schema", "subject_member_id", "reason", *_RULE_FIELDS}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != PLAN_REQUEST_SCHEMA:
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")
    subject = _identifier(value.get("subject_member_id"))
    reason = value.get("reason")
    source_version = value.get("rule_source_version")
    source_sha = value.get("rule_source_sha256")
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or len(reason.strip()) > 512
        or any(ord(ch) < 32 for ch in reason.strip())
        or not isinstance(source_version, str)
        or _VERSION.fullmatch(source_version) is None
        or not isinstance(source_sha, str)
        or _SHA256.fullmatch(source_sha) is None
    ):
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")
    schedule = value.get("schedule")
    if not isinstance(schedule, list) or len(schedule) > 64:
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")
    normalized_schedule: list[dict[str, int]] = []
    for item in schedule:
        if not isinstance(item, dict) or set(item) != {"weekday", "start_minute", "end_minute"}:
            raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")
        weekday = item.get("weekday")
        start = item.get("start_minute")
        end = item.get("end_minute")
        if (
            type(weekday) is not int or not 0 <= weekday <= 6
            or type(start) is not int or not 0 <= start <= 1438
            or type(end) is not int or not 1 <= end <= 1439
            or end <= start
        ):
            raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")
        normalized_schedule.append({"weekday": weekday, "start_minute": start, "end_minute": end})
    break_minutes = value.get("break_minutes")
    grace_minutes = value.get("grace_minutes")
    bonus_minutes = value.get("bonus_minutes")
    if (
        type(break_minutes) is not int or not 0 <= break_minutes <= 1440
        or type(grace_minutes) is not int or not 0 <= grace_minutes <= 60
        or type(bonus_minutes) is not int or not 0 <= bonus_minutes <= 1440
    ):
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")
    return {
        "schema": PLAN_REQUEST_SCHEMA,
        "subject_member_id": subject,
        "rule_source_id": _identifier(value.get("rule_source_id")),
        "rule_source_version": source_version,
        "rule_source_sha256": source_sha,
        "allow_domains": _bounded_list(value.get("allow_domains"), 512, 253),
        "deny_domains": _bounded_list(value.get("deny_domains"), 512, 253),
        "allow_categories": _bounded_list(value.get("allow_categories"), 256, 128),
        "deny_categories": _bounded_list(value.get("deny_categories"), 256, 128),
        "schedule": normalized_schedule,
        "daily_quota_minutes": _optional_limit(value.get("daily_quota_minutes"), 1440),
        "weekly_quota_minutes": _optional_limit(value.get("weekly_quota_minutes"), 10080),
        "continuous_session_minutes": _optional_limit(value.get("continuous_session_minutes"), 1440),
        "break_minutes": break_minutes,
        "grace_minutes": grace_minutes,
        "bonus_minutes": bonus_minutes,
        "reason": reason.strip(),
    }


def parse_parental_internet_confirm_request(value: object) -> dict[str, object]:
    required = {"schema", "plan_id", "confirmed"}
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != CONFIRM_REQUEST_SCHEMA
        or value.get("confirmed") is not True
        or not isinstance(value.get("plan_id"), str)
        or _PLAN_ID.fullmatch(value["plan_id"]) is None
    ):
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_confirm_request")
    return {"schema": CONFIRM_REQUEST_SCHEMA, "plan_id": value["plan_id"], "confirmed": True}


def _validated_desired(value: object) -> dict[str, object]:
    required = {
        "schema", "household_id", "member_id", "generation", "plan_id",
        "verified_base_state_sha256", "base_policy_id", "base_policy_sha256",
        "policy", "policy_sha256", "reason", "enforcement_verified",
        "reconciliation_required", "dns_policy_applied", "proxy_policy_applied",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != DESIRED_STATE_SCHEMA:
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_desired_state")
    policy = value.get("policy")
    household_id = value.get("household_id")
    member_id = value.get("member_id")
    base_policy_id = value.get("base_policy_id")
    base_policy_sha256 = value.get("base_policy_sha256")
    policy_sha256 = value.get("policy_sha256")
    reason = value.get("reason")
    if (
        not isinstance(household_id, str)
        or not household_id
        or len(household_id) > 128
        or not isinstance(member_id, str)
        or not member_id
        or len(member_id) > 128
        or type(value.get("generation")) is not int
        or value["generation"] < 1
        or not isinstance(value.get("plan_id"), str)
        or _PLAN_ID.fullmatch(value["plan_id"]) is None
        or not isinstance(value.get("verified_base_state_sha256"), str)
        or _SHA256.fullmatch(value["verified_base_state_sha256"]) is None
        or not isinstance(base_policy_id, str)
        or _BASE_POLICY_ID.fullmatch(base_policy_id) is None
        or not isinstance(base_policy_sha256, str)
        or _SHA256.fullmatch(base_policy_sha256) is None
        or not isinstance(policy_sha256, str)
        or _SHA256.fullmatch(policy_sha256) is None
        or not isinstance(reason, str)
        or not reason.strip()
        or len(reason.strip()) > 512
        or not isinstance(policy, dict)
        or policy.get("schema") != POLICY_SCHEMA
        or not isinstance(policy.get("policy_id"), str)
        or _POLICY_ID.fullmatch(policy["policy_id"]) is None
        or policy.get("household_id") != household_id
        or policy.get("member_id") != member_id
        or policy.get("subject_role") != "child"
        or policy.get("base_policy_id") != base_policy_id
        or policy.get("base_policy_sha256") != base_policy_sha256
        or _digest(policy) != policy_sha256
        or policy.get("default_decision") != "deny"
        or policy.get("dns_policy_required") is not True
        or policy.get("proxy_policy_required") is not True
        or policy.get("enforcement_authorized") is not False
        or policy.get("infrastructure_mutation_authorized") is not False
        or policy.get("external_publication_authorized") is not False
        or value.get("enforcement_verified") is not False
        or value.get("reconciliation_required") is not True
        or value.get("dns_policy_applied") is not False
        or value.get("proxy_policy_applied") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_desired_state")
    return dict(value)


def cozy_parental_internet_desired_projection(value: object) -> dict[str, object]:
    desired = _validated_desired(value)
    policy = desired["policy"]
    assert isinstance(policy, dict)
    return {
        "schema": COZY_DESIRED_SCHEMA,
        "member_id": desired["member_id"],
        "generation": desired["generation"],
        "title": "Семейные правила сохранены",
        "status": "Ожидают применения и проверки",
        "daily_quota_minutes": policy.get("daily_quota_minutes"),
        "weekly_quota_minutes": policy.get("weekly_quota_minutes"),
        "continuous_session_minutes": policy.get("continuous_session_minutes"),
        "enforcement_verified": False,
        "dns_policy_applied": False,
        "proxy_policy_applied": False,
        "reconciliation_required": True,
    }


def full_parental_internet_desired_projection(value: object) -> dict[str, object]:
    desired = _validated_desired(value)
    return {
        "schema": FULL_DESIRED_SCHEMA,
        "household_id": desired["household_id"],
        "member_id": desired["member_id"],
        "generation": desired["generation"],
        "plan_id": desired["plan_id"],
        "verified_base_state_sha256": desired["verified_base_state_sha256"],
        "base_policy_id": desired["base_policy_id"],
        "base_policy_sha256": desired["base_policy_sha256"],
        "policy_sha256": desired["policy_sha256"],
        "policy": dict(desired["policy"]),
        "enforcement_verified": False,
        "dns_policy_applied": False,
        "proxy_policy_applied": False,
        "reconciliation_required": True,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
