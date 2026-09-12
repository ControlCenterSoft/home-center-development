"""Side-effect-free Home Center 0.60 parental Internet policy domain."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .household import HouseholdRole, InternetPolicy
from .household_policy_composer import ComposedPolicy
from .home_services import _identifier
from .util import canonical_json

POLICY_SCHEMA = "home-center.parental-internet-policy.v1"
DECISION_SCHEMA = "home-center.parental-internet-decision.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class ParentalInternetPolicyError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class AccessDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _bounded_int(value: object, low: int, high: int, code: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ParentalInternetPolicyError(code)
    return value


def _optional_limit(value: object, high: int, code: str) -> int | None:
    return None if value is None else _bounded_int(value, 1, high, code)


def _domain(value: object) -> str:
    if not isinstance(value, str):
        raise ParentalInternetPolicyError("parental_domain_invalid")
    raw = value.strip().rstrip(".").lower()
    try:
        result = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ParentalInternetPolicyError("parental_domain_invalid") from exc
    labels = result.split(".")
    if not result or len(result) > 253 or len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(x) for x in labels):
        raise ParentalInternetPolicyError("parental_domain_invalid")
    return result


def _category(value: object) -> str:
    if not isinstance(value, str):
        raise ParentalInternetPolicyError("parental_category_invalid")
    try:
        return _identifier(value, "parental_category_invalid")
    except ValueError as exc:
        raise ParentalInternetPolicyError("parental_category_invalid") from exc


def _rule_list(values: object, normalizer, code: str, maximum: int) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > maximum:
        raise ParentalInternetPolicyError(code)
    try:
        result = tuple(sorted(normalizer(value) for value in values))
    except ParentalInternetPolicyError:
        raise
    except (TypeError, ValueError) as exc:
        raise ParentalInternetPolicyError(code) from exc
    if len(result) != len(set(result)):
        raise ParentalInternetPolicyError(code)
    return result


def _domain_matches(domain: str, rule: str) -> bool:
    return domain == rule or domain.endswith("." + rule)


@dataclass(frozen=True, slots=True, order=True)
class ScheduleWindow:
    weekday: int
    start_minute: int
    end_minute: int

    def __post_init__(self) -> None:
        _bounded_int(self.weekday, 0, 6, "parental_schedule_weekday_invalid")
        _bounded_int(self.start_minute, 0, 1438, "parental_schedule_start_invalid")
        _bounded_int(self.end_minute, 1, 1439, "parental_schedule_end_invalid")
        if self.end_minute <= self.start_minute:
            raise ParentalInternetPolicyError("parental_schedule_window_invalid")

    def to_dict(self) -> dict[str, int]:
        return {"weekday": self.weekday, "start_minute": self.start_minute, "end_minute": self.end_minute}


def _schedule(values: object) -> tuple[ScheduleWindow, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > 64:
        raise ParentalInternetPolicyError("parental_schedule_invalid")
    windows: list[ScheduleWindow] = []
    for value in values:
        if isinstance(value, ScheduleWindow):
            windows.append(value)
            continue
        if not isinstance(value, dict) or set(value) != {"weekday", "start_minute", "end_minute"}:
            raise ParentalInternetPolicyError("parental_schedule_invalid")
        try:
            windows.append(
                ScheduleWindow(
                    weekday=value["weekday"],
                    start_minute=value["start_minute"],
                    end_minute=value["end_minute"],
                )
            )
        except ParentalInternetPolicyError:
            raise
        except (TypeError, ValueError) as exc:
            raise ParentalInternetPolicyError("parental_schedule_invalid") from exc
    result = tuple(sorted(windows))
    for left, right in zip(result, result[1:]):
        if left.weekday == right.weekday and right.start_minute < left.end_minute:
            raise ParentalInternetPolicyError("parental_schedule_overlap")
    return result


@dataclass(frozen=True, slots=True)
class ParentalInternetPolicy:
    policy_id: str
    household_id: str
    member_id: str
    base_policy_id: str
    base_policy_sha256: str
    rule_source_id: str
    rule_source_version: str
    rule_source_sha256: str
    allow_domains: tuple[str, ...]
    deny_domains: tuple[str, ...]
    allow_categories: tuple[str, ...]
    deny_categories: tuple[str, ...]
    schedule: tuple[ScheduleWindow, ...]
    daily_quota_minutes: int | None
    weekly_quota_minutes: int | None
    continuous_session_minutes: int | None
    break_minutes: int
    grace_minutes: int
    bonus_minutes: int
    schema: str = field(default=POLICY_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema, "policy_id": self.policy_id,
            "household_id": self.household_id, "member_id": self.member_id,
            "subject_role": "child", "base_policy_id": self.base_policy_id,
            "base_policy_sha256": self.base_policy_sha256,
            "rule_source_id": self.rule_source_id,
            "rule_source_version": self.rule_source_version, "rule_source_sha256": self.rule_source_sha256,
            "allow_domains": list(self.allow_domains), "deny_domains": list(self.deny_domains),
            "allow_categories": list(self.allow_categories), "deny_categories": list(self.deny_categories),
            "schedule": [x.to_dict() for x in self.schedule],
            "daily_quota_minutes": self.daily_quota_minutes, "weekly_quota_minutes": self.weekly_quota_minutes,
            "continuous_session_minutes": self.continuous_session_minutes, "break_minutes": self.break_minutes,
            "grace_minutes": self.grace_minutes, "bonus_minutes": self.bonus_minutes,
            "default_decision": "deny", "dns_policy_required": True, "proxy_policy_required": True,
            "enforcement_authorized": False, "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class InternetAccessQuery:
    policy_id: str
    household_id: str
    member_id: str
    domain: str
    category: str | None
    weekday: int
    minute_of_day: int
    daily_used_minutes: int
    weekly_used_minutes: int
    continuous_used_minutes: int
    rule_source_id: str
    rule_source_version: str
    rule_source_sha256: str


@dataclass(frozen=True, slots=True)
class InternetPolicyDecision:
    policy_id: str
    decision: AccessDecision
    reason: str
    rule_source_id: str
    rule_source_version: str
    rule_source_sha256: str
    required_break_minutes: int = 0
    schema: str = field(default=DECISION_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema, "policy_id": self.policy_id, "decision": self.decision.value,
            "reason": self.reason, "rule_source_id": self.rule_source_id,
            "rule_source_version": self.rule_source_version, "rule_source_sha256": self.rule_source_sha256,
            "required_break_minutes": self.required_break_minutes, "fail_closed": True,
            "enforcement_authorized": False, "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def build_parental_internet_policy(*, base: ComposedPolicy, rule_source_id: str, rule_source_version: str,
    rule_source_sha256: str, allow_domains: object=(), deny_domains: object=(), allow_categories: object=(),
    deny_categories: object=(), schedule: object=(), daily_quota_minutes: object=None,
    weekly_quota_minutes: object=None, continuous_session_minutes: object=None, break_minutes: object=0,
    grace_minutes: object=0, bonus_minutes: object=0) -> ParentalInternetPolicy:
    if not isinstance(base, ComposedPolicy):
        raise TypeError("parental_base_policy_invalid")
    if base.role is not HouseholdRole.CHILD or base.internet_policy is InternetPolicy.FULL or base.vpn_allowed:
        raise ParentalInternetPolicyError("parental_policy_child_boundary_rejected")
    try:
        source_id = _identifier(rule_source_id, "parental_rule_source_id_invalid")
    except (TypeError, ValueError) as exc:
        raise ParentalInternetPolicyError("parental_rule_source_id_invalid") from exc
    if not isinstance(rule_source_version, str) or not _SOURCE_VERSION.fullmatch(rule_source_version):
        raise ParentalInternetPolicyError("parental_rule_source_version_invalid")
    if not isinstance(rule_source_sha256, str) or not _SHA256.fullmatch(rule_source_sha256):
        raise ParentalInternetPolicyError("parental_rule_source_sha256_invalid")
    allow_d = _rule_list(allow_domains, _domain, "parental_allow_domains_invalid", 512)
    deny_d = _rule_list(deny_domains, _domain, "parental_deny_domains_invalid", 512)
    allow_c = _rule_list(allow_categories, _category, "parental_allow_categories_invalid", 256)
    deny_c = _rule_list(deny_categories, _category, "parental_deny_categories_invalid", 256)
    if set(allow_d) & set(deny_d) or set(allow_c) & set(deny_c):
        raise ParentalInternetPolicyError("parental_rule_conflict")
    windows = _schedule(schedule)
    daily = _optional_limit(daily_quota_minutes, 1440, "parental_daily_quota_invalid")
    weekly = _optional_limit(weekly_quota_minutes, 10080, "parental_weekly_quota_invalid")
    continuous = _optional_limit(continuous_session_minutes, 1440, "parental_continuous_session_invalid")
    break_value = _bounded_int(break_minutes, 0, 1440, "parental_break_minutes_invalid")
    grace = _bounded_int(grace_minutes, 0, 60, "parental_grace_minutes_invalid")
    bonus = _bounded_int(bonus_minutes, 0, 1440, "parental_bonus_minutes_invalid")
    if continuous is None and (break_value or grace):
        raise ParentalInternetPolicyError("parental_continuous_controls_without_limit")
    if daily is None and bonus:
        raise ParentalInternetPolicyError("parental_bonus_without_daily_quota")
    values = dict(
        household_id=base.household_id,
        member_id=base.member_id,
        base_policy_id=base.policy_id,
        base_policy_sha256=_digest(base.to_dict()),
        rule_source_id=source_id,
        rule_source_version=rule_source_version,
        rule_source_sha256=rule_source_sha256,
        allow_domains=allow_d,
        deny_domains=deny_d,
        allow_categories=allow_c,
        deny_categories=deny_c,
        schedule=windows,
        daily_quota_minutes=daily,
        weekly_quota_minutes=weekly,
        continuous_session_minutes=continuous,
        break_minutes=break_value,
        grace_minutes=grace,
        bonus_minutes=bonus,
    )
    canonical = {
        "subject_role": "child",
        **{k: ([x.to_dict() for x in v] if k == "schedule" else v) for k, v in values.items()},
    }
    policy_id = "hcip-" + _digest(canonical)[:24]
    return ParentalInternetPolicy(policy_id=policy_id, **values)


def evaluate_parental_internet_policy(*, policy: ParentalInternetPolicy, query: InternetAccessQuery) -> InternetPolicyDecision:
    def out(decision: AccessDecision, reason: str, break_minutes: int=0) -> InternetPolicyDecision:
        return InternetPolicyDecision(policy.policy_id, decision, reason, policy.rule_source_id,
            policy.rule_source_version, policy.rule_source_sha256, break_minutes)
    if not isinstance(policy, ParentalInternetPolicy) or not isinstance(query, InternetAccessQuery):
        raise TypeError("parental_policy_query_invalid")
    try:
        domain = _domain(query.domain)
        category = None if query.category is None else _category(query.category)
        _bounded_int(query.weekday, 0, 6, "parental_query_weekday_invalid")
        _bounded_int(query.minute_of_day, 0, 1439, "parental_query_minute_invalid")
        for value in (query.daily_used_minutes, query.weekly_used_minutes, query.continuous_used_minutes):
            _bounded_int(value, 0, 10080, "parental_query_usage_invalid")
    except ParentalInternetPolicyError:
        return out(AccessDecision.DENY, "query_invalid")
    if (query.policy_id, query.household_id, query.member_id) != (policy.policy_id, policy.household_id, policy.member_id):
        return out(AccessDecision.DENY, "policy_binding_mismatch")
    if (query.rule_source_id, query.rule_source_version, query.rule_source_sha256) != (policy.rule_source_id, policy.rule_source_version, policy.rule_source_sha256):
        return out(AccessDecision.DENY, "rule_source_stale_or_mismatched")
    if any(_domain_matches(domain, rule) for rule in policy.deny_domains):
        return out(AccessDecision.DENY, "explicit_domain_deny")
    if policy.schedule and not any(x.weekday == query.weekday and x.start_minute <= query.minute_of_day < x.end_minute for x in policy.schedule):
        return out(AccessDecision.DENY, "outside_allowed_schedule")
    if policy.weekly_quota_minutes is not None and query.weekly_used_minutes >= policy.weekly_quota_minutes:
        return out(AccessDecision.DENY, "weekly_quota_exhausted")
    if policy.daily_quota_minutes is not None and query.daily_used_minutes >= policy.daily_quota_minutes + policy.bonus_minutes:
        return out(AccessDecision.DENY, "daily_quota_exhausted")
    if policy.continuous_session_minutes is not None and query.continuous_used_minutes >= policy.continuous_session_minutes + policy.grace_minutes:
        return out(AccessDecision.DENY, "continuous_session_limit", policy.break_minutes)
    if any(_domain_matches(domain, rule) for rule in policy.allow_domains):
        return out(AccessDecision.ALLOW, "explicit_domain_allow")
    if category is None:
        return out(AccessDecision.DENY, "classification_unknown")
    if category in policy.deny_categories:
        return out(AccessDecision.DENY, "category_deny")
    if category not in policy.allow_categories:
        return out(AccessDecision.DENY, "category_not_allowed")
    return out(AccessDecision.ALLOW, "category_allowed")
