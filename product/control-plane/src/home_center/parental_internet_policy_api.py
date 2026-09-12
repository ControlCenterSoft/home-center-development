"""Transport-neutral helpers for Home Center 0.60 parental Internet policy.

No HTTP route or enforcement adapter is registered here. A future transport must
reuse the existing Home Center session/RBAC/origin/re-auth fences.
"""
from __future__ import annotations

import re

from .parental_internet_policy import (
    AccessDecision,
    InternetAccessQuery,
    InternetPolicyDecision,
)

QUERY_SCHEMA = "home-center.parental-internet-query.v1"
COZY_DECISION_SCHEMA = "home-center.cozy-parental-internet-decision.v1"
FULL_DECISION_SCHEMA = "home-center.full-parental-internet-decision.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_POLICY_ID = re.compile(r"hcip-[0-9a-f]{24}\Z")


class ParentalInternetPolicyAPIError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or any(ord(ch) < 33 for ch in value)
    ):
        raise ParentalInternetPolicyAPIError("invalid_parental_internet_query")
    return value


def _minute(value: object, maximum: int) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ParentalInternetPolicyAPIError("invalid_parental_internet_query")
    return value


def parse_parental_internet_query(value: object) -> InternetAccessQuery:
    required = {
        "schema", "policy_id", "household_id", "member_id", "domain", "category",
        "weekday", "minute_of_day", "daily_used_minutes", "weekly_used_minutes",
        "continuous_used_minutes", "rule_source_id", "rule_source_version", "rule_source_sha256",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != QUERY_SCHEMA:
        raise ParentalInternetPolicyAPIError("invalid_parental_internet_query")
    policy_id = value.get("policy_id")
    domain = value.get("domain")
    category = value.get("category")
    source_version = value.get("rule_source_version")
    source_sha = value.get("rule_source_sha256")
    if (
        not isinstance(policy_id, str)
        or _POLICY_ID.fullmatch(policy_id) is None
        or not isinstance(domain, str)
        or not domain.strip()
        or len(domain) > 253
        or (category is not None and (not isinstance(category, str) or not category or len(category) > 128))
        or not isinstance(source_version, str)
        or not _VERSION.fullmatch(source_version)
        or not isinstance(source_sha, str)
        or not _SHA256.fullmatch(source_sha)
    ):
        raise ParentalInternetPolicyAPIError("invalid_parental_internet_query")
    weekday = _minute(value.get("weekday"), 6)
    minute_of_day = _minute(value.get("minute_of_day"), 1439)
    daily = _minute(value.get("daily_used_minutes"), 10080)
    weekly = _minute(value.get("weekly_used_minutes"), 10080)
    continuous = _minute(value.get("continuous_used_minutes"), 10080)
    return InternetAccessQuery(
        policy_id=policy_id,
        household_id=_identifier(value.get("household_id")),
        member_id=_identifier(value.get("member_id")),
        domain=domain.strip(),
        category=category,
        weekday=weekday,
        minute_of_day=minute_of_day,
        daily_used_minutes=daily,
        weekly_used_minutes=weekly,
        continuous_used_minutes=continuous,
        rule_source_id=_identifier(value.get("rule_source_id")),
        rule_source_version=source_version,
        rule_source_sha256=source_sha,
    )


_DENY_TEXT = {
    "query_invalid": "Не удалось безопасно проверить запрос — доступ заблокирован.",
    "policy_binding_mismatch": "Правило относится к другому состоянию семьи — доступ заблокирован.",
    "rule_source_stale_or_mismatched": "Источник семейных правил изменился или устарел — доступ заблокирован.",
    "explicit_domain_deny": "Этот сайт заблокирован семейным правилом.",
    "outside_allowed_schedule": "Сейчас доступ закрыт по расписанию.",
    "weekly_quota_exhausted": "Недельный лимит времени исчерпан.",
    "daily_quota_exhausted": "Дневной лимит времени исчерпан.",
    "continuous_session_limit": "Нужен обязательный перерыв перед продолжением.",
    "classification_unknown": "Категорию сайта определить не удалось — доступ заблокирован.",
    "category_deny": "Эта категория заблокирована семейным правилом.",
    "category_not_allowed": "Эта категория не входит в разрешённый список.",
}
_ALLOW_REASONS = {"explicit_domain_allow", "category_allowed"}


def _validate_decision(decision: InternetPolicyDecision) -> None:
    if not isinstance(decision, InternetPolicyDecision):
        raise TypeError("invalid_parental_internet_decision")
    if (
        not isinstance(decision.policy_id, str)
        or _POLICY_ID.fullmatch(decision.policy_id) is None
        or not isinstance(decision.rule_source_id, str)
        or not decision.rule_source_id
        or len(decision.rule_source_id) > 128
        or any(ord(ch) < 33 for ch in decision.rule_source_id)
        or not isinstance(decision.rule_source_version, str)
        or _VERSION.fullmatch(decision.rule_source_version) is None
        or not isinstance(decision.rule_source_sha256, str)
        or _SHA256.fullmatch(decision.rule_source_sha256) is None
        or type(decision.required_break_minutes) is not int
        or not 0 <= decision.required_break_minutes <= 1440
        or not isinstance(decision.decision, AccessDecision)
    ):
        raise ParentalInternetPolicyAPIError("invalid_parental_internet_decision")
    if decision.decision is AccessDecision.ALLOW:
        if decision.reason not in _ALLOW_REASONS or decision.required_break_minutes != 0:
            raise ParentalInternetPolicyAPIError("invalid_parental_internet_decision")
        return
    if decision.reason not in _DENY_TEXT:
        raise ParentalInternetPolicyAPIError("invalid_parental_internet_decision")
    if decision.reason != "continuous_session_limit" and decision.required_break_minutes != 0:
        raise ParentalInternetPolicyAPIError("invalid_parental_internet_decision")


def cozy_parental_internet_projection(decision: InternetPolicyDecision) -> dict[str, object]:
    _validate_decision(decision)
    if decision.decision is AccessDecision.ALLOW:
        title = "Доступ разрешён правилами"
        explanation = (
            "Сайт явно разрешён семейным правилом."
            if decision.reason == "explicit_domain_allow"
            else "Категория разрешена семейным правилом."
        )
    else:
        explanation = _DENY_TEXT[decision.reason]
        title = "Доступ запрещён правилами"
        if decision.reason == "continuous_session_limit" and decision.required_break_minutes:
            explanation = f"Нужен обязательный перерыв: {decision.required_break_minutes} мин."
    return {
        "schema": COZY_DECISION_SCHEMA,
        "policy_id": decision.policy_id,
        "decision": decision.decision.value,
        "reason": decision.reason,
        "title": title,
        "explanation": explanation,
        "required_break_minutes": decision.required_break_minutes,
        "enforcement_verified": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def full_parental_internet_projection(decision: InternetPolicyDecision) -> dict[str, object]:
    _validate_decision(decision)
    return {
        "schema": FULL_DECISION_SCHEMA,
        "decision": decision.to_dict(),
        "enforcement_verified": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
