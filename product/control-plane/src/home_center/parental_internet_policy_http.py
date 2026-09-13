"""HTTP-specific request normalization for Home Center 0.60 parental policy.

The transport-neutral policy contract carries a rule-source identity because providers
and persisted evidence must be content-addressed. The ordinary Home Center UI must not
be able to invent that identity. This module therefore accepts only user-visible rule
facts and derives a deterministic local source id/version/SHA-256 server-side before
passing the request to the strict transport-neutral parser.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .parental_internet_policy_change_api import (
    ParentalInternetPolicyChangeAPIError,
    parse_parental_internet_plan_request,
)
from .parental_internet_policy_runtime import PLAN_REQUEST_SCHEMA
from .util import canonical_json

HTTP_PLAN_REQUEST_SCHEMA = "home-center.parental-internet-policy-http-plan-request.v1"
LOCAL_RULE_SOURCE_ID = "household-local-rules"

_USER_RULE_FIELDS = {
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


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def parse_parental_internet_http_plan_request(value: object) -> dict[str, Any]:
    required = {"schema", "subject_member_id", "reason", *_USER_RULE_FIELDS}
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != HTTP_PLAN_REQUEST_SCHEMA
    ):
        raise ParentalInternetPolicyChangeAPIError("invalid_parental_internet_plan_request")

    # Content-address the user-visible rule material before transport normalization.
    # Identity fields are deliberately absent from the HTTP request shape.
    rules = {name: value.get(name) for name in sorted(_USER_RULE_FIELDS)}
    source_sha256 = _digest(rules)
    normalized = {
        "schema": PLAN_REQUEST_SCHEMA,
        "subject_member_id": value.get("subject_member_id"),
        "rule_source_id": LOCAL_RULE_SOURCE_ID,
        "rule_source_version": "local-" + source_sha256[:16],
        "rule_source_sha256": source_sha256,
        **rules,
        "reason": value.get("reason"),
    }
    return parse_parental_internet_plan_request(normalized)
