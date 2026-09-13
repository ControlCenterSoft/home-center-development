"""Transport-neutral API helpers for the Home Center 0.59 Policy Composer.

These helpers deliberately do not register HTTP routes.  A later transport layer must
apply the existing authenticated session, same-origin/CSRF, scoped re-auth and request
idempotency fences before calling the runtime mutation boundary.
"""

from __future__ import annotations

from typing import Any

from .household_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    DESIRED_STATE_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeError,
)


class HouseholdPolicyAPIError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_policy_plan_request(value: object) -> dict[str, Any]:
    required = {"schema", "subject_member_id", "bundle", "reason"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != PLAN_REQUEST_SCHEMA:
        raise HouseholdPolicyAPIError("invalid_household_policy_plan_request")
    subject = value.get("subject_member_id")
    reason = value.get("reason")
    bundle = value.get("bundle")
    if (
        not isinstance(subject, str)
        or not subject
        or len(subject) > 128
        or not isinstance(reason, str)
        or not reason.strip()
        or len(reason.strip()) > 512
        or any(ord(char) < 32 for char in reason.strip())
        or not isinstance(bundle, dict)
    ):
        raise HouseholdPolicyAPIError("invalid_household_policy_plan_request")
    return {
        "schema": PLAN_REQUEST_SCHEMA,
        "subject_member_id": subject,
        "bundle": dict(bundle),
        "reason": reason.strip(),
    }


def parse_policy_confirm_request(value: object) -> dict[str, Any]:
    required = {"schema", "plan_id", "confirmed"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != CONFIRM_REQUEST_SCHEMA:
        raise HouseholdPolicyAPIError("invalid_household_policy_confirm_request")
    plan_id = value.get("plan_id")
    if not isinstance(plan_id, str) or not plan_id.startswith("hpcp-") or value.get("confirmed") is not True:
        raise HouseholdPolicyAPIError("invalid_household_policy_confirm_request")
    return {"schema": CONFIRM_REQUEST_SCHEMA, "plan_id": plan_id, "confirmed": True}


def cozy_policy_projection(value: object) -> dict[str, object]:
    """Return truthful Cozy wording without converting Desired State into false success."""

    if not isinstance(value, dict) or value.get("schema") != DESIRED_STATE_SCHEMA:
        raise HouseholdPolicyAPIError("invalid_household_policy_desired_state")
    policy = value.get("policy")
    if (
        not isinstance(policy, dict)
        or not isinstance(policy.get("explanation_ru"), str)
        or value.get("enforcement_verified") is not False
        or value.get("reconciliation_required") is not True
    ):
        raise HouseholdPolicyAPIError("invalid_household_policy_desired_state")
    return {
        "schema": "home-center.cozy-household-policy-projection.v1",
        "member_id": value.get("member_id"),
        "generation": value.get("generation"),
        "title": "Правила сохранены",
        "status": "Ожидают применения и проверки",
        "explanation": policy["explanation_ru"],
        "enforcement_verified": False,
        "reconciliation_required": True,
    }


def full_policy_projection(value: object) -> dict[str, object]:
    """Return exact technical Desired State fields for the Full interface."""

    if not isinstance(value, dict) or value.get("schema") != DESIRED_STATE_SCHEMA:
        raise HouseholdPolicyAPIError("invalid_household_policy_desired_state")
    policy = value.get("policy")
    if not isinstance(policy, dict) or value.get("enforcement_verified") is not False:
        raise HouseholdPolicyAPIError("invalid_household_policy_desired_state")
    return {
        "schema": "home-center.full-household-policy-projection.v1",
        "household_id": value.get("household_id"),
        "member_id": value.get("member_id"),
        "generation": value.get("generation"),
        "plan_id": value.get("plan_id"),
        "policy_sha256": value.get("policy_sha256"),
        "policy": dict(policy),
        "enforcement_verified": False,
        "reconciliation_required": value.get("reconciliation_required") is True,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def map_policy_runtime_error(exc: HouseholdPolicyRuntimeError) -> tuple[int, dict[str, str]]:
    """Provide a transport-neutral fail-closed status mapping for later HTTP wiring."""

    if not isinstance(exc, HouseholdPolicyRuntimeError):
        raise TypeError("invalid_household_policy_runtime_error")
    if exc.code in {"household_actor_not_bound", "household_policy_change_not_authorized", "household_policy_actor_mismatch"}:
        status = 403
    elif exc.code.endswith("_stale") or exc.code in {
        "household_policy_desired_generation_stale",
        "household_policy_current_digest_stale",
    }:
        status = 409
    elif exc.code == "household_policy_plan_not_found":
        status = 404
    else:
        status = 400
    return status, {"error": exc.code}
