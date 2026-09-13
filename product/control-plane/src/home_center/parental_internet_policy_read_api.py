"""Authenticated read/preview boundary for Home Center 0.60 parental Internet policy.

This service never executes a DNS/proxy adapter and never accepts policy identity,
rule-source identity or authorization material from the caller.  It reads the current
protected Desired State, revalidates its exact verified 0.59 policy base and builds a
side-effect-free decision preview from caller-supplied request facts.  A preview is UI
evidence only and must never be interpreted as provider enforcement or Actual State.
"""
from __future__ import annotations

from typing import Any

from .parental_internet_policy import InternetAccessQuery, evaluate_parental_internet_policy
from .parental_internet_policy_api import (
    cozy_parental_internet_projection,
    full_parental_internet_projection,
)
from .parental_internet_policy_change_api import (
    cozy_parental_internet_desired_projection,
    full_parental_internet_desired_projection,
)
from .parental_internet_policy_runtime import (
    ParentalInternetPolicyRuntimeError,
    ParentalInternetPolicyRuntimeService,
)
from .parental_internet_policy_validation import parental_internet_policy_from_dict
from .store import StateStore

DESIRED_READ_SCHEMA = "home-center.parental-internet-policy-desired-read.v1"
PREVIEW_REQUEST_SCHEMA = "home-center.parental-internet-decision-preview-request.v1"
PREVIEW_RESULT_SCHEMA = "home-center.parental-internet-decision-preview-result.v1"
_VIEWS = frozenset({"cozy", "full"})


class ParentalInternetPolicyReadAPIError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _member_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or any(ord(ch) < 33 for ch in value)
    ):
        raise ParentalInternetPolicyReadAPIError("invalid_parental_internet_read_request")
    return value


def _view(value: object) -> str:
    if value not in _VIEWS:
        raise ParentalInternetPolicyReadAPIError("invalid_parental_internet_read_request")
    assert isinstance(value, str)
    return value


def _bounded_int(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ParentalInternetPolicyReadAPIError("invalid_parental_internet_preview_request")
    return value


def parse_parental_internet_preview_request(value: object) -> dict[str, Any]:
    required = {
        "schema",
        "member_id",
        "domain",
        "category",
        "weekday",
        "minute_of_day",
        "daily_used_minutes",
        "weekly_used_minutes",
        "continuous_used_minutes",
        "view",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != PREVIEW_REQUEST_SCHEMA
    ):
        raise ParentalInternetPolicyReadAPIError("invalid_parental_internet_preview_request")
    domain = value.get("domain")
    category = value.get("category")
    if (
        not isinstance(domain, str)
        or not domain.strip()
        or len(domain.strip()) > 253
        or (
            category is not None
            and (not isinstance(category, str) or not category or len(category) > 128)
        )
    ):
        raise ParentalInternetPolicyReadAPIError("invalid_parental_internet_preview_request")
    return {
        "schema": PREVIEW_REQUEST_SCHEMA,
        "member_id": _member_id(value.get("member_id")),
        "domain": domain.strip(),
        "category": category,
        "weekday": _bounded_int(value.get("weekday"), 6),
        "minute_of_day": _bounded_int(value.get("minute_of_day"), 1439),
        "daily_used_minutes": _bounded_int(value.get("daily_used_minutes"), 10080),
        "weekly_used_minutes": _bounded_int(value.get("weekly_used_minutes"), 10080),
        "continuous_used_minutes": _bounded_int(value.get("continuous_used_minutes"), 10080),
        "view": _view(value.get("view")),
    }


class ParentalInternetPolicyReadAPIService:
    """Read current saved parental rules and produce non-authoritative decision previews."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self.runtime = ParentalInternetPolicyRuntimeService(store)

    @staticmethod
    def _translate_runtime_error(exc: ParentalInternetPolicyRuntimeError) -> ParentalInternetPolicyReadAPIError:
        return ParentalInternetPolicyReadAPIError(exc.code)

    def read_desired(self, *, actor: str, member_id: object, view: object) -> dict[str, object]:
        subject = _member_id(member_id)
        selected_view = _view(view)
        try:
            desired = self.runtime.desired_state(actor=actor, member_id=subject)
        except ParentalInternetPolicyRuntimeError as exc:
            raise self._translate_runtime_error(exc) from exc
        if desired is None:
            value = None
            state = "absent"
        else:
            try:
                value = (
                    cozy_parental_internet_desired_projection(desired)
                    if selected_view == "cozy"
                    else full_parental_internet_desired_projection(desired)
                )
            except ValueError as exc:
                raise ParentalInternetPolicyReadAPIError(
                    "parental_internet_desired_state_invalid"
                ) from exc
            state = "present"
        return {
            "schema": DESIRED_READ_SCHEMA,
            "member_id": subject,
            "view": selected_view,
            "state": state,
            "value": value,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    def preview(self, *, actor: str, request: object) -> dict[str, object]:
        parsed = parse_parental_internet_preview_request(request)
        subject = str(parsed["member_id"])
        try:
            desired = self.runtime.desired_state(actor=actor, member_id=subject)
            if desired is None:
                raise ParentalInternetPolicyReadAPIError(
                    "parental_internet_desired_state_missing"
                )
            snapshot, bindings = self.runtime._state()
            self.runtime._actor_parent(actor, snapshot, bindings)
            verified = self.runtime._verified_base(
                household_id=snapshot.household_id,
                member_id=subject,
            )
            self.runtime._require_current_role_base(snapshot, verified)
        except ParentalInternetPolicyReadAPIError:
            raise
        except ParentalInternetPolicyRuntimeError as exc:
            raise self._translate_runtime_error(exc) from exc

        if (
            desired.get("verified_base_state_sha256") != verified.verified_state_sha256
            or desired.get("base_policy_id") != verified.policy.policy_id
            or desired.get("base_policy_sha256") != verified.policy_sha256
            or not isinstance(desired.get("policy"), dict)
        ):
            raise ParentalInternetPolicyReadAPIError(
                "parental_internet_desired_state_stale"
            )
        try:
            policy = parental_internet_policy_from_dict(
                value=desired["policy"],
                base=verified.policy,
            )
        except (ValueError, TypeError) as exc:
            raise ParentalInternetPolicyReadAPIError(
                "parental_internet_desired_state_invalid"
            ) from exc

        query = InternetAccessQuery(
            policy_id=policy.policy_id,
            household_id=policy.household_id,
            member_id=policy.member_id,
            domain=str(parsed["domain"]),
            category=parsed["category"] if isinstance(parsed["category"], str) else None,
            weekday=int(parsed["weekday"]),
            minute_of_day=int(parsed["minute_of_day"]),
            daily_used_minutes=int(parsed["daily_used_minutes"]),
            weekly_used_minutes=int(parsed["weekly_used_minutes"]),
            continuous_used_minutes=int(parsed["continuous_used_minutes"]),
            rule_source_id=policy.rule_source_id,
            rule_source_version=policy.rule_source_version,
            rule_source_sha256=policy.rule_source_sha256,
        )
        decision = evaluate_parental_internet_policy(policy=policy, query=query)
        selected_view = str(parsed["view"])
        projection = (
            cozy_parental_internet_projection(decision)
            if selected_view == "cozy"
            else full_parental_internet_projection(decision)
        )
        return {
            "schema": PREVIEW_RESULT_SCHEMA,
            "member_id": subject,
            "view": selected_view,
            "policy_id": policy.policy_id,
            "policy_sha256": desired["policy_sha256"],
            "decision": projection,
            "preview_only": True,
            "enforcement_verified": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }
