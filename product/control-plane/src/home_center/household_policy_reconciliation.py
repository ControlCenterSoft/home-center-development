"""Typed, read-only Actual State verification for Home Center 0.59 Policy Composer.

This module deliberately does not execute or mutate a policy backend.  It binds one
protected Household policy Desired State to one explicitly selected backend read-back
and returns deterministic verification evidence.  ``enforcement_verified`` can become
true only when a fresh, exact-bound read-back proves the exact desired policy digest.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .util import canonical_json

REQUEST_SCHEMA = "home-center.household-policy-reconciliation-request.v1"
OBSERVATION_SCHEMA = "home-center.household-policy-actual-state-observation.v1"
EVIDENCE_SCHEMA = "home-center.household-policy-reconciliation-evidence.v1"
DESIRED_STATE_SCHEMA = "home-center.household-policy-desired-state.v1"

SHA256 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REQUEST_ID = re.compile(r"^hprq-[0-9a-f]{24}$")
EVIDENCE_ID = re.compile(r"^hpev-[0-9a-f]{24}$")
OBSERVED_STATES = frozenset({"enforced", "not-enforced", "unknown", "ambiguous"})
MAX_OBSERVATION_AGE_SECONDS = 900


class HouseholdPolicyReconciliationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _id(value: object, code: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise HouseholdPolicyReconciliationError(code)
    return value


def _sha(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise HouseholdPolicyReconciliationError(code)
    return value


def _generation(value: object, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise HouseholdPolicyReconciliationError(code)
    return value


def _timestamp(value: object, code: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or UTC_SECONDS.fullmatch(value) is None:
        raise HouseholdPolicyReconciliationError(code)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise HouseholdPolicyReconciliationError(code) from exc
    return value, parsed


def _max_age(value: object) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > MAX_OBSERVATION_AGE_SECONDS
    ):
        raise HouseholdPolicyReconciliationError("invalid_policy_reconciliation_max_age")
    return value


@dataclass(frozen=True, slots=True)
class PolicyReconciliationBinding:
    household_id: str
    member_id: str
    desired_generation: int
    desired_plan_id: str
    policy_id: str
    policy_sha256: str

    def __post_init__(self) -> None:
        _id(self.household_id, "invalid_policy_reconciliation_household_id")
        _id(self.member_id, "invalid_policy_reconciliation_member_id")
        _generation(self.desired_generation, "invalid_policy_reconciliation_generation")
        if (
            not isinstance(self.desired_plan_id, str)
            or re.fullmatch(r"hpcp-[0-9a-f]{24}", self.desired_plan_id) is None
        ):
            raise HouseholdPolicyReconciliationError("invalid_policy_reconciliation_plan_id")
        if (
            not isinstance(self.policy_id, str)
            or re.fullmatch(r"hcpol-[0-9a-f]{24}", self.policy_id) is None
        ):
            raise HouseholdPolicyReconciliationError("invalid_policy_reconciliation_policy_id")
        _sha(self.policy_sha256, "invalid_policy_reconciliation_policy_digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "household_id": self.household_id,
            "member_id": self.member_id,
            "desired_generation": self.desired_generation,
            "desired_plan_id": self.desired_plan_id,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
        }


@dataclass(frozen=True, slots=True)
class PolicyReconciliationRequest:
    request_id: str
    backend_id: str
    requested_at: str
    max_observed_age_seconds: int
    binding: PolicyReconciliationBinding
    schema: str = field(default=REQUEST_SCHEMA, init=False)
    backend_read_only_required: bool = field(default=True, init=False)
    backend_mutation_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "backend_id": self.backend_id,
            "requested_at": self.requested_at,
            "max_observed_age_seconds": self.max_observed_age_seconds,
            "binding": self.binding.to_dict(),
            "backend_read_only_required": True,
            "backend_mutation_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class PolicyActualStateObservation:
    request_id: str
    backend_id: str
    observed_at: str
    observed_state: str
    binding: PolicyReconciliationBinding
    actual_policy_sha256: str | None
    schema: str = field(default=OBSERVATION_SCHEMA, init=False)
    read_only: bool = field(default=True, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "backend_id": self.backend_id,
            "observed_at": self.observed_at,
            "observed_state": self.observed_state,
            "binding": self.binding.to_dict(),
            "actual_policy_sha256": self.actual_policy_sha256,
            "read_only": True,
        }


def _binding_from_dict(value: object) -> PolicyReconciliationBinding:
    expected = {
        "household_id",
        "member_id",
        "desired_generation",
        "desired_plan_id",
        "policy_id",
        "policy_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise HouseholdPolicyReconciliationError("invalid_policy_reconciliation_binding")
    return PolicyReconciliationBinding(**value)  # type: ignore[arg-type]


def build_reconciliation_request(
    *,
    desired_state: dict[str, object],
    backend_id: str,
    requested_at: str,
    max_observed_age_seconds: int,
) -> PolicyReconciliationRequest:
    required = {
        "schema",
        "household_id",
        "member_id",
        "generation",
        "plan_id",
        "policy",
        "policy_sha256",
        "reason",
        "enforcement_verified",
        "reconciliation_required",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(desired_state, dict) or set(desired_state) != required:
        raise HouseholdPolicyReconciliationError("invalid_policy_desired_state")
    if (
        desired_state.get("schema") != DESIRED_STATE_SCHEMA
        or desired_state.get("enforcement_verified") is not False
        or desired_state.get("reconciliation_required") is not True
        or desired_state.get("infrastructure_mutation_authorized") is not False
        or desired_state.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyReconciliationError("invalid_policy_desired_state")
    policy = desired_state.get("policy")
    if not isinstance(policy, dict):
        raise HouseholdPolicyReconciliationError("invalid_policy_desired_state")
    policy_sha256 = _sha(
        desired_state.get("policy_sha256"), "invalid_policy_reconciliation_policy_digest"
    )
    if _digest(policy) != policy_sha256:
        raise HouseholdPolicyReconciliationError("policy_desired_state_digest_mismatch")
    household_id = _id(
        desired_state.get("household_id"), "invalid_policy_reconciliation_household_id"
    )
    member_id = _id(desired_state.get("member_id"), "invalid_policy_reconciliation_member_id")
    if policy.get("household_id") != household_id or policy.get("member_id") != member_id:
        raise HouseholdPolicyReconciliationError("policy_desired_state_binding_mismatch")
    policy_id = policy.get("policy_id")
    binding = PolicyReconciliationBinding(
        household_id=household_id,
        member_id=member_id,
        desired_generation=_generation(
            desired_state.get("generation"), "invalid_policy_reconciliation_generation"
        ),
        desired_plan_id=str(desired_state.get("plan_id")),
        policy_id=str(policy_id),
        policy_sha256=policy_sha256,
    )
    backend_id = _id(backend_id, "invalid_policy_reconciliation_backend_id")
    requested_at, _ = _timestamp(requested_at, "invalid_policy_reconciliation_requested_at")
    max_age = _max_age(max_observed_age_seconds)
    identity = {
        "backend_id": backend_id,
        "requested_at": requested_at,
        "max_observed_age_seconds": max_age,
        "binding": binding.to_dict(),
    }
    return PolicyReconciliationRequest(
        request_id="hprq-" + _digest(identity)[:24],
        backend_id=backend_id,
        requested_at=requested_at,
        max_observed_age_seconds=max_age,
        binding=binding,
    )


def request_from_dict(value: object) -> PolicyReconciliationRequest:
    expected = {
        "schema",
        "request_id",
        "backend_id",
        "requested_at",
        "max_observed_age_seconds",
        "binding",
        "backend_read_only_required",
        "backend_mutation_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != REQUEST_SCHEMA:
        raise HouseholdPolicyReconciliationError("invalid_policy_reconciliation_request")
    if (
        value.get("backend_read_only_required") is not True
        or value.get("backend_mutation_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyReconciliationError("invalid_policy_reconciliation_request")
    binding = _binding_from_dict(value.get("binding"))
    requested_at, _ = _timestamp(
        value.get("requested_at"), "invalid_policy_reconciliation_requested_at"
    )
    backend_id = _id(value.get("backend_id"), "invalid_policy_reconciliation_backend_id")
    max_age = _max_age(value.get("max_observed_age_seconds"))
    identity = {
        "backend_id": backend_id,
        "requested_at": requested_at,
        "max_observed_age_seconds": max_age,
        "binding": binding.to_dict(),
    }
    request_id = value.get("request_id")
    if (
        not isinstance(request_id, str)
        or REQUEST_ID.fullmatch(request_id) is None
        or request_id != "hprq-" + _digest(identity)[:24]
    ):
        raise HouseholdPolicyReconciliationError("invalid_policy_reconciliation_request_id")
    return PolicyReconciliationRequest(request_id, backend_id, requested_at, max_age, binding)


def observation_from_dict(value: object) -> PolicyActualStateObservation:
    expected = {
        "schema",
        "request_id",
        "backend_id",
        "observed_at",
        "observed_state",
        "binding",
        "actual_policy_sha256",
        "read_only",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema") != OBSERVATION_SCHEMA
        or value.get("read_only") is not True
    ):
        raise HouseholdPolicyReconciliationError("invalid_policy_actual_state_observation")
    request_id = value.get("request_id")
    if not isinstance(request_id, str) or REQUEST_ID.fullmatch(request_id) is None:
        raise HouseholdPolicyReconciliationError("invalid_policy_reconciliation_request_id")
    backend_id = _id(value.get("backend_id"), "invalid_policy_reconciliation_backend_id")
    observed_at, _ = _timestamp(
        value.get("observed_at"), "invalid_policy_actual_state_observed_at"
    )
    state = value.get("observed_state")
    if state not in OBSERVED_STATES:
        raise HouseholdPolicyReconciliationError("invalid_policy_actual_state")
    digest = value.get("actual_policy_sha256")
    if digest is not None:
        digest = _sha(digest, "invalid_policy_actual_state_digest")
    if state == "enforced" and digest is None:
        raise HouseholdPolicyReconciliationError("policy_actual_state_digest_required")
    return PolicyActualStateObservation(
        request_id=request_id,
        backend_id=backend_id,
        observed_at=observed_at,
        observed_state=str(state),
        binding=_binding_from_dict(value.get("binding")),
        actual_policy_sha256=digest,
    )


def verify_policy_reconciliation(
    *,
    request: PolicyReconciliationRequest,
    observation: PolicyActualStateObservation,
    trusted_now: str,
) -> dict[str, object]:
    if not isinstance(request, PolicyReconciliationRequest) or not isinstance(
        observation, PolicyActualStateObservation
    ):
        raise TypeError("invalid_policy_reconciliation_input")
    _, now = _timestamp(trusted_now, "invalid_policy_reconciliation_trusted_time")
    _, requested_at = _timestamp(
        request.requested_at, "invalid_policy_reconciliation_requested_at"
    )
    _, observed_at = _timestamp(
        observation.observed_at, "invalid_policy_actual_state_observed_at"
    )
    if requested_at > now or observed_at > now:
        raise HouseholdPolicyReconciliationError("policy_reconciliation_future_evidence")
    if (now - observed_at).total_seconds() > request.max_observed_age_seconds:
        raise HouseholdPolicyReconciliationError("policy_reconciliation_observation_stale")
    if observation.request_id != request.request_id:
        raise HouseholdPolicyReconciliationError("policy_reconciliation_request_mismatch")
    if observation.backend_id != request.backend_id:
        raise HouseholdPolicyReconciliationError("policy_reconciliation_backend_mismatch")
    if observation.binding != request.binding:
        raise HouseholdPolicyReconciliationError("policy_reconciliation_binding_mismatch")

    if (
        observation.observed_state == "enforced"
        and observation.actual_policy_sha256 == request.binding.policy_sha256
    ):
        status = "verified"
        blocker = None
        enforcement_verified = True
        reconciliation_required = False
    elif observation.observed_state == "enforced":
        status = "mismatch"
        blocker = "actual-policy-digest-mismatch"
        enforcement_verified = False
        reconciliation_required = True
    elif observation.observed_state == "not-enforced":
        status = "pending"
        blocker = "policy-not-enforced"
        enforcement_verified = False
        reconciliation_required = True
    else:
        status = "blocked"
        blocker = "actual-state-" + observation.observed_state
        enforcement_verified = False
        reconciliation_required = True

    material = {
        "request": request.to_dict(),
        "observation": observation.to_dict(),
        "status": status,
        "blocker": blocker,
        "enforcement_verified": enforcement_verified,
        "reconciliation_required": reconciliation_required,
    }
    evidence_id = "hpev-" + _digest(material)[:24]
    assert EVIDENCE_ID.fullmatch(evidence_id) is not None
    return {
        "schema": EVIDENCE_SCHEMA,
        "evidence_id": evidence_id,
        "request_id": request.request_id,
        "backend_id": request.backend_id,
        "binding": request.binding.to_dict(),
        "observed_at": observation.observed_at,
        "observed_state": observation.observed_state,
        "actual_policy_sha256": observation.actual_policy_sha256,
        "status": status,
        "blocker": blocker,
        "enforcement_verified": enforcement_verified,
        "reconciliation_required": reconciliation_required,
        "backend_mutation_performed": False,
        "infrastructure_mutation_performed": False,
        "external_publication_performed": False,
    }
