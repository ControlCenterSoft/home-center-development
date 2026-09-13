"""Fail-closed admission evidence for Home Center 0.59 policy enforcement.

The current enforcement runtime can perform one deliberately qualified backend
mutation after explicit confirmation.  This module defines the independent
pre-mutation admission decision that future runtime wiring must satisfy before
crossing that boundary.  A positive decision is evidence only: it never grants
execution, infrastructure mutation, external publication, automatic retry or
an enforcement-success claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

PLAN_SCHEMA = "home-center.household-policy-enforcement-plan.v1"
DECISION_SCHEMA = "home-center.household-policy-enforcement-admission.v1"

_IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_MEMBER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PLAN_ID = re.compile(r"^hpep-[0-9a-f]{24}$")
_DESIRED_PLAN_ID = re.compile(r"^hpcp-[0-9a-f]{24}$")
_POLICY_ID = re.compile(r"^hcpol-[0-9a-f]{24}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_PLAN_FIELDS = {
    "schema",
    "plan_id",
    "household_id",
    "member_id",
    "backend_id",
    "desired_generation",
    "desired_plan_id",
    "policy_id",
    "policy_sha256",
    "desired_state_sha256",
    "backend_mutation_authorized",
    "automatic_retry_authorized",
    "enforcement_success_claim_authorized",
    "infrastructure_mutation_authorized",
    "external_publication_authorized",
}


class HouseholdPolicyEnforcementAdmissionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _text(value: object, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise HouseholdPolicyEnforcementAdmissionError(code)
    return value


def _sha256(value: object, code: str) -> str:
    return _text(value, _SHA256, code)


def _validate_current_plan(value: object) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != _PLAN_FIELDS
        or value.get("schema") != PLAN_SCHEMA
    ):
        raise HouseholdPolicyEnforcementAdmissionError(
            "household_policy_enforcement_admission_plan_invalid"
        )

    normalized = dict(value)
    normalized["plan_id"] = _text(
        value.get("plan_id"), _PLAN_ID, "household_policy_enforcement_admission_plan_invalid"
    )
    normalized["household_id"] = _text(
        value.get("household_id"), _MEMBER, "household_policy_enforcement_admission_plan_invalid"
    )
    normalized["member_id"] = _text(
        value.get("member_id"), _MEMBER, "household_policy_enforcement_admission_plan_invalid"
    )
    normalized["backend_id"] = _text(
        value.get("backend_id"), _IDENTIFIER, "household_policy_enforcement_admission_plan_invalid"
    )
    generation = value.get("desired_generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise HouseholdPolicyEnforcementAdmissionError(
            "household_policy_enforcement_admission_plan_invalid"
        )
    normalized["desired_generation"] = generation
    normalized["desired_plan_id"] = _text(
        value.get("desired_plan_id"),
        _DESIRED_PLAN_ID,
        "household_policy_enforcement_admission_plan_invalid",
    )
    normalized["policy_id"] = _text(
        value.get("policy_id"), _POLICY_ID, "household_policy_enforcement_admission_plan_invalid"
    )
    normalized["policy_sha256"] = _sha256(
        value.get("policy_sha256"), "household_policy_enforcement_admission_plan_invalid"
    )
    normalized["desired_state_sha256"] = _sha256(
        value.get("desired_state_sha256"), "household_policy_enforcement_admission_plan_invalid"
    )

    for name in (
        "backend_mutation_authorized",
        "automatic_retry_authorized",
        "enforcement_success_claim_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        if value.get(name) is not False:
            raise HouseholdPolicyEnforcementAdmissionError(
                "household_policy_enforcement_admission_plan_invalid"
            )
    return normalized


@dataclass(frozen=True, slots=True)
class PolicyEnforcementAdmissionDecision:
    plan_id: str
    backend_id: str
    backend_version: str
    backend_capability_evidence_sha256: str
    ready: bool
    blockers: tuple[str, ...]
    schema: str = field(default=DECISION_SCHEMA, init=False)
    post_condition_verification_required: bool = field(default=True, init=False)
    fresh_revalidation_required: bool = field(default=True, init=False)
    automatic_retry_authorized: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    enforcement_success_claim_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "backend_id": self.backend_id,
            "backend_version": self.backend_version,
            "backend_capability_evidence_sha256": self.backend_capability_evidence_sha256,
            "ready": self.ready,
            "blockers": list(self.blockers),
            "post_condition_verification_required": True,
            "fresh_revalidation_required": True,
            "automatic_retry_authorized": False,
            "execution_authorized": False,
            "enforcement_success_claim_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def evaluate_policy_enforcement_admission(
    *,
    plan: object,
    backend_version: object,
    backend_capability_evidence_sha256: object,
    explicit_confirmation: bool,
    actor_authority_current: bool,
    scoped_reauth_current: bool,
    desired_state_current: bool,
    backend_registered: bool,
    backend_mutation_capable: bool,
    backend_readback_capable: bool,
    backend_qualification_current: bool,
) -> PolicyEnforcementAdmissionDecision:
    """Evaluate bounded pre-mutation evidence without creating authority."""

    current_plan = _validate_current_plan(plan)
    version = _text(
        backend_version,
        _MEMBER,
        "household_policy_enforcement_backend_version_invalid",
    )
    capability_digest = _sha256(
        backend_capability_evidence_sha256,
        "household_policy_enforcement_backend_capability_evidence_invalid",
    )

    checks = (
        (explicit_confirmation, "explicit_confirmation_required"),
        (actor_authority_current, "actor_authority_stale_or_missing"),
        (scoped_reauth_current, "scoped_reauth_required"),
        (desired_state_current, "desired_state_stale_or_mismatched"),
        (backend_registered, "backend_not_registered"),
        (backend_mutation_capable, "backend_mutation_capability_missing"),
        (backend_readback_capable, "backend_readback_capability_missing"),
        (backend_qualification_current, "backend_qualification_stale_or_mismatched"),
    )
    blockers: list[str] = []
    for passed, blocker in checks:
        if type(passed) is not bool:
            raise HouseholdPolicyEnforcementAdmissionError(
                "household_policy_enforcement_admission_input_invalid"
            )
        if not passed:
            blockers.append(blocker)

    return PolicyEnforcementAdmissionDecision(
        plan_id=str(current_plan["plan_id"]),
        backend_id=str(current_plan["backend_id"]),
        backend_version=version,
        backend_capability_evidence_sha256=capability_digest,
        ready=not blockers,
        blockers=tuple(blockers),
    )
