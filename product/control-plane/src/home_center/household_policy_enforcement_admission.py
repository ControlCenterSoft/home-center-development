"""Fail-closed policy enforcement admission preparation for Home Center 0.59.

This module deliberately stops before backend mutation. It binds a future
policy-enforcement attempt to one exact protected Desired State and one exact
backend capability evidence identity, then evaluates whether the request is
ready to cross into a later execution boundary.

A positive admission decision is evidence only. It never invokes a backend,
never grants execution/publication/infrastructure authority and always requires
fresh exact-state revalidation immediately before a future mutation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .util import canonical_json

DESIRED_STATE_SCHEMA = "home-center.household-policy-desired-state.v1"
PLAN_SCHEMA = "home-center.household-policy-enforcement-plan.v1"
DECISION_SCHEMA = "home-center.household-policy-enforcement-admission.v1"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PLAN_ID = re.compile(r"^hpenf-[0-9a-f]{24}$")
_PLAN_FIELDS = {
    "schema",
    "plan_id",
    "household_id",
    "member_id",
    "desired_generation",
    "source_plan_id",
    "policy_id",
    "policy_sha256",
    "desired_state_sha256",
    "backend_id",
    "backend_version",
    "backend_capability_evidence_sha256",
    "post_condition_verification_required",
    "fresh_revalidation_required",
    "automatic_retry_authorized",
    "execution_authorized",
    "infrastructure_mutation_authorized",
    "external_publication_authorized",
}


class HouseholdPolicyEnforcementAdmissionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise HouseholdPolicyEnforcementAdmissionError(code)
    return value


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise HouseholdPolicyEnforcementAdmissionError(code)
    return value


def _positive_int(value: object, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise HouseholdPolicyEnforcementAdmissionError(code)
    return value


def _validate_desired_state(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != DESIRED_STATE_SCHEMA:
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_desired_state_invalid")

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
    if set(value) != required:
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_desired_state_invalid")

    household_id = _identifier(
        value.get("household_id"), "household_policy_household_id_invalid"
    )
    member_id = _identifier(value.get("member_id"), "household_policy_member_id_invalid")
    source_plan_id = _identifier(
        value.get("plan_id"), "household_policy_source_plan_id_invalid"
    )
    generation = _positive_int(
        value.get("generation"), "household_policy_desired_generation_invalid"
    )

    policy = value.get("policy")
    if not isinstance(policy, dict):
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_desired_policy_invalid")
    policy_id = _identifier(policy.get("policy_id"), "household_policy_policy_id_invalid")
    if policy.get("household_id") != household_id:
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_policy_household_mismatch")
    if policy.get("member_id") != member_id:
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_policy_member_mismatch")

    policy_sha256 = _sha256(
        value.get("policy_sha256"), "household_policy_policy_digest_invalid"
    )
    if _digest(policy) != policy_sha256:
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_policy_digest_mismatch")

    if value.get("enforcement_verified") is not False:
        raise HouseholdPolicyEnforcementAdmissionError(
            "household_policy_already_enforcement_verified"
        )
    if value.get("reconciliation_required") is not True:
        raise HouseholdPolicyEnforcementAdmissionError(
            "household_policy_reconciliation_not_required"
        )
    if value.get("infrastructure_mutation_authorized") is not False:
        raise HouseholdPolicyEnforcementAdmissionError(
            "household_policy_infrastructure_authority_rejected"
        )
    if value.get("external_publication_authorized") is not False:
        raise HouseholdPolicyEnforcementAdmissionError(
            "household_policy_publication_authority_rejected"
        )

    reason = value.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 512:
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_reason_invalid")

    normalized = dict(value)
    normalized["household_id"] = household_id
    normalized["member_id"] = member_id
    normalized["generation"] = generation
    normalized["plan_id"] = source_plan_id
    normalized["policy"] = dict(policy)
    normalized["policy"]["policy_id"] = policy_id
    normalized["policy_sha256"] = policy_sha256
    return normalized


def _plan_canonical(
    *,
    household_id: str,
    member_id: str,
    desired_generation: int,
    source_plan_id: str,
    policy_id: str,
    policy_sha256: str,
    desired_state_sha256: str,
    backend_id: str,
    backend_version: str,
    backend_capability_evidence_sha256: str,
) -> dict[str, object]:
    return {
        "household_id": household_id,
        "member_id": member_id,
        "desired_generation": desired_generation,
        "source_plan_id": source_plan_id,
        "policy_id": policy_id,
        "policy_sha256": policy_sha256,
        "desired_state_sha256": desired_state_sha256,
        "backend_id": backend_id,
        "backend_version": backend_version,
        "backend_capability_evidence_sha256": backend_capability_evidence_sha256,
    }


def _plan_id(canonical: dict[str, object]) -> str:
    return "hpenf-" + _digest(canonical)[:24]


@dataclass(frozen=True, slots=True)
class PolicyEnforcementPlan:
    plan_id: str
    household_id: str
    member_id: str
    desired_generation: int
    source_plan_id: str
    policy_id: str
    policy_sha256: str
    desired_state_sha256: str
    backend_id: str
    backend_version: str
    backend_capability_evidence_sha256: str
    schema: str = field(default=PLAN_SCHEMA, init=False)
    post_condition_verification_required: bool = field(default=True, init=False)
    fresh_revalidation_required: bool = field(default=True, init=False)
    automatic_retry_authorized: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "desired_generation": self.desired_generation,
            "source_plan_id": self.source_plan_id,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "desired_state_sha256": self.desired_state_sha256,
            "backend_id": self.backend_id,
            "backend_version": self.backend_version,
            "backend_capability_evidence_sha256": self.backend_capability_evidence_sha256,
            "post_condition_verification_required": True,
            "fresh_revalidation_required": True,
            "automatic_retry_authorized": False,
            "execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class PolicyEnforcementAdmissionDecision:
    plan_id: str
    ready: bool
    blockers: tuple[str, ...]
    schema: str = field(default=DECISION_SCHEMA, init=False)
    post_condition_verification_required: bool = field(default=True, init=False)
    fresh_revalidation_required: bool = field(default=True, init=False)
    automatic_retry_authorized: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "ready": self.ready,
            "blockers": list(self.blockers),
            "post_condition_verification_required": True,
            "fresh_revalidation_required": True,
            "automatic_retry_authorized": False,
            "execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def build_policy_enforcement_plan(
    *,
    desired_state: object,
    backend_id: object,
    backend_version: object,
    backend_capability_evidence_sha256: object,
) -> PolicyEnforcementPlan:
    desired = _validate_desired_state(desired_state)
    backend = _identifier(backend_id, "household_policy_backend_id_invalid")
    version = _identifier(backend_version, "household_policy_backend_version_invalid")
    capability_digest = _sha256(
        backend_capability_evidence_sha256,
        "household_policy_backend_capability_evidence_invalid",
    )
    canonical = _plan_canonical(
        household_id=desired["household_id"],
        member_id=desired["member_id"],
        desired_generation=desired["generation"],
        source_plan_id=desired["plan_id"],
        policy_id=desired["policy"]["policy_id"],
        policy_sha256=desired["policy_sha256"],
        desired_state_sha256=_digest(desired),
        backend_id=backend,
        backend_version=version,
        backend_capability_evidence_sha256=capability_digest,
    )
    return PolicyEnforcementPlan(
        plan_id=_plan_id(canonical),
        household_id=str(canonical["household_id"]),
        member_id=str(canonical["member_id"]),
        desired_generation=int(canonical["desired_generation"]),
        source_plan_id=str(canonical["source_plan_id"]),
        policy_id=str(canonical["policy_id"]),
        policy_sha256=str(canonical["policy_sha256"]),
        desired_state_sha256=str(canonical["desired_state_sha256"]),
        backend_id=backend,
        backend_version=version,
        backend_capability_evidence_sha256=capability_digest,
    )


def policy_enforcement_plan_from_dict(value: object) -> PolicyEnforcementPlan:
    if (
        not isinstance(value, dict)
        or value.get("schema") != PLAN_SCHEMA
        or set(value) != _PLAN_FIELDS
    ):
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_enforcement_plan_invalid")

    supplied_plan_id = value.get("plan_id")
    if not isinstance(supplied_plan_id, str) or _PLAN_ID.fullmatch(supplied_plan_id) is None:
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_enforcement_plan_invalid")
    for field_name in ("post_condition_verification_required", "fresh_revalidation_required"):
        if value.get(field_name) is not True:
            raise HouseholdPolicyEnforcementAdmissionError("household_policy_enforcement_plan_invalid")
    for field_name in (
        "automatic_retry_authorized",
        "execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        if value.get(field_name) is not False:
            raise HouseholdPolicyEnforcementAdmissionError("household_policy_enforcement_plan_invalid")

    canonical = _plan_canonical(
        household_id=_identifier(value.get("household_id"), "household_policy_enforcement_plan_invalid"),
        member_id=_identifier(value.get("member_id"), "household_policy_enforcement_plan_invalid"),
        desired_generation=_positive_int(
            value.get("desired_generation"), "household_policy_enforcement_plan_invalid"
        ),
        source_plan_id=_identifier(
            value.get("source_plan_id"), "household_policy_enforcement_plan_invalid"
        ),
        policy_id=_identifier(value.get("policy_id"), "household_policy_enforcement_plan_invalid"),
        policy_sha256=_sha256(
            value.get("policy_sha256"), "household_policy_enforcement_plan_invalid"
        ),
        desired_state_sha256=_sha256(
            value.get("desired_state_sha256"), "household_policy_enforcement_plan_invalid"
        ),
        backend_id=_identifier(value.get("backend_id"), "household_policy_enforcement_plan_invalid"),
        backend_version=_identifier(
            value.get("backend_version"), "household_policy_enforcement_plan_invalid"
        ),
        backend_capability_evidence_sha256=_sha256(
            value.get("backend_capability_evidence_sha256"),
            "household_policy_enforcement_plan_invalid",
        ),
    )
    if supplied_plan_id != _plan_id(canonical):
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_enforcement_plan_invalid")

    return PolicyEnforcementPlan(
        plan_id=supplied_plan_id,
        household_id=str(canonical["household_id"]),
        member_id=str(canonical["member_id"]),
        desired_generation=int(canonical["desired_generation"]),
        source_plan_id=str(canonical["source_plan_id"]),
        policy_id=str(canonical["policy_id"]),
        policy_sha256=str(canonical["policy_sha256"]),
        desired_state_sha256=str(canonical["desired_state_sha256"]),
        backend_id=str(canonical["backend_id"]),
        backend_version=str(canonical["backend_version"]),
        backend_capability_evidence_sha256=str(
            canonical["backend_capability_evidence_sha256"]
        ),
    )


def evaluate_policy_enforcement_admission(
    *,
    plan: PolicyEnforcementPlan,
    explicit_confirmation: bool,
    actor_authority_current: bool,
    scoped_reauth_current: bool,
    desired_state_current: bool,
    backend_registered: bool,
    backend_mutation_capable: bool,
    backend_readback_capable: bool,
    backend_capability_evidence_current: bool,
) -> PolicyEnforcementAdmissionDecision:
    if not isinstance(plan, PolicyEnforcementPlan):
        raise HouseholdPolicyEnforcementAdmissionError("household_policy_enforcement_plan_invalid")

    blockers: list[str] = []
    checks = (
        (explicit_confirmation, "explicit_confirmation_required"),
        (actor_authority_current, "actor_authority_stale_or_missing"),
        (scoped_reauth_current, "scoped_reauth_required"),
        (desired_state_current, "desired_state_stale_or_mismatched"),
        (backend_registered, "backend_not_registered"),
        (backend_mutation_capable, "backend_mutation_capability_missing"),
        (backend_readback_capable, "backend_readback_capability_missing"),
        (
            backend_capability_evidence_current,
            "backend_capability_evidence_stale_or_mismatched",
        ),
    )
    for passed, blocker in checks:
        if type(passed) is not bool:
            raise HouseholdPolicyEnforcementAdmissionError(
                "household_policy_enforcement_admission_input_invalid"
            )
        if not passed:
            blockers.append(blocker)

    return PolicyEnforcementAdmissionDecision(
        plan_id=plan.plan_id,
        ready=not blockers,
        blockers=tuple(blockers),
    )
