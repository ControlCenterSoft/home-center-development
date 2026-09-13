"""Validate the exact verified Home Center 0.59 child-policy base for 0.60."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .household import HouseholdRole, InternetPolicy
from .household_policy_composer import COMPOSED_POLICY_SCHEMA, ComposedPolicy
from .household_policy_runtime import DESIRED_STATE_SCHEMA
from .household_policy_verification_state import VERIFIED_STATE_SCHEMA
from .util import canonical_json

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_ID = re.compile(r"hcpol-[0-9a-f]{24}\Z")
_BUNDLE_ID = re.compile(r"hpb-[0-9a-f]{24}\Z")


class ParentalInternetVerifiedBaseError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifiedParentalPolicyBase:
    household_id: str
    member_id: str
    policy: ComposedPolicy
    policy_sha256: str
    verified_state_sha256: str
    source_desired_state_sha256: str
    desired_generation: int
    desired_plan_id: str
    request_id: str
    backend_id: str
    evidence_id: str
    evidence_sha256: str
    observed_at: str


def _composed_policy(value: object) -> ComposedPolicy:
    required = {
        "schema", "policy_id", "household_id", "member_id", "role", "base_policy_id",
        "bundle_id", "internet_policy", "vpn_allowed", "managed_device_required",
        "home_files_allowed", "smart_home_control_allowed", "administration_allowed",
        "external_publication_allowed", "enforcement_verified", "production_mutation_enabled",
        "explanation_ru",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != COMPOSED_POLICY_SCHEMA:
        raise ParentalInternetVerifiedBaseError("parental_verified_base_policy_invalid")
    try:
        role = HouseholdRole(value["role"])
        internet = InternetPolicy(value["internet_policy"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ParentalInternetVerifiedBaseError("parental_verified_base_policy_invalid") from exc
    explanation = value.get("explanation_ru")
    if (
        role is not HouseholdRole.CHILD
        or internet is InternetPolicy.FULL
        or value.get("vpn_allowed") is not False
        or value.get("managed_device_required") is not True
        or value.get("smart_home_control_allowed") is not False
        or value.get("administration_allowed") is not False
        or value.get("external_publication_allowed") is not False
        or value.get("enforcement_verified") is not False
        or value.get("production_mutation_enabled") is not False
        or not isinstance(explanation, str)
        or not explanation
        or len(explanation) > 1024
        or any(ord(ch) < 32 for ch in explanation)
        or not isinstance(value.get("policy_id"), str)
        or _POLICY_ID.fullmatch(value["policy_id"]) is None
        or not isinstance(value.get("bundle_id"), str)
        or _BUNDLE_ID.fullmatch(value["bundle_id"]) is None
    ):
        raise ParentalInternetVerifiedBaseError("parental_verified_base_policy_invalid")
    for name in ("household_id", "member_id", "base_policy_id"):
        item = value.get(name)
        if not isinstance(item, str) or not item or len(item) > 128:
            raise ParentalInternetVerifiedBaseError("parental_verified_base_policy_invalid")
    if type(value.get("home_files_allowed")) is not bool:
        raise ParentalInternetVerifiedBaseError("parental_verified_base_policy_invalid")
    canonical = {
        "household_id": value["household_id"],
        "member_id": value["member_id"],
        "role": role.value,
        "base_policy_id": value["base_policy_id"],
        "bundle_id": value["bundle_id"],
        "internet_policy": internet.value,
        "vpn_allowed": False,
        "managed_device_required": True,
        "home_files_allowed": value["home_files_allowed"],
        "smart_home_control_allowed": False,
        "administration_allowed": False,
        "external_publication_allowed": False,
    }
    if value["policy_id"] != "hcpol-" + _digest(canonical)[:24]:
        raise ParentalInternetVerifiedBaseError("parental_verified_base_policy_identity_mismatch")
    policy = ComposedPolicy(
        policy_id=value["policy_id"],
        household_id=value["household_id"],
        member_id=value["member_id"],
        role=role,
        base_policy_id=value["base_policy_id"],
        bundle_id=value["bundle_id"],
        internet_policy=internet,
        vpn_allowed=False,
        managed_device_required=True,
        home_files_allowed=value["home_files_allowed"],
        smart_home_control_allowed=False,
        administration_allowed=False,
        explanation_ru=explanation,
    )
    if policy.to_dict() != value:
        raise ParentalInternetVerifiedBaseError("parental_verified_base_policy_invalid")
    return policy


def verified_parental_policy_base_from_dict(value: object) -> VerifiedParentalPolicyBase:
    required = {
        "schema", "household_id", "member_id", "desired_generation", "desired_plan_id",
        "policy_id", "policy_sha256", "source_desired_state_sha256", "request_id",
        "backend_id", "evidence_id", "evidence_sha256", "observed_at",
        "enforcement_verified", "reconciliation_required", "backend_mutation_performed",
        "infrastructure_mutation_performed", "external_publication_performed", "desired_state",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != VERIFIED_STATE_SCHEMA:
        raise ParentalInternetVerifiedBaseError("parental_verified_base_invalid")
    if (
        value.get("enforcement_verified") is not True
        or value.get("reconciliation_required") is not False
        or value.get("backend_mutation_performed") is not False
        or value.get("infrastructure_mutation_performed") is not False
        or value.get("external_publication_performed") is not False
    ):
        raise ParentalInternetVerifiedBaseError("parental_verified_base_not_verified")
    desired = value.get("desired_state")
    desired_required = {
        "schema", "household_id", "member_id", "generation", "plan_id", "policy",
        "policy_sha256", "reason", "enforcement_verified", "reconciliation_required",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    }
    if (
        not isinstance(desired, dict)
        or set(desired) != desired_required
        or desired.get("schema") != DESIRED_STATE_SCHEMA
        or desired.get("enforcement_verified") is not False
        or desired.get("reconciliation_required") is not True
        or desired.get("infrastructure_mutation_authorized") is not False
        or desired.get("external_publication_authorized") is not False
    ):
        raise ParentalInternetVerifiedBaseError("parental_verified_base_desired_state_invalid")
    policy = _composed_policy(desired.get("policy"))
    policy_sha256 = _digest(policy.to_dict())
    desired_sha256 = _digest(desired)
    generation = value.get("desired_generation")
    if (
        type(generation) is not int
        or generation < 1
        or desired.get("household_id") != value.get("household_id")
        or desired.get("member_id") != value.get("member_id")
        or desired.get("generation") != generation
        or desired.get("plan_id") != value.get("desired_plan_id")
        or desired.get("policy_sha256") != policy_sha256
        or value.get("policy_id") != policy.policy_id
        or value.get("policy_sha256") != policy_sha256
        or value.get("source_desired_state_sha256") != desired_sha256
        or policy.household_id != value.get("household_id")
        or policy.member_id != value.get("member_id")
    ):
        raise ParentalInternetVerifiedBaseError("parental_verified_base_binding_mismatch")
    for name in ("policy_sha256", "source_desired_state_sha256", "evidence_sha256"):
        item = value.get(name)
        if not isinstance(item, str) or _SHA256.fullmatch(item) is None:
            raise ParentalInternetVerifiedBaseError("parental_verified_base_digest_invalid")
    for name in ("household_id", "member_id", "desired_plan_id", "request_id", "backend_id", "evidence_id", "observed_at"):
        item = value.get(name)
        if not isinstance(item, str) or not item or len(item) > 256:
            raise ParentalInternetVerifiedBaseError("parental_verified_base_identity_invalid")
    return VerifiedParentalPolicyBase(
        household_id=value["household_id"],
        member_id=value["member_id"],
        policy=policy,
        policy_sha256=policy_sha256,
        verified_state_sha256=_digest(value),
        source_desired_state_sha256=desired_sha256,
        desired_generation=generation,
        desired_plan_id=value["desired_plan_id"],
        request_id=value["request_id"],
        backend_id=value["backend_id"],
        evidence_id=value["evidence_id"],
        evidence_sha256=value["evidence_sha256"],
        observed_at=value["observed_at"],
    )
