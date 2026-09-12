"""Read-only Actual-State verification for Home Center 0.60 parental policy.

The verifier never invokes an adapter and never mutates Home Center or provider state.
It may report ``enforcement_verified=true`` only for fresh exact-bound observations of
both required enforcement planes against the current protected Desired State.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .parental_internet_policy_adapter import (
    ParentalInternetEnforcementApplyRequest,
    ParentalInternetEnforcementApplyResult,
    ParentalInternetEnforcementObservation,
)
from .parental_internet_policy_change_api import (
    ParentalInternetPolicyChangeAPIError,
    full_parental_internet_desired_projection,
)
from .util import canonical_json

VERIFICATION_SCHEMA = "home-center.parental-internet-enforcement-verification.v1"
_RFC3339_UTC_SECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
MIN_FRESHNESS_SECONDS = 30
MAX_FRESHNESS_SECONDS = 3600
DEFAULT_FRESHNESS_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 5


class ParentalInternetEnforcementVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _time(value: object, *, code: str) -> datetime:
    if not isinstance(value, str) or _RFC3339_UTC_SECONDS.fullmatch(value) is None:
        raise ParentalInternetEnforcementVerificationError(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ParentalInternetEnforcementVerificationError(code) from exc


@dataclass(frozen=True, slots=True)
class ParentalInternetEnforcementVerification:
    adapter_id: str
    adapter_version: str
    provider_operation_id: str
    desired_state_sha256: str
    policy_sha256: str
    observation_sha256: str
    observed_at: str
    verified_at: str
    freshness_seconds: int
    dns_verified: bool
    proxy_verified: bool
    blockers: tuple[str, ...]
    schema: str = field(default=VERIFICATION_SCHEMA, init=False)
    backend_mutation_performed: bool = field(default=False, init=False)
    infrastructure_mutation_performed: bool = field(default=False, init=False)
    external_publication_performed: bool = field(default=False, init=False)

    @property
    def enforcement_verified(self) -> bool:
        return not self.blockers and self.dns_verified and self.proxy_verified

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "provider_operation_id": self.provider_operation_id,
            "desired_state_sha256": self.desired_state_sha256,
            "policy_sha256": self.policy_sha256,
            "observation_sha256": self.observation_sha256,
            "observed_at": self.observed_at,
            "verified_at": self.verified_at,
            "freshness_seconds": self.freshness_seconds,
            "dns_verified": self.dns_verified,
            "proxy_verified": self.proxy_verified,
            "blockers": list(self.blockers),
            "enforcement_verified": self.enforcement_verified,
            "backend_mutation_performed": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
        }


def verify_parental_internet_enforcement(
    *,
    current_desired_state: object,
    apply_request: ParentalInternetEnforcementApplyRequest,
    apply_result: ParentalInternetEnforcementApplyResult,
    observation: ParentalInternetEnforcementObservation,
    verified_at: str,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
) -> ParentalInternetEnforcementVerification:
    """Verify one observation without provider reinvocation or state mutation."""

    if not isinstance(apply_request, ParentalInternetEnforcementApplyRequest):
        raise TypeError("parental_enforcement_apply_request_invalid")
    if not isinstance(apply_result, ParentalInternetEnforcementApplyResult):
        raise TypeError("parental_enforcement_apply_result_invalid")
    if not isinstance(observation, ParentalInternetEnforcementObservation):
        raise TypeError("parental_enforcement_observation_invalid")
    if type(freshness_seconds) is not int or not MIN_FRESHNESS_SECONDS <= freshness_seconds <= MAX_FRESHNESS_SECONDS:
        raise ParentalInternetEnforcementVerificationError("parental_enforcement_freshness_invalid")
    now = _time(verified_at, code="parental_enforcement_verified_at_invalid")
    observed = _time(observation.observed_at, code="parental_enforcement_observed_at_invalid")

    try:
        projection = full_parental_internet_desired_projection(current_desired_state)
    except ParentalInternetPolicyChangeAPIError as exc:
        raise ParentalInternetEnforcementVerificationError(
            "parental_enforcement_current_desired_state_invalid"
        ) from exc
    if not isinstance(current_desired_state, dict):
        raise ParentalInternetEnforcementVerificationError(
            "parental_enforcement_current_desired_state_invalid"
        )
    policy = projection.get("policy")
    if not isinstance(policy, dict):
        raise ParentalInternetEnforcementVerificationError(
            "parental_enforcement_current_desired_state_invalid"
        )

    blockers: list[str] = []
    current_desired_sha = _digest(current_desired_state)
    current_policy_sha = str(projection["policy_sha256"])

    expected_apply_binding = (
        apply_request.household_id == projection["household_id"]
        and apply_request.member_id == projection["member_id"]
        and apply_request.desired_generation == projection["generation"]
        and apply_request.desired_plan_id == projection["plan_id"]
        and apply_request.desired_state_sha256 == current_desired_sha
        and apply_request.verified_base_state_sha256 == projection["verified_base_state_sha256"]
        and apply_request.policy_id == policy.get("policy_id")
        and apply_request.policy_sha256 == current_policy_sha
        and apply_request.policy == policy
        and apply_request.adapter_execution_authorized is True
        and apply_request.credential_value_access_authorized is False
        and apply_request.external_publication_authorized is False
        and apply_request.enforcement_verified is False
    )
    if not expected_apply_binding:
        blockers.append("apply_request_binding_mismatch")

    if (
        apply_result.adapter_id != apply_request.adapter_id
        or apply_result.adapter_version != apply_request.adapter_version
        or apply_result.post_condition_verified is not False
        or apply_result.enforcement_verified is not False
        or apply_result.actual_state_readback_required is not True
    ):
        blockers.append("apply_result_binding_mismatch")

    if (
        observation.adapter_id != apply_request.adapter_id
        or observation.adapter_version != apply_request.adapter_version
        or observation.provider_operation_id != apply_result.provider_operation_id
        or observation.desired_state_sha256 != current_desired_sha
        or observation.policy_sha256 != current_policy_sha
        or observation.backend_mutation_performed is not False
        or observation.infrastructure_mutation_performed is not False
        or observation.external_publication_performed is not False
        or observation.enforcement_verified is not False
    ):
        blockers.append("observation_binding_mismatch")

    age = (now - observed).total_seconds()
    if age < -MAX_FUTURE_SKEW_SECONDS:
        blockers.append("observation_from_future")
    elif age > freshness_seconds:
        blockers.append("observation_stale")

    dns_verified = (
        observation.dns_state == "enforced"
        and observation.dns_policy_sha256 == current_policy_sha
    )
    proxy_verified = (
        observation.proxy_state == "enforced"
        and observation.proxy_policy_sha256 == current_policy_sha
    )
    if not dns_verified:
        blockers.append(
            "dns_policy_mismatch"
            if observation.dns_state == "enforced"
            else "dns_not_enforced"
        )
    if not proxy_verified:
        blockers.append(
            "proxy_policy_mismatch"
            if observation.proxy_state == "enforced"
            else "proxy_not_enforced"
        )
    if observation.blocker is not None:
        blockers.append("adapter_blocker:" + observation.blocker)

    blockers = list(dict.fromkeys(blockers))
    return ParentalInternetEnforcementVerification(
        adapter_id=apply_request.adapter_id,
        adapter_version=apply_request.adapter_version,
        provider_operation_id=apply_result.provider_operation_id,
        desired_state_sha256=current_desired_sha,
        policy_sha256=current_policy_sha,
        observation_sha256=_digest(observation.to_dict()),
        observed_at=observation.observed_at,
        verified_at=verified_at,
        freshness_seconds=freshness_seconds,
        dns_verified=dns_verified,
        proxy_verified=proxy_verified,
        blockers=tuple(blockers),
    )
