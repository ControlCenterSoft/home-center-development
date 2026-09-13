"""Typed provider-neutral DNS/Proxy adapter boundary for Home Center 0.60.

This module defines contracts only.  It deliberately does not register a concrete
production adapter and never treats provider command acceptance as enforcement success.
Actual-State read-back and separate verification are required before any future
``enforcement_verified=true`` claim.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Protocol

from .parental_internet_policy_change_api import (
    ParentalInternetPolicyChangeAPIError,
    full_parental_internet_desired_projection,
)
from .util import canonical_json

CAPABILITIES_SCHEMA = "home-center.parental-internet-enforcement-adapter-capabilities.v1"
APPLY_REQUEST_SCHEMA = "home-center.parental-internet-enforcement-apply-request.v1"
APPLY_RESULT_SCHEMA = "home-center.parental-internet-enforcement-apply-result.v1"
READBACK_REQUEST_SCHEMA = "home-center.parental-internet-enforcement-readback-request.v1"
OBSERVATION_SCHEMA = "home-center.parental-internet-enforcement-observation.v1"
ROLLBACK_REQUEST_SCHEMA = "home-center.parental-internet-enforcement-rollback-request.v1"
ROLLBACK_RESULT_SCHEMA = "home-center.parental-internet-enforcement-rollback-result.v1"

_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_RFC3339_UTC_SECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_POLICY_STATE = frozenset({"enforced", "not-enforced", "unknown"})


class ParentalInternetEnforcementAdapterError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _identifier(value: object, *, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ParentalInternetEnforcementAdapterError(code)
    return value


def _version(value: object) -> str:
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        raise ParentalInternetEnforcementAdapterError("parental_adapter_version_invalid")
    return value


def _sha256(value: object, *, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ParentalInternetEnforcementAdapterError(code)
    return value


def _operation_id(value: object, *, code: str) -> str:
    if not isinstance(value, str) or _OPERATION_ID.fullmatch(value) is None:
        raise ParentalInternetEnforcementAdapterError(code)
    return value


def _job_id(value: object) -> str:
    if not isinstance(value, str) or _JOB_ID.fullmatch(value) is None:
        raise ParentalInternetEnforcementAdapterError("parental_adapter_job_id_invalid")
    return value


def _observed_at(value: object) -> str:
    if not isinstance(value, str) or _RFC3339_UTC_SECONDS.fullmatch(value) is None:
        raise ParentalInternetEnforcementAdapterError("parental_adapter_observed_at_invalid")
    return value


@dataclass(frozen=True, slots=True)
class ParentalInternetEnforcementAdapterCapabilities:
    adapter_id: str
    adapter_version: str
    supports_dns: bool
    supports_proxy: bool
    supports_readback: bool
    supports_rollback: bool
    schema: str = field(default=CAPABILITIES_SCHEMA, init=False)
    credential_value_access_required: bool = field(default=False, init=False)
    external_publication_required: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, code="parental_adapter_id_invalid")
        _version(self.adapter_version)
        for value in (
            self.supports_dns,
            self.supports_proxy,
            self.supports_readback,
            self.supports_rollback,
        ):
            if type(value) is not bool:
                raise ParentalInternetEnforcementAdapterError("parental_adapter_capabilities_invalid")
        if not self.supports_readback:
            raise ParentalInternetEnforcementAdapterError("parental_adapter_readback_required")
        if not self.supports_dns or not self.supports_proxy:
            raise ParentalInternetEnforcementAdapterError("parental_adapter_dns_proxy_required")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "supports_dns": self.supports_dns,
            "supports_proxy": self.supports_proxy,
            "supports_readback": self.supports_readback,
            "supports_rollback": self.supports_rollback,
            "credential_value_access_required": False,
            "external_publication_required": False,
        }


@dataclass(frozen=True, slots=True)
class ParentalInternetEnforcementApplyRequest:
    job_id: str
    adapter_id: str
    adapter_version: str
    household_id: str
    member_id: str
    desired_generation: int
    desired_plan_id: str
    desired_state_sha256: str
    verified_base_state_sha256: str
    policy_id: str
    policy_sha256: str
    policy: dict[str, object]
    schema: str = field(default=APPLY_REQUEST_SCHEMA, init=False)
    adapter_execution_authorized: bool = field(default=True, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)
    enforcement_verified: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "desired_generation": self.desired_generation,
            "desired_plan_id": self.desired_plan_id,
            "desired_state_sha256": self.desired_state_sha256,
            "verified_base_state_sha256": self.verified_base_state_sha256,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "policy": self.policy,
            "adapter_execution_authorized": True,
            "credential_value_access_authorized": False,
            "external_publication_authorized": False,
            "enforcement_verified": False,
        }


@dataclass(frozen=True, slots=True)
class ParentalInternetEnforcementApplyResult:
    adapter_id: str
    adapter_version: str
    provider_operation_id: str
    schema: str = field(default=APPLY_RESULT_SCHEMA, init=False)
    state: str = field(default="accepted", init=False)
    post_condition_verified: bool = field(default=False, init=False)
    enforcement_verified: bool = field(default=False, init=False)
    actual_state_readback_required: bool = field(default=True, init=False)

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, code="parental_adapter_id_invalid")
        _version(self.adapter_version)
        _operation_id(
            self.provider_operation_id,
            code="parental_adapter_provider_operation_id_invalid",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state": "accepted",
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "provider_operation_id": self.provider_operation_id,
            "post_condition_verified": False,
            "enforcement_verified": False,
            "actual_state_readback_required": True,
        }


@dataclass(frozen=True, slots=True)
class ParentalInternetEnforcementReadbackRequest:
    adapter_id: str
    adapter_version: str
    provider_operation_id: str
    desired_state_sha256: str
    policy_sha256: str
    schema: str = field(default=READBACK_REQUEST_SCHEMA, init=False)
    backend_mutation_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, code="parental_adapter_id_invalid")
        _version(self.adapter_version)
        _operation_id(
            self.provider_operation_id,
            code="parental_adapter_provider_operation_id_invalid",
        )
        _sha256(self.desired_state_sha256, code="parental_adapter_desired_state_sha256_invalid")
        _sha256(self.policy_sha256, code="parental_adapter_policy_sha256_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "provider_operation_id": self.provider_operation_id,
            "desired_state_sha256": self.desired_state_sha256,
            "policy_sha256": self.policy_sha256,
            "backend_mutation_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class ParentalInternetEnforcementObservation:
    adapter_id: str
    adapter_version: str
    provider_operation_id: str
    desired_state_sha256: str
    policy_sha256: str
    observed_at: str
    dns_state: str
    proxy_state: str
    dns_policy_sha256: str | None
    proxy_policy_sha256: str | None
    blocker: str | None
    schema: str = field(default=OBSERVATION_SCHEMA, init=False)
    backend_mutation_performed: bool = field(default=False, init=False)
    infrastructure_mutation_performed: bool = field(default=False, init=False)
    external_publication_performed: bool = field(default=False, init=False)
    enforcement_verified: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, code="parental_adapter_id_invalid")
        _version(self.adapter_version)
        _operation_id(
            self.provider_operation_id,
            code="parental_adapter_provider_operation_id_invalid",
        )
        _sha256(self.desired_state_sha256, code="parental_adapter_desired_state_sha256_invalid")
        _sha256(self.policy_sha256, code="parental_adapter_policy_sha256_invalid")
        _observed_at(self.observed_at)
        if self.dns_state not in _POLICY_STATE or self.proxy_state not in _POLICY_STATE:
            raise ParentalInternetEnforcementAdapterError("parental_adapter_observation_state_invalid")
        for state, digest, name in (
            (self.dns_state, self.dns_policy_sha256, "dns"),
            (self.proxy_state, self.proxy_policy_sha256, "proxy"),
        ):
            if state == "enforced":
                _sha256(digest, code=f"parental_adapter_{name}_policy_sha256_invalid")
            elif digest is not None:
                raise ParentalInternetEnforcementAdapterError(
                    f"parental_adapter_{name}_policy_sha256_unexpected"
                )
        if self.blocker is not None:
            _identifier(self.blocker, code="parental_adapter_observation_blocker_invalid")
        if self.dns_state == "enforced" and self.proxy_state == "enforced" and self.blocker is not None:
            raise ParentalInternetEnforcementAdapterError("parental_adapter_observation_blocker_conflict")
        if (self.dns_state != "enforced" or self.proxy_state != "enforced") and self.blocker is None:
            raise ParentalInternetEnforcementAdapterError("parental_adapter_observation_blocker_required")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "provider_operation_id": self.provider_operation_id,
            "desired_state_sha256": self.desired_state_sha256,
            "policy_sha256": self.policy_sha256,
            "observed_at": self.observed_at,
            "dns_state": self.dns_state,
            "proxy_state": self.proxy_state,
            "dns_policy_sha256": self.dns_policy_sha256,
            "proxy_policy_sha256": self.proxy_policy_sha256,
            "blocker": self.blocker,
            "backend_mutation_performed": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
            "enforcement_verified": False,
        }


@dataclass(frozen=True, slots=True)
class ParentalInternetEnforcementRollbackRequest:
    job_id: str
    adapter_id: str
    adapter_version: str
    provider_operation_id: str
    failed_desired_state_sha256: str
    failed_policy_sha256: str
    recovery_evidence_sha256: str
    schema: str = field(default=ROLLBACK_REQUEST_SCHEMA, init=False)
    rollback_authorized: bool = field(default=True, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _job_id(self.job_id)
        _identifier(self.adapter_id, code="parental_adapter_id_invalid")
        _version(self.adapter_version)
        _operation_id(
            self.provider_operation_id,
            code="parental_adapter_provider_operation_id_invalid",
        )
        _sha256(
            self.failed_desired_state_sha256,
            code="parental_adapter_failed_desired_state_sha256_invalid",
        )
        _sha256(self.failed_policy_sha256, code="parental_adapter_failed_policy_sha256_invalid")
        _sha256(self.recovery_evidence_sha256, code="parental_adapter_recovery_evidence_sha256_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "provider_operation_id": self.provider_operation_id,
            "failed_desired_state_sha256": self.failed_desired_state_sha256,
            "failed_policy_sha256": self.failed_policy_sha256,
            "recovery_evidence_sha256": self.recovery_evidence_sha256,
            "rollback_authorized": True,
            "credential_value_access_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class ParentalInternetEnforcementRollbackResult:
    adapter_id: str
    adapter_version: str
    provider_operation_id: str
    schema: str = field(default=ROLLBACK_RESULT_SCHEMA, init=False)
    state: str = field(default="rollback-accepted", init=False)
    post_condition_verified: bool = field(default=False, init=False)
    rollback_verified: bool = field(default=False, init=False)
    actual_state_readback_required: bool = field(default=True, init=False)

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, code="parental_adapter_id_invalid")
        _version(self.adapter_version)
        _operation_id(
            self.provider_operation_id,
            code="parental_adapter_provider_operation_id_invalid",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state": "rollback-accepted",
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "provider_operation_id": self.provider_operation_id,
            "post_condition_verified": False,
            "rollback_verified": False,
            "actual_state_readback_required": True,
        }


class ParentalInternetEnforcementAdapter(Protocol):
    capabilities: ParentalInternetEnforcementAdapterCapabilities

    def apply(
        self, request: ParentalInternetEnforcementApplyRequest
    ) -> ParentalInternetEnforcementApplyResult: ...

    def read_actual_state(
        self, request: ParentalInternetEnforcementReadbackRequest
    ) -> ParentalInternetEnforcementObservation: ...

    def rollback(
        self, request: ParentalInternetEnforcementRollbackRequest
    ) -> ParentalInternetEnforcementRollbackResult: ...


class ParentalInternetEnforcementAdapterRegistry:
    """Fail-closed registry; no production adapter is registered by this module."""

    def __init__(self) -> None:
        self._adapters: dict[str, ParentalInternetEnforcementAdapter] = {}

    def register(self, adapter: ParentalInternetEnforcementAdapter) -> None:
        capabilities = getattr(adapter, "capabilities", None)
        if not isinstance(capabilities, ParentalInternetEnforcementAdapterCapabilities):
            raise ParentalInternetEnforcementAdapterError("parental_adapter_registration_invalid")
        if capabilities.adapter_id in self._adapters:
            raise ParentalInternetEnforcementAdapterError("parental_adapter_already_registered")
        if not callable(getattr(adapter, "apply", None)) or not callable(
            getattr(adapter, "read_actual_state", None)
        ):
            raise ParentalInternetEnforcementAdapterError("parental_adapter_registration_invalid")
        if capabilities.supports_rollback and not callable(getattr(adapter, "rollback", None)):
            raise ParentalInternetEnforcementAdapterError("parental_adapter_registration_invalid")
        self._adapters[capabilities.adapter_id] = adapter

    def resolve(self, adapter_id: str) -> ParentalInternetEnforcementAdapter:
        _identifier(adapter_id, code="parental_adapter_id_invalid")
        adapter = self._adapters.get(adapter_id)
        if adapter is None:
            raise ParentalInternetEnforcementAdapterError("parental_adapter_not_registered")
        return adapter

    def capabilities(self) -> tuple[ParentalInternetEnforcementAdapterCapabilities, ...]:
        return tuple(
            sorted(
                (adapter.capabilities for adapter in self._adapters.values()),
                key=lambda item: item.adapter_id,
            )
        )


def build_parental_internet_apply_request(
    *,
    desired_state: object,
    job_id: str,
    capabilities: ParentalInternetEnforcementAdapterCapabilities,
) -> ParentalInternetEnforcementApplyRequest:
    """Bind one future adapter call to an exact protected 0.60 Desired State."""

    _job_id(job_id)
    if not isinstance(capabilities, ParentalInternetEnforcementAdapterCapabilities):
        raise TypeError("parental_adapter_capabilities_invalid")
    try:
        projection = full_parental_internet_desired_projection(desired_state)
    except ParentalInternetPolicyChangeAPIError as exc:
        raise ParentalInternetEnforcementAdapterError("parental_adapter_desired_state_invalid") from exc
    if not isinstance(desired_state, dict):
        raise ParentalInternetEnforcementAdapterError("parental_adapter_desired_state_invalid")
    policy = projection.get("policy")
    if not isinstance(policy, dict):
        raise ParentalInternetEnforcementAdapterError("parental_adapter_desired_state_invalid")
    if policy.get("dns_policy_required") is not True or policy.get("proxy_policy_required") is not True:
        raise ParentalInternetEnforcementAdapterError("parental_adapter_dns_proxy_required")
    return ParentalInternetEnforcementApplyRequest(
        job_id=job_id,
        adapter_id=capabilities.adapter_id,
        adapter_version=capabilities.adapter_version,
        household_id=str(projection["household_id"]),
        member_id=str(projection["member_id"]),
        desired_generation=int(projection["generation"]),
        desired_plan_id=str(projection["plan_id"]),
        desired_state_sha256=_digest(desired_state),
        verified_base_state_sha256=str(projection["verified_base_state_sha256"]),
        policy_id=str(policy["policy_id"]),
        policy_sha256=str(projection["policy_sha256"]),
        policy=dict(policy),
    )


def apply_result_from_dict(value: object) -> ParentalInternetEnforcementApplyResult:
    required = {
        "schema", "state", "adapter_id", "adapter_version", "provider_operation_id",
        "post_condition_verified", "enforcement_verified", "actual_state_readback_required",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != APPLY_RESULT_SCHEMA
        or value.get("state") != "accepted"
        or value.get("post_condition_verified") is not False
        or value.get("enforcement_verified") is not False
        or value.get("actual_state_readback_required") is not True
    ):
        raise ParentalInternetEnforcementAdapterError("parental_adapter_apply_result_rejected")
    try:
        result = ParentalInternetEnforcementApplyResult(
            adapter_id=value["adapter_id"],
            adapter_version=value["adapter_version"],
            provider_operation_id=value["provider_operation_id"],
        )
    except (KeyError, ParentalInternetEnforcementAdapterError) as exc:
        raise ParentalInternetEnforcementAdapterError("parental_adapter_apply_result_rejected") from exc
    if result.to_dict() != value:
        raise ParentalInternetEnforcementAdapterError("parental_adapter_apply_result_rejected")
    return result


def observation_from_dict(value: object) -> ParentalInternetEnforcementObservation:
    required = {
        "schema", "adapter_id", "adapter_version", "provider_operation_id",
        "desired_state_sha256", "policy_sha256", "observed_at", "dns_state",
        "proxy_state", "dns_policy_sha256", "proxy_policy_sha256", "blocker",
        "backend_mutation_performed", "infrastructure_mutation_performed",
        "external_publication_performed", "enforcement_verified",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != OBSERVATION_SCHEMA
        or value.get("backend_mutation_performed") is not False
        or value.get("infrastructure_mutation_performed") is not False
        or value.get("external_publication_performed") is not False
        or value.get("enforcement_verified") is not False
    ):
        raise ParentalInternetEnforcementAdapterError("parental_adapter_observation_rejected")
    try:
        observation = ParentalInternetEnforcementObservation(
            adapter_id=value["adapter_id"],
            adapter_version=value["adapter_version"],
            provider_operation_id=value["provider_operation_id"],
            desired_state_sha256=value["desired_state_sha256"],
            policy_sha256=value["policy_sha256"],
            observed_at=value["observed_at"],
            dns_state=value["dns_state"],
            proxy_state=value["proxy_state"],
            dns_policy_sha256=value["dns_policy_sha256"],
            proxy_policy_sha256=value["proxy_policy_sha256"],
            blocker=value["blocker"],
        )
    except (KeyError, ParentalInternetEnforcementAdapterError) as exc:
        raise ParentalInternetEnforcementAdapterError("parental_adapter_observation_rejected") from exc
    if observation.to_dict() != value:
        raise ParentalInternetEnforcementAdapterError("parental_adapter_observation_rejected")
    return observation
