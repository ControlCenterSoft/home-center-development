"""Typed bounded action-adapter boundary for Home Center 0.64 safe auto-repair.

This module defines a provider-free adapter contract for the closed low-risk repair
actions. A deliberately registered adapter may perform only the exact typed local
repair authorized by a future durable Job runtime. Adapter acceptance is never repair
success: authoritative read-back and separate post-condition verification remain
mandatory before success can be claimed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from .safe_auto_repair import RepairAction

CAPABILITIES_SCHEMA = "home-center.safe-auto-repair-adapter-capabilities.v1"
APPLY_REQUEST_SCHEMA = "home-center.safe-auto-repair-adapter-apply-request.v1"
APPLY_RESULT_SCHEMA = "home-center.safe-auto-repair-adapter-apply-result.v1"
READBACK_REQUEST_SCHEMA = "home-center.safe-auto-repair-adapter-readback-request.v1"
OBSERVATION_SCHEMA = "home-center.safe-auto-repair-adapter-observation.v1"

_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SafeAutoRepairAdapterError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SafeAutoRepairAdapterError(code)
    return value


def _version(value: object) -> str:
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        raise SafeAutoRepairAdapterError("safe_repair_adapter_version_invalid")
    return value


def _token(value: object, code: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise SafeAutoRepairAdapterError(code)
    return value


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SafeAutoRepairAdapterError(code)
    return value


class SafeRepairApplyOutcome(StrEnum):
    ACCEPTED = "accepted"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"


class SafeRepairObservationState(StrEnum):
    SATISFIED = "satisfied"
    NOT_SATISFIED = "not-satisfied"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SafeAutoRepairAdapterCapabilities:
    adapter_id: str
    adapter_version: str
    supported_actions: frozenset[RepairAction]
    supports_readback: bool = True
    supports_rollback: bool = False
    schema: str = field(default=CAPABILITIES_SCHEMA, init=False)
    credential_value_access_required: bool = field(default=False, init=False)
    provider_execution_required: bool = field(default=False, init=False)
    infrastructure_mutation_required: bool = field(default=False, init=False)
    external_publication_required: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, "safe_repair_adapter_id_invalid")
        _version(self.adapter_version)
        if not isinstance(self.supported_actions, frozenset) or not self.supported_actions:
            raise SafeAutoRepairAdapterError("safe_repair_adapter_actions_invalid")
        if not all(isinstance(action, RepairAction) for action in self.supported_actions):
            raise SafeAutoRepairAdapterError("safe_repair_adapter_actions_invalid")
        if type(self.supports_readback) is not bool or not self.supports_readback:
            raise SafeAutoRepairAdapterError("safe_repair_adapter_readback_required")
        if type(self.supports_rollback) is not bool:
            raise SafeAutoRepairAdapterError("safe_repair_adapter_rollback_capability_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "supported_actions": sorted(action.value for action in self.supported_actions),
            "supports_readback": True,
            "supports_rollback": self.supports_rollback,
            "credential_value_access_required": False,
            "provider_execution_required": False,
            "infrastructure_mutation_required": False,
            "external_publication_required": False,
        }


@dataclass(frozen=True, slots=True)
class SafeAutoRepairApplyRequest:
    job_id: str
    adapter_id: str
    adapter_version: str
    recommendation_id: str
    recommendation_sha256: str
    household_id: str
    resource_id: str
    resource_generation: int
    source_evidence_sha256: str
    action: RepairAction
    policy_id: str
    policy_sha256: str
    schema: str = field(default=APPLY_REQUEST_SCHEMA, init=False)
    adapter_execution_authorized: bool = field(default=True, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)
    post_condition_verified: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _token(self.job_id, "safe_repair_adapter_job_id_invalid")
        _identifier(self.adapter_id, "safe_repair_adapter_id_invalid")
        _version(self.adapter_version)
        _token(self.recommendation_id, "safe_repair_adapter_recommendation_id_invalid")
        _sha256(self.recommendation_sha256, "safe_repair_adapter_recommendation_sha256_invalid")
        _token(self.household_id, "safe_repair_adapter_household_id_invalid")
        _token(self.resource_id, "safe_repair_adapter_resource_id_invalid")
        if type(self.resource_generation) is not int or self.resource_generation < 0:
            raise SafeAutoRepairAdapterError("safe_repair_adapter_resource_generation_invalid")
        _sha256(self.source_evidence_sha256, "safe_repair_adapter_source_evidence_invalid")
        if not isinstance(self.action, RepairAction):
            raise SafeAutoRepairAdapterError("safe_repair_adapter_action_invalid")
        _token(self.policy_id, "safe_repair_adapter_policy_id_invalid")
        _sha256(self.policy_sha256, "safe_repair_adapter_policy_sha256_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "recommendation_id": self.recommendation_id,
            "recommendation_sha256": self.recommendation_sha256,
            "household_id": self.household_id,
            "resource_id": self.resource_id,
            "resource_generation": self.resource_generation,
            "source_evidence_sha256": self.source_evidence_sha256,
            "action": self.action.value,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "adapter_execution_authorized": True,
            "credential_value_access_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
            "post_condition_verified": False,
        }


@dataclass(frozen=True, slots=True)
class SafeAutoRepairApplyResult:
    adapter_id: str
    adapter_version: str
    operation_id: str
    outcome: SafeRepairApplyOutcome
    schema: str = field(default=APPLY_RESULT_SCHEMA, init=False)
    post_condition_verified: bool = field(default=False, init=False)
    readback_required: bool = field(default=True, init=False)
    automatic_retry_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, "safe_repair_adapter_id_invalid")
        _version(self.adapter_version)
        _token(self.operation_id, "safe_repair_adapter_operation_id_invalid")
        if not isinstance(self.outcome, SafeRepairApplyOutcome):
            raise SafeAutoRepairAdapterError("safe_repair_adapter_apply_outcome_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "operation_id": self.operation_id,
            "outcome": self.outcome.value,
            "post_condition_verified": False,
            "readback_required": True,
            "automatic_retry_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class SafeAutoRepairReadbackRequest:
    adapter_id: str
    adapter_version: str
    operation_id: str
    recommendation_id: str
    recommendation_sha256: str
    resource_id: str
    expected_generation: int
    action: RepairAction
    schema: str = field(default=READBACK_REQUEST_SCHEMA, init=False)
    adapter_mutation_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, "safe_repair_adapter_id_invalid")
        _version(self.adapter_version)
        _token(self.operation_id, "safe_repair_adapter_operation_id_invalid")
        _token(self.recommendation_id, "safe_repair_adapter_recommendation_id_invalid")
        _sha256(self.recommendation_sha256, "safe_repair_adapter_recommendation_sha256_invalid")
        _token(self.resource_id, "safe_repair_adapter_resource_id_invalid")
        if type(self.expected_generation) is not int or self.expected_generation < 0:
            raise SafeAutoRepairAdapterError("safe_repair_adapter_expected_generation_invalid")
        if not isinstance(self.action, RepairAction):
            raise SafeAutoRepairAdapterError("safe_repair_adapter_action_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "operation_id": self.operation_id,
            "recommendation_id": self.recommendation_id,
            "recommendation_sha256": self.recommendation_sha256,
            "resource_id": self.resource_id,
            "expected_generation": self.expected_generation,
            "action": self.action.value,
            "adapter_mutation_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class SafeAutoRepairObservation:
    adapter_id: str
    adapter_version: str
    operation_id: str
    recommendation_id: str
    recommendation_sha256: str
    resource_id: str
    observed_generation: int
    action: RepairAction
    state: SafeRepairObservationState
    actual_evidence_sha256: str | None
    blocker: str | None
    schema: str = field(default=OBSERVATION_SCHEMA, init=False)
    post_condition_verified: bool = field(default=False, init=False)
    adapter_mutation_performed: bool = field(default=False, init=False)
    provider_execution_performed: bool = field(default=False, init=False)
    infrastructure_mutation_performed: bool = field(default=False, init=False)
    external_publication_performed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, "safe_repair_adapter_id_invalid")
        _version(self.adapter_version)
        _token(self.operation_id, "safe_repair_adapter_operation_id_invalid")
        _token(self.recommendation_id, "safe_repair_adapter_recommendation_id_invalid")
        _sha256(self.recommendation_sha256, "safe_repair_adapter_recommendation_sha256_invalid")
        _token(self.resource_id, "safe_repair_adapter_resource_id_invalid")
        if type(self.observed_generation) is not int or self.observed_generation < 0:
            raise SafeAutoRepairAdapterError("safe_repair_adapter_observed_generation_invalid")
        if not isinstance(self.action, RepairAction):
            raise SafeAutoRepairAdapterError("safe_repair_adapter_action_invalid")
        if not isinstance(self.state, SafeRepairObservationState):
            raise SafeAutoRepairAdapterError("safe_repair_adapter_observation_state_invalid")
        if self.state is SafeRepairObservationState.UNKNOWN:
            if self.actual_evidence_sha256 is not None:
                raise SafeAutoRepairAdapterError("safe_repair_adapter_unknown_evidence_unexpected")
            if self.blocker is None:
                raise SafeAutoRepairAdapterError("safe_repair_adapter_observation_blocker_required")
        else:
            _sha256(self.actual_evidence_sha256, "safe_repair_adapter_actual_evidence_invalid")
            if self.state is SafeRepairObservationState.SATISFIED and self.blocker is not None:
                raise SafeAutoRepairAdapterError("safe_repair_adapter_observation_blocker_conflict")
            if self.state is SafeRepairObservationState.NOT_SATISFIED and self.blocker is None:
                raise SafeAutoRepairAdapterError("safe_repair_adapter_observation_blocker_required")
        if self.blocker is not None:
            _identifier(self.blocker, "safe_repair_adapter_observation_blocker_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "operation_id": self.operation_id,
            "recommendation_id": self.recommendation_id,
            "recommendation_sha256": self.recommendation_sha256,
            "resource_id": self.resource_id,
            "observed_generation": self.observed_generation,
            "action": self.action.value,
            "state": self.state.value,
            "actual_evidence_sha256": self.actual_evidence_sha256,
            "blocker": self.blocker,
            "post_condition_verified": False,
            "adapter_mutation_performed": False,
            "provider_execution_performed": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
        }


class SafeAutoRepairAdapter(Protocol):
    capabilities: SafeAutoRepairAdapterCapabilities

    def apply(self, request: SafeAutoRepairApplyRequest) -> SafeAutoRepairApplyResult: ...

    def read_back(self, request: SafeAutoRepairReadbackRequest) -> SafeAutoRepairObservation: ...


class SafeAutoRepairAdapterRegistry:
    """Explicit fail-closed registration by typed repair action."""

    def __init__(self) -> None:
        self._by_action: dict[RepairAction, SafeAutoRepairAdapter] = {}

    def register(self, adapter: SafeAutoRepairAdapter) -> None:
        capabilities = getattr(adapter, "capabilities", None)
        if not isinstance(capabilities, SafeAutoRepairAdapterCapabilities):
            raise SafeAutoRepairAdapterError("safe_repair_adapter_capabilities_missing")
        for action in capabilities.supported_actions:
            if action in self._by_action:
                raise SafeAutoRepairAdapterError("safe_repair_adapter_action_already_registered")
        for action in capabilities.supported_actions:
            self._by_action[action] = adapter

    def require(self, action: RepairAction) -> SafeAutoRepairAdapter:
        if not isinstance(action, RepairAction):
            raise SafeAutoRepairAdapterError("safe_repair_adapter_action_invalid")
        adapter = self._by_action.get(action)
        if adapter is None:
            raise SafeAutoRepairAdapterError("safe_repair_adapter_unavailable")
        return adapter
