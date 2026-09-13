"""Typed adapter/read-back boundaries for Home Center 0.64 safe auto-repair.

This module defines the narrow capability seam used by a future repair worker. It does
not register a production adapter and does not execute anything by itself. Unknown or
duplicate adapters fail closed. Post-condition observations are exact-bound evidence;
only a `matched` observation is verified, and even that evidence does not grant a new
mutation authority.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from .safe_auto_repair import RepairAction, SafeAutoRepairRecommendation
from .safe_auto_repair_job import RepairExecutionOutcome, SafeAutoRepairJob
from .util import canonical_json

SAFE_REPAIR_ADAPTER_REQUEST_SCHEMA = "home-center.safe-auto-repair-adapter-request.v1"
SAFE_REPAIR_ADAPTER_RESULT_SCHEMA = "home-center.safe-auto-repair-adapter-result.v1"
SAFE_REPAIR_POST_CONDITION_SCHEMA = "home-center.safe-auto-repair-post-condition.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SafeRepairAdapterError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise SafeRepairAdapterError(code)
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SafeRepairAdapterRequest:
    job_id: str
    recommendation_id: str
    recommendation_sha256: str
    household_id: str
    resource_id: str
    resource_generation: int
    source_evidence_sha256: str
    action: RepairAction
    schema: str = field(default=SAFE_REPAIR_ADAPTER_REQUEST_SCHEMA, init=False)

    def __post_init__(self) -> None:
        _sha256(self.recommendation_sha256, "safe_repair_adapter_recommendation_digest_invalid")
        _sha256(self.source_evidence_sha256, "safe_repair_adapter_source_evidence_invalid")
        if type(self.resource_generation) is not int or self.resource_generation < 0:
            raise SafeRepairAdapterError("safe_repair_adapter_generation_invalid")
        if not isinstance(self.action, RepairAction):
            raise SafeRepairAdapterError("safe_repair_adapter_action_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "recommendation_id": self.recommendation_id,
            "recommendation_sha256": self.recommendation_sha256,
            "household_id": self.household_id,
            "resource_id": self.resource_id,
            "resource_generation": self.resource_generation,
            "source_evidence_sha256": self.source_evidence_sha256,
            "action": self.action.value,
            "credential_value_access_authorized": False,
            "provider_execution_authorized": False,
            "generic_infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class SafeRepairAdapterResult:
    job_id: str
    recommendation_id: str
    action: RepairAction
    outcome: RepairExecutionOutcome
    effect_receipt_sha256: str
    schema: str = field(default=SAFE_REPAIR_ADAPTER_RESULT_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.action, RepairAction):
            raise SafeRepairAdapterError("safe_repair_adapter_result_action_invalid")
        if not isinstance(self.outcome, RepairExecutionOutcome):
            raise SafeRepairAdapterError("safe_repair_adapter_result_outcome_invalid")
        _sha256(self.effect_receipt_sha256, "safe_repair_adapter_result_receipt_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "recommendation_id": self.recommendation_id,
            "action": self.action.value,
            "outcome": self.outcome.value,
            "effect_receipt_sha256": self.effect_receipt_sha256,
            "post_condition_verified": False,
            "automatic_retry_authorized": False,
            "provider_execution_performed": False,
            "generic_infrastructure_mutation_performed": False,
            "external_publication_performed": False,
        }


class PostConditionState(StrEnum):
    MATCHED = "matched"
    MISMATCHED = "mismatched"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SafeRepairPostConditionObservation:
    job_id: str
    recommendation_id: str
    household_id: str
    resource_id: str
    observed_generation: int
    observation_sha256: str
    state: PostConditionState
    schema: str = field(default=SAFE_REPAIR_POST_CONDITION_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if type(self.observed_generation) is not int or self.observed_generation < 0:
            raise SafeRepairAdapterError("safe_repair_post_condition_generation_invalid")
        _sha256(self.observation_sha256, "safe_repair_post_condition_digest_invalid")
        if not isinstance(self.state, PostConditionState):
            raise SafeRepairAdapterError("safe_repair_post_condition_state_invalid")

    @property
    def verified(self) -> bool:
        return self.state is PostConditionState.MATCHED

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "recommendation_id": self.recommendation_id,
            "household_id": self.household_id,
            "resource_id": self.resource_id,
            "observed_generation": self.observed_generation,
            "observation_sha256": self.observation_sha256,
            "state": self.state.value,
            "post_condition_verified": self.verified,
            "execution_authorized": False,
            "provider_execution_authorized": False,
            "generic_infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


class SafeRepairActionAdapter(Protocol):
    @property
    def action(self) -> RepairAction: ...

    def execute(self, request: SafeRepairAdapterRequest) -> SafeRepairAdapterResult: ...

    def read_back(self, request: SafeRepairAdapterRequest) -> SafeRepairPostConditionObservation: ...


class SafeRepairAdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[RepairAction, SafeRepairActionAdapter] = {}

    def register(self, adapter: SafeRepairActionAdapter) -> None:
        action = getattr(adapter, "action", None)
        if not isinstance(action, RepairAction):
            raise SafeRepairAdapterError("safe_repair_adapter_registration_invalid")
        if action in self._adapters:
            raise SafeRepairAdapterError("safe_repair_adapter_duplicate")
        self._adapters[action] = adapter

    def require(self, action: RepairAction) -> SafeRepairActionAdapter:
        adapter = self._adapters.get(action)
        if adapter is None:
            raise SafeRepairAdapterError("safe_repair_adapter_unavailable")
        return adapter


def build_safe_repair_adapter_request(
    *,
    job: SafeAutoRepairJob,
    recommendation: SafeAutoRepairRecommendation,
) -> SafeRepairAdapterRequest:
    if not isinstance(job, SafeAutoRepairJob):
        raise TypeError("safe_repair_adapter_job_invalid")
    if not isinstance(recommendation, SafeAutoRepairRecommendation):
        raise TypeError("safe_repair_adapter_recommendation_invalid")
    recommendation_sha = _digest(recommendation.to_dict())
    if job.recommendation_id != recommendation.recommendation_id:
        raise SafeRepairAdapterError("safe_repair_adapter_recommendation_identity_mismatch")
    if job.recommendation_sha256 != recommendation_sha:
        raise SafeRepairAdapterError("safe_repair_adapter_recommendation_digest_mismatch")
    candidate = recommendation.candidate
    return SafeRepairAdapterRequest(
        job_id=job.job_id,
        recommendation_id=recommendation.recommendation_id,
        recommendation_sha256=recommendation_sha,
        household_id=candidate.household_id,
        resource_id=candidate.resource_id,
        resource_generation=candidate.resource_generation,
        source_evidence_sha256=candidate.evidence_sha256,
        action=candidate.action,
    )
