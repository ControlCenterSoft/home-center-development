"""Home Center 0.64 recommendation and safe auto-repair eligibility foundation.

This module is intentionally non-executing. It classifies a bounded repair candidate
against an explicit allowlist and produces deterministic recommendation evidence.
Eligibility is evidence only: it never grants execution, provider, infrastructure or
external-publication authority. Any future automatic repair path must separately bind
the exact recommendation to a durable Job, execute a typed adapter, verify the
post-condition and persist recovery/audit evidence.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .util import canonical_json

SAFE_REPAIR_RECOMMENDATION_SCHEMA = "home-center.safe-auto-repair-recommendation.v1"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SafeAutoRepairError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RepairAction(StrEnum):
    """Typed low-risk product actions that may be considered for future auto-repair."""

    RECONCILE_DERIVED_STATE = "reconcile-derived-state"
    REBUILD_DERIVED_INDEX = "rebuild-derived-index"
    REFRESH_LOCAL_READ_MODEL = "refresh-local-read-model"


class RepairRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RepairBlocker(StrEnum):
    ACTION_NOT_ALLOWED = "action-not-allowed"
    RISK_NOT_ALLOWED = "risk-not-allowed"
    RECOVERY_NOT_PROVEN = "recovery-not-proven"
    POST_CONDITION_NOT_VERIFIABLE = "post-condition-not-verifiable"
    PROVIDER_EXECUTION_REQUIRED = "provider-execution-required"
    INFRASTRUCTURE_MUTATION_REQUIRED = "infrastructure-mutation-required"
    EXTERNAL_PUBLICATION_REQUIRED = "external-publication-required"


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SafeAutoRepairError(code)
    return value


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise SafeAutoRepairError(code)
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RepairCandidate:
    household_id: str
    resource_id: str
    resource_generation: int
    evidence_sha256: str
    action: RepairAction
    risk: RepairRisk
    recovery_proven: bool
    post_condition_verifiable: bool
    provider_execution_required: bool = False
    infrastructure_mutation_required: bool = False
    external_publication_required: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "household_id", _identifier(self.household_id, "repair_household_id_invalid"))
        object.__setattr__(self, "resource_id", _identifier(self.resource_id, "repair_resource_id_invalid"))
        if type(self.resource_generation) is not int or self.resource_generation < 0:
            raise SafeAutoRepairError("repair_resource_generation_invalid")
        object.__setattr__(self, "evidence_sha256", _sha256(self.evidence_sha256, "repair_evidence_digest_invalid"))
        if not isinstance(self.action, RepairAction):
            raise SafeAutoRepairError("repair_action_invalid")
        if not isinstance(self.risk, RepairRisk):
            raise SafeAutoRepairError("repair_risk_invalid")
        for field_name in (
            "recovery_proven",
            "post_condition_verifiable",
            "provider_execution_required",
            "infrastructure_mutation_required",
            "external_publication_required",
        ):
            if type(getattr(self, field_name)) is not bool:
                raise SafeAutoRepairError(f"{field_name}_invalid")

    def identity_material(self) -> dict[str, object]:
        return {
            "household_id": self.household_id,
            "resource_id": self.resource_id,
            "resource_generation": self.resource_generation,
            "evidence_sha256": self.evidence_sha256,
            "action": self.action.value,
            "risk": self.risk.value,
            "recovery_proven": self.recovery_proven,
            "post_condition_verifiable": self.post_condition_verifiable,
            "provider_execution_required": self.provider_execution_required,
            "infrastructure_mutation_required": self.infrastructure_mutation_required,
            "external_publication_required": self.external_publication_required,
        }


@dataclass(frozen=True, slots=True)
class SafeRepairPolicy:
    policy_id: str
    policy_sha256: str
    allowed_actions: frozenset[RepairAction]
    allowed_risks: frozenset[RepairRisk] = field(default_factory=lambda: frozenset({RepairRisk.LOW}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy_id", _identifier(self.policy_id, "repair_policy_id_invalid"))
        object.__setattr__(self, "policy_sha256", _sha256(self.policy_sha256, "repair_policy_digest_invalid"))
        if not isinstance(self.allowed_actions, frozenset) or not self.allowed_actions:
            raise SafeAutoRepairError("repair_policy_actions_invalid")
        if not all(isinstance(item, RepairAction) for item in self.allowed_actions):
            raise SafeAutoRepairError("repair_policy_actions_invalid")
        if not isinstance(self.allowed_risks, frozenset) or not self.allowed_risks:
            raise SafeAutoRepairError("repair_policy_risks_invalid")
        if not all(isinstance(item, RepairRisk) for item in self.allowed_risks):
            raise SafeAutoRepairError("repair_policy_risks_invalid")


@dataclass(frozen=True, slots=True)
class SafeAutoRepairRecommendation:
    recommendation_id: str
    candidate: RepairCandidate
    policy_id: str
    policy_sha256: str
    eligible_for_auto_repair: bool
    blockers: tuple[RepairBlocker, ...]
    schema: str = field(default=SAFE_REPAIR_RECOMMENDATION_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "recommendation_id": self.recommendation_id,
            "household_id": self.candidate.household_id,
            "resource_id": self.candidate.resource_id,
            "resource_generation": self.candidate.resource_generation,
            "evidence_sha256": self.candidate.evidence_sha256,
            "action": self.candidate.action.value,
            "risk": self.candidate.risk.value,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "eligible_for_auto_repair": self.eligible_for_auto_repair,
            "blockers": [item.value for item in self.blockers],
            "recovery_proven": self.candidate.recovery_proven,
            "post_condition_verification_required": True,
            "repair_history_required": True,
            "execution_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def evaluate_safe_auto_repair(
    *,
    candidate: RepairCandidate,
    policy: SafeRepairPolicy,
) -> SafeAutoRepairRecommendation:
    """Return exact-bound eligibility evidence without granting mutation authority."""

    blockers: list[RepairBlocker] = []
    if candidate.action not in policy.allowed_actions:
        blockers.append(RepairBlocker.ACTION_NOT_ALLOWED)
    if candidate.risk not in policy.allowed_risks:
        blockers.append(RepairBlocker.RISK_NOT_ALLOWED)
    if not candidate.recovery_proven:
        blockers.append(RepairBlocker.RECOVERY_NOT_PROVEN)
    if not candidate.post_condition_verifiable:
        blockers.append(RepairBlocker.POST_CONDITION_NOT_VERIFIABLE)
    if candidate.provider_execution_required:
        blockers.append(RepairBlocker.PROVIDER_EXECUTION_REQUIRED)
    if candidate.infrastructure_mutation_required:
        blockers.append(RepairBlocker.INFRASTRUCTURE_MUTATION_REQUIRED)
    if candidate.external_publication_required:
        blockers.append(RepairBlocker.EXTERNAL_PUBLICATION_REQUIRED)

    material = {
        "candidate": candidate.identity_material(),
        "policy_id": policy.policy_id,
        "policy_sha256": policy.policy_sha256,
    }
    recommendation_id = "hcrpr-" + _digest(material)[:24]
    return SafeAutoRepairRecommendation(
        recommendation_id=recommendation_id,
        candidate=candidate,
        policy_id=policy.policy_id,
        policy_sha256=policy.policy_sha256,
        eligible_for_auto_repair=not blockers,
        blockers=tuple(blockers),
    )
