"""Fail-closed recommendation and safe-repair planning for Home Center 0.64.

This module is deliberately plan-only. It turns bounded, content-addressed
evidence into a deterministic recommendation while keeping every execution
authority false. A later runtime may consume a qualified plan only through the
normal Identity/RBAC -> Change/Job -> typed execution -> read-back -> Audit /
recovery path.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping

from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.household import Household, HouseholdRole, effective_policy


RECOMMENDATION_EVIDENCE_SCHEMA = "home-center.recommendation-evidence.v1"
SAFE_REPAIR_PLAN_SCHEMA = "home-center.safe-repair-plan.v1"
MAX_RECOMMENDATION_EVIDENCE_TTL_SECONDS = 86_400

_REQUIRED_EVIDENCE_KEYS = frozenset(
    {
        "schema",
        "evidence_id",
        "household_id",
        "kind",
        "subject_member_id",
        "target_id",
        "household_sha256",
        "observation_sha256",
        "observed_at_epoch",
        "expires_at_epoch",
    }
)

_REQUIRED_PLAN_KEYS = frozenset(
    {
        "schema",
        "plan_id",
        "household_id",
        "household_sha256",
        "evidence_id",
        "evidence_sha256",
        "actor_member_id",
        "subject_member_id",
        "target_id",
        "recommendation_kind",
        "repair_action",
        "explanation_ru",
        "technical_reason",
        "risk",
        "confirmation_required",
        "post_condition_verification_required",
        "recovery_required",
        "recovery_contract",
        "automation_eligible",
        "mutation_authorized",
        "automatic_execution_authorized",
        "provider_execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
)


class RecommendationKind(StrEnum):
    """Bounded recommendation classes admitted by the 0.64 foundation."""

    MANAGED_DEVICE_POLICY = "managed-device-policy"
    HOUSEHOLD_POLICY_RECONCILIATION = "household-policy-reconciliation"
    COMPATIBILITY_EVIDENCE_REFRESH = "compatibility-evidence-refresh"


class RepairRisk(StrEnum):
    LOW = "low"
    ELEVATED = "elevated"


def _sha256(value: str, error: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        raise HomeServiceCatalogError(error)
    digest = value[7:]
    if any(char not in "0123456789abcdef" for char in digest):
        raise HomeServiceCatalogError(error)
    return value


def _epoch(value: object, error: str) -> int:
    if type(value) is not int or value < 0:
        raise HomeServiceCatalogError(error)
    return value


def _bounded_text(value: object, error: str, *, limit: int = 240) -> str:
    if not isinstance(value, str):
        raise HomeServiceCatalogError(error)
    normalized = value.strip()
    if not normalized or len(normalized) > limit or any(ord(char) < 32 for char in normalized):
        raise HomeServiceCatalogError(error)
    return normalized


def household_snapshot_sha256(household: Household) -> str:
    """Return a canonical digest for the exact Household state used by a plan."""

    if not isinstance(household, Household):
        raise TypeError("invalid_household")
    encoded = json.dumps(
        household.to_dict(),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class RecommendationEvidence:
    """Content-addressed observation admitted to recommendation planning."""

    evidence_id: str
    household_id: str
    kind: RecommendationKind
    subject_member_id: str
    target_id: str
    household_sha256: str
    observation_sha256: str
    observed_at_epoch: int
    expires_at_epoch: int
    schema: str = field(default=RECOMMENDATION_EVIDENCE_SCHEMA, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_id", _identifier(self.evidence_id, "invalid_recommendation_evidence_id"))
        object.__setattr__(self, "household_id", _identifier(self.household_id, "invalid_recommendation_household_id"))
        object.__setattr__(
            self,
            "subject_member_id",
            _identifier(self.subject_member_id, "invalid_recommendation_subject_member_id"),
        )
        object.__setattr__(self, "target_id", _identifier(self.target_id, "invalid_recommendation_target_id"))
        if not isinstance(self.kind, RecommendationKind):
            raise HomeServiceCatalogError("invalid_recommendation_kind")
        object.__setattr__(
            self,
            "household_sha256",
            _sha256(self.household_sha256, "invalid_recommendation_household_sha256"),
        )
        object.__setattr__(
            self,
            "observation_sha256",
            _sha256(self.observation_sha256, "invalid_recommendation_observation_sha256"),
        )
        observed = _epoch(self.observed_at_epoch, "invalid_recommendation_observed_at")
        expires = _epoch(self.expires_at_epoch, "invalid_recommendation_expires_at")
        if expires <= observed or expires - observed > MAX_RECOMMENDATION_EVIDENCE_TTL_SECONDS:
            raise HomeServiceCatalogError("invalid_recommendation_evidence_ttl")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_id": self.evidence_id,
            "household_id": self.household_id,
            "kind": self.kind.value,
            "subject_member_id": self.subject_member_id,
            "target_id": self.target_id,
            "household_sha256": self.household_sha256,
            "observation_sha256": self.observation_sha256,
            "observed_at_epoch": self.observed_at_epoch,
            "expires_at_epoch": self.expires_at_epoch,
        }

    @property
    def evidence_sha256(self) -> str:
        encoded = json.dumps(
            self.to_dict(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class _RepairPolicy:
    action: str
    risk: RepairRisk
    confirmation_required: bool
    automation_eligible: bool
    recovery_contract: str
    explanation_ru: str
    technical_reason: str


_REPAIR_POLICIES: Mapping[RecommendationKind, _RepairPolicy] = {
    RecommendationKind.MANAGED_DEVICE_POLICY: _RepairPolicy(
        action="household.device.reconcile-managed-policy",
        risk=RepairRisk.ELEVATED,
        confirmation_required=True,
        automation_eligible=False,
        recovery_contract="read-back-or-rollback",
        explanation_ru="Устройство требует безопасной повторной проверки правил управления.",
        technical_reason="managed_device_required_but_not_managed",
    ),
    RecommendationKind.HOUSEHOLD_POLICY_RECONCILIATION: _RepairPolicy(
        action="household.policy.reconcile",
        risk=RepairRisk.ELEVATED,
        confirmation_required=True,
        automation_eligible=False,
        recovery_contract="read-back-or-rollback",
        explanation_ru="Правила семьи требуют повторной сверки с фактическим состоянием.",
        technical_reason="household_policy_reconciliation_required",
    ),
    RecommendationKind.COMPATIBILITY_EVIDENCE_REFRESH: _RepairPolicy(
        action="compatibility.refresh-evidence",
        risk=RepairRisk.LOW,
        confirmation_required=False,
        automation_eligible=True,
        recovery_contract="read-only-refresh",
        explanation_ru="Данные о совместимости устарели и могут быть безопасно обновлены.",
        technical_reason="compatibility_evidence_refresh_required",
    ),
}


@dataclass(frozen=True, slots=True)
class SafeRepairPlan:
    """Deterministic recommendation evidence without execution authority."""

    plan_id: str
    household_id: str
    household_sha256: str
    evidence_id: str
    evidence_sha256: str
    actor_member_id: str
    subject_member_id: str
    target_id: str
    recommendation_kind: RecommendationKind
    repair_action: str
    explanation_ru: str
    technical_reason: str
    risk: RepairRisk
    confirmation_required: bool
    recovery_contract: str
    automation_eligible: bool
    schema: str = field(default=SAFE_REPAIR_PLAN_SCHEMA, init=False)
    post_condition_verification_required: bool = field(default=True, init=False)
    recovery_required: bool = field(default=True, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    automatic_execution_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.plan_id, str) or not self.plan_id.startswith("srp-") or len(self.plan_id) != 28:
            raise HomeServiceCatalogError("invalid_safe_repair_plan_id")
        if any(char not in "0123456789abcdef" for char in self.plan_id[4:]):
            raise HomeServiceCatalogError("invalid_safe_repair_plan_id")
        object.__setattr__(self, "household_id", _identifier(self.household_id, "invalid_safe_repair_household_id"))
        object.__setattr__(
            self,
            "actor_member_id",
            _identifier(self.actor_member_id, "invalid_safe_repair_actor_member_id"),
        )
        object.__setattr__(
            self,
            "subject_member_id",
            _identifier(self.subject_member_id, "invalid_safe_repair_subject_member_id"),
        )
        object.__setattr__(self, "target_id", _identifier(self.target_id, "invalid_safe_repair_target_id"))
        object.__setattr__(self, "evidence_id", _identifier(self.evidence_id, "invalid_safe_repair_evidence_id"))
        object.__setattr__(
            self,
            "household_sha256",
            _sha256(self.household_sha256, "invalid_safe_repair_household_sha256"),
        )
        object.__setattr__(
            self,
            "evidence_sha256",
            _sha256(self.evidence_sha256, "invalid_safe_repair_evidence_sha256"),
        )
        if not isinstance(self.recommendation_kind, RecommendationKind):
            raise HomeServiceCatalogError("invalid_safe_repair_kind")
        if not isinstance(self.risk, RepairRisk):
            raise HomeServiceCatalogError("invalid_safe_repair_risk")
        object.__setattr__(self, "repair_action", _bounded_text(self.repair_action, "invalid_safe_repair_action"))
        object.__setattr__(
            self,
            "explanation_ru",
            _bounded_text(self.explanation_ru, "invalid_safe_repair_explanation"),
        )
        object.__setattr__(
            self,
            "technical_reason",
            _bounded_text(self.technical_reason, "invalid_safe_repair_reason"),
        )
        object.__setattr__(
            self,
            "recovery_contract",
            _bounded_text(self.recovery_contract, "invalid_safe_repair_recovery_contract"),
        )
        if type(self.confirmation_required) is not bool or type(self.automation_eligible) is not bool:
            raise HomeServiceCatalogError("invalid_safe_repair_flags")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "household_id": self.household_id,
            "household_sha256": self.household_sha256,
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
            "actor_member_id": self.actor_member_id,
            "subject_member_id": self.subject_member_id,
            "target_id": self.target_id,
            "recommendation_kind": self.recommendation_kind.value,
            "repair_action": self.repair_action,
            "explanation_ru": self.explanation_ru,
            "technical_reason": self.technical_reason,
            "risk": self.risk.value,
            "confirmation_required": self.confirmation_required,
            "post_condition_verification_required": True,
            "recovery_required": True,
            "recovery_contract": self.recovery_contract,
            "automation_eligible": self.automation_eligible,
            "mutation_authorized": False,
            "automatic_execution_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def recommendation_evidence_from_dict(payload: object) -> RecommendationEvidence:
    """Strictly reconstruct persisted/transport evidence and reject drift."""

    if not isinstance(payload, dict) or set(payload) != _REQUIRED_EVIDENCE_KEYS:
        raise HomeServiceCatalogError("recommendation_evidence_contract_invalid")
    if payload.get("schema") != RECOMMENDATION_EVIDENCE_SCHEMA:
        raise HomeServiceCatalogError("recommendation_evidence_contract_invalid")
    try:
        kind = RecommendationKind(payload["kind"])
    except (TypeError, ValueError):
        raise HomeServiceCatalogError("recommendation_evidence_contract_invalid") from None
    evidence = RecommendationEvidence(
        evidence_id=payload["evidence_id"],
        household_id=payload["household_id"],
        kind=kind,
        subject_member_id=payload["subject_member_id"],
        target_id=payload["target_id"],
        household_sha256=payload["household_sha256"],
        observation_sha256=payload["observation_sha256"],
        observed_at_epoch=payload["observed_at_epoch"],
        expires_at_epoch=payload["expires_at_epoch"],
    )
    if evidence.to_dict() != payload:
        raise HomeServiceCatalogError("recommendation_evidence_contract_invalid")
    return evidence


def _plan_identity_payload(
    *,
    household_id: str,
    household_sha256: str,
    evidence_id: str,
    evidence_sha256: str,
    actor_member_id: str,
    subject_member_id: str,
    target_id: str,
    recommendation_kind: RecommendationKind,
    policy: _RepairPolicy,
) -> dict[str, object]:
    return {
        "household_id": household_id,
        "household_sha256": household_sha256,
        "evidence_id": evidence_id,
        "evidence_sha256": evidence_sha256,
        "actor_member_id": actor_member_id,
        "subject_member_id": subject_member_id,
        "target_id": target_id,
        "recommendation_kind": recommendation_kind.value,
        "repair_action": policy.action,
        "risk": policy.risk.value,
        "confirmation_required": policy.confirmation_required,
        "recovery_contract": policy.recovery_contract,
        "automation_eligible": policy.automation_eligible,
    }


def _plan_id(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return "srp-" + hashlib.sha256(encoded).hexdigest()[:24]


def plan_safe_repair(
    household: Household,
    *,
    actor_member_id: str,
    evidence: RecommendationEvidence,
    now_epoch_seconds: int,
) -> SafeRepairPlan:
    """Build a fail-closed recommendation without authorizing any mutation."""

    if not isinstance(household, Household):
        raise TypeError("invalid_household")
    if not isinstance(evidence, RecommendationEvidence):
        raise TypeError("invalid_recommendation_evidence")
    now = _epoch(now_epoch_seconds, "invalid_recommendation_now")

    actor = household.member(actor_member_id)
    if not actor.enabled:
        raise HomeServiceCatalogError("safe_repair_actor_disabled")
    actor_policy = effective_policy(household, actor.member_id)
    if actor.role is not HouseholdRole.PARENT or not actor_policy.administration_allowed:
        raise HomeServiceCatalogError("safe_repair_not_authorized")

    if evidence.household_id != household.household_id:
        raise HomeServiceCatalogError("safe_repair_household_mismatch")
    exact_household_sha256 = household_snapshot_sha256(household)
    if evidence.household_sha256 != exact_household_sha256:
        raise HomeServiceCatalogError("safe_repair_household_stale")
    if evidence.observed_at_epoch > now:
        raise HomeServiceCatalogError("safe_repair_evidence_from_future")
    if evidence.expires_at_epoch < now:
        raise HomeServiceCatalogError("safe_repair_evidence_expired")

    subject = household.member(evidence.subject_member_id)
    if not subject.enabled:
        raise HomeServiceCatalogError("safe_repair_subject_disabled")

    policy = _REPAIR_POLICIES[evidence.kind]

    if evidence.kind is RecommendationKind.MANAGED_DEVICE_POLICY:
        device = next((item for item in household.devices if item.device_id == evidence.target_id), None)
        if device is None or device.member_id != subject.member_id:
            raise HomeServiceCatalogError("safe_repair_target_not_found")
        effective = effective_policy(household, subject.member_id)
        if not effective.managed_device_required or device.managed:
            raise HomeServiceCatalogError("safe_repair_no_longer_applicable")
    elif evidence.kind is RecommendationKind.HOUSEHOLD_POLICY_RECONCILIATION:
        if evidence.target_id != subject.member_id:
            raise HomeServiceCatalogError("safe_repair_target_mismatch")

    identity = _plan_identity_payload(
        household_id=household.household_id,
        household_sha256=exact_household_sha256,
        evidence_id=evidence.evidence_id,
        evidence_sha256=evidence.evidence_sha256,
        actor_member_id=actor.member_id,
        subject_member_id=subject.member_id,
        target_id=evidence.target_id,
        recommendation_kind=evidence.kind,
        policy=policy,
    )
    return SafeRepairPlan(
        plan_id=_plan_id(identity),
        household_id=household.household_id,
        household_sha256=exact_household_sha256,
        evidence_id=evidence.evidence_id,
        evidence_sha256=evidence.evidence_sha256,
        actor_member_id=actor.member_id,
        subject_member_id=subject.member_id,
        target_id=evidence.target_id,
        recommendation_kind=evidence.kind,
        repair_action=policy.action,
        explanation_ru=policy.explanation_ru,
        technical_reason=policy.technical_reason,
        risk=policy.risk,
        confirmation_required=policy.confirmation_required,
        recovery_contract=policy.recovery_contract,
        automation_eligible=policy.automation_eligible,
    )


def safe_repair_plan_from_dict(payload: object) -> SafeRepairPlan:
    """Strict reconstruction for storage/transport boundaries.

    Reconstruction validates all hard-false authority flags and recomputes the
    content-addressed plan identifier so a stored plan cannot silently gain
    execution authority or be rebound to different evidence.
    """

    if not isinstance(payload, dict) or set(payload) != _REQUIRED_PLAN_KEYS:
        raise HomeServiceCatalogError("safe_repair_plan_contract_invalid")
    if payload.get("schema") != SAFE_REPAIR_PLAN_SCHEMA:
        raise HomeServiceCatalogError("safe_repair_plan_contract_invalid")
    for name in (
        "post_condition_verification_required",
        "recovery_required",
    ):
        if payload.get(name) is not True:
            raise HomeServiceCatalogError("safe_repair_plan_contract_invalid")
    for name in (
        "mutation_authorized",
        "automatic_execution_authorized",
        "provider_execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        if payload.get(name) is not False:
            raise HomeServiceCatalogError("safe_repair_plan_contract_invalid")

    try:
        kind = RecommendationKind(payload["recommendation_kind"])
        risk = RepairRisk(payload["risk"])
    except (TypeError, ValueError):
        raise HomeServiceCatalogError("safe_repair_plan_contract_invalid") from None

    policy = _REPAIR_POLICIES[kind]
    if (
        payload.get("repair_action") != policy.action
        or payload.get("technical_reason") != policy.technical_reason
        or payload.get("explanation_ru") != policy.explanation_ru
        or risk is not policy.risk
        or payload.get("confirmation_required") is not policy.confirmation_required
        or payload.get("recovery_contract") != policy.recovery_contract
        or payload.get("automation_eligible") is not policy.automation_eligible
    ):
        raise HomeServiceCatalogError("safe_repair_plan_contract_invalid")

    identity = _plan_identity_payload(
        household_id=payload["household_id"],
        household_sha256=payload["household_sha256"],
        evidence_id=payload["evidence_id"],
        evidence_sha256=payload["evidence_sha256"],
        actor_member_id=payload["actor_member_id"],
        subject_member_id=payload["subject_member_id"],
        target_id=payload["target_id"],
        recommendation_kind=kind,
        policy=policy,
    )
    if payload.get("plan_id") != _plan_id(identity):
        raise HomeServiceCatalogError("safe_repair_plan_contract_invalid")

    plan = SafeRepairPlan(
        plan_id=payload["plan_id"],
        household_id=payload["household_id"],
        household_sha256=payload["household_sha256"],
        evidence_id=payload["evidence_id"],
        evidence_sha256=payload["evidence_sha256"],
        actor_member_id=payload["actor_member_id"],
        subject_member_id=payload["subject_member_id"],
        target_id=payload["target_id"],
        recommendation_kind=kind,
        repair_action=payload["repair_action"],
        explanation_ru=payload["explanation_ru"],
        technical_reason=payload["technical_reason"],
        risk=risk,
        confirmation_required=payload["confirmation_required"],
        recovery_contract=payload["recovery_contract"],
        automation_eligible=payload["automation_eligible"],
    )
    if plan.to_dict() != payload:
        raise HomeServiceCatalogError("safe_repair_plan_contract_invalid")
    return plan
