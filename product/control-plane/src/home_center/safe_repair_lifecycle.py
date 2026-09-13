"""Fail-closed admission, completion evidence and history projection for Home Center 0.64.

This layer deliberately does not execute repairs. It revalidates an exact
:class:`SafeRepairPlan`, binds any future execution to a durable Job, and
ensures user-visible success can only be produced from fresh post-condition
verification plus recovery evidence. The actual executor remains a separate
qualified boundary and must use the normal Identity/RBAC -> Change/Job -> typed
execution -> read-back -> Audit/recovery path.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .home_services import HomeServiceCatalogError, _identifier
from .household import Household
from .safe_recommendations import (
    RecommendationEvidence,
    RecommendationKind,
    RepairRisk,
    SafeRepairPlan,
    plan_safe_repair,
)

SAFE_REPAIR_ADMISSION_SCHEMA = "home-center.safe-repair-admission.v1"
SAFE_REPAIR_COMPLETION_SCHEMA = "home-center.safe-repair-completion-evidence.v1"
SAFE_REPAIR_HISTORY_SCHEMA = "home-center.safe-repair-history-entry.v1"

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PLAN_ID = re.compile(r"srp-[0-9a-f]{24}\Z")
_ADMISSION_ID = re.compile(r"sra-[0-9a-f]{24}\Z")
_COMPLETION_ID = re.compile(r"src-[0-9a-f]{24}\Z")
_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class SafeRepairAdmissionMode(StrEnum):
    MANUAL_CONFIRMED = "manual-confirmed"
    AUTOMATION_CANDIDATE = "automation-candidate"


class SafeRepairOutcome(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    RECONCILE_REQUIRED = "reconcile-required"


class SafeRepairHistoryStatus(StrEnum):
    FIXED = "fixed"
    FAILED = "failed"
    NEEDS_ATTENTION = "needs-attention"


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise HomeServiceCatalogError(code)
    return value


def _epoch(value: object, code: str) -> int:
    if type(value) is not int or value < 0:
        raise HomeServiceCatalogError(code)
    return value


def _job_id(value: object) -> str:
    if not isinstance(value, str) or _JOB_ID.fullmatch(value) is None:
        raise HomeServiceCatalogError("safe_repair_job_id_invalid")
    return value


def _bounded_text(value: object, code: str, *, limit: int = 320) -> str:
    if not isinstance(value, str):
        raise HomeServiceCatalogError(code)
    normalized = value.strip()
    if not normalized or len(normalized) > limit or any(ord(char) < 32 for char in normalized):
        raise HomeServiceCatalogError(code)
    return normalized


def _content_id(prefix: str, payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return prefix + hashlib.sha256(encoded).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class SafeRepairAdmission:
    admission_id: str
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
    risk: RepairRisk
    mode: SafeRepairAdmissionMode
    confirmation_required: bool
    confirmed: bool
    automation_candidate: bool
    schema: str = field(default=SAFE_REPAIR_ADMISSION_SCHEMA, init=False)
    durable_job_required: bool = field(default=True, init=False)
    audit_required: bool = field(default=True, init=False)
    post_condition_verification_required: bool = field(default=True, init=False)
    recovery_evidence_required: bool = field(default=True, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    automatic_execution_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.admission_id, str) or _ADMISSION_ID.fullmatch(self.admission_id) is None:
            raise HomeServiceCatalogError("safe_repair_admission_id_invalid")
        if not isinstance(self.plan_id, str) or _PLAN_ID.fullmatch(self.plan_id) is None:
            raise HomeServiceCatalogError("safe_repair_admission_plan_id_invalid")
        object.__setattr__(self, "household_id", _identifier(self.household_id, "safe_repair_admission_household_id_invalid"))
        object.__setattr__(self, "evidence_id", _identifier(self.evidence_id, "safe_repair_admission_evidence_id_invalid"))
        object.__setattr__(self, "actor_member_id", _identifier(self.actor_member_id, "safe_repair_admission_actor_invalid"))
        object.__setattr__(self, "subject_member_id", _identifier(self.subject_member_id, "safe_repair_admission_subject_invalid"))
        object.__setattr__(self, "target_id", _identifier(self.target_id, "safe_repair_admission_target_invalid"))
        object.__setattr__(self, "household_sha256", _sha256(self.household_sha256, "safe_repair_admission_household_sha_invalid"))
        object.__setattr__(self, "evidence_sha256", _sha256(self.evidence_sha256, "safe_repair_admission_evidence_sha_invalid"))
        object.__setattr__(self, "repair_action", _bounded_text(self.repair_action, "safe_repair_admission_action_invalid"))
        if not isinstance(self.recommendation_kind, RecommendationKind):
            raise HomeServiceCatalogError("safe_repair_admission_kind_invalid")
        if not isinstance(self.risk, RepairRisk):
            raise HomeServiceCatalogError("safe_repair_admission_risk_invalid")
        if not isinstance(self.mode, SafeRepairAdmissionMode):
            raise HomeServiceCatalogError("safe_repair_admission_mode_invalid")
        for value in (self.confirmation_required, self.confirmed, self.automation_candidate):
            if type(value) is not bool:
                raise HomeServiceCatalogError("safe_repair_admission_flags_invalid")
        if self.mode is SafeRepairAdmissionMode.MANUAL_CONFIRMED:
            if not self.confirmation_required or not self.confirmed or self.automation_candidate:
                raise HomeServiceCatalogError("safe_repair_admission_mode_invalid")
        elif self.mode is SafeRepairAdmissionMode.AUTOMATION_CANDIDATE:
            if self.confirmation_required or self.confirmed or not self.automation_candidate:
                raise HomeServiceCatalogError("safe_repair_admission_mode_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "admission_id": self.admission_id,
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
            "risk": self.risk.value,
            "mode": self.mode.value,
            "confirmation_required": self.confirmation_required,
            "confirmed": self.confirmed,
            "automation_candidate": self.automation_candidate,
            "durable_job_required": True,
            "audit_required": True,
            "post_condition_verification_required": True,
            "recovery_evidence_required": True,
            "mutation_authorized": False,
            "execution_authorized": False,
            "automatic_execution_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _admission_identity(*, plan: SafeRepairPlan, mode: SafeRepairAdmissionMode, confirmed: bool) -> dict[str, object]:
    return {
        "plan_id": plan.plan_id,
        "household_id": plan.household_id,
        "household_sha256": plan.household_sha256,
        "evidence_id": plan.evidence_id,
        "evidence_sha256": plan.evidence_sha256,
        "actor_member_id": plan.actor_member_id,
        "subject_member_id": plan.subject_member_id,
        "target_id": plan.target_id,
        "recommendation_kind": plan.recommendation_kind.value,
        "repair_action": plan.repair_action,
        "risk": plan.risk.value,
        "mode": mode.value,
        "confirmation_required": plan.confirmation_required,
        "confirmed": confirmed,
        "automation_candidate": mode is SafeRepairAdmissionMode.AUTOMATION_CANDIDATE,
    }


def admit_safe_repair(
    household: Household,
    *,
    plan: SafeRepairPlan,
    evidence: RecommendationEvidence,
    now_epoch_seconds: int,
    confirmed: bool,
) -> SafeRepairAdmission:
    """Revalidate an exact plan immediately before any durable Job admission.

    ``automation_candidate`` is classification only. Even the low-risk read-only
    refresh class remains ``automatic_execution_authorized=false`` until a
    later qualified runtime creates and verifies its durable Job.
    """

    if not isinstance(plan, SafeRepairPlan) or not isinstance(evidence, RecommendationEvidence):
        raise HomeServiceCatalogError("safe_repair_admission_input_invalid")
    if type(confirmed) is not bool:
        raise HomeServiceCatalogError("safe_repair_admission_confirmation_invalid")
    if (
        evidence.evidence_id != plan.evidence_id
        or evidence.evidence_sha256 != plan.evidence_sha256
        or evidence.household_id != plan.household_id
        or evidence.subject_member_id != plan.subject_member_id
        or evidence.target_id != plan.target_id
        or evidence.kind is not plan.recommendation_kind
    ):
        raise HomeServiceCatalogError("safe_repair_admission_evidence_binding_mismatch")

    rebuilt = plan_safe_repair(
        household,
        actor_member_id=plan.actor_member_id,
        evidence=evidence,
        now_epoch_seconds=now_epoch_seconds,
    )
    if rebuilt != plan:
        raise HomeServiceCatalogError("safe_repair_admission_plan_stale")

    if plan.confirmation_required:
        if confirmed is not True:
            raise HomeServiceCatalogError("safe_repair_admission_confirmation_required")
        mode = SafeRepairAdmissionMode.MANUAL_CONFIRMED
        normalized_confirmed = True
    else:
        if not plan.automation_eligible:
            raise HomeServiceCatalogError("safe_repair_admission_unconfirmed_not_eligible")
        mode = SafeRepairAdmissionMode.AUTOMATION_CANDIDATE
        normalized_confirmed = False

    identity = _admission_identity(plan=plan, mode=mode, confirmed=normalized_confirmed)
    return SafeRepairAdmission(
        admission_id=_content_id("sra-", identity),
        plan_id=plan.plan_id,
        household_id=plan.household_id,
        household_sha256=plan.household_sha256,
        evidence_id=plan.evidence_id,
        evidence_sha256=plan.evidence_sha256,
        actor_member_id=plan.actor_member_id,
        subject_member_id=plan.subject_member_id,
        target_id=plan.target_id,
        recommendation_kind=plan.recommendation_kind,
        repair_action=plan.repair_action,
        risk=plan.risk,
        mode=mode,
        confirmation_required=plan.confirmation_required,
        confirmed=normalized_confirmed,
        automation_candidate=mode is SafeRepairAdmissionMode.AUTOMATION_CANDIDATE,
    )


_ADMISSION_KEYS = frozenset(
    {
        "schema", "admission_id", "plan_id", "household_id", "household_sha256",
        "evidence_id", "evidence_sha256", "actor_member_id", "subject_member_id",
        "target_id", "recommendation_kind", "repair_action", "risk", "mode",
        "confirmation_required", "confirmed", "automation_candidate", "durable_job_required",
        "audit_required", "post_condition_verification_required", "recovery_evidence_required",
        "mutation_authorized", "execution_authorized", "automatic_execution_authorized",
        "provider_execution_authorized", "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
)


def safe_repair_admission_from_dict(payload: object) -> SafeRepairAdmission:
    if not isinstance(payload, dict) or set(payload) != _ADMISSION_KEYS:
        raise HomeServiceCatalogError("safe_repair_admission_contract_invalid")
    if payload.get("schema") != SAFE_REPAIR_ADMISSION_SCHEMA:
        raise HomeServiceCatalogError("safe_repair_admission_contract_invalid")
    for key in ("durable_job_required", "audit_required", "post_condition_verification_required", "recovery_evidence_required"):
        if payload.get(key) is not True:
            raise HomeServiceCatalogError("safe_repair_admission_contract_invalid")
    for key in (
        "mutation_authorized", "execution_authorized", "automatic_execution_authorized",
        "provider_execution_authorized", "infrastructure_mutation_authorized", "external_publication_authorized",
    ):
        if payload.get(key) is not False:
            raise HomeServiceCatalogError("safe_repair_admission_contract_invalid")
    try:
        kind = RecommendationKind(payload["recommendation_kind"])
        risk = RepairRisk(payload["risk"])
        mode = SafeRepairAdmissionMode(payload["mode"])
    except (TypeError, ValueError):
        raise HomeServiceCatalogError("safe_repair_admission_contract_invalid") from None

    admission = SafeRepairAdmission(
        admission_id=payload["admission_id"],
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
        risk=risk,
        mode=mode,
        confirmation_required=payload["confirmation_required"],
        confirmed=payload["confirmed"],
        automation_candidate=payload["automation_candidate"],
    )
    identity = {
        "plan_id": admission.plan_id,
        "household_id": admission.household_id,
        "household_sha256": admission.household_sha256,
        "evidence_id": admission.evidence_id,
        "evidence_sha256": admission.evidence_sha256,
        "actor_member_id": admission.actor_member_id,
        "subject_member_id": admission.subject_member_id,
        "target_id": admission.target_id,
        "recommendation_kind": admission.recommendation_kind.value,
        "repair_action": admission.repair_action,
        "risk": admission.risk.value,
        "mode": admission.mode.value,
        "confirmation_required": admission.confirmation_required,
        "confirmed": admission.confirmed,
        "automation_candidate": admission.automation_candidate,
    }
    if admission.admission_id != _content_id("sra-", identity) or admission.to_dict() != payload:
        raise HomeServiceCatalogError("safe_repair_admission_contract_invalid")
    return admission


@dataclass(frozen=True, slots=True)
class SafeRepairCompletionEvidence:
    completion_id: str
    admission_id: str
    plan_id: str
    household_id: str
    target_id: str
    recommendation_kind: RecommendationKind
    repair_action: str
    job_id: str
    before_evidence_sha256: str
    after_evidence_sha256: str
    post_condition_evidence_sha256: str
    recovery_evidence_sha256: str
    outcome: SafeRepairOutcome
    post_condition_verified: bool
    completed_at_epoch: int
    schema: str = field(default=SAFE_REPAIR_COMPLETION_SCHEMA, init=False)
    repair_verified: bool = field(default=False, init=False)
    state_change_authorized: bool = field(default=False, init=False)
    automatic_success_claim_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.completion_id, str) or _COMPLETION_ID.fullmatch(self.completion_id) is None:
            raise HomeServiceCatalogError("safe_repair_completion_id_invalid")
        if not isinstance(self.admission_id, str) or _ADMISSION_ID.fullmatch(self.admission_id) is None:
            raise HomeServiceCatalogError("safe_repair_completion_admission_id_invalid")
        if not isinstance(self.plan_id, str) or _PLAN_ID.fullmatch(self.plan_id) is None:
            raise HomeServiceCatalogError("safe_repair_completion_plan_id_invalid")
        object.__setattr__(self, "household_id", _identifier(self.household_id, "safe_repair_completion_household_id_invalid"))
        object.__setattr__(self, "target_id", _identifier(self.target_id, "safe_repair_completion_target_id_invalid"))
        object.__setattr__(self, "repair_action", _bounded_text(self.repair_action, "safe_repair_completion_action_invalid"))
        object.__setattr__(self, "job_id", _job_id(self.job_id))
        for name in (
            "before_evidence_sha256", "after_evidence_sha256", "post_condition_evidence_sha256", "recovery_evidence_sha256",
        ):
            object.__setattr__(self, name, _sha256(getattr(self, name), f"safe_repair_completion_{name}_invalid"))
        if not isinstance(self.recommendation_kind, RecommendationKind):
            raise HomeServiceCatalogError("safe_repair_completion_kind_invalid")
        if not isinstance(self.outcome, SafeRepairOutcome):
            raise HomeServiceCatalogError("safe_repair_completion_outcome_invalid")
        if type(self.post_condition_verified) is not bool:
            raise HomeServiceCatalogError("safe_repair_completion_postcondition_invalid")
        _epoch(self.completed_at_epoch, "safe_repair_completion_time_invalid")
        if self.outcome is SafeRepairOutcome.VERIFIED and self.post_condition_verified is not True:
            raise HomeServiceCatalogError("safe_repair_completion_false_success")
        if self.outcome is not SafeRepairOutcome.VERIFIED and self.post_condition_verified is not False:
            raise HomeServiceCatalogError("safe_repair_completion_inconsistent_failure")
        object.__setattr__(self, "repair_verified", self.outcome is SafeRepairOutcome.VERIFIED and self.post_condition_verified)

    @property
    def summary_ru(self) -> str:
        if self.outcome is SafeRepairOutcome.VERIFIED:
            return "Исправление выполнено, результат проверен."
        if self.outcome is SafeRepairOutcome.RECONCILE_REQUIRED:
            return "Результат исправления не подтверждён и требует повторной сверки."
        return "Исправление завершилось ошибкой; успешный результат не подтверждён."

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "completion_id": self.completion_id,
            "admission_id": self.admission_id,
            "plan_id": self.plan_id,
            "household_id": self.household_id,
            "target_id": self.target_id,
            "recommendation_kind": self.recommendation_kind.value,
            "repair_action": self.repair_action,
            "job_id": self.job_id,
            "before_evidence_sha256": self.before_evidence_sha256,
            "after_evidence_sha256": self.after_evidence_sha256,
            "post_condition_evidence_sha256": self.post_condition_evidence_sha256,
            "recovery_evidence_sha256": self.recovery_evidence_sha256,
            "outcome": self.outcome.value,
            "post_condition_verified": self.post_condition_verified,
            "repair_verified": self.repair_verified,
            "summary_ru": self.summary_ru,
            "completed_at_epoch": self.completed_at_epoch,
            "state_change_authorized": False,
            "automatic_success_claim_authorized": False,
            "external_publication_authorized": False,
        }


def _completion_identity(
    *,
    admission_id: str,
    plan_id: str,
    household_id: str,
    target_id: str,
    recommendation_kind: RecommendationKind,
    repair_action: str,
    job_id: str,
    before_evidence_sha256: str,
    after_evidence_sha256: str,
    post_condition_evidence_sha256: str,
    recovery_evidence_sha256: str,
    outcome: SafeRepairOutcome,
    post_condition_verified: bool,
    completed_at_epoch: int,
) -> dict[str, object]:
    return {
        "admission_id": admission_id,
        "plan_id": plan_id,
        "household_id": household_id,
        "target_id": target_id,
        "recommendation_kind": recommendation_kind.value,
        "repair_action": repair_action,
        "job_id": job_id,
        "before_evidence_sha256": before_evidence_sha256,
        "after_evidence_sha256": after_evidence_sha256,
        "post_condition_evidence_sha256": post_condition_evidence_sha256,
        "recovery_evidence_sha256": recovery_evidence_sha256,
        "outcome": outcome.value,
        "post_condition_verified": post_condition_verified,
        "completed_at_epoch": completed_at_epoch,
    }


def build_safe_repair_completion(
    *,
    admission: SafeRepairAdmission,
    job_id: str,
    before_evidence_sha256: str,
    after_evidence_sha256: str,
    post_condition_evidence_sha256: str,
    recovery_evidence_sha256: str,
    outcome: SafeRepairOutcome,
    post_condition_verified: bool,
    completed_at_epoch: int,
) -> SafeRepairCompletionEvidence:
    if not isinstance(admission, SafeRepairAdmission):
        raise HomeServiceCatalogError("safe_repair_completion_admission_invalid")
    if not isinstance(outcome, SafeRepairOutcome):
        raise HomeServiceCatalogError("safe_repair_completion_outcome_invalid")
    normalized_job_id = _job_id(job_id)
    before = _sha256(before_evidence_sha256, "safe_repair_completion_before_evidence_invalid")
    after = _sha256(after_evidence_sha256, "safe_repair_completion_after_evidence_invalid")
    post = _sha256(post_condition_evidence_sha256, "safe_repair_completion_postcondition_evidence_invalid")
    recovery = _sha256(recovery_evidence_sha256, "safe_repair_completion_recovery_evidence_invalid")
    completed = _epoch(completed_at_epoch, "safe_repair_completion_time_invalid")
    if type(post_condition_verified) is not bool:
        raise HomeServiceCatalogError("safe_repair_completion_postcondition_invalid")
    if outcome is SafeRepairOutcome.VERIFIED and not post_condition_verified:
        raise HomeServiceCatalogError("safe_repair_completion_false_success")
    if outcome is not SafeRepairOutcome.VERIFIED and post_condition_verified:
        raise HomeServiceCatalogError("safe_repair_completion_inconsistent_failure")

    identity = _completion_identity(
        admission_id=admission.admission_id,
        plan_id=admission.plan_id,
        household_id=admission.household_id,
        target_id=admission.target_id,
        recommendation_kind=admission.recommendation_kind,
        repair_action=admission.repair_action,
        job_id=normalized_job_id,
        before_evidence_sha256=before,
        after_evidence_sha256=after,
        post_condition_evidence_sha256=post,
        recovery_evidence_sha256=recovery,
        outcome=outcome,
        post_condition_verified=post_condition_verified,
        completed_at_epoch=completed,
    )
    return SafeRepairCompletionEvidence(
        completion_id=_content_id("src-", identity),
        admission_id=admission.admission_id,
        plan_id=admission.plan_id,
        household_id=admission.household_id,
        target_id=admission.target_id,
        recommendation_kind=admission.recommendation_kind,
        repair_action=admission.repair_action,
        job_id=normalized_job_id,
        before_evidence_sha256=before,
        after_evidence_sha256=after,
        post_condition_evidence_sha256=post,
        recovery_evidence_sha256=recovery,
        outcome=outcome,
        post_condition_verified=post_condition_verified,
        completed_at_epoch=completed,
    )


_COMPLETION_KEYS = frozenset(
    {
        "schema", "completion_id", "admission_id", "plan_id", "household_id", "target_id",
        "recommendation_kind", "repair_action", "job_id", "before_evidence_sha256",
        "after_evidence_sha256", "post_condition_evidence_sha256", "recovery_evidence_sha256",
        "outcome", "post_condition_verified", "repair_verified", "summary_ru", "completed_at_epoch",
        "state_change_authorized", "automatic_success_claim_authorized", "external_publication_authorized",
    }
)


def safe_repair_completion_from_dict(payload: object) -> SafeRepairCompletionEvidence:
    if not isinstance(payload, dict) or set(payload) != _COMPLETION_KEYS:
        raise HomeServiceCatalogError("safe_repair_completion_contract_invalid")
    if payload.get("schema") != SAFE_REPAIR_COMPLETION_SCHEMA:
        raise HomeServiceCatalogError("safe_repair_completion_contract_invalid")
    for key in ("state_change_authorized", "automatic_success_claim_authorized", "external_publication_authorized"):
        if payload.get(key) is not False:
            raise HomeServiceCatalogError("safe_repair_completion_contract_invalid")
    try:
        kind = RecommendationKind(payload["recommendation_kind"])
        outcome = SafeRepairOutcome(payload["outcome"])
    except (TypeError, ValueError):
        raise HomeServiceCatalogError("safe_repair_completion_contract_invalid") from None

    if not isinstance(payload.get("admission_id"), str) or _ADMISSION_ID.fullmatch(payload["admission_id"]) is None:
        raise HomeServiceCatalogError("safe_repair_completion_contract_invalid")

    completion = SafeRepairCompletionEvidence(
        completion_id=payload["completion_id"],
        admission_id=payload["admission_id"],
        plan_id=payload["plan_id"],
        household_id=payload["household_id"],
        target_id=payload["target_id"],
        recommendation_kind=kind,
        repair_action=payload["repair_action"],
        job_id=payload["job_id"],
        before_evidence_sha256=payload["before_evidence_sha256"],
        after_evidence_sha256=payload["after_evidence_sha256"],
        post_condition_evidence_sha256=payload["post_condition_evidence_sha256"],
        recovery_evidence_sha256=payload["recovery_evidence_sha256"],
        outcome=outcome,
        post_condition_verified=payload["post_condition_verified"],
        completed_at_epoch=payload["completed_at_epoch"],
    )
    identity = _completion_identity(
        admission_id=completion.admission_id,
        plan_id=completion.plan_id,
        household_id=completion.household_id,
        target_id=completion.target_id,
        recommendation_kind=completion.recommendation_kind,
        repair_action=completion.repair_action,
        job_id=completion.job_id,
        before_evidence_sha256=completion.before_evidence_sha256,
        after_evidence_sha256=completion.after_evidence_sha256,
        post_condition_evidence_sha256=completion.post_condition_evidence_sha256,
        recovery_evidence_sha256=completion.recovery_evidence_sha256,
        outcome=completion.outcome,
        post_condition_verified=completion.post_condition_verified,
        completed_at_epoch=completion.completed_at_epoch,
    )
    if completion.completion_id != _content_id("src-", identity):
        raise HomeServiceCatalogError("safe_repair_completion_contract_invalid")
    if completion.repair_verified is not payload.get("repair_verified") or completion.summary_ru != payload.get("summary_ru"):
        raise HomeServiceCatalogError("safe_repair_completion_contract_invalid")
    if completion.to_dict() != payload:
        raise HomeServiceCatalogError("safe_repair_completion_contract_invalid")
    return completion


def validate_completion_binding(admission: SafeRepairAdmission, completion: SafeRepairCompletionEvidence) -> None:
    """Fail closed when completion evidence is rebound to another admission."""

    if not isinstance(admission, SafeRepairAdmission) or not isinstance(completion, SafeRepairCompletionEvidence):
        raise HomeServiceCatalogError("safe_repair_completion_binding_invalid")
    if (
        completion.admission_id != admission.admission_id
        or completion.plan_id != admission.plan_id
        or completion.household_id != admission.household_id
        or completion.target_id != admission.target_id
        or completion.recommendation_kind is not admission.recommendation_kind
        or completion.repair_action != admission.repair_action
    ):
        raise HomeServiceCatalogError("safe_repair_completion_binding_invalid")

    identity = _completion_identity(
        admission_id=admission.admission_id,
        plan_id=admission.plan_id,
        household_id=admission.household_id,
        target_id=admission.target_id,
        recommendation_kind=admission.recommendation_kind,
        repair_action=admission.repair_action,
        job_id=completion.job_id,
        before_evidence_sha256=completion.before_evidence_sha256,
        after_evidence_sha256=completion.after_evidence_sha256,
        post_condition_evidence_sha256=completion.post_condition_evidence_sha256,
        recovery_evidence_sha256=completion.recovery_evidence_sha256,
        outcome=completion.outcome,
        post_condition_verified=completion.post_condition_verified,
        completed_at_epoch=completion.completed_at_epoch,
    )
    if completion.completion_id != _content_id("src-", identity):
        raise HomeServiceCatalogError("safe_repair_completion_binding_invalid")


@dataclass(frozen=True, slots=True)
class SafeRepairHistoryEntry:
    entry_id: str
    job_id: str
    target_id: str
    recommendation_kind: RecommendationKind
    status: SafeRepairHistoryStatus
    title_ru: str
    detail_ru: str
    completed_at_epoch: int
    repair_verified: bool
    schema: str = field(default=SAFE_REPAIR_HISTORY_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "entry_id": self.entry_id,
            "job_id": self.job_id,
            "target_id": self.target_id,
            "recommendation_kind": self.recommendation_kind.value,
            "status": self.status.value,
            "title_ru": self.title_ru,
            "detail_ru": self.detail_ru,
            "completed_at_epoch": self.completed_at_epoch,
            "repair_verified": self.repair_verified,
        }


def project_safe_repair_history(admission: SafeRepairAdmission, completion: SafeRepairCompletionEvidence) -> SafeRepairHistoryEntry:
    """Create a privacy-bounded Cozy/Full history entry from verified evidence."""

    validate_completion_binding(admission, completion)
    if completion.outcome is SafeRepairOutcome.VERIFIED:
        status = SafeRepairHistoryStatus.FIXED
        title = "Исправлено"
        detail = f"{completion.summary_ru} Действие: {admission.repair_action}."
    elif completion.outcome is SafeRepairOutcome.RECONCILE_REQUIRED:
        status = SafeRepairHistoryStatus.NEEDS_ATTENTION
        title = "Требуется проверка"
        detail = completion.summary_ru
    else:
        status = SafeRepairHistoryStatus.FAILED
        title = "Не исправлено"
        detail = completion.summary_ru
    return SafeRepairHistoryEntry(
        entry_id=completion.completion_id,
        job_id=completion.job_id,
        target_id=completion.target_id,
        recommendation_kind=completion.recommendation_kind,
        status=status,
        title_ru=title,
        detail_ru=detail,
        completed_at_epoch=completion.completed_at_epoch,
        repair_verified=completion.repair_verified,
    )
