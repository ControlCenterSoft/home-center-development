"""Read-only Cozy/Full history projection for Home Center 0.64 safe auto-repair.

This module never admits or executes repair work. It renders durable recommendation
and Job evidence truthfully and fails closed on malformed or mismatched evidence.
Only an exact SUCCEEDED Job with verified post-condition evidence may be shown as
"Исправлено".
"""
from __future__ import annotations

import re
from enum import StrEnum
from typing import Mapping

from .safe_auto_repair import SAFE_REPAIR_RECOMMENDATION_SCHEMA
from .safe_auto_repair_job import RepairJobState, SafeAutoRepairJob

SAFE_REPAIR_HISTORY_PROJECTION_SCHEMA = "home-center.safe-auto-repair-history-projection.v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SafeRepairHistoryProjectionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SafeRepairHistoryStatus(StrEnum):
    BLOCKED = "blocked"
    SUGGESTED = "suggested"
    QUEUED = "queued"
    IN_PROGRESS = "in-progress"
    VERIFYING = "verifying"
    FIXED = "fixed"
    FAILED = "failed"
    NEEDS_REVIEW = "needs-review"


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SafeRepairHistoryProjectionError(code)
    return value


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise SafeRepairHistoryProjectionError(code)
    return value


def _recommendation(entry: Mapping[str, object]) -> dict[str, object]:
    recommendation = entry.get("recommendation")
    if not isinstance(recommendation, dict):
        raise SafeRepairHistoryProjectionError("safe_repair_history_recommendation_invalid")
    if recommendation.get("schema") != SAFE_REPAIR_RECOMMENDATION_SCHEMA:
        raise SafeRepairHistoryProjectionError("safe_repair_history_schema_invalid")
    if type(entry.get("recorded_at_epoch")) is not int or int(entry["recorded_at_epoch"]) < 0:
        raise SafeRepairHistoryProjectionError("safe_repair_history_recorded_at_invalid")

    expected_fields = {
        "schema",
        "recommendation_id",
        "household_id",
        "resource_id",
        "resource_generation",
        "evidence_sha256",
        "action",
        "risk",
        "policy_id",
        "policy_sha256",
        "eligible_for_auto_repair",
        "blockers",
        "recovery_proven",
        "post_condition_verification_required",
        "repair_history_required",
        "execution_authorized",
        "provider_execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if set(recommendation) != expected_fields:
        raise SafeRepairHistoryProjectionError("safe_repair_history_fields_invalid")
    if type(recommendation.get("recovery_proven")) is not bool:
        raise SafeRepairHistoryProjectionError("safe_repair_history_recovery_invalid")
    if recommendation.get("post_condition_verification_required") is not True:
        raise SafeRepairHistoryProjectionError("safe_repair_history_verification_boundary_invalid")
    if recommendation.get("repair_history_required") is not True:
        raise SafeRepairHistoryProjectionError("safe_repair_history_history_boundary_invalid")

    for field_name in (
        "execution_authorized",
        "provider_execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        if recommendation.get(field_name) is not False:
            raise SafeRepairHistoryProjectionError("safe_repair_history_authority_invalid")

    _identifier(recommendation.get("recommendation_id"), "safe_repair_history_recommendation_id_invalid")
    _identifier(recommendation.get("household_id"), "safe_repair_history_household_id_invalid")
    _identifier(recommendation.get("resource_id"), "safe_repair_history_resource_id_invalid")
    _identifier(recommendation.get("action"), "safe_repair_history_action_invalid")
    _identifier(recommendation.get("risk"), "safe_repair_history_risk_invalid")
    _identifier(recommendation.get("policy_id"), "safe_repair_history_policy_id_invalid")
    _sha256(recommendation.get("evidence_sha256"), "safe_repair_history_evidence_invalid")
    _sha256(recommendation.get("policy_sha256"), "safe_repair_history_policy_digest_invalid")
    if type(recommendation.get("resource_generation")) is not int:
        raise SafeRepairHistoryProjectionError("safe_repair_history_generation_invalid")
    if int(recommendation["resource_generation"]) < 0:
        raise SafeRepairHistoryProjectionError("safe_repair_history_generation_invalid")
    if type(recommendation.get("eligible_for_auto_repair")) is not bool:
        raise SafeRepairHistoryProjectionError("safe_repair_history_eligibility_invalid")
    blockers = recommendation.get("blockers")
    if not isinstance(blockers, list) or not all(isinstance(item, str) for item in blockers):
        raise SafeRepairHistoryProjectionError("safe_repair_history_blockers_invalid")
    return recommendation


def _status(
    recommendation: Mapping[str, object],
    job: SafeAutoRepairJob | None,
) -> SafeRepairHistoryStatus:
    eligible = recommendation["eligible_for_auto_repair"]
    blockers = recommendation["blockers"]
    if eligible is False:
        if not blockers:
            raise SafeRepairHistoryProjectionError("safe_repair_history_blocked_without_reason")
        if job is not None:
            raise SafeRepairHistoryProjectionError("safe_repair_history_blocked_job_invalid")
        return SafeRepairHistoryStatus.BLOCKED
    if blockers:
        raise SafeRepairHistoryProjectionError("safe_repair_history_eligible_with_blockers")
    if job is None:
        return SafeRepairHistoryStatus.SUGGESTED

    if job.recommendation_id != recommendation["recommendation_id"]:
        raise SafeRepairHistoryProjectionError("safe_repair_history_job_binding_invalid")

    mapping = {
        RepairJobState.ADMITTED: SafeRepairHistoryStatus.QUEUED,
        RepairJobState.RUNNING: SafeRepairHistoryStatus.IN_PROGRESS,
        RepairJobState.VERIFYING: SafeRepairHistoryStatus.VERIFYING,
        RepairJobState.FAILED: SafeRepairHistoryStatus.FAILED,
        RepairJobState.RECONCILE_REQUIRED: SafeRepairHistoryStatus.NEEDS_REVIEW,
    }
    if job.state is RepairJobState.SUCCEEDED:
        if not job.post_condition_verified or job.post_condition_evidence_sha256 is None:
            raise SafeRepairHistoryProjectionError("safe_repair_history_false_success")
        return SafeRepairHistoryStatus.FIXED
    try:
        return mapping[job.state]
    except KeyError as exc:
        raise SafeRepairHistoryProjectionError("safe_repair_history_job_state_invalid") from exc


_COZY_MESSAGE = {
    SafeRepairHistoryStatus.BLOCKED: "Автоисправление недоступно: требуется безопасное действие вручную.",
    SafeRepairHistoryStatus.SUGGESTED: "Найдено безопасное исправление.",
    SafeRepairHistoryStatus.QUEUED: "Исправление подготовлено.",
    SafeRepairHistoryStatus.IN_PROGRESS: "Исправление выполняется.",
    SafeRepairHistoryStatus.VERIFYING: "Проверяем результат исправления.",
    SafeRepairHistoryStatus.FIXED: "Исправлено и проверено.",
    SafeRepairHistoryStatus.FAILED: "Исправить автоматически не удалось.",
    SafeRepairHistoryStatus.NEEDS_REVIEW: "Результат неоднозначен — нужна проверка.",
}


def project_safe_repair_history_entry(
    entry: Mapping[str, object],
    *,
    job: SafeAutoRepairJob | None = None,
) -> dict[str, object]:
    """Project one durable recommendation/Job pair without creating mutation authority."""

    if not isinstance(entry, Mapping):
        raise SafeRepairHistoryProjectionError("safe_repair_history_entry_invalid")
    recommendation = _recommendation(entry)
    status = _status(recommendation, job)
    repair_verified = status is SafeRepairHistoryStatus.FIXED

    return {
        "schema": SAFE_REPAIR_HISTORY_PROJECTION_SCHEMA,
        "recommendation_id": recommendation["recommendation_id"],
        "household_id": recommendation["household_id"],
        "resource_id": recommendation["resource_id"],
        "resource_generation": recommendation["resource_generation"],
        "action": recommendation["action"],
        "risk": recommendation["risk"],
        "status": status.value,
        "cozy_message": _COZY_MESSAGE[status],
        "recorded_at_epoch": entry["recorded_at_epoch"],
        "job_id": job.job_id if job is not None else None,
        "job_updated_at_epoch": job.updated_at_epoch if job is not None else None,
        "repair_verified": repair_verified,
        "post_condition_evidence_sha256": (
            job.post_condition_evidence_sha256 if repair_verified and job is not None else None
        ),
        "execution_authorized": False,
        "provider_execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


__all__ = [
    "SAFE_REPAIR_HISTORY_PROJECTION_SCHEMA",
    "SafeRepairHistoryProjectionError",
    "SafeRepairHistoryStatus",
    "project_safe_repair_history_entry",
]
