"""Truthful read-only UI projections for Home Center 0.64 recommendations.

Both Cozy and Full projections consume the same exact recommendation evidence. They do
not grant execution authority and never present eligibility as completed repair.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping

from .safe_auto_repair import RepairAction, RepairBlocker, RepairRisk, SafeAutoRepairRecommendation

SCHEMA_UI = "home-center.safe-auto-repair-ui.v1"

_ACTION_RU = {
    RepairAction.RECONCILE_DERIVED_STATE: "Обновить производное состояние",
    RepairAction.REBUILD_DERIVED_INDEX: "Перестроить локальный индекс",
    RepairAction.REFRESH_LOCAL_READ_MODEL: "Обновить локальное представление",
}
_RISK_RU = {RepairRisk.LOW: "Низкий", RepairRisk.MEDIUM: "Средний", RepairRisk.HIGH: "Высокий"}
_BLOCKER_RU = {
    RepairBlocker.ACTION_NOT_ALLOWED.value: "Действие не разрешено политикой",
    RepairBlocker.RISK_NOT_ALLOWED.value: "Уровень риска не разрешён политикой",
    RepairBlocker.RECOVERY_NOT_PROVEN.value: "Не подтверждён безопасный путь восстановления",
    RepairBlocker.POST_CONDITION_NOT_VERIFIABLE.value: "Нельзя надёжно проверить результат",
    RepairBlocker.PROVIDER_EXECUTION_REQUIRED.value: "Требуется отдельное действие провайдера",
    RepairBlocker.INFRASTRUCTURE_MUTATION_REQUIRED.value: "Требуется изменение инфраструктуры",
    RepairBlocker.EXTERNAL_PUBLICATION_REQUIRED.value: "Требуется внешняя публикация",
}


class RecommendationUiError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RecommendationUiState(StrEnum):
    ELIGIBLE = "eligible"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class SafeAutoRepairUiProjection:
    recommendation_id: str
    household_id: str
    resource_id: str
    resource_generation: int
    state: RecommendationUiState
    cozy_title: str
    cozy_summary: str
    action_label: str
    risk_label: str
    blocker_messages: tuple[str, ...]
    evidence_sha256: str
    policy_id: str
    policy_sha256: str
    recorded_at_epoch: int | None = None
    schema: str = field(default=SCHEMA_UI, init=False)
    automatic_repair_eligible: bool = False
    execution_available: bool = field(default=False, init=False)
    repair_completed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "recommendation_id": self.recommendation_id,
            "household_id": self.household_id,
            "resource_id": self.resource_id,
            "resource_generation": self.resource_generation,
            "state": self.state.value,
            "cozy_title": self.cozy_title,
            "cozy_summary": self.cozy_summary,
            "action_label": self.action_label,
            "risk_label": self.risk_label,
            "blocker_messages": list(self.blocker_messages),
            "evidence_sha256": self.evidence_sha256,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "recorded_at_epoch": self.recorded_at_epoch,
            "automatic_repair_eligible": self.automatic_repair_eligible,
            "execution_available": False,
            "repair_completed": False,
            "execution_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def project_recommendation(recommendation: SafeAutoRepairRecommendation) -> SafeAutoRepairUiProjection:
    if not isinstance(recommendation, SafeAutoRepairRecommendation):
        raise RecommendationUiError("recommendation_ui_input_invalid")
    candidate = recommendation.candidate
    eligible = recommendation.eligible_for_auto_repair
    blockers = tuple(_BLOCKER_RU[item.value] for item in recommendation.blockers)
    if eligible:
        title = "Можно безопасно подготовить исправление"
        summary = "Проверки допуска пройдены. Исправление ещё не выполнялось и результат не подтверждён."
        state = RecommendationUiState.ELIGIBLE
    else:
        title = "Автоматическое исправление недоступно"
        summary = "Home Center не будет выполнять изменение, пока остаются ограничения безопасности."
        state = RecommendationUiState.BLOCKED
    return SafeAutoRepairUiProjection(
        recommendation_id=recommendation.recommendation_id,
        household_id=candidate.household_id,
        resource_id=candidate.resource_id,
        resource_generation=candidate.resource_generation,
        state=state,
        cozy_title=title,
        cozy_summary=summary,
        action_label=_ACTION_RU[candidate.action],
        risk_label=_RISK_RU[candidate.risk],
        blocker_messages=blockers,
        evidence_sha256=candidate.evidence_sha256,
        policy_id=recommendation.policy_id,
        policy_sha256=recommendation.policy_sha256,
        automatic_repair_eligible=eligible,
    )


def project_history_row(row: Mapping[str, object]) -> SafeAutoRepairUiProjection:
    if not isinstance(row, Mapping):
        raise RecommendationUiError("recommendation_history_row_invalid")
    recommendation = row.get("recommendation")
    recorded_at = row.get("recorded_at_epoch")
    if not isinstance(recommendation, Mapping) or type(recorded_at) is not int or recorded_at < 0:
        raise RecommendationUiError("recommendation_history_row_invalid")
    for key in (
        "execution_authorized", "provider_execution_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    ):
        if recommendation.get(key) is not False:
            raise RecommendationUiError("recommendation_history_authority_invalid")
    try:
        action = RepairAction(str(recommendation["action"]))
        risk = RepairRisk(str(recommendation["risk"]))
        blocker_values = tuple(str(value) for value in recommendation.get("blockers", ()))
        blockers = tuple(_BLOCKER_RU[value] for value in blocker_values)
        eligible = recommendation["eligible_for_auto_repair"] is True
        state = RecommendationUiState.ELIGIBLE if eligible else RecommendationUiState.BLOCKED
        if eligible and blocker_values:
            raise RecommendationUiError("recommendation_history_eligibility_conflict")
        if not eligible and not blocker_values:
            raise RecommendationUiError("recommendation_history_blocker_missing")
        return SafeAutoRepairUiProjection(
            recommendation_id=str(recommendation["recommendation_id"]),
            household_id=str(recommendation["household_id"]),
            resource_id=str(recommendation["resource_id"]),
            resource_generation=int(recommendation["resource_generation"]),
            state=state,
            cozy_title=("Можно безопасно подготовить исправление" if eligible else "Автоматическое исправление недоступно"),
            cozy_summary=(
                "Проверки допуска пройдены. Исправление ещё не выполнялось и результат не подтверждён."
                if eligible else
                "Home Center не будет выполнять изменение, пока остаются ограничения безопасности."
            ),
            action_label=_ACTION_RU[action],
            risk_label=_RISK_RU[risk],
            blocker_messages=blockers,
            evidence_sha256=str(recommendation["evidence_sha256"]),
            policy_id=str(recommendation["policy_id"]),
            policy_sha256=str(recommendation["policy_sha256"]),
            recorded_at_epoch=recorded_at,
            automatic_repair_eligible=eligible,
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, RecommendationUiError):
            raise
        raise RecommendationUiError("recommendation_history_payload_invalid") from exc
