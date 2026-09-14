"""Read-only Home Center 0.64 safe-repair history API composition.

The service joins durable recommendation evidence with the newest durable Job for each
recommendation and delegates truthfulness to the closed Cozy/Full history projection.
It never creates, starts, retries or mutates a Job.
"""
from __future__ import annotations

import re

from .safe_auto_repair_history import SQLiteSafeAutoRepairHistoryRepository
from .safe_auto_repair_job_store import SQLiteSafeAutoRepairJobRepository
from .safe_auto_repair_projection import project_safe_repair_history_entry

SAFE_REPAIR_HISTORY_RESPONSE_SCHEMA = "home-center.safe-auto-repair-history-response.v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class SafeRepairHistoryReadError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SafeRepairHistoryReadError(code)
    return value


class SafeRepairHistoryReadService:
    """Bounded Household-scoped read model over canonical durable evidence."""

    def __init__(
        self,
        history: SQLiteSafeAutoRepairHistoryRepository,
        jobs: SQLiteSafeAutoRepairJobRepository,
    ) -> None:
        if not isinstance(history, SQLiteSafeAutoRepairHistoryRepository):
            raise TypeError("safe_repair_history_read_history_repository_invalid")
        if not isinstance(jobs, SQLiteSafeAutoRepairJobRepository):
            raise TypeError("safe_repair_history_read_job_repository_invalid")
        self.history = history
        self.jobs = jobs

    def list(
        self,
        *,
        household_id: str,
        resource_id: str | None = None,
        limit: int = 50,
    ) -> dict[str, object]:
        household = _identifier(household_id, "safe_repair_history_read_household_id_invalid")
        resource = (
            _identifier(resource_id, "safe_repair_history_read_resource_id_invalid")
            if resource_id is not None
            else None
        )
        if type(limit) is not int or limit < 1 or limit > 100:
            raise SafeRepairHistoryReadError("safe_repair_history_read_limit_invalid")

        entries = self.history.recent(
            household_id=household,
            resource_id=resource,
            limit=limit,
        )
        items: list[dict[str, object]] = []
        for entry in entries:
            recommendation = entry.get("recommendation")
            if not isinstance(recommendation, dict):
                raise SafeRepairHistoryReadError("safe_repair_history_read_recommendation_invalid")
            if recommendation.get("household_id") != household:
                raise SafeRepairHistoryReadError("safe_repair_history_read_household_binding_invalid")
            if resource is not None and recommendation.get("resource_id") != resource:
                raise SafeRepairHistoryReadError("safe_repair_history_read_resource_binding_invalid")
            recommendation_id = _identifier(
                recommendation.get("recommendation_id"),
                "safe_repair_history_read_recommendation_id_invalid",
            )
            recent_jobs = self.jobs.recent_for_recommendation(
                recommendation_id=recommendation_id,
                limit=1,
            )
            job = recent_jobs[0] if recent_jobs else None
            items.append(project_safe_repair_history_entry(entry, job=job))

        return {
            "schema": SAFE_REPAIR_HISTORY_RESPONSE_SCHEMA,
            "household_id": household,
            "resource_id": resource,
            "items": items,
            "mutation_authorized": False,
            "execution_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


__all__ = [
    "SAFE_REPAIR_HISTORY_RESPONSE_SCHEMA",
    "SafeRepairHistoryReadError",
    "SafeRepairHistoryReadService",
]
