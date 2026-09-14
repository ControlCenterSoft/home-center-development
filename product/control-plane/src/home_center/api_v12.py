"""Home Center 0.64 authenticated read-only safe-repair history HTTP boundary.

This version adds no repair admission or execution route. It exposes only exact durable
recommendation/Job evidence to an authenticated enabled Household parent. The Cozy/Full
projection never turns running, verifying, ambiguous or failed evidence into success.
"""
from __future__ import annotations

from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from .api_v11 import RuntimeRequestHandlerV11
from .household import HouseholdRole
from .household_runtime import HouseholdRuntimeError
from .safe_auto_repair_read_api import SafeRepairHistoryReadError, SafeRepairHistoryReadService


class RuntimeRequestHandlerV12(RuntimeRequestHandlerV11):
    SAFE_REPAIR_HISTORY_GET = "/api/v1/household/safe-repair/history"

    def _safe_repair_history_service(self) -> SafeRepairHistoryReadService:
        history = getattr(self.runtime, "safe_repair_history", None)
        jobs = getattr(self.runtime, "safe_repair_jobs", None)
        if history is None or jobs is None:
            raise SafeRepairHistoryReadError("safe_repair_history_http_runtime_unavailable")
        return SafeRepairHistoryReadService(history, jobs)

    @staticmethod
    def _require_safe_repair_parent(snapshot, actor_member_id: str) -> None:
        try:
            member = snapshot.household.member(actor_member_id)
        except Exception as exc:
            raise SafeRepairHistoryReadError(
                "safe_repair_history_http_actor_member_unavailable"
            ) from exc
        if not member.enabled or member.role is not HouseholdRole.PARENT:
            raise SafeRepairHistoryReadError("safe_repair_history_http_parent_required")

    @staticmethod
    def _history_query(raw_query: str) -> tuple[str | None, int]:
        try:
            query = parse_qs(
                raw_query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=2,
            )
        except ValueError as exc:
            raise SafeRepairHistoryReadError("safe_repair_history_http_query_invalid") from exc
        if set(query) - {"resource_id", "limit"}:
            raise SafeRepairHistoryReadError("safe_repair_history_http_query_invalid")
        if any(len(values) != 1 for values in query.values()):
            raise SafeRepairHistoryReadError("safe_repair_history_http_query_invalid")

        resource_id: str | None = None
        if "resource_id" in query:
            resource_id = query["resource_id"][0]
            if not resource_id:
                raise SafeRepairHistoryReadError("safe_repair_history_http_query_invalid")

        limit = 50
        if "limit" in query:
            raw_limit = query["limit"][0]
            if not raw_limit.isascii() or not raw_limit.isdecimal():
                raise SafeRepairHistoryReadError("safe_repair_history_http_query_invalid")
            limit = int(raw_limit)
            if limit < 1 or limit > 100:
                raise SafeRepairHistoryReadError("safe_repair_history_http_query_invalid")
        return resource_id, limit

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path != self.SAFE_REPAIR_HISTORY_GET:
            super().do_GET()
            return

        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(parsed.path, context):
            self.close_connection = True
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return

        actor = self._require_actor(correlation_id)
        if not actor:
            return

        try:
            snapshot, bindings = self._household_state()
            actor_member_id = self.runtime.household._actor_member(actor, bindings)
            self._require_safe_repair_parent(snapshot, actor_member_id)
            resource_id, limit = self._history_query(parsed.query)
            result = self._safe_repair_history_service().list(
                household_id=snapshot.household_id,
                resource_id=resource_id,
                limit=limit,
            )
            self.runtime.store.audit(
                actor=actor,
                action="household.safe-repair.history.read",
                target=snapshot.household_id,
                outcome="succeeded",
                correlation_id=correlation_id,
                details={
                    "resource_filter_present": resource_id is not None,
                    "result_count": len(result["items"]),
                },
            )
            self._json(HTTPStatus.OK, result)
            return
        except (SafeRepairHistoryReadError, HouseholdRuntimeError) as exc:
            code = getattr(exc, "code", str(exc))
            forbidden = {
                "household_actor_not_bound",
                "household_member_disabled",
                "safe_repair_history_http_actor_member_unavailable",
                "safe_repair_history_http_parent_required",
            }
            unavailable = {"safe_repair_history_http_runtime_unavailable"}
            if code in forbidden:
                status = HTTPStatus.FORBIDDEN
            elif code in unavailable:
                status = HTTPStatus.SERVICE_UNAVAILABLE
            else:
                status = HTTPStatus.BAD_REQUEST
            self.runtime.store.audit(
                actor=actor,
                action="household.safe-repair.history.read",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code},
            )
            self._error(
                status,
                code,
                "История исправлений не прошла безопасную проверку",
                correlation_id,
            )


__all__ = ["RuntimeRequestHandlerV12"]
