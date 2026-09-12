"""0.59 read-only Policy Composer web boundary.

This handler exposes only the effective-state projection. It inherits all existing
request classification and session authentication fences from V5, performs no
backend call and never accepts mutation authority from the request.
"""

from __future__ import annotations

from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from .api_v5 import RuntimeRequestHandlerV5
from .household_policy_effective_state import (
    HouseholdPolicyEffectiveStateError,
    HouseholdPolicyEffectiveStateService,
)


EFFECTIVE_STATE_PATH = "/api/v1/household/policy/effective-state"


def _member_id_from_query(path: str) -> str:
    parsed = urlsplit(path)
    values = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    if set(values) != {"member_id"} or len(values["member_id"]) != 1:
        raise ValueError("invalid_household_policy_effective_state_query")
    member_id = values["member_id"][0]
    if not member_id:
        raise ValueError("invalid_household_policy_effective_state_query")
    return member_id


class RuntimeRequestHandlerV6(RuntimeRequestHandlerV5):
    """Expose the 0.59 read-only effective policy state without adding mutation paths."""

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path != EFFECTIVE_STATE_PATH:
            super().do_GET()
            return

        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(parsed.path, context):
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return
        actor = self._require_actor(correlation_id)
        if not actor:
            return

        try:
            member_id = _member_id_from_query(self.path)
            value = HouseholdPolicyEffectiveStateService(self.runtime.store).read(
                actor=actor,
                member_id=member_id,
            )
        except ValueError as exc:
            if isinstance(exc, HouseholdPolicyEffectiveStateError):
                forbidden = {
                    "household_actor_not_bound",
                    "household_member_disabled",
                    "household_policy_effective_state_not_authorized",
                }
                not_found = {
                    "household_not_configured",
                    "household_member_not_found",
                }
                unavailable = {
                    "household_state_invalid",
                    "household_policy_effective_state_policy_invalid",
                    "household_policy_effective_state_desired_invalid",
                    "household_policy_effective_state_verified_invalid",
                    "household_policy_effective_state_verification_evidence_missing",
                    "household_policy_effective_state_verification_evidence_invalid",
                    "household_policy_effective_state_orphan_verified",
                    "household_policy_effective_state_verified_generation_invalid",
                    "household_policy_effective_state_verified_mismatch",
                }
                if exc.code in forbidden:
                    status = HTTPStatus.FORBIDDEN
                elif exc.code in not_found:
                    status = HTTPStatus.NOT_FOUND
                elif exc.code in unavailable:
                    status = HTTPStatus.SERVICE_UNAVAILABLE
                else:
                    status = HTTPStatus.BAD_REQUEST
                self._error(
                    status,
                    exc.code,
                    "Состояние семейных правил не прошло безопасную проверку",
                    correlation_id,
                )
                return
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_household_policy_effective_state_query",
                "Некорректный запрос состояния семейных правил",
                correlation_id,
            )
            return

        self._json(HTTPStatus.OK, value)
