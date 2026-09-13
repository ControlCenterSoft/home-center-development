"""0.60 authenticated read/preview HTTP boundary for parental Internet policy.

The handler intentionally exposes no parental Desired State mutation and no DNS/proxy
adapter execution.  GET returns the current saved policy projection for an authorized
parent.  POST produces a side-effect-free decision preview from the current server-side
policy identity and rule-source binding; caller data can never select or replace policy
identity, grant execution authority or claim Actual-State enforcement.
"""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from .api_v8 import RuntimeRequestHandlerV8
from .parental_internet_policy_read_api import (
    ParentalInternetPolicyReadAPIError,
    ParentalInternetPolicyReadAPIService,
)

DESIRED_PATH = "/api/v1/household/parental-internet/desired"
PREVIEW_PATH = "/api/v1/household/parental-internet/decision-preview"


def _desired_query(path: str) -> tuple[str, str]:
    parsed = urlsplit(path)
    try:
        values = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise ValueError("invalid_parental_internet_read_request") from exc
    if set(values) != {"member_id", "view"}:
        raise ValueError("invalid_parental_internet_read_request")
    if len(values["member_id"]) != 1 or len(values["view"]) != 1:
        raise ValueError("invalid_parental_internet_read_request")
    member_id = values["member_id"][0]
    view = values["view"][0]
    if not member_id or view not in {"cozy", "full"}:
        raise ValueError("invalid_parental_internet_read_request")
    return member_id, view


class RuntimeRequestHandlerV9(RuntimeRequestHandlerV8):
    """Expose parent-authorized 0.60 saved-policy reads and decision previews."""

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path != DESIRED_PATH:
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
            member_id, view = _desired_query(self.path)
            value = ParentalInternetPolicyReadAPIService(self.runtime.store).read_desired(
                actor=actor,
                member_id=member_id,
                view=view,
            )
        except ParentalInternetPolicyReadAPIError as exc:
            self._read_error(exc.code, correlation_id)
            return
        except ValueError:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_parental_internet_read_request",
                "Некорректный запрос семейных правил интернета",
                correlation_id,
            )
            return

        self._json(HTTPStatus.OK, value)

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path != PREVIEW_PATH:
            super().do_POST()
            return

        self._request_body_complete = False
        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(path, context):
            self.close_connection = True
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return
        if not self._same_origin_post_allowed(context):
            self.close_connection = True
            self.runtime.store.audit(
                actor=f"network:{context.client_address}",
                action="request.origin",
                target=self.runtime.config.node_id,
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "cross_origin_request", **self._origin_details(context)},
            )
            self._error(
                HTTPStatus.FORBIDDEN,
                "cross_origin_request_rejected",
                "Запрос из другого источника запрещён",
                correlation_id,
            )
            return

        actor = self._require_actor(correlation_id)
        if not actor:
            return
        try:
            body = self._read_json(max_bytes=4096)
            value = ParentalInternetPolicyReadAPIService(self.runtime.store).preview(
                actor=actor,
                request=body,
            )
            self._json(HTTPStatus.OK, value)
            return
        except ParentalInternetPolicyReadAPIError as exc:
            self.runtime.store.audit(
                actor=actor,
                action="household.parental-internet.preview",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code, "path": path},
            )
            self._read_error(exc.code, correlation_id)
        except (ValueError, TypeError, json.JSONDecodeError):
            code = "invalid_parental_internet_preview_request"
            self.runtime.store.audit(
                actor=actor,
                action="household.parental-internet.preview",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                code,
                "Некорректный запрос предварительной проверки семейных правил",
                correlation_id,
            )

    def _read_error(self, code: str, correlation_id: str) -> None:
        forbidden = {
            "household_actor_not_bound",
            "household_member_disabled",
            "parental_internet_change_not_authorized",
        }
        not_found = {
            "household_not_configured",
            "household_member_not_found",
            "parental_internet_desired_state_missing",
        }
        unavailable = {
            "household_state_invalid",
            "parental_internet_verified_base_missing",
            "parental_internet_verified_base_binding_mismatch",
            "parental_internet_verified_base_stale",
            "parental_internet_desired_state_invalid",
            "parental_internet_desired_state_stale",
        }
        if code in forbidden:
            status = HTTPStatus.FORBIDDEN
        elif code in not_found:
            status = HTTPStatus.NOT_FOUND
        elif code in unavailable:
            status = HTTPStatus.SERVICE_UNAVAILABLE
        else:
            status = HTTPStatus.BAD_REQUEST
        self._error(
            status,
            code,
            "Семейные правила интернета не прошли безопасную проверку",
            correlation_id,
        )
