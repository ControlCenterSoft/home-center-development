"""0.59 Household policy enforcement HTTP boundary.

The HTTP surface exposes the existing qualification-bound enforcement service without
registering or substituting any backend adapter. A plan never authorizes backend
mutation; confirmation is a separate explicit action; execution can reach a backend
only when a concrete adapter has already been registered and passes the runtime's
qualification metadata checks. Backend acceptance never becomes an enforcement
success claim: read-only reconciliation remains mandatory.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v7 import RuntimeRequestHandlerV7
from .household_policy_enforcement_runtime import HouseholdPolicyEnforcementError


PLAN_REQUEST_SCHEMA = "home-center.household-policy-enforcement-plan-request.v1"
CONFIRM_REQUEST_SCHEMA = "home-center.household-policy-enforcement-confirm-request.v1"
EXECUTE_REQUEST_SCHEMA = "home-center.household-policy-enforcement-execute-request.v1"


class RuntimeRequestHandlerV8(RuntimeRequestHandlerV7):
    """Expose explicit, fail-closed policy enforcement lifecycle operations."""

    POLICY_ENFORCEMENT_PLAN_POSTS = {
        "/api/v1/household/policy/enforcement/plan",
    }
    POLICY_ENFORCEMENT_CONFIRM_POSTS = {
        "/api/v1/household/policy/enforcement/confirm",
    }
    POLICY_ENFORCEMENT_EXECUTE_POSTS = {
        "/api/v1/household/policy/enforcement/execute",
    }
    POLICY_ENFORCEMENT_POSTS = (
        POLICY_ENFORCEMENT_PLAN_POSTS
        | POLICY_ENFORCEMENT_CONFIRM_POSTS
        | POLICY_ENFORCEMENT_EXECUTE_POSTS
    )

    @staticmethod
    def _schema_body(
        body: object,
        *,
        schema: str,
        fields: set[str],
    ) -> dict[str, object]:
        required = {"schema", *fields}
        if (
            not isinstance(body, dict)
            or set(body) != required
            or body.get("schema") != schema
        ):
            raise ValueError("invalid_household_policy_enforcement_http_request")
        return body

    @staticmethod
    def _text_field(body: dict[str, object], name: str) -> str:
        value = body.get(name)
        if not isinstance(value, str):
            raise ValueError("invalid_household_policy_enforcement_http_request")
        return value

    @staticmethod
    def _bool_field(body: dict[str, object], name: str) -> bool:
        value = body.get(name)
        if not isinstance(value, bool):
            raise ValueError("invalid_household_policy_enforcement_http_request")
        return value

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in self.POLICY_ENFORCEMENT_POSTS:
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
            service = self.runtime.household_policy_enforcement
            if path in self.POLICY_ENFORCEMENT_PLAN_POSTS:
                request = self._schema_body(
                    body,
                    schema=PLAN_REQUEST_SCHEMA,
                    fields={"member_id", "backend_id"},
                )
                member_id = self._text_field(request, "member_id")
                backend_id = self._text_field(request, "backend_id")
                value = service.plan(
                    actor=actor,
                    member_id=member_id,
                    backend_id=backend_id,
                    correlation_id=correlation_id,
                )
            elif path in self.POLICY_ENFORCEMENT_CONFIRM_POSTS:
                request = self._schema_body(
                    body,
                    schema=CONFIRM_REQUEST_SCHEMA,
                    fields={"plan_id", "confirmed"},
                )
                plan_id = self._text_field(request, "plan_id")
                confirmed = self._bool_field(request, "confirmed")
                if self.headers.get("Idempotency-Key") != plan_id:
                    raise HouseholdPolicyEnforcementError(
                        "household_policy_enforcement_http_idempotency_key_required"
                    )
                value = service.confirm(
                    actor=actor,
                    plan_id=plan_id,
                    confirmed=confirmed,
                    correlation_id=correlation_id,
                )
            else:
                request = self._schema_body(
                    body,
                    schema=EXECUTE_REQUEST_SCHEMA,
                    fields={"plan_id"},
                )
                plan_id = self._text_field(request, "plan_id")
                if self.headers.get("Idempotency-Key") != plan_id:
                    raise HouseholdPolicyEnforcementError(
                        "household_policy_enforcement_http_idempotency_key_required"
                    )
                value = service.execute(
                    actor=actor,
                    plan_id=plan_id,
                    correlation_id=correlation_id,
                )
            self._json(HTTPStatus.OK, value)
            return
        except HouseholdPolicyEnforcementError as exc:
            forbidden = {
                "household_actor_not_bound",
                "household_member_disabled",
                "household_policy_enforcement_not_authorized",
            }
            not_found = {
                "household_not_configured",
                "household_member_not_found",
                "household_policy_enforcement_plan_not_found",
            }
            conflict = {
                "household_policy_enforcement_plan_conflict",
                "household_policy_enforcement_desired_state_stale",
                "household_policy_enforcement_confirmation_required",
                "household_policy_enforcement_state_invalid",
                "household_policy_enforcement_reconciliation_required",
                "household_policy_enforcement_previous_attempt_failed",
                "household_policy_enforcement_idempotency_conflict",
                "household_policy_enforcement_job_state_invalid",
                "household_policy_enforcement_backend_rejected",
            }
            unavailable = {
                "household_state_invalid",
                "household_policy_enforcement_adapter_unavailable",
                "household_policy_enforcement_backend_outcome_ambiguous",
            }
            if exc.code in forbidden:
                status = HTTPStatus.FORBIDDEN
            elif exc.code in not_found:
                status = HTTPStatus.NOT_FOUND
            elif exc.code in conflict:
                status = HTTPStatus.CONFLICT
            elif exc.code in unavailable:
                status = HTTPStatus.SERVICE_UNAVAILABLE
            else:
                status = HTTPStatus.BAD_REQUEST
            self.runtime.store.audit(
                actor=actor,
                action="household.policy.enforcement.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code, "path": path},
            )
            self._error(
                status,
                exc.code,
                "Изменение политики не прошло безопасную проверку",
                correlation_id,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            code = "invalid_household_policy_enforcement_http_request"
            self.runtime.store.audit(
                actor=actor,
                action="household.policy.enforcement.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                code,
                "Некорректный запрос изменения политики",
                correlation_id,
            )
