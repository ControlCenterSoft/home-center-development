"""Home Center 0.62 verified identity-binding HTTP boundary.

The client can request only a binding of one exact provisioning plan to one exact
execution Job. Verified receipt evidence is resolved from durable server-side Job
state; provider evidence or receipts are never accepted from the client and the
provider is never reinvoked by this route.
"""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v9 import RuntimeRequestHandlerV9
from .role_identity_binding_api_composition import role_identity_binding_api_for_runtime
from .role_identity_binding_api_runtime import IdentityBindingApiRuntimeError

BIND_REQUEST_SCHEMA = "home-center.role-identity-provisioning-api-bind-request.v1"


class RuntimeRequestHandlerV10(RuntimeRequestHandlerV9):
    """Add the separate confirmed verified-binding transition to API v9."""

    IDENTITY_BIND_POSTS = {"/api/v1/household/identity/provisioning/bind"}

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in self.IDENTITY_BIND_POSTS:
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
            request = self._schema_body(
                body,
                schema=BIND_REQUEST_SCHEMA,
                fields={"plan_id", "execution_job_id", "confirmed"},
            )
            idempotency_key = self.headers.get("Idempotency-Key")
            if not isinstance(idempotency_key, str) or not idempotency_key:
                raise IdentityBindingApiRuntimeError("identity_binding_api_idempotency_key_invalid")
            service = role_identity_binding_api_for_runtime(self.runtime)
            value = service.bind(
                actor=actor,
                plan_id=self._text(request, "plan_id"),
                execution_job_id=self._text(request, "execution_job_id"),
                confirmed=self._boolean(request, "confirmed"),
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
            )
            self._json(HTTPStatus.OK, value)
            return
        except IdentityBindingApiRuntimeError as exc:
            forbidden = {
                "household_actor_not_bound",
                "household_member_disabled",
                "identity_binding_transition_not_authorized",
            }
            not_found = {
                "identity_binding_api_plan_not_found",
                "identity_binding_api_execution_job_not_found",
            }
            conflict = {
                "identity_binding_api_confirmation_required",
                "identity_binding_api_verified_execution_required",
                "identity_binding_idempotency_conflict",
                "identity_binding_previous_attempt_failed",
                "identity_binding_household_stale",
                "identity_binding_member_stale",
                "identity_binding_conflict",
                "identity_binding_execution_evidence_invalid",
                "identity_binding_execution_receipt_invalid",
            }
            if exc.code in forbidden:
                status = HTTPStatus.FORBIDDEN
            elif exc.code in not_found:
                status = HTTPStatus.NOT_FOUND
            elif exc.code in conflict:
                status = HTTPStatus.CONFLICT
            else:
                status = HTTPStatus.BAD_REQUEST
            self.runtime.store.audit(
                actor=actor,
                action="household.identity.binding.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={
                    "reason": exc.code,
                    "path": path,
                    "provider_reinvocation_authorized": False,
                    "credential_material_included": False,
                },
            )
            self._error(
                status,
                exc.code,
                "Привязка подтверждённой учётной записи не прошла безопасную проверку",
                correlation_id,
            )
        except RuntimeError as exc:
            if str(exc) != "identity_binding_api_safe_runtime_composition_unavailable":
                raise
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "identity_binding_api_safe_runtime_composition_unavailable",
                "Безопасный сервис привязки учётной записи недоступен",
                correlation_id,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            code = "invalid_identity_binding_http_request"
            self.runtime.store.audit(
                actor=actor,
                action="household.identity.binding.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                code,
                "Некорректный запрос привязки учётной записи",
                correlation_id,
            )
