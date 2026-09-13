"""Home Center 0.62 identity provisioning HTTP boundary.

The client can submit only bounded user intent, an already-generated plan identity,
opaque ``secret://`` references, and durable Job identities. Provider capability,
qualification evidence, read-only preflight observations, verified execution
receipts and Household authority remain server-side.

This handler is source-prepared for the later production-composition slice. Merely
importing it does not register a provider or enable account provisioning.
"""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v8 import RuntimeRequestHandlerV8
from .role_identity_provisioning_api_runtime import IdentityProvisioningApiRuntimeError

PLAN_REQUEST_SCHEMA = "home-center.role-identity-provisioning-api-plan-request.v1"
PREFLIGHT_REQUEST_SCHEMA = "home-center.role-identity-provisioning-api-preflight-request.v1"
EXECUTE_REQUEST_SCHEMA = "home-center.role-identity-provisioning-api-execute-request.v1"
BIND_REQUEST_SCHEMA = "home-center.role-identity-provisioning-api-bind-request.v1"


class RuntimeRequestHandlerV9(RuntimeRequestHandlerV8):
    IDENTITY_PLAN_POSTS = {"/api/v1/household/identity/provisioning/plan"}
    IDENTITY_PREFLIGHT_POSTS = {"/api/v1/household/identity/provisioning/preflight"}
    IDENTITY_EXECUTE_POSTS = {"/api/v1/household/identity/provisioning/execute"}
    IDENTITY_BIND_POSTS = {"/api/v1/household/identity/provisioning/bind"}
    IDENTITY_POSTS = (
        IDENTITY_PLAN_POSTS
        | IDENTITY_PREFLIGHT_POSTS
        | IDENTITY_EXECUTE_POSTS
        | IDENTITY_BIND_POSTS
    )

    @staticmethod
    def _closed_body(
        body: object,
        *,
        schema: str,
        fields: set[str],
    ) -> dict[str, object]:
        expected = {"schema", *fields}
        if not isinstance(body, dict) or set(body) != expected or body.get("schema") != schema:
            raise ValueError("invalid_identity_provisioning_http_request")
        return body

    @staticmethod
    def _text(body: dict[str, object], name: str) -> str:
        value = body.get(name)
        if not isinstance(value, str):
            raise ValueError("invalid_identity_provisioning_http_request")
        return value

    @staticmethod
    def _boolean(body: dict[str, object], name: str) -> bool:
        value = body.get(name)
        if type(value) is not bool:
            raise ValueError("invalid_identity_provisioning_http_request")
        return value

    def _idempotency_key(self) -> str:
        value = self.headers.get("Idempotency-Key")
        if not isinstance(value, str) or not value:
            raise IdentityProvisioningApiRuntimeError("identity_api_idempotency_key_invalid")
        return value

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in self.IDENTITY_POSTS:
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
            body = self._read_json(max_bytes=8192)
            service = self.runtime.role_identity_provisioning_api

            if path in self.IDENTITY_PLAN_POSTS:
                request = self._closed_body(
                    body,
                    schema=PLAN_REQUEST_SCHEMA,
                    fields={
                        "member_id",
                        "provider_id",
                        "account_name",
                        "home_directory_mode",
                        "profile_mode",
                    },
                )
                result = service.plan(
                    actor=actor,
                    member_id=self._text(request, "member_id"),
                    provider_id=self._text(request, "provider_id"),
                    account_name=self._text(request, "account_name"),
                    home_directory_mode=self._text(request, "home_directory_mode"),
                    profile_mode=self._text(request, "profile_mode"),
                    correlation_id=correlation_id,
                )
            elif path in self.IDENTITY_PREFLIGHT_POSTS:
                request = self._closed_body(
                    body,
                    schema=PREFLIGHT_REQUEST_SCHEMA,
                    fields={"plan_id"},
                )
                result = service.preflight(
                    actor=actor,
                    plan_id=self._text(request, "plan_id"),
                    correlation_id=correlation_id,
                )
            elif path in self.IDENTITY_EXECUTE_POSTS:
                request = self._closed_body(
                    body,
                    schema=EXECUTE_REQUEST_SCHEMA,
                    fields={"plan_id", "confirmed", "credential_references"},
                )
                references = request.get("credential_references")
                if not isinstance(references, list):
                    raise ValueError("invalid_identity_provisioning_http_request")
                result = service.execute(
                    actor=actor,
                    plan_id=self._text(request, "plan_id"),
                    credential_references=references,
                    confirmed=self._boolean(request, "confirmed"),
                    idempotency_key=self._idempotency_key(),
                    correlation_id=correlation_id,
                )
            else:
                request = self._closed_body(
                    body,
                    schema=BIND_REQUEST_SCHEMA,
                    fields={"plan_id", "execution_job_id"},
                )
                result = service.bind(
                    actor=actor,
                    plan_id=self._text(request, "plan_id"),
                    execution_job_id=self._text(request, "execution_job_id"),
                    idempotency_key=self._idempotency_key(),
                    correlation_id=correlation_id,
                )

            self._json(HTTPStatus.OK, result)
            return
        except IdentityProvisioningApiRuntimeError as exc:
            forbidden = {
                "household_actor_not_bound",
                "household_member_disabled",
                "identity_api_not_authorized",
                "identity_binding_transition_not_authorized",
            }
            not_found = {
                "household_not_configured",
                "identity_api_plan_not_found",
                "identity_api_verified_execution_not_found",
            }
            conflict = {
                "identity_api_plan_conflict",
                "identity_api_plan_stale",
                "identity_api_confirmation_required",
                "identity_api_preflight_not_ready",
                "identity_runtime_idempotency_conflict",
                "identity_runtime_execution_in_progress",
                "identity_runtime_previous_attempt_failed",
                "identity_runtime_job_state_invalid",
                "identity_binding_idempotency_conflict",
                "identity_binding_previous_attempt_failed",
                "identity_binding_conflict",
                "identity_binding_household_stale",
                "identity_binding_member_stale",
                "identity_binding_job_state_invalid",
            }
            unavailable = {
                "identity_api_provider_unavailable",
                "identity_api_preflight_unavailable",
                "identity_runtime_adapter_unavailable",
                "identity_runtime_provider_timeout",
                "identity_runtime_provider_error",
                "identity_runtime_verification_unavailable",
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
                action="household.identity.provisioning.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code, "path": path},
            )
            self._error(
                status,
                exc.code,
                "Операция учётной записи не прошла безопасную проверку",
                correlation_id,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            code = "invalid_identity_provisioning_http_request"
            self.runtime.store.audit(
                actor=actor,
                action="household.identity.provisioning.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                code,
                "Некорректный запрос управления учётной записью",
                correlation_id,
            )
