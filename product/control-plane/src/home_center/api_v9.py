"""Home Center 0.62 role-driven identity provisioning HTTP boundary.

The HTTP surface preserves the existing authenticated/same-origin request fences and
exposes plan -> verified provider execution -> separate binding transition. A provider
can be reached only through the production-safe qualification-bound registry. Secret
values are never accepted: execution accepts only bounded `secret://` references.
"""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v8 import RuntimeRequestHandlerV8
from .role_identity_provisioning_api_runtime import RoleIdentityProvisioningApiError


class RuntimeRequestHandlerV9(RuntimeRequestHandlerV8):
    """Expose the bounded 0.62 identity provisioning lifecycle."""

    IDENTITY_PLAN_POSTS = {"/api/v1/household/identity/provisioning/plan"}
    IDENTITY_EXECUTE_POSTS = {"/api/v1/household/identity/provisioning/execute"}
    IDENTITY_BIND_POSTS = {"/api/v1/household/identity/provisioning/bind"}
    IDENTITY_POSTS = IDENTITY_PLAN_POSTS | IDENTITY_EXECUTE_POSTS | IDENTITY_BIND_POSTS

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
                value = service.plan(actor=actor, request=body, correlation_id=correlation_id)
            else:
                idempotency_key = self.headers.get("Idempotency-Key")
                if not isinstance(idempotency_key, str) or not idempotency_key:
                    raise RoleIdentityProvisioningApiError(
                        "identity_provisioning_api_idempotency_key_required"
                    )
                if path in self.IDENTITY_EXECUTE_POSTS:
                    value = service.execute(
                        actor=actor,
                        request=body,
                        idempotency_key=idempotency_key,
                        correlation_id=correlation_id,
                    )
                else:
                    value = service.bind(
                        actor=actor,
                        request=body,
                        idempotency_key=idempotency_key,
                        correlation_id=correlation_id,
                    )
            self._json(HTTPStatus.OK, value)
            return
        except RoleIdentityProvisioningApiError as exc:
            forbidden = {
                "household_actor_not_bound",
                "household_member_disabled",
                "identity_provisioning_api_not_authorized",
            }
            not_found = {
                "household_not_configured",
                "identity_provisioning_api_plan_not_found",
            }
            conflict = {
                "identity_provisioning_api_plan_conflict",
                "identity_provisioning_api_plan_stale",
                "identity_provisioning_api_provider_stale",
                "identity_provisioning_api_execution_conflict",
                "identity_provisioning_api_binding_conflict",
                "identity_provisioning_api_verified_execution_required",
                "identity_runtime_execution_in_progress",
                "identity_runtime_previous_attempt_failed",
                "identity_runtime_idempotency_conflict",
                "identity_binding_idempotency_conflict",
                "identity_binding_previous_attempt_failed",
                "identity_binding_household_stale",
                "identity_binding_member_stale",
                "identity_binding_conflict",
            }
            unavailable = {
                "identity_runtime_qualified_provider_unavailable",
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
                details={"reason": exc.code, "path": path, "credential_material_included": False},
            )
            self._error(
                status,
                exc.code,
                "Операция управления учётной записью не прошла безопасную проверку",
                correlation_id,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            code = "identity_provisioning_api_request_invalid"
            self.runtime.store.audit(
                actor=actor,
                action="household.identity.provisioning.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path, "credential_material_included": False},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                code,
                "Некорректный запрос управления учётной записью",
                correlation_id,
            )
