"""0.59 read-only Household policy reconciliation web boundary.

This handler composes the read-only reconciliation POST boundary on top of V6's
read-only effective-policy GET projection. It inherits the existing authentication,
first-login, external-access and same-origin fences, requires an explicit HTTP
idempotency key, and grants no Desired State, backend mutation, infrastructure
mutation or external-publication authority.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v6 import RuntimeRequestHandlerV6
from .household_policy_reconciliation_runtime import HouseholdPolicyReconciliationRuntimeError


class RuntimeRequestHandlerV7(RuntimeRequestHandlerV6):
    """Expose read-only policy reconciliation while preserving V6 effective-state reads."""

    POLICY_RECONCILIATION_POSTS = {
        "/api/v1/household/policy/reconciliation",
    }

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in self.POLICY_RECONCILIATION_POSTS:
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
            value = self.runtime.household_policy_reconciliation_api.reconcile(
                actor=actor,
                request=body,
                idempotency_key=self.headers.get("Idempotency-Key"),
                correlation_id=correlation_id,
            )
            self._json(HTTPStatus.OK, value)
            return
        except HouseholdPolicyReconciliationRuntimeError as exc:
            forbidden = {
                "household_actor_not_bound",
                "household_policy_reconciliation_not_authorized",
            }
            not_found = {
                "household_not_configured",
                "household_member_not_found",
                "household_policy_desired_state_not_found",
            }
            conflict = {
                "household_policy_reconciliation_binding_mismatch",
                "household_policy_reconciliation_desired_state_stale",
                "household_policy_reconciliation_idempotency_conflict",
                "household_policy_reconciliation_in_progress",
                "household_policy_reconciliation_previous_attempt_failed",
                "household_policy_reconciliation_state_invalid",
                "household_policy_reconciliation_job_state_invalid",
                "household_policy_reconciliation_http_idempotency_conflict",
                "household_policy_reconciliation_http_in_progress",
                "household_policy_reconciliation_http_previous_attempt_failed",
                "household_policy_reconciliation_http_idempotency_state_invalid",
            }
            unavailable = {
                "household_state_invalid",
                "household_policy_reconciliation_adapter_unavailable",
                "household_policy_reconciliation_backend_read_failed",
                "household_policy_reconciliation_evidence_readback_failed",
                "household_policy_reconciliation_http_runtime_failed",
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
                action="household.policy.reconciliation.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code, "path": path},
            )
            self._error(
                status,
                exc.code,
                "Запрос сверки политики не прошёл безопасную проверку",
                correlation_id,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            self.runtime.store.audit(
                actor=actor,
                action="household.policy.reconciliation.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={
                    "reason": "invalid_household_policy_reconciliation_http_request",
                    "path": path,
                },
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_household_policy_reconciliation_http_request",
                "Некорректный запрос сверки политики",
                correlation_id,
            )
