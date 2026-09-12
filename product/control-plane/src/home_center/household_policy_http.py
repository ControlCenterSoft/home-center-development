"""Authenticated HTTP boundary for Home Center 0.59 Policy Composer.

The routes deliberately reuse the existing V2 request classifier, authentication
and same-origin controls, and add an explicit fail-closed external boundary for
all policy operations. They expose only plan/presentation, explicit
confirm+Desired-State materialization, fail-closed confirmation recovery, and
explicit rollback to immutable policy history. No route grants provider execution
or infrastructure mutation authority.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v2 import RuntimeRequestHandlerV2
from .household_policy_desired_state import HouseholdPolicyDesiredStateError
from .household_policy_history import HouseholdPolicyHistoryError
from .household_policy_presentation import HouseholdPolicyPresentationError
from .household_policy_runtime import HouseholdPolicyRuntimeError


POLICY_POSTS = {
    "/api/v1/household/policies/plan",
    "/api/v1/household/policies/confirm",
    "/api/v1/household/policies/recover",
    "/api/v1/household/policies/rollback",
}


class RuntimeRequestHandlerPolicy(RuntimeRequestHandlerV2):
    """Add the 0.59 policy workflow without weakening the established HTTP gates."""

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in POLICY_POSTS:
            super().do_POST()
            return

        self._request_body_complete = False
        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if context.external or self._blocked_for_external(path, context):
            self.close_connection = True
            self.runtime.store.audit(
                actor=f"network:{context.client_address}",
                action="household.policy.external-access",
                target="household-policy",
                outcome="denied",
                correlation_id=correlation_id,
                details={
                    "path": path,
                    "external_publication_authorized": False,
                    "infrastructure_mutation_authorized": False,
                },
            )
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
            if path == "/api/v1/household/policies/plan":
                value = self.runtime.household_policy_workflow.plan(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
            elif path == "/api/v1/household/policies/confirm":
                value = self.runtime.household_policy_workflow.confirm_and_apply(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
            elif path == "/api/v1/household/policies/recover":
                value = self.runtime.household_policy_workflow.recover(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
            else:
                value = self.runtime.household_policy_workflow.rollback(
                    actor=actor,
                    request=body,
                    correlation_id=correlation_id,
                )
            self._json(HTTPStatus.OK, value)
            return
        except (
            HouseholdPolicyRuntimeError,
            HouseholdPolicyDesiredStateError,
            HouseholdPolicyHistoryError,
            HouseholdPolicyPresentationError,
        ) as exc:
            conflict_codes = {
                "household_policy_composition_stale",
                "household_policy_presentation_stale",
                "household_policy_confirmation_recovery_required",
                "household_policy_proposal_invalidated",
                "household_policy_desired_state_precondition_failed",
                "household_policy_apply_invalidated",
                "household_policy_rollback_precondition_failed",
                "household_policy_rollback_invalidated",
            }
            forbidden_codes = {
                "household_actor_not_bound",
                "household_policy_composition_not_authorized",
                "household_policy_composition_actor_mismatch",
                "household_policy_rollback_not_authorized",
                "household_policy_rollback_resource_mismatch",
            }
            not_found_codes = {
                "household_not_configured",
                "household_policy_presentation_member_unavailable",
                "household_policy_history_not_found",
            }
            unavailable_codes = {
                "household_state_invalid",
                "household_policy_proposal_state_invalid",
                "household_policy_confirmation_invalid",
                "household_policy_materialization_receipt_invalid",
                "household_policy_apply_state_invalid",
                "household_policy_desired_state_invalid",
                "household_policy_desired_state_missing",
                "household_policy_desired_state_evidence_mismatch",
                "household_policy_proposal_evidence_mismatch",
                "household_policy_confirmation_evidence_mismatch",
                "household_policy_presentation_evidence_mismatch",
                "household_policy_history_invalid",
                "household_policy_history_evidence_mismatch",
                "household_policy_history_conflict",
                "household_policy_history_audit_invalid",
                "household_policy_history_audit_missing",
                "household_policy_history_audit_mismatch",
                "household_policy_rollback_state_invalid",
                "household_policy_rollback_evidence_mismatch",
            }
            if exc.code in conflict_codes:
                status = HTTPStatus.CONFLICT
            elif exc.code in forbidden_codes:
                status = HTTPStatus.FORBIDDEN
            elif exc.code in not_found_codes:
                status = HTTPStatus.NOT_FOUND
            elif exc.code in unavailable_codes:
                status = HTTPStatus.SERVICE_UNAVAILABLE
            else:
                status = HTTPStatus.BAD_REQUEST
            self.runtime.store.audit(
                actor=actor,
                action="household.policy.request",
                target="household-policy",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code, "path": path},
            )
            self._error(status, exc.code, "Запрос правил семьи не прошёл безопасную проверку", correlation_id)
        except (ValueError, TypeError, json.JSONDecodeError):
            self.runtime.store.audit(
                actor=actor,
                action="household.policy.request",
                target="household-policy",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "invalid_household_policy_request", "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_household_policy_request",
                "Некорректный запрос правил семьи",
                correlation_id,
            )