"""Home Center 0.63 authenticated same-origin QR product-effect HTTP boundary.

The QR invitation transition remains separate from the product effect. These routes
require an authenticated Household parent, same-origin/CSRF protection and a second
explicit confirmation. The admit route reconstructs the exact handoff server-side
from durable terminal QR state; the run route accepts only the durable Job id and
drives the restart-safe worker. A positive response is emitted only after exact
post-condition verification succeeds.
"""
from __future__ import annotations

import json
import time
from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v10 import RuntimeRequestHandlerV10
from .household import HouseholdRole
from .household_runtime import HouseholdRuntimeError
from .qr_onboarding_effect_api import (
    QrOnboardingEffectApiError,
    QrOnboardingEffectApiService,
)


class RuntimeRequestHandlerV11(RuntimeRequestHandlerV10):
    """Expose explicit terminal QR effect admission/run behind current HTTP fences."""

    QR_EFFECT_ADMIT_POSTS = {"/api/v1/household/qr-onboarding/effect/admit"}
    QR_EFFECT_RUN_POSTS = {"/api/v1/household/qr-onboarding/effect/run"}
    QR_EFFECT_POSTS = QR_EFFECT_ADMIT_POSTS | QR_EFFECT_RUN_POSTS

    def _qr_effect_api(self) -> QrOnboardingEffectApiService:
        source = getattr(self.runtime, "qr_effect_source", None)
        admissions = getattr(self.runtime, "qr_effect_admission", None)
        worker = getattr(self.runtime, "qr_effect_worker", None)
        if source is None or admissions is None or worker is None:
            raise QrOnboardingEffectApiError("qr_effect_http_runtime_unavailable")
        return QrOnboardingEffectApiService(source, admissions, worker)

    @staticmethod
    def _require_parent(snapshot, actor_member_id: str) -> None:
        try:
            member = snapshot.household.member(actor_member_id)
        except Exception as exc:
            raise QrOnboardingEffectApiError("qr_effect_http_actor_member_unavailable") from exc
        if not member.enabled or member.role is not HouseholdRole.PARENT:
            raise QrOnboardingEffectApiError("qr_effect_http_parent_required")

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in self.QR_EFFECT_POSTS:
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
            snapshot, bindings = self._household_state()
            actor_member_id = self.runtime.household._actor_member(actor, bindings)
            self._require_parent(snapshot, actor_member_id)
            service = self._qr_effect_api()

            if path in self.QR_EFFECT_ADMIT_POSTS:
                result = service.admit(
                    snapshot=snapshot,
                    actor=actor,
                    correlation_id=correlation_id,
                    body=body,
                    now_epoch=int(time.time()),
                )
                self._json(HTTPStatus.ACCEPTED, result.to_dict())
                return

            result = service.run(
                actor=actor,
                correlation_id=correlation_id,
                body=body,
            )
            self._json(HTTPStatus.OK, result.to_dict())
            return
        except (QrOnboardingEffectApiError, HouseholdRuntimeError) as exc:
            code = getattr(exc, "code", str(exc))
            forbidden = {
                "household_actor_not_bound",
                "qr_effect_http_actor_member_unavailable",
                "qr_effect_http_parent_required",
            }
            not_found = {
                "household_not_configured",
                "qr_effect_source_invitation_missing",
                "qr_runtime_invitation_not_found",
                "qr_effect_admission_recovery_job_missing",
                "qr_effect_worker_job_missing",
            }
            conflict = {
                "qr_effect_api_confirmation_required",
                "qr_effect_source_invitation_not_terminal",
                "qr_effect_source_household_state_stale",
                "qr_effect_admission_household_state_stale",
                "qr_effect_admission_idempotency_conflict",
                "qr_effect_execution_household_state_stale",
                "qr_effect_worker_outcome_uncertain",
                "qr_effect_worker_job_failed",
            }
            unavailable = {
                "qr_effect_http_runtime_unavailable",
                "qr_effect_adapter_unavailable",
            }
            if code in forbidden:
                status = HTTPStatus.FORBIDDEN
            elif code in not_found:
                status = HTTPStatus.NOT_FOUND
            elif code in conflict:
                status = HTTPStatus.CONFLICT
            elif code in unavailable:
                status = HTTPStatus.SERVICE_UNAVAILABLE
            else:
                status = HTTPStatus.BAD_REQUEST
            self.runtime.store.audit(
                actor=actor,
                action="household.qr-onboarding.effect.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(status, code, "QR-действие не прошло безопасную проверку", correlation_id)
        except (ValueError, TypeError, json.JSONDecodeError):
            code = "invalid_qr_onboarding_effect_http_request"
            self.runtime.store.audit(
                actor=actor,
                action="household.qr-onboarding.effect.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                code,
                "Некорректный запрос QR-действия",
                correlation_id,
            )
