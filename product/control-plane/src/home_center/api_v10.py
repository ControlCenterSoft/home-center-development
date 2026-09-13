"""Home Center 0.63 authenticated same-origin QR onboarding HTTP boundary.

The handler reuses the existing request classification, external-access, session and
same-origin/CSRF fences. It exposes only the bounded QR invitation state machine;
consuming an invitation still does not create an account, bind a device, change
managed state, execute a provider, mutate infrastructure or publish anything.
"""
from __future__ import annotations

import json
import time
from http import HTTPStatus
from typing import Any
from urllib.parse import urlsplit

from .api_v9 import RuntimeRequestHandlerV9
from .household_runtime import HouseholdRuntimeError
from .qr_onboarding_api import QrOnboardingApiError, QrOnboardingApiService
from .qr_onboarding_state_audit import (
    QrOnboardingAuditedRuntimeService,
    QrOnboardingStateAuditError,
)


class _CorrelatedQrRuntime:
    """Inject the server correlation ID into the audited runtime boundary."""

    def __init__(self, runtime: QrOnboardingAuditedRuntimeService, correlation_id: str) -> None:
        self._runtime = runtime
        self._correlation_id = correlation_id

    @property
    def repository(self) -> Any:
        return self._runtime.repository

    def issue(self, **kwargs: Any) -> Any:
        return self._runtime.issue(correlation_id=self._correlation_id, **kwargs)

    def consume(self, **kwargs: Any) -> Any:
        return self._runtime.consume(correlation_id=self._correlation_id, **kwargs)

    def revoke(self, **kwargs: Any) -> Any:
        return self._runtime.revoke(correlation_id=self._correlation_id, **kwargs)

    def plan_redemption(self, **kwargs: Any) -> Any:
        return self._runtime.runtime.plan_redemption(**kwargs)


class RuntimeRequestHandlerV10(RuntimeRequestHandlerV9):
    """Expose bounded 0.63 QR invitation operations behind existing HTTP fences."""

    QR_ISSUE_POSTS = {"/api/v1/household/qr-onboarding/issue"}
    QR_PLAN_POSTS = {"/api/v1/household/qr-onboarding/plan"}
    QR_CONSUME_POSTS = {"/api/v1/household/qr-onboarding/consume"}
    QR_REVOKE_POSTS = {"/api/v1/household/qr-onboarding/revoke"}
    QR_POSTS = QR_ISSUE_POSTS | QR_PLAN_POSTS | QR_CONSUME_POSTS | QR_REVOKE_POSTS

    def _qr_api(self, correlation_id: str) -> QrOnboardingApiService:
        runtime = getattr(self.runtime, "qr_onboarding", None)
        if runtime is None:
            raise QrOnboardingApiError("qr_api_runtime_unavailable")
        audited = QrOnboardingAuditedRuntimeService(runtime, self.runtime.store)
        return QrOnboardingApiService(_CorrelatedQrRuntime(audited, correlation_id))

    def _household_state(self):
        household = getattr(self.runtime, "household", None)
        if household is None:
            raise HouseholdRuntimeError("household_not_configured")
        return household._read_state()

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in self.QR_POSTS:
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
            snapshot, bindings = self._household_state()
            service = self._qr_api(correlation_id)
            now_epoch = int(time.time())

            if path in self.QR_ISSUE_POSTS:
                actor_member_id = self.runtime.household._actor_member(actor, bindings)
                result = service.issue(
                    snapshot=snapshot,
                    actor_member_id=actor_member_id,
                    body=body,
                    now_epoch=now_epoch,
                )
                value = {
                    "schema": "home-center.qr-onboarding-http-issue-result.v1",
                    "record": result.record.to_dict(),
                    "payload": result.payload.to_dict(),
                    "receipt": result.receipt.to_dict(),
                }
                self._json(HTTPStatus.CREATED, value)
                return

            if path in self.QR_PLAN_POSTS:
                plan = service.plan(snapshot=snapshot, body=body, now_epoch=now_epoch)
                self._json(HTTPStatus.OK, plan.to_dict())
                return

            if path in self.QR_CONSUME_POSTS:
                record, receipt = service.consume(
                    snapshot=snapshot,
                    actor=actor,
                    body=body,
                    now_epoch=now_epoch,
                )
            else:
                actor_member_id = self.runtime.household._actor_member(actor, bindings)
                record, receipt = service.revoke(
                    snapshot=snapshot,
                    actor_member_id=actor_member_id,
                    body=body,
                    now_epoch=now_epoch,
                )
            self._json(
                HTTPStatus.OK,
                {
                    "schema": "home-center.qr-onboarding-http-operation-result.v1",
                    "record": record.to_dict(),
                    "receipt": receipt.to_dict(),
                },
            )
            return
        except (QrOnboardingApiError, QrOnboardingStateAuditError, HouseholdRuntimeError) as exc:
            code = getattr(exc, "code", str(exc))
            forbidden = {
                "household_actor_not_bound",
                "qr_runtime_parent_required",
                "qr_runtime_member_unavailable",
            }
            not_found = {
                "household_not_configured",
                "qr_runtime_invitation_not_found",
                "qr_runtime_device_not_registered",
            }
            conflict = {
                "qr_api_confirmation_required",
                "qr_runtime_confirmation_required",
                "qr_runtime_household_state_stale",
                "qr_runtime_redemption_plan_stale",
                "qr_runtime_stale_version",
                "qr_runtime_transition_race",
                "qr_runtime_idempotency_conflict",
                "qr_runtime_invitation_consumed",
                "qr_runtime_invitation_revoked",
                "qr_runtime_invitation_expired",
            }
            unavailable = {
                "qr_api_runtime_unavailable",
                "qr_audited_repository_unavailable",
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
                action="household.qr-onboarding.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(status, code, "QR-подключение не прошло безопасную проверку", correlation_id)
        except (ValueError, TypeError, json.JSONDecodeError):
            code = "invalid_qr_onboarding_http_request"
            self.runtime.store.audit(
                actor=actor,
                action="household.qr-onboarding.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                code,
                "Некорректный запрос QR-подключения",
                correlation_id,
            )
