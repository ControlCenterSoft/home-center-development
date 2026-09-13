"""0.60 authenticated HTTP boundary for parental Internet policy.

Read and preview routes remain non-authoritative. Parental Desired State mutation is
split into plan -> scoped credential re-auth -> explicit confirm. No route in this
handler registers or invokes DNS/proxy enforcement or grants infrastructure/publication
authority. The safe runtime repeats exact-state checks after the single-use grant is
consumed, so state drift fails closed before any durable write.
"""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from .ad_auth import AdAuthError
from .api_v8 import RuntimeRequestHandlerV8
from .local_admin_auth import LocalAdminAuthError
from .parental_internet_policy_change_api import (
    ParentalInternetPolicyChangeAPIError,
    parse_parental_internet_confirm_request,
    parse_parental_internet_plan_request,
)
from .parental_internet_policy_read_api import (
    ParentalInternetPolicyReadAPIError,
    ParentalInternetPolicyReadAPIService,
)
from .parental_internet_policy_runtime import ParentalInternetPolicyRuntimeError
from .parental_internet_policy_runtime_safe import SafeParentalInternetPolicyRuntimeService
from .step_up import StepUpError

DESIRED_PATH = "/api/v1/household/parental-internet/desired"
PREVIEW_PATH = "/api/v1/household/parental-internet/decision-preview"
PLAN_PATH = "/api/v1/household/parental-internet/plan"
CONFIRM_PATH = "/api/v1/household/parental-internet/confirm"
REAUTH_PATH = "/api/v1/household/parental-internet/reauth"
REAUTH_REQUEST_SCHEMA = "home-center.parental-internet-reauth-request.v1"
REAUTH_RESULT_SCHEMA = "home-center.parental-internet-reauth-result.v1"
PARENTAL_POSTS = frozenset({PREVIEW_PATH, PLAN_PATH, CONFIRM_PATH, REAUTH_PATH})


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
    """Expose 0.60 parent-authorized reads, previews and protected Desired State changes."""

    def _safe_parental(self) -> SafeParentalInternetPolicyRuntimeService:
        return SafeParentalInternetPolicyRuntimeService(self.runtime.store, self.runtime.step_up)

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
                actor=actor, member_id=member_id, view=view
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
        if path not in PARENTAL_POSTS:
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
        if path == REAUTH_PATH:
            self._parental_reauth(actor, correlation_id, context)
            return

        try:
            if path == PREVIEW_PATH:
                body = self._read_json(max_bytes=4096)
                value = ParentalInternetPolicyReadAPIService(self.runtime.store).preview(
                    actor=actor, request=body
                )
                self._json(HTTPStatus.OK, value)
                return

            service = self._safe_parental()
            if path == PLAN_PATH:
                body = self._read_json(max_bytes=262_144)
                request = parse_parental_internet_plan_request(body)
                value = service.plan(actor=actor, request=request, correlation_id=correlation_id)
            else:
                body = self._read_json(max_bytes=4096)
                request = parse_parental_internet_confirm_request(body)
                plan_id = str(request["plan_id"])
                if self.headers.get("Idempotency-Key") != plan_id:
                    raise ParentalInternetPolicyRuntimeError(
                        "parental_internet_http_idempotency_key_required"
                    )
                value = service.confirm(
                    actor=actor,
                    request=request,
                    step_up_token=self.headers.get("X-Home-Center-Step-Up"),
                    correlation_id=correlation_id,
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
        except (ParentalInternetPolicyChangeAPIError, ParentalInternetPolicyRuntimeError) as exc:
            self.runtime.store.audit(
                actor=actor,
                action="household.parental-internet.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code, "path": path},
            )
            self._change_error(exc.code, correlation_id)
        except (ValueError, TypeError, json.JSONDecodeError):
            code = (
                "invalid_parental_internet_preview_request"
                if path == PREVIEW_PATH
                else "invalid_parental_internet_http_request"
            )
            self.runtime.store.audit(
                actor=actor,
                action="household.parental-internet.http",
                target="household",
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code, "path": path},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                code,
                "Некорректный запрос семейных правил интернета",
                correlation_id,
            )

    def _parental_reauth(self, actor: str, correlation_id: str, context: object) -> None:
        limiter_key = context.limiter_key + ":parental-reauth"  # type: ignore[attr-defined]
        if not self.runtime.login_limiter.allow(limiter_key):
            self._error(
                HTTPStatus.TOO_MANY_REQUESTS,
                "rate_limited",
                "Слишком много попыток повторной аутентификации",
                correlation_id,
                headers={"Retry-After": "60"},
            )
            return

        try:
            body = self._read_json(max_bytes=4096)
            if set(body) != {"schema", "provider", "username", "password", "plan_id"}:
                raise ValueError("invalid parental reauth shape")
            if body.get("schema") != REAUTH_REQUEST_SCHEMA:
                raise ValueError("invalid parental reauth schema")
            provider = body.get("provider")
            username = body.get("username")
            password = body.get("password")
            plan_id = body.get("plan_id")
            if (
                provider not in {"local", "ad"}
                or not isinstance(username, str)
                or not isinstance(password, str)
                or not isinstance(plan_id, str)
            ):
                raise ValueError("invalid parental reauth values")
        except (ValueError, TypeError, json.JSONDecodeError):
            self.runtime.store.audit(
                actor=actor,
                action="session.reauth.parental-internet",
                target=self.runtime.config.node_id,
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "invalid_parental_internet_reauth_request"},
            )
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_parental_internet_reauth_request",
                "Некорректный запрос повторной аутентификации",
                correlation_id,
            )
            return

        expected_provider = (
            "local" if actor.startswith("local-admin:")
            else "ad" if actor.startswith("ad-admin:")
            else None
        )
        expected_username = actor.split(":", 1)[1] if expected_provider is not None else None
        if provider != expected_provider:
            canonical_username = None
        else:
            try:
                canonical_username = (
                    self.runtime.local_admin.authenticate(username, password)
                    if provider == "local"
                    else self.runtime.ad_auth.authenticate(username, password)
                )
            except (LocalAdminAuthError, AdAuthError):
                self.runtime.store.audit(
                    actor=actor,
                    action="session.reauth.parental-internet",
                    target=self.runtime.config.node_id,
                    outcome="failed",
                    correlation_id=correlation_id,
                    details={"reason": "authentication_unavailable"},
                )
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "authentication_unavailable",
                    "Служба аутентификации недоступна",
                    correlation_id,
                )
                return
        if canonical_username is None or canonical_username != expected_username:
            self.runtime.store.audit(
                actor=actor,
                action="session.reauth.parental-internet",
                target=self.runtime.config.node_id,
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "invalid_credentials"},
            )
            self._error(
                HTTPStatus.FORBIDDEN,
                "reauthentication_failed",
                "Повторная аутентификация не пройдена",
                correlation_id,
            )
            return

        try:
            scope = self._safe_parental().confirmation_scope(actor=actor, plan_id=plan_id)
            if scope is None:
                raise ParentalInternetPolicyRuntimeError("parental_internet_reauth_not_required")
            token, expires_in = self.runtime.step_up.issue(actor=actor, scope=scope)
        except ParentalInternetPolicyRuntimeError as exc:
            self.runtime.store.audit(
                actor=actor,
                action="session.reauth.parental-internet",
                target=self.runtime.config.node_id,
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": exc.code},
            )
            self._change_error(exc.code, correlation_id)
            return
        except StepUpError as exc:
            self._error(
                HTTPStatus.BAD_REQUEST,
                exc.code,
                "Некорректная область повторной аутентификации",
                correlation_id,
            )
            return

        self.runtime.login_limiter.clear(limiter_key)
        self.runtime.store.audit(
            actor=actor,
            action="session.reauth.parental-internet",
            target=self.runtime.config.node_id,
            outcome="accepted",
            correlation_id=correlation_id,
            details={"scope": scope, **self._origin_details(context)},
        )
        self._json(
            HTTPStatus.OK,
            {
                "schema": REAUTH_RESULT_SCHEMA,
                "state": "verified",
                "plan_id": plan_id,
                "scope": scope,
                "step_up_token": token,
                "expires_in_seconds": expires_in,
                "single_use": True,
            },
        )

    def _read_error(self, code: str, correlation_id: str) -> None:
        forbidden = {
            "household_actor_not_bound", "household_member_disabled",
            "parental_internet_change_not_authorized",
        }
        not_found = {
            "household_not_configured", "household_member_not_found",
            "parental_internet_desired_state_missing",
        }
        unavailable = {
            "household_state_invalid", "parental_internet_verified_base_missing",
            "parental_internet_verified_base_binding_mismatch",
            "parental_internet_verified_base_stale",
            "parental_internet_desired_state_invalid", "parental_internet_desired_state_stale",
        }
        status = (
            HTTPStatus.FORBIDDEN if code in forbidden
            else HTTPStatus.NOT_FOUND if code in not_found
            else HTTPStatus.SERVICE_UNAVAILABLE if code in unavailable
            else HTTPStatus.BAD_REQUEST
        )
        self._error(
            status, code, "Семейные правила интернета не прошли безопасную проверку", correlation_id
        )

    def _change_error(self, code: str, correlation_id: str) -> None:
        forbidden = {
            "household_actor_not_bound", "household_member_disabled",
            "parental_internet_change_not_authorized", "parental_internet_actor_mismatch",
            "step_up_required", "step_up_expired", "step_up_binding_mismatch",
            "step_up_actor_invalid", "step_up_scope_invalid",
        }
        not_found = {
            "household_not_configured", "household_member_not_found",
            "parental_internet_plan_not_found",
        }
        conflict = {
            "parental_internet_subject_not_eligible", "parental_internet_plan_state_invalid",
            "parental_internet_plan_stale", "parental_internet_verified_base_stale",
            "parental_internet_desired_generation_stale", "parental_internet_current_policy_stale",
            "parental_internet_idempotency_conflict", "parental_internet_job_in_progress",
            "parental_internet_job_evidence_mismatch", "parental_internet_reauth_not_required",
            "parental_internet_http_idempotency_key_required",
        }
        unavailable = {
            "household_state_invalid", "parental_internet_verified_base_missing",
            "parental_internet_verified_base_binding_mismatch",
            "parental_internet_desired_state_invalid",
            "parental_internet_desired_state_readback_failed",
        }
        status = (
            HTTPStatus.FORBIDDEN if code in forbidden
            else HTTPStatus.NOT_FOUND if code in not_found
            else HTTPStatus.CONFLICT if code in conflict
            else HTTPStatus.SERVICE_UNAVAILABLE if code in unavailable
            else HTTPStatus.BAD_REQUEST
        )
        self._error(
            status,
            code,
            "Изменение семейных правил интернета не прошло безопасную проверку",
            correlation_id,
        )
