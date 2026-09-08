"""Versioned HTTPS API and static Web UI handler."""

from __future__ import annotations

import json
import logging
import mimetypes
import re
import socket
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .actions import (
    ActionIdempotencyConflict,
    ActionNotFound,
    ActionPermissionDenied,
    ActionRequestError,
    ActionTargetConflict,
)
from .ad_auth import AdAuthError
from .auth import SessionManager
from .automation_execution import AutomationPlanningError, action_catalog
from .certificate_api import (
    CertificateApiError,
    CertificateInventoryUnavailable,
    CertificateNotFound,
    CertificateRenewalPolicy,
)
from .external_access import ExternalAccessRejected, ExternalRequestContext
from .local_admin_auth import LocalAdminAuthError
from .node_inventory_api import NodeInventoryError
from .local_admin_change import LocalAdminPasswordChangeError
from .runtime import Runtime
from .util import utc_now


LOG = logging.getLogger("home_center.api")
STATIC_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
EXTERNAL_INTERNAL_PATHS = frozenset({"/healthz", "/readyz", "/api/v1/meta", "/api/v1/tls/ca.crt"})
REQUEST_BODY_TIMEOUT_SECONDS = 2.0


class RuntimeRequestHandler(BaseHTTPRequestHandler):
    server_version = "HomeCenter"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def runtime(self) -> Runtime:
        return self.server.runtime  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        LOG.info("request remote=%s message=%s", self.client_address[0], fmt % args)

    def handle_one_request(self) -> None:
        self._current_request_context: ExternalRequestContext | None = None
        self._request_body_complete = True
        super().handle_one_request()

    def _correlation_id(self) -> str:
        supplied = self.headers.get("X-Correlation-ID", "")
        if re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", supplied):
            return supplied
        return str(uuid.uuid4())

    def _base_headers(self, content_type: str, length: int, *, cache: str = "no-store") -> None:
        if self.command == "POST" and not self._request_body_complete:
            self.close_connection = True
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", cache)
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if self.close_connection:
            self.send_header("Connection", "close")

    def _json(
        self,
        status: int,
        value: Any,
        *,
        cookie: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self._base_headers("application/json; charset=utf-8", len(body))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _error(
        self,
        status: int,
        code: str,
        message: str,
        correlation_id: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self._json(
            status,
            {
                "schema": "home-center.error.v1",
                "error": {"code": code, "message": message},
                "correlation_id": correlation_id,
            },
            headers=headers,
        )

    def _actor(self) -> str | None:
        return self.runtime.sessions.actor_from_headers(self.headers.get("Cookie"))

    def _require_actor(
        self,
        correlation_id: str,
        *,
        allow_password_change_required: bool = False,
    ) -> str | None:
        actor = self._actor()
        if not actor:
            self._error(HTTPStatus.UNAUTHORIZED, "authentication_required", "Требуется вход", correlation_id)
            return None
        if not allow_password_change_required and self.runtime.actor_requires_password_change(actor):
            self._error(
                HTTPStatus.FORBIDDEN,
                "password_change_required",
                "Перед началом работы необходимо сменить пароль администратора",
                correlation_id,
            )
            return None
        return actor

    def _classify_request(self, correlation_id: str) -> ExternalRequestContext | None:
        if self._current_request_context is not None:
            return self._current_request_context
        try:
            context = self.runtime.external_access.classify(self.client_address[0], self.headers)
        except ExternalAccessRejected as exc:
            self.close_connection = True
            LOG.warning(
                "request boundary rejected remote=%s reason=%s correlation_id=%s",
                self.client_address[0],
                exc.code,
                correlation_id,
            )
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return None
        if not self.runtime.external_request_limiter.allow(context):
            self.close_connection = True
            self.runtime.store.audit(
                actor=f"network:{context.client_address}",
                action="request.external-rate-limit",
                target=self.runtime.config.node_id,
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": "external_rate_limited", "proxy_address": context.proxy_address},
            )
            self._error(
                HTTPStatus.TOO_MANY_REQUESTS,
                "rate_limited",
                "Слишком много запросов",
                correlation_id,
                headers={"Retry-After": "60"},
            )
            return None
        self._current_request_context = context
        return context

    @staticmethod
    def _blocked_for_external(path: str, context: ExternalRequestContext) -> bool:
        return context.external and (path in EXTERNAL_INTERNAL_PATHS or path.startswith("/internal/"))

    @staticmethod
    def _origin_details(context: ExternalRequestContext) -> dict[str, Any]:
        details: dict[str, Any] = {
            "remote_address": context.client_address,
            "access_origin": "external" if context.external else "lan",
        }
        if context.proxy_address is not None:
            details["proxy_address"] = context.proxy_address
        return details

    def do_GET(self) -> None:  # noqa: N802
        correlation_id = self._correlation_id()
        parsed = urlsplit(self.path)
        path = parsed.path
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(path, context):
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return
        if path == "/external/healthz":
            if not context.external:
                self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
                return
            ready, _reasons = self.runtime.ready()
            self._json(
                HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE,
                {"schema": "home-center.external-health.v1", "status": "ok" if ready else "unavailable"},
            )
            return
        if path == "/healthz":
            self._json(200, {"schema": "home-center.health.v1", "status": "ok", "version": __version__, "node_id": self.runtime.config.node_id, "observed_at": utc_now()})
            return
        if path == "/readyz":
            ready, reasons = self.runtime.ready()
            self._json(200 if ready else 503, {"schema": "home-center.readiness.v1", "status": "ready" if ready else "not_ready", "reasons": reasons, "version": __version__, "node_id": self.runtime.config.node_id, "observed_at": utc_now()})
            return
        if path == "/api/v1/auth/providers":
            self._json(
                HTTPStatus.OK,
                {
                    "schema": "home-center.auth-providers.v1",
                    "providers": [
                        {"id": "local", "enabled": True},
                        {"id": "ad", "enabled": self.runtime.config.ad_auth.enabled},
                    ],
                },
            )
            return
        if path == "/api/v1/meta":
            self._json(200, {"schema": "home-center.meta.v1", "product": "Home Center", "version": __version__, "node_name": self.runtime.config.node_name, "role": self.runtime.config.role})
            return
        if path in {"/", "/index.html"}:
            self._static("index.html")
            return
        if path.startswith("/static/"):
            self._static(path.removeprefix("/static/"))
            return
        if path == "/api/v1/session":
            actor = self._require_actor(correlation_id, allow_password_change_required=True)
            if not actor:
                return
            self._json(
                200,
                {
                    "schema": "home-center.session.v1",
                    "authenticated": True,
                    "actor": actor,
                    "password_change_required": self.runtime.actor_requires_password_change(actor),
                },
            )
            return
        actor = self._require_actor(correlation_id)
        if not actor:
            return
        if path in {"/api/v1/overview", "/api/v1/cluster"}:
            self._json(200, self.runtime.overview())
        elif path == "/api/v1/infrastructure":
            try:
                inventory = self.runtime.node_inventory.snapshot()
            except NodeInventoryError:
                LOG.error("typed infrastructure inventory rejected inconsistent persisted facts")
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "infrastructure_inventory_unavailable",
                    "Инвентаризация инфраструктуры временно недоступна",
                    correlation_id,
                )
                return
            except Exception:
                LOG.exception("typed infrastructure inventory unavailable")
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "infrastructure_inventory_unavailable",
                    "Инвентаризация инфраструктуры временно недоступна",
                    correlation_id,
                )
                return
            self._json(HTTPStatus.OK, inventory)
        elif path == "/api/v1/nodes":
            self._json(200, {"schema": "home-center.nodes.v1", "items": self.runtime.store.nodes()})
        elif path == "/api/v1/actions":
            self._json(200, self.runtime.actions.catalog())
        elif path == "/api/v1/automation/actions":
            self._json(200, action_catalog())
        elif path == "/api/v1/jobs":
            self._json(200, {"schema": "home-center.jobs.v1", "items": self.runtime.store.jobs(100)})
        elif path == "/api/v1/audit":
            params = parse_qs(parsed.query)
            try:
                limit = int(params.get("limit", ["100"])[0])
            except ValueError:
                limit = 100
            self._json(200, {"schema": "home-center.audit-list.v1", "items": self.runtime.store.audit_events(limit), "chain_head": self.runtime.store.verify_audit_chain()})
        elif path == "/api/v1/desired-state":
            self._json(200, {"schema": "home-center.desired-state-list.v1", "items": self.runtime.store.desired_state()})
        elif path == "/api/v1/deployment-profile":
            self._json(200, self.runtime.profile)
        elif path == "/api/v1/backups":
            self._json(200, {"schema": "home-center.backup-list.v1", "items": self.runtime.backup_inventory()})
        elif path == "/api/v1/external-access":
            self._json(200, self.runtime.external_access.status())
        elif path == "/api/v1/certificates":
            try:
                self._json(HTTPStatus.OK, self.runtime.certificates.inventory())
            except (CertificateApiError, CertificateInventoryUnavailable):
                LOG.exception("certificate inventory failed")
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "certificate_inventory_unavailable",
                    "Инвентаризация сертификатов временно недоступна",
                    correlation_id,
                )
        else:
            self._error(404, "not_found", "Ресурс не найден", correlation_id)

    def _same_origin_post_allowed(self, context: ExternalRequestContext) -> bool:
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site is not None and fetch_site not in {"same-origin", "none"}:
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        host = context.public_hostname if context.external else self.headers.get("Host")
        if not host:
            return False
        try:
            parsed = urlsplit(origin)
            return (
                parsed.scheme == "https"
                and parsed.netloc.casefold() == host.casefold()
                and parsed.username is None
                and parsed.password is None
                and parsed.path == ""
                and parsed.query == ""
                and parsed.fragment == ""
            )
        except ValueError:
            return False

    def do_POST(self) -> None:  # noqa: N802
        self._request_body_complete = False
        correlation_id = self._correlation_id()
        path = urlsplit(self.path).path
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
        if path == "/api/v1/session":
            self._login(correlation_id, context)
            return
        if path == "/api/v1/session/logout":
            actor = self._require_actor(correlation_id, allow_password_change_required=True)
            if not actor:
                return
            self.runtime.store.audit(
                actor=actor,
                action="session.logout",
                target=self.runtime.config.node_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={},
            )
            self._json(200, {"schema": "home-center.session.v1", "authenticated": False}, cookie=SessionManager.expired_cookie())
            return
        if path == "/api/v1/auth/local-admin/password/change":
            actor = self._require_actor(correlation_id, allow_password_change_required=True)
            if not actor:
                return
            self._change_local_admin_password(actor, correlation_id)
            return
        actor = self._require_actor(correlation_id)
        if not actor:
            return
        if path == "/api/v1/automation/runbooks/plan":
            try:
                body = self._read_json(max_bytes=32768)
                plan = self.runtime.automation.plan(body)
            except AutomationPlanningError as exc:
                self.runtime.store.audit(
                    actor=actor,
                    action="automation.runbook.plan",
                    target="automation-runbook",
                    outcome="denied",
                    correlation_id=correlation_id,
                    details={"reason": exc.code},
                )
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    exc.code,
                    "Runbook не прошёл безопасную проверку",
                    correlation_id,
                )
                return
            except (ValueError, TypeError, json.JSONDecodeError):
                self.runtime.store.audit(
                    actor=actor,
                    action="automation.runbook.plan",
                    target="automation-runbook",
                    outcome="denied",
                    correlation_id=correlation_id,
                    details={"reason": "invalid_runbook_request"},
                )
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_runbook_request",
                    "Некорректный запрос планирования runbook",
                    correlation_id,
                )
                return
            except Exception:
                LOG.exception("typed automation planning failed")
                self._error(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "automation_planning_unavailable",
                    "Планирование automation временно недоступно",
                    correlation_id,
                )
                return
            self.runtime.store.audit(
                actor=actor,
                action="automation.runbook.plan",
                target=plan["runbook_id"],
                outcome="accepted" if plan["planning_ready"] else "blocked",
                correlation_id=correlation_id,
                details={
                    "plan_sha256": plan["plan_sha256"],
                    "blocker_count": len(plan["blockers"]),
                },
            )
            self._json(HTTPStatus.OK, plan)
            return
        if path == "/api/v1/certificates/renewal-plan":
            safe_target = "certificate"
            try:
                body = self._read_json(max_bytes=4096)
                policy = CertificateRenewalPolicy.from_mapping(body)
                safe_target = policy.certificate_id
                plan = self.runtime.certificates.plan(policy)
            except CertificateNotFound as exc:
                status, code, message = HTTPStatus.NOT_FOUND, exc.code, "Сертификат не найден"
            except (CertificateApiError, ValueError, TypeError, json.JSONDecodeError) as exc:
                status = HTTPStatus.BAD_REQUEST
                code = exc.code if isinstance(exc, CertificateApiError) else "invalid_certificate_policy"
                message = "Некорректная политика обновления сертификата"
            except CertificateInventoryUnavailable:
                status = HTTPStatus.SERVICE_UNAVAILABLE
                code = "certificate_inventory_unavailable"
                message = "Инвентаризация сертификатов временно недоступна"
            except Exception:
                LOG.exception("certificate renewal planning failed")
                self._error(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "certificate_planning_unavailable",
                    "Планирование обновления сертификата временно недоступно",
                    correlation_id,
                )
                return
            else:
                self.runtime.store.audit(
                    actor=actor,
                    action="certificate.renewal.plan",
                    target=safe_target,
                    outcome="accepted",
                    correlation_id=correlation_id,
                    details={"plan_id": plan["plan_id"], "state": plan["state"], "status": plan["status"]},
                )
                self._json(HTTPStatus.OK, plan)
                return
            self.runtime.store.audit(
                actor=actor,
                action="certificate.renewal.plan",
                target=safe_target,
                outcome="denied",
                correlation_id=correlation_id,
                details={"reason": code},
            )
            self._error(status, code, message, correlation_id)
            return
        if path.startswith("/api/v1/actions/"):
            action_id = path.removeprefix("/api/v1/actions/")
            try:
                body = self._read_json(max_bytes=8192)
                job, replay = self.runtime.actions.run(
                    actor=actor,
                    action_id=action_id,
                    request=body,
                    correlation_id=correlation_id,
                )
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                if isinstance(exc, ActionNotFound):
                    status, code, message = HTTPStatus.NOT_FOUND, exc.code, "Действие не зарегистрировано"
                elif isinstance(exc, ActionPermissionDenied):
                    status, code, message = HTTPStatus.FORBIDDEN, exc.code, "Недостаточно прав"
                elif isinstance(exc, ActionIdempotencyConflict):
                    status, code, message = HTTPStatus.CONFLICT, exc.code, "Ключ идемпотентности уже использован"
                elif isinstance(exc, ActionTargetConflict):
                    status, code, message = HTTPStatus.CONFLICT, exc.code, "Целевой узел не является локальным"
                else:
                    status, code, message = HTTPStatus.BAD_REQUEST, "invalid_action_request", "Некорректный запрос действия"
                safe_target = action_id if re.fullmatch(r"[a-z][a-z0-9.-]{0,127}", action_id) else "invalid-action"
                self.runtime.store.audit(
                    actor=actor,
                    action="action.request",
                    target=safe_target,
                    outcome="denied",
                    correlation_id=correlation_id,
                    details={"reason": code},
                )
                self._error(status, code, message, correlation_id)
                return
            except Exception:
                LOG.exception("typed action request failed")
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "action_internal_error", "Внутренняя ошибка действия", correlation_id)
                return
            self._json(
                HTTPStatus.OK,
                {
                    "schema": "home-center.action-result.v1",
                    "idempotent_replay": replay,
                    "job": job,
                },
            )
            return
        self._error(405, "typed_action_not_available", "Изменение не входит в эту сертифицированную версию", correlation_id)

    def do_PUT(self) -> None:  # noqa: N802
        self._reject_mutation()

    def do_PATCH(self) -> None:  # noqa: N802
        self._reject_mutation()

    def do_DELETE(self) -> None:  # noqa: N802
        self._reject_mutation()

    def _reject_mutation(self) -> None:
        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None or self._blocked_for_external(urlsplit(self.path).path, context):
            if context is not None:
                self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return
        if not self._require_actor(correlation_id):
            return
        self._error(405, "typed_action_not_available", "Изменение не входит в эту сертифицированную версию", correlation_id)

    def _read_json(self, max_bytes: int = 4096) -> dict[str, Any]:
        if self.headers.get_content_type() != "application/json":
            raise ValueError("content type")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValueError("content length")
        length = int(raw_length)
        if length < 1 or length > max_bytes:
            raise ValueError("body size")
        previous_timeout = self.connection.gettimeout()
        self.connection.settimeout(REQUEST_BODY_TIMEOUT_SECONDS)
        try:
            raw = self.rfile.read(length)
        except (TimeoutError, socket.timeout) as exc:
            self.close_connection = True
            raise ValueError("body timeout") from exc
        finally:
            self.connection.settimeout(previous_timeout)
        if len(raw) != length:
            self.close_connection = True
            raise ValueError("body truncated")
        self._request_body_complete = True
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value

    def _login(self, correlation_id: str, context: ExternalRequestContext) -> None:
        remote = context.client_address
        limiter_key = context.limiter_key
        if not self.runtime.login_limiter.allow(limiter_key):
            self._error(429, "rate_limited", "Слишком много попыток входа", correlation_id)
            return
        try:
            body = self._read_json()
            if set(body) != {"provider", "username", "password"}:
                raise ValueError("invalid login shape")
            provider = body.get("provider")
            username = body.get("username")
            password = body.get("password")
            if provider not in {"local", "ad"} or not isinstance(username, str) or not isinstance(password, str):
                raise ValueError("invalid login types")
        except (ValueError, TypeError, json.JSONDecodeError):
            self.runtime.store.audit(actor=f"network:{remote}", action="session.login", target=self.runtime.config.node_id, outcome="denied", correlation_id=correlation_id, details={"reason": "invalid_credentials"})
            self._error(401, "invalid_credentials", "Неверные учётные данные", correlation_id)
            return

        try:
            if provider == "local":
                canonical_username = self.runtime.local_admin.authenticate(username, password)
                actor_prefix = "local-admin"
            else:
                canonical_username = self.runtime.ad_auth.authenticate(username, password)
                actor_prefix = "ad-admin"
        except (LocalAdminAuthError, AdAuthError):
            LOG.error("authentication backend unavailable")
            self.runtime.store.audit(actor=f"network:{remote}", action="session.login", target=self.runtime.config.node_id, outcome="denied", correlation_id=correlation_id, details={"reason": "authentication_unavailable"})
            self._error(503, "authentication_unavailable", "Служба аутентификации недоступна", correlation_id)
            return
        if canonical_username is None:
            self.runtime.store.audit(actor=f"network:{remote}", action="session.login", target=self.runtime.config.node_id, outcome="denied", correlation_id=correlation_id, details={"reason": "invalid_credentials"})
            self._error(401, "invalid_credentials", "Неверные учётные данные", correlation_id)
            return

        self.runtime.login_limiter.clear(limiter_key)
        actor = f"{actor_prefix}:{canonical_username}"
        session, expires = self.runtime.sessions.new_session(actor)
        self.runtime.store.audit(
            actor=actor,
            action="session.login",
            target=self.runtime.config.node_id,
            outcome="accepted",
            correlation_id=correlation_id,
            details=self._origin_details(context),
        )
        self._json(
            200,
            {
                "schema": "home-center.session.v1",
                "authenticated": True,
                "actor": actor,
                "expires_at_epoch": expires,
                "password_change_required": self.runtime.actor_requires_password_change(actor),
            },
            cookie=SessionManager.cookie(session, expires - int(time.time())),
        )

    def _change_local_admin_password(self, actor: str, correlation_id: str) -> None:
        if not actor.startswith("local-admin:"):
            self._error(
                HTTPStatus.FORBIDDEN,
                "local_admin_required",
                "Смена локального пароля доступна только локальному администратору",
                correlation_id,
            )
            return
        try:
            body = self._read_json()
            if set(body) != {"schema", "current_password", "new_password"}:
                raise ValueError("invalid password change shape")
            if body.get("schema") != "home-center.local-admin-password-change.v1":
                raise ValueError("invalid password change schema")
            current_password = body.get("current_password")
            new_password = body.get("new_password")
            if not isinstance(current_password, str) or not isinstance(new_password, str):
                raise ValueError("invalid password change values")
        except (ValueError, TypeError, json.JSONDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_password_change", "Некорректный запрос смены пароля", correlation_id)
            return

        username = actor.removeprefix("local-admin:")
        try:
            self.runtime.change_local_admin_password(username, current_password, new_password)
        except LocalAdminPasswordChangeError as exc:
            if exc.code == "current_password_invalid":
                status, code, message = HTTPStatus.FORBIDDEN, exc.code, "Текущий пароль неверен"
            elif exc.code in {
                "password_too_short",
                "password_letter_required",
                "password_digit_required",
                "password_rejected",
            }:
                status, code, message = HTTPStatus.BAD_REQUEST, exc.code, "Новый пароль не соответствует требованиям"
            else:
                status, code, message = HTTPStatus.SERVICE_UNAVAILABLE, "password_change_unavailable", "Смена пароля временно недоступна"
            self.runtime.store.audit(
                actor=actor,
                action="local-admin.password.change",
                target=self.runtime.config.node_id,
                outcome="denied" if status in {HTTPStatus.BAD_REQUEST, HTTPStatus.FORBIDDEN} else "failed",
                correlation_id=correlation_id,
                details={"reason": code},
            )
            self._error(status, code, message, correlation_id)
            return

        self.runtime.store.audit(
            actor=actor,
            action="local-admin.password.change",
            target=self.runtime.config.node_id,
            outcome="accepted",
            correlation_id=correlation_id,
            details={},
        )
        self._json(
            HTTPStatus.OK,
            {
                "schema": "home-center.local-admin-password-change-result.v1",
                "status": "changed",
                "node_id": self.runtime.config.node_id,
            },
            cookie=SessionManager.expired_cookie(),
        )

    def _static(self, name: str) -> None:
        if not STATIC_NAME.fullmatch(name):
            self._error(404, "not_found", "Ресурс не найден", self._correlation_id())
            return
        root = self.runtime.config.web_root.resolve()
        path = (root / name).resolve()
        if path.parent != root or not path.is_file():
            self._error(404, "not_found", "Ресурс не найден", self._correlation_id())
            return
        data = path.read_bytes()
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        self.send_response(200)
        self._base_headers(content_type, len(data), cache="no-cache")
        self.end_headers()
        self.wfile.write(data)


class PeerRequestHandler(BaseHTTPRequestHandler):
    server_version = "HomeCenterPeer"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def runtime(self) -> Runtime:
        return self.server.runtime  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        LOG.info("peer remote=%s message=%s", self.client_address[0], fmt % args)

    def do_GET(self) -> None:  # noqa: N802
        if not self._peer_identity_matches():
            self.send_error(403)
            return
        if urlsplit(self.path).path != "/internal/v1/node":
            self.send_error(404)
            return
        value = {"schema": "home-center.peer-node.v1", "cluster_id": self.runtime.config.cluster_id, "capability": self.runtime.reconciler.local_capability()}
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _peer_identity_matches(self) -> bool:
        certificate = self.connection.getpeercert()  # type: ignore[attr-defined]
        subjects = dict(item[0] for item in certificate.get("subject", ()))
        common_name = subjects.get("commonName")
        return any(common_name == peer.certificate_name for peer in self.runtime.config.peers)
