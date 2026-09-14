"""Home Center HA writer-admission HTTP boundary."""
from __future__ import annotations

from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v11 import RuntimeRequestHandlerV11
from .ha_admission import writer_admission
from .ha_status import status as ha_status


class RuntimeRequestHandlerV12(RuntimeRequestHandlerV11):
    """Expose HA evidence and allow mutations only on the durable HA writer."""

    HA_STATUS_PATH = "/api/v1/ha"
    SESSION_ONLY_POSTS = {
        "/api/v1/session",
        "/api/v1/session/logout",
        "/api/v1/session/reauth",
    }

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path != self.HA_STATUS_PATH:
            super().do_GET()
            return
        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(path, context):
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return
        if not self._require_actor(correlation_id):
            return
        self._json(HTTPStatus.OK, ha_status(self.runtime))

    def _require_actor(
        self,
        correlation_id: str,
        *,
        allow_password_change_required: bool = False,
    ) -> str | None:
        actor = super()._require_actor(
            correlation_id,
            allow_password_change_required=allow_password_change_required,
        )
        if actor is None:
            return None
        if getattr(self, "command", "GET") != "POST":
            return actor

        path = urlsplit(self.path).path
        if path in self.SESSION_ONLY_POSTS:
            return actor

        admission = writer_admission(
            self.runtime.store._connection,  # noqa: SLF001 - canonical StateStore transaction domain
            local_node_id=self.runtime.config.node_id,
            bootstrap_role=self.runtime.config.role,
        )
        if admission.allowed:
            return actor

        self.runtime.store.audit(
            actor=actor,
            action="ha.writer-admission",
            target=self.runtime.config.node_id,
            outcome="denied",
            correlation_id=correlation_id,
            details={
                "reason": admission.reason,
                "writer_node_id": admission.writer_node_id,
                "writer_generation": admission.generation,
                "path": path,
            },
        )
        self._error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "not_authoritative_writer",
            "Изменения разрешены только на активном узле кластера",
            correlation_id,
        )
        return None