"""Versioned internal HA API on the existing mutually-authenticated peer listener."""
from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import urlsplit

from .api import PeerRequestHandler
from .ha_peer import HAPeerProtocolError, build_authoritative_export, build_ha_status


class PeerRequestHandlerV2(PeerRequestHandler):
    """Keep node discovery intact and add bounded read-only HA peer endpoints."""

    HA_STATUS_PATH = "/internal/v1/ha/status"
    HA_SNAPSHOT_PATH = "/internal/v1/ha/authoritative-state"

    def _json(self, status: int, value: dict) -> None:
        body = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in {self.HA_STATUS_PATH, self.HA_SNAPSHOT_PATH}:
            super().do_GET()
            return
        if not self._peer_identity_matches():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        try:
            if path == self.HA_STATUS_PATH:
                value = build_ha_status(self.runtime)
            else:
                value = build_authoritative_export(self.runtime)
        except HAPeerProtocolError as exc:
            unavailable = {
                "ha_release_identity_unavailable",
                "ha_requires_immutable_release",
                "ha_release_revision_unqualified",
            }
            status = HTTPStatus.SERVICE_UNAVAILABLE if str(exc) in unavailable else HTTPStatus.CONFLICT
            self._json(
                status,
                {
                    "schema": "home-center.ha-peer-error.v1",
                    "error": str(exc),
                },
            )
            return
        self._json(HTTPStatus.OK, value)
