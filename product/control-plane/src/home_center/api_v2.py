from __future__ import annotations

import os
import ssl
import stat
import subprocess
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlsplit

from .api import RuntimeRequestHandler
from .release_identity import ReleaseIdentityError, current_release_identity
from .tls_status import _certificate_profile, _chain_valid, status as tls_status


def _read_public_certificate(path: Path) -> tuple[bytes, bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_size < 128
            or info.st_size > 64 * 1024
        ):
            raise ValueError("public_certificate_metadata_rejected")
        data = bytearray()
        while len(data) <= 64 * 1024:
            block = os.read(descriptor, 8192)
            if not block:
                break
            data.extend(block)
        if len(data) > 64 * 1024:
            raise ValueError("public_certificate_size_rejected")
    finally:
        os.close(descriptor)
    payload = bytes(data)
    der = ssl.PEM_cert_to_DER_cert(payload.decode("ascii"))
    return payload, der


def _validated_web_ca(config: object) -> bytes:
    web_ca = getattr(config, "web_ca")
    cluster_ca = getattr(config, "cluster_ca")
    data, web_der = _read_public_certificate(web_ca)
    _, peer_der = _read_public_certificate(cluster_ca)
    if web_der == peer_der:
        raise ValueError("web_ca_must_differ_from_peer_ca")
    if not _chain_valid(web_ca, web_ca):
        raise ValueError("web_ca_self_chain_rejected")
    profile = _certificate_profile(web_ca, scope="browser-web-ca")
    if not profile.get("profile_valid"):
        raise ValueError("web_ca_profile_rejected")
    return data


class RuntimeRequestHandlerV2(RuntimeRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(path, context):
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return
        if path == "/api/v1/meta":
            try:
                release = current_release_identity()
            except ReleaseIdentityError:
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "release_identity_unavailable",
                    "Идентичность установленного релиза не подтверждена",
                    correlation_id,
                )
                return
            self._json(
                HTTPStatus.OK,
                {
                    "schema": "home-center.meta.v2",
                    "product": "Home Center",
                    "version": release["version"],
                    "revision": release["revision"],
                    "build": release["build"],
                    "release_source": release["source"],
                    "node_name": self.runtime.config.node_name,
                    "role": self.runtime.config.role,
                },
            )
            return
        if path == "/api/v1/tls/ca.crt":
            try:
                data = _validated_web_ca(self.runtime.config)
            except (OSError, UnicodeDecodeError, ValueError, ssl.SSLError, subprocess.SubprocessError):
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "tls_trust_anchor_unavailable",
                    "Корневой сертификат Web TLS временно недоступен",
                    self._correlation_id(),
                )
                return
            self.send_response(HTTPStatus.OK)
            self._base_headers("application/x-pem-file", len(data), cache="public, max-age=300")
            self.send_header("Content-Disposition", 'attachment; filename="home-center-web-ca.crt"')
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/api/v1/tls":
            if not self._require_actor(correlation_id):
                return
            try:
                value = tls_status(self.runtime.config)
            except Exception:
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "tls_status_unavailable",
                    "Статус TLS временно недоступен",
                    correlation_id,
                )
                return
            self._json(HTTPStatus.OK, value)
            return
        super().do_GET()
