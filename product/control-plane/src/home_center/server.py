"""TLS server bootstrap and process lifecycle."""

from __future__ import annotations

import hashlib
import logging
import pwd
import re
import signal
import ssl
import stat
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from .api import PeerRequestHandler
from .api_v5 import RuntimeRequestHandlerV5
from .config import load_config
from .runtime import Runtime


LOG = logging.getLogger("home_center")

WEB_MINIMUM_TLS_VERSION = ssl.TLSVersion.TLSv1_2
PEER_MINIMUM_TLS_VERSION = ssl.TLSVersion.TLSv1_3
WEB_ROOT = Path("/etc/home-center/pki/web")
WEB_RELEASES = WEB_ROOT / "releases"
WEB_CURRENT = WEB_ROOT / "current"
WEB_CERTIFICATE = WEB_CURRENT / "tls.crt"
WEB_PRIVATE_KEY = WEB_CURRENT / "tls.key"


class HomeCenterServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type, runtime: Runtime) -> None:
        self.runtime = runtime
        super().__init__(address, handler)


def _server_context(certificate: Path, private_key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(private_key))
    return context


def _separate_web_identity_present() -> bool:
    if not (WEB_CURRENT.exists() or WEB_CURRENT.is_symlink()):
        return False
    if not WEB_CURRENT.is_symlink():
        raise RuntimeError("web_current_must_be_symlink")
    try:
        release = WEB_CURRENT.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("web_current_dangling") from exc
    if release.parent != WEB_RELEASES or re.fullmatch(r"[0-9a-f]{24}", release.name) is None:
        raise RuntimeError("web_current_outside_release_root")
    account = pwd.getpwnam("home-center")
    release_info = release.lstat()
    if (
        not stat.S_ISDIR(release_info.st_mode)
        or stat.S_ISLNK(release_info.st_mode)
        or release_info.st_uid != 0
        or release_info.st_gid != account.pw_gid
        or stat.S_IMODE(release_info.st_mode) != 0o750
    ):
        raise RuntimeError("web_current_release_metadata_rejected")
    for path, mode in ((WEB_CERTIFICATE, 0o644), (WEB_PRIVATE_KEY, 0o640)):
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise RuntimeError("web_identity_incomplete") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != account.pw_gid
            or stat.S_IMODE(info.st_mode) != mode
        ):
            raise RuntimeError("web_identity_metadata_rejected")
    try:
        certificate_der = ssl.PEM_cert_to_DER_cert(WEB_CERTIFICATE.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, ValueError, ssl.SSLError) as exc:
        raise RuntimeError("web_certificate_rejected") from exc
    if hashlib.sha256(certificate_der).hexdigest()[:24] != release.name:
        raise RuntimeError("web_release_identity_mismatch")
    return True


def _web_context(runtime: Runtime) -> ssl.SSLContext:
    separate = _separate_web_identity_present()
    certificate = WEB_CERTIFICATE if separate else runtime.config.tls_certificate
    private_key = WEB_PRIVATE_KEY if separate else runtime.config.tls_private_key
    context = _server_context(certificate, private_key)
    context.minimum_version = WEB_MINIMUM_TLS_VERSION
    return context


def _peer_context(runtime: Runtime) -> ssl.SSLContext:
    context = _server_context(runtime.config.tls_certificate, runtime.config.tls_private_key)
    context.minimum_version = PEER_MINIMUM_TLS_VERSION
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(runtime.config.cluster_ca))
    return context


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = load_config()
    runtime = Runtime(config)
    runtime.start()
    web = HomeCenterServer(config.web_bind, RuntimeRequestHandlerV5, runtime)
    peer = HomeCenterServer(config.peer_bind, PeerRequestHandler, runtime)
    web.socket = _web_context(runtime).wrap_socket(web.socket, server_side=True)
    peer.socket = _peer_context(runtime).wrap_socket(peer.socket, server_side=True)

    stop = threading.Event()

    def request_stop(signum: int, _frame: object) -> None:
        LOG.info("shutdown requested signal=%s", signum)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    web_thread = threading.Thread(target=web.serve_forever, name="home-center-web", daemon=True)
    peer_thread = threading.Thread(target=peer.serve_forever, name="home-center-peer", daemon=True)
    web_thread.start()
    peer_thread.start()
    LOG.info("Home Center started node=%s role=%s web_tls=%s", config.node_name, config.role, "separate" if _separate_web_identity_present() else "legacy-fallback")
    stop.wait()
    web.shutdown()
    peer.shutdown()
    web.server_close()
    peer.server_close()
    runtime.stop()
    LOG.info("Home Center stopped")
