from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

from home_center.api_v3 import RuntimeRequestHandlerV3
from home_center.config import Config
from home_center.runtime import Runtime
from home_center.server import HomeCenterServer


NODE_ID = "node-release-057-live"
NODE_NAME = "release-057-live"
CLUSTER_ID = "cluster-release-057-live"
STATE_KEY = "qualification.release-057.live-runtime"


def _run(args: list[str]) -> None:
    subprocess.run(args, check=True, capture_output=True, text=True)


def _write_secret(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o640)


def _credential(path: Path) -> None:
    material = base64.b64encode(b"q" * 32).decode("ascii")
    path.write_text(
        json.dumps(
            {
                "schema": "home-center.local-admin-credential.v2",
                "username": "admin",
                "kdf": "scrypt",
                "n": 1 << 15,
                "r": 8,
                "p": 1,
                "dklen": 32,
                "salt_b64": material,
                "verifier_b64": material,
                "password_change_required": True,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    path.chmod(0o640)


def _certificate(tmp_path: Path) -> tuple[Path, Path]:
    certificate = tmp_path / "tls.crt"
    private_key = tmp_path / "tls.key"
    _run(
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=Home Center 0.57 qualification",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ]
    )
    private_key.chmod(0o640)
    certificate.chmod(0o644)
    return certificate, private_key


def _profile(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "home-center.deployment-profile.v2",
                "profile_id": "release-057-live-runtime",
                "directory_provider": None,
                "nodes": [
                    {
                        "node_id": NODE_ID,
                        "hostname": None,
                        "endpoint": None,
                        "roles": ["control-plane"],
                        "required_capabilities": ["inventory.v1"],
                    }
                ],
                "placement": {
                    "minimum_ready_nodes": 1,
                    "maximum_nodes": 1,
                    "allow_single_node": True,
                    "require_distinct_failure_domains": False,
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _config(tmp_path: Path, certificate: Path, private_key: Path) -> Config:
    web_root = tmp_path / "web"
    backup_dir = tmp_path / "backups"
    web_root.mkdir(exist_ok=True)
    backup_dir.mkdir(exist_ok=True)

    credentials = tmp_path / "local-admin.json"
    session_key = tmp_path / "session.key"
    audit_key = tmp_path / "audit.key"
    deployment_profile = tmp_path / "deployment-profile.json"
    _credential(credentials)
    _write_secret(session_key, b"s" * 32)
    _write_secret(audit_key, b"a" * 32)
    _profile(deployment_profile)

    return Config(
        cluster_id=CLUSTER_ID,
        node_id=NODE_ID,
        node_name=NODE_NAME,
        role="control-plane",
        management_address="127.0.0.1",
        web_port=8443,
        peer_port=9443,
        state_db=tmp_path / "state.sqlite3",
        backup_dir=backup_dir,
        web_root=web_root,
        local_admin_credentials_file=credentials,
        session_key_file=session_key,
        audit_key_file=audit_key,
        tls_certificate=certificate,
        tls_private_key=private_key,
        cluster_ca=certificate,
        web_ca=certificate,
        deployment_profile=deployment_profile,
        peers=(),
        reconcile_interval_seconds=5,
        peer_timeout_seconds=1,
    )


def _serve(runtime: Runtime, certificate: Path, private_key: Path) -> tuple[HomeCenterServer, threading.Thread, int]:
    server = HomeCenterServer(("127.0.0.1", 0), RuntimeRequestHandlerV3, runtime)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(private_key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, name="release-057-live-runtime", daemon=True)
    thread.start()
    return server, thread, port


def _ready(port: int, certificate: Path) -> dict[str, object]:
    context = ssl.create_default_context(cafile=str(certificate))
    request = urllib.request.Request(
        f"https://127.0.0.1:{port}/readyz",
        headers={"Accept": "application/json", "User-Agent": "home-center-release-qualification/0.57"},
    )
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        assert response.status == 200
        assert response.headers.get_content_type() == "application/json"
        return json.loads(response.read(64 * 1024))


def _stop(server: HomeCenterServer, thread: threading.Thread, runtime: Runtime) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    runtime.stop()
    assert not thread.is_alive()


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="live runtime readiness qualification runs once on the hosted Python 3.12 leg",
)
def test_release_057_live_runtime_readiness_survives_restart(tmp_path: Path) -> None:
    """Run the real 0.57 runtime/HTTPS handler and prove ready state survives restart."""

    certificate, private_key = _certificate(tmp_path)
    config = _config(tmp_path, certificate, private_key)
    credential_before = config.local_admin_credentials_file.read_bytes()

    first = Runtime(config, local_admin_expected_uid=os.geteuid())
    first.start()
    first.store.set_meta(STATE_KEY, {"schema": "home-center.release-057-live-runtime.v1", "state": "preserve"})
    server, thread, port = _serve(first, certificate, private_key)
    first_ready = _ready(port, certificate)
    assert first_ready["schema"] == "home-center.readiness.v1"
    assert first_ready["status"] == "ready"
    assert first_ready["node_id"] == NODE_ID
    assert first_ready["reasons"] == []
    _stop(server, thread, first)

    second = Runtime(config, local_admin_expected_uid=os.geteuid())
    second.start()
    assert second.store.get_meta(STATE_KEY) == {
        "schema": "home-center.release-057-live-runtime.v1",
        "state": "preserve",
    }
    server, thread, port = _serve(second, certificate, private_key)
    second_ready = _ready(port, certificate)
    assert second_ready["schema"] == "home-center.readiness.v1"
    assert second_ready["status"] == "ready"
    assert second_ready["node_id"] == NODE_ID
    assert second_ready["reasons"] == []
    assert config.local_admin_credentials_file.read_bytes() == credential_before
    _stop(server, thread, second)
