from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
STABLE_VERSION = "0.56.0"
CANDIDATE_VERSION = "0.57.0"
STABLE_REPO = "ControlCenterSoft/home-center-stable"


def _run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=check,
    )


def _sudo(script: str) -> subprocess.CompletedProcess[str]:
    return _run(["sudo", "bash", "-ceu", script])


def _download(url: str, target: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "home-center-release-qualification/0.57-systemd"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        target.write_bytes(response.read())


def _host_address() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("1.1.1.1", 443))
        address = str(probe.getsockname()[0])
    finally:
        probe.close()
    if address.startswith("127.") or address == "0.0.0.0":
        raise RuntimeError("qualified non-loopback address unavailable")
    return address


def _free_port(address: str) -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((address, 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


def _wait_ready(address: str, port: int, certificate: Path, *, timeout: float = 45.0) -> dict[str, object]:
    context = ssl.create_default_context(cafile=str(certificate))
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(
                f"https://{address}:{port}/readyz",
                headers={
                    "Accept": "application/json",
                    "User-Agent": "home-center-release-qualification/0.57-systemd",
                },
            )
            with urllib.request.urlopen(request, timeout=5, context=context) as response:
                if response.status == 200:
                    payload = json.loads(response.read(64 * 1024))
                    if payload.get("status") == "ready" and payload.get("reasons") == []:
                        return payload
        except BaseException as exc:  # pragma: no cover - diagnostic retry boundary
            last_error = exc
        time.sleep(1)
    journal = _run(
        ["sudo", "journalctl", "-u", "home-center.service", "--no-pager", "-n", "120"],
        check=False,
    )
    raise AssertionError(
        "Home Center did not become ready under real systemd; "
        f"last_error={last_error!r}\n{journal.stdout}\n{journal.stderr}"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _state_value(path: str) -> str:
    completed = _sudo(
        f"""python3 - <<'PY'
import sqlite3
con = sqlite3.connect({path!r}, timeout=10)
try:
    row = con.execute("SELECT v FROM qualification_systemd WHERE k='sentinel'").fetchone()
    if row is None:
        raise SystemExit(70)
    print(row[0])
finally:
    con.close()
PY"""
    )
    return completed.stdout.strip()


def _assert_systemd_manager() -> None:
    if not Path("/run/systemd/system").is_dir():
        pytest.fail("GitHub-hosted runner has no active systemd manager")
    probe = _run(["systemctl", "list-units", "--type=service", "--no-pager"], check=False)
    if probe.returncode != 0:
        pytest.fail(f"systemd manager unavailable: {probe.stdout}\n{probe.stderr}")


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="real systemd upgrade qualification runs once on the hosted Python 3.12 leg",
)
def test_release_057_real_systemd_upgrade_health_and_rollback(tmp_path: Path) -> None:
    """Run the actual 0.56 -> 0.57 installer and rollback under systemd.

    The older filesystem drill deliberately shims systemctl. This qualification is
    complementary: it starts the published 0.56 service through the real service
    manager, upgrades with the production installer, checks HTTPS readiness and
    state/credential preservation, then executes the real rollback and repeats the
    health checks. It does not claim multi-node or provider-adapter qualification.
    """

    _assert_systemd_manager()
    address = _host_address()
    web_port = _free_port(address)
    peer_port = _free_port(address)
    while peer_port == web_port:
        peer_port = _free_port(address)

    stable_artifact = tmp_path / f"home-center-{STABLE_VERSION}-linux-amd64.tar.gz"
    stable_sidecar = tmp_path / f"{stable_artifact.name}.sha256"
    release_base = f"https://github.com/{STABLE_REPO}/releases/download/v{STABLE_VERSION}"
    _download(f"{release_base}/{stable_artifact.name}", stable_artifact)
    _download(f"{release_base}/{stable_sidecar.name}", stable_sidecar)
    stable_digest = stable_sidecar.read_text(encoding="utf-8").split()[0]
    assert _sha256(stable_artifact) == stable_digest

    stable_extract = tmp_path / "stable"
    stable_extract.mkdir()
    _run(["tar", "-xzf", str(stable_artifact), "-C", str(stable_extract)])
    stable_revision = (stable_extract / "REVISION").read_text(encoding="utf-8").strip()
    assert (stable_extract / "VERSION").read_text(encoding="utf-8").strip() == STABLE_VERSION
    assert len(stable_revision) == 40

    candidate_worktree = tmp_path / "candidate-src"
    _run(["git", "worktree", "add", "--detach", str(candidate_worktree), "HEAD"], cwd=ROOT)
    had_user = False
    baseline_release = "/opt/home-center/releases/qualification-systemd-0.56.0"
    state_db = "/var/lib/home-center/qualification-057-systemd.sqlite3"
    config = Path("/etc/home-center/config.json")
    credentials = Path("/etc/home-center/local-admin.json")
    session_key = Path("/etc/home-center/session.key")
    audit_key = Path("/etc/home-center/audit.key")
    tls_certificate = Path("/etc/home-center/tls.crt")
    tls_private_key = Path("/etc/home-center/tls.key")
    cluster_ca = tls_certificate
    web_ca = Path("/etc/home-center/web-ca.crt")
    deployment_profile = Path("/etc/home-center/deployment-profile.json")
    transaction_id = "20260912T031000Z-057057057057"
    node_name = socket.gethostname().split(".", 1)[0]

    try:
        init_path = candidate_worktree / "product/control-plane/src/home_center/__init__.py"
        init_text = init_path.read_text(encoding="utf-8")
        old_marker = f'__version__ = "{STABLE_VERSION}"'
        new_marker = f'__version__ = "{CANDIDATE_VERSION}"'
        assert old_marker in init_text
        init_path.write_text(init_text.replace(old_marker, new_marker, 1), encoding="utf-8")

        candidate_dist = tmp_path / "candidate-dist"
        build = _run(
            ["bash", "deploy/scripts/build-deployment-artifact.sh", str(candidate_dist)],
            cwd=candidate_worktree,
        )
        assert "DEPLOYMENT_ARTIFACT=" in build.stdout
        candidate_artifact = candidate_dist / f"home-center-{CANDIDATE_VERSION}-linux-amd64.tar.gz"
        candidate_sidecar = Path(f"{candidate_artifact}.sha256")
        candidate_digest = candidate_sidecar.read_text(encoding="utf-8").split()[0]
        assert _sha256(candidate_artifact) == candidate_digest

        candidate_extract = tmp_path / "candidate"
        candidate_extract.mkdir()
        _run(["tar", "-xzf", str(candidate_artifact), "-C", str(candidate_extract)])
        candidate_revision = (candidate_extract / "REVISION").read_text(encoding="utf-8").strip()
        assert candidate_revision == _run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()

        had_user = _run(["id", "-u", "home-center"], check=False).returncode == 0
        if Path("/opt/home-center/current").exists() or Path("/etc/home-center").exists():
            pytest.fail("hosted runner unexpectedly contains a pre-existing Home Center installation")

        _sudo(
            f"""
if ! id -u home-center >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home home-center
fi
install -d -m 0755 /opt/home-center/releases {baseline_release}
install -d -m 0750 -o home-center -g home-center /var/lib/home-center /var/backups/home-center
install -d -m 0755 /etc/home-center
tar -xzf {stable_artifact} -C {baseline_release}
rm -f /opt/home-center/current
ln -s {baseline_release} /opt/home-center/current
"""
        )

        _run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                f"/CN={address}",
                "-addext",
                f"subjectAltName=IP:{address}",
                "-keyout",
                str(tmp_path / "tls.key"),
                "-out",
                str(tmp_path / "tls.crt"),
            ]
        )
        _run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=Home Center qualification web CA",
                "-keyout",
                str(tmp_path / "web-ca.key"),
                "-out",
                str(tmp_path / "web-ca.crt"),
            ]
        )

        material = base64.b64encode(b"q" * 32).decode("ascii")
        credential_document = json.dumps(
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
                "password_change_required": False,
            },
            sort_keys=True,
        )
        profile_document = json.dumps(
            {
                "schema": "home-center.deployment-profile.v2",
                "profile_id": "release-057-systemd-qualification",
                "directory_provider": None,
                "nodes": [
                    {
                        "node_id": "node-release-057-systemd",
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
        )
        config_document = json.dumps(
            {
                "schema": "home-center.config.v5",
                "cluster_id": "cluster-release-057-systemd",
                "node_id": "node-release-057-systemd",
                "node_name": "release-057-systemd",
                "role": "control-plane",
                "management_address": address,
                "web_port": web_port,
                "peer_port": peer_port,
                "state_db": state_db,
                "backup_dir": "/var/backups/home-center",
                "web_root": "/opt/home-center/current/web",
                "local_admin_credentials_file": str(credentials),
                "session_key_file": str(session_key),
                "audit_key_file": str(audit_key),
                "tls_certificate": str(tls_certificate),
                "tls_private_key": str(tls_private_key),
                "cluster_ca": str(cluster_ca),
                "web_ca": str(web_ca),
                "deployment_profile": str(deployment_profile),
                "peers": [],
                "reconcile_interval_seconds": 5,
                "peer_timeout_seconds": 1,
                "ad_auth": {
                    "enabled": False,
                    "realm": "EXAMPLE.TEST",
                    "kdc_hosts": ["dc.example.test"],
                    "allowed_admin_groups": ["Home Center Admins"],
                    "timeout_seconds": 2,
                    "cache_root": "/var/lib/home-center/ad-auth",
                },
                "external_access": {
                    "enabled": False,
                    "mode": "trusted-reverse-proxy",
                    "public_hostname": None,
                    "trusted_proxy_addresses": [],
                },
            },
            sort_keys=True,
        )

        staging = tmp_path / "configuration"
        staging.mkdir()
        (staging / "config.json").write_text(config_document + "\n", encoding="utf-8")
        (staging / "local-admin.json").write_text(credential_document + "\n", encoding="utf-8")
        (staging / "session.key").write_bytes(b"s" * 32)
        (staging / "audit.key").write_bytes(b"a" * 32)
        (staging / "deployment-profile.json").write_text(profile_document + "\n", encoding="utf-8")

        _sudo(
            f"""
home_gid=$(getent group home-center | cut -d: -f3)
install -m 0644 -o root -g root {staging / 'config.json'} {config}
install -m 0640 -o root -g "$home_gid" {staging / 'local-admin.json'} {credentials}
install -m 0640 -o root -g "$home_gid" {staging / 'session.key'} {session_key}
install -m 0640 -o root -g "$home_gid" {staging / 'audit.key'} {audit_key}
install -m 0644 -o root -g root {staging / 'deployment-profile.json'} {deployment_profile}
install -m 0644 -o root -g root {tmp_path / 'tls.crt'} {tls_certificate}
install -m 0640 -o root -g "$home_gid" {tmp_path / 'tls.key'} {tls_private_key}
install -m 0644 -o root -g root {tmp_path / 'web-ca.crt'} {web_ca}
install -m 0644 -o root -g root {stable_extract / 'deploy/home-center.service'} /etc/systemd/system/home-center.service
install -m 0644 -o root -g root {stable_extract / 'deploy/home-center-backup.service'} /etc/systemd/system/home-center-backup.service
install -m 0644 -o root -g root {stable_extract / 'deploy/home-center-backup.timer'} /etc/systemd/system/home-center-backup.timer
systemctl daemon-reload
systemctl enable home-center.service home-center-backup.timer >/dev/null
systemctl start home-center.service
"""
        )

        stable_ready = _wait_ready(address, web_port, tls_certificate)
        assert stable_ready["node_id"] == "node-release-057-systemd"
        assert _run(["sudo", "systemctl", "is-active", "home-center.service"]).stdout.strip() == "active"

        _sudo(
            f"""python3 - <<'PY'
import sqlite3
con = sqlite3.connect({state_db!r}, timeout=10)
try:
    con.execute("CREATE TABLE IF NOT EXISTS qualification_systemd (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
    con.execute("INSERT OR REPLACE INTO qualification_systemd(k,v) VALUES ('sentinel','stable-user-state')")
    con.commit()
finally:
    con.close()
PY
chown home-center:home-center {state_db}
chmod 0640 {state_db}
"""
        )

        preserved = {
            "config": _sha256(config),
            "credentials": _sha256(credentials),
            "session": _sha256(session_key),
            "audit": _sha256(audit_key),
        }

        installed = _run(
            [
                "sudo",
                "bash",
                str(candidate_extract / "deploy/install-node.sh"),
                "--artifact",
                str(candidate_artifact),
                "--sha256",
                candidate_digest,
                "--node-name",
                node_name,
                "--transaction-id",
                transaction_id,
                "--expected-current-release",
                baseline_release,
                "--expected-current-version",
                STABLE_VERSION,
                "--expected-current-revision",
                stable_revision,
            ]
        )
        assert "NODE_DEPLOYMENT=PASS" in installed.stdout
        rollback_point = next(
            line.split("=", 1)[1]
            for line in installed.stdout.splitlines()
            if line.startswith("ROLLBACK_POINT=")
        )
        target_release = next(
            line.split("=", 1)[1]
            for line in installed.stdout.splitlines()
            if line.startswith("RELEASE=")
        )
        assert _run(["sudo", "readlink", "-f", "/opt/home-center/current"]).stdout.strip() == target_release
        assert _run(["sudo", "cat", "/opt/home-center/current/VERSION"]).stdout.strip() == CANDIDATE_VERSION
        assert _run(["sudo", "cat", "/opt/home-center/current/REVISION"]).stdout.strip() == candidate_revision
        assert _wait_ready(address, web_port, tls_certificate)["status"] == "ready"
        assert _state_value(state_db) == "stable-user-state"
        assert preserved == {
            "config": _sha256(config),
            "credentials": _sha256(credentials),
            "session": _sha256(session_key),
            "audit": _sha256(audit_key),
        }

        rolled_back = _run(
            [
                "sudo",
                "bash",
                str(candidate_extract / "deploy/rollback-node.sh"),
                "--rollback-point",
                rollback_point,
            ]
        )
        assert "NODE_ROLLBACK=PASS" in rolled_back.stdout
        assert _run(["sudo", "readlink", "-f", "/opt/home-center/current"]).stdout.strip() == baseline_release
        assert _run(["sudo", "cat", "/opt/home-center/current/VERSION"]).stdout.strip() == STABLE_VERSION
        assert _run(["sudo", "systemctl", "is-active", "home-center.service"]).stdout.strip() == "active"
        assert _wait_ready(address, web_port, tls_certificate)["status"] == "ready"
        assert _state_value(state_db) == "stable-user-state"
        assert preserved == {
            "config": _sha256(config),
            "credentials": _sha256(credentials),
            "session": _sha256(session_key),
            "audit": _sha256(audit_key),
        }
    finally:
        _run(["git", "worktree", "remove", "--force", str(candidate_worktree)], cwd=ROOT, check=False)
        _run(["sudo", "systemctl", "disable", "--now", "home-center-backup.timer"], check=False)
        _run(["sudo", "systemctl", "disable", "--now", "home-center.service"], check=False)
        _run(["sudo", "systemctl", "stop", "home-center-backup.service"], check=False)
        _sudo(
            """
rm -f /etc/systemd/system/home-center.service /etc/systemd/system/home-center-backup.service /etc/systemd/system/home-center-backup.timer
systemctl daemon-reload || true
rm -f /opt/home-center/current /opt/home-center/.current.new /opt/home-center/.current.rollback
rm -rf /opt/home-center/releases/qualification-systemd-0.56.0
find /opt/home-center/releases -maxdepth 1 -type d -name '0.57.0-*' -exec rm -rf {} + 2>/dev/null || true
rm -rf /run/home-center-locks
rm -f /var/lib/home-center/qualification-057-systemd.sqlite3*
rm -f /var/lib/home-center-deploy/transactions/20260912T031000Z-057057057057-*.json
rm -rf /var/backups/home-center-deploy/20260912T031000Z-057057057057-*
rm -rf /var/backups/home-center
rm -rf /etc/home-center
"""
        )
        if not had_user:
            _run(["sudo", "userdel", "home-center"], check=False)
