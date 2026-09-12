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


def _run(args: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=check)


def _sudo(script: str) -> subprocess.CompletedProcess[str]:
    return _run(["sudo", "bash", "-ceu", script])


def _download(url: str, target: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "home-center-release-qualification/0.57-systemd"})
    with urllib.request.urlopen(request, timeout=60) as response:
        target.write_bytes(response.read())


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _root_sha256(path: Path) -> str:
    completed = _run(["sudo", "sha256sum", "--", str(path)])
    digest = completed.stdout.split()[0]
    assert len(digest) == 64
    return digest


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


def _wait_ready(address: str, port: int, certificate: Path, timeout: float = 45.0) -> dict[str, object]:
    context = ssl.create_default_context(cafile=str(certificate))
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(
                f"https://{address}:{port}/readyz",
                headers={"Accept": "application/json", "User-Agent": "home-center-release-qualification/0.57-systemd"},
            )
            with urllib.request.urlopen(request, timeout=5, context=context) as response:
                payload = json.loads(response.read(64 * 1024))
                if response.status == 200 and payload.get("status") == "ready" and payload.get("reasons") == []:
                    return payload
        except BaseException as exc:  # pragma: no cover - diagnostic retry boundary
            last_error = exc
        time.sleep(1)
    journal = _run(["sudo", "journalctl", "-u", "home-center.service", "--no-pager", "-n", "120"], check=False)
    raise AssertionError(f"service not ready: {last_error!r}\n{journal.stdout}\n{journal.stderr}")


def _state_value(path: str) -> str:
    return _sudo(
        f"""python3 - <<'PY'
import sqlite3
con = sqlite3.connect({path!r}, timeout=10)
try:
    print(con.execute("SELECT v FROM qualification_systemd WHERE k='sentinel'").fetchone()[0])
finally:
    con.close()
PY"""
    ).stdout.strip()


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
    """Exercise real systemd across Stable 0.56 -> candidate 0.57 -> rollback."""

    _assert_systemd_manager()
    address = _host_address()
    web_port = _free_port(address)
    peer_port = _free_port(address)
    while peer_port == web_port:
        peer_port = _free_port(address)

    stable_artifact = tmp_path / f"home-center-{STABLE_VERSION}-linux-amd64.tar.gz"
    stable_sidecar = tmp_path / f"{stable_artifact.name}.sha256"
    base = f"https://github.com/{STABLE_REPO}/releases/download/v{STABLE_VERSION}"
    _download(f"{base}/{stable_artifact.name}", stable_artifact)
    _download(f"{base}/{stable_sidecar.name}", stable_sidecar)
    assert _sha256(stable_artifact) == stable_sidecar.read_text(encoding="utf-8").split()[0]

    stable_extract = tmp_path / "stable"
    stable_extract.mkdir()
    _run(["tar", "-xzf", str(stable_artifact), "-C", str(stable_extract)])
    stable_revision = (stable_extract / "REVISION").read_text(encoding="utf-8").strip()
    assert (stable_extract / "VERSION").read_text(encoding="utf-8").strip() == STABLE_VERSION

    candidate_worktree = tmp_path / "candidate-src"
    _run(["git", "worktree", "add", "--detach", str(candidate_worktree), "HEAD"], cwd=ROOT)
    had_user = False
    baseline_release = "/opt/home-center/releases/qualification-systemd-0.56.0"
    state_db = "/var/lib/home-center/qualification-057-systemd.sqlite3"
    transaction_id = "20260912T031000Z-057057057057"
    node_name = socket.gethostname().split(".", 1)[0]
    config = Path("/etc/home-center/config.json")
    credentials = Path("/etc/home-center/local-admin.json")
    session_key = Path("/etc/home-center/session.key")
    audit_key = Path("/etc/home-center/audit.key")
    tls_certificate = Path("/etc/home-center/tls.crt")

    try:
        init_path = candidate_worktree / "product/control-plane/src/home_center/__init__.py"
        init_text = init_path.read_text(encoding="utf-8")
        assert f'__version__ = "{STABLE_VERSION}"' in init_text
        init_path.write_text(
            init_text.replace(f'__version__ = "{STABLE_VERSION}"', f'__version__ = "{CANDIDATE_VERSION}"', 1),
            encoding="utf-8",
        )
        candidate_dist = tmp_path / "candidate-dist"
        _run(["bash", "deploy/scripts/build-deployment-artifact.sh", str(candidate_dist)], cwd=candidate_worktree)
        candidate_artifact = candidate_dist / f"home-center-{CANDIDATE_VERSION}-linux-amd64.tar.gz"
        candidate_digest = Path(f"{candidate_artifact}.sha256").read_text(encoding="utf-8").split()[0]
        assert _sha256(candidate_artifact) == candidate_digest
        candidate_extract = tmp_path / "candidate"
        candidate_extract.mkdir()
        _run(["tar", "-xzf", str(candidate_artifact), "-C", str(candidate_extract)])
        candidate_revision = (candidate_extract / "REVISION").read_text(encoding="utf-8").strip()
        assert candidate_revision == _run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()

        had_user = _run(["id", "-u", "home-center"], check=False).returncode == 0
        for path in (Path("/opt/home-center/current"), Path("/etc/home-center"), Path("/var/lib/home-center")):
            if path.exists() or path.is_symlink():
                pytest.fail(f"unexpected pre-existing Home Center path: {path}")

        _sudo(
            f"""
if ! id -u home-center >/dev/null 2>&1; then useradd --system --user-group --no-create-home home-center; fi
install -d -m 0755 /opt/home-center/releases {baseline_release}
install -d -m 0750 -o home-center -g home-center /var/lib/home-center /var/backups/home-center
install -d -m 0755 /etc/home-center
tar -xzf {stable_artifact} -C {baseline_release}
ln -s {baseline_release} /opt/home-center/current
"""
        )

        _run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
            "-subj", f"/CN={address}", "-addext", f"subjectAltName=IP:{address}",
            "-keyout", str(tmp_path / "tls.key"), "-out", str(tmp_path / "tls.crt"),
        ])
        _run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
            "-subj", "/CN=Home Center qualification web CA",
            "-keyout", str(tmp_path / "web-ca.key"), "-out", str(tmp_path / "web-ca.crt"),
        ])

        material = base64.b64encode(b"q" * 32).decode("ascii")
        staging = tmp_path / "configuration"
        staging.mkdir()
        (staging / "local-admin.json").write_text(json.dumps({
            "schema": "home-center.local-admin-credential.v2", "username": "admin", "kdf": "scrypt",
            "n": 1 << 15, "r": 8, "p": 1, "dklen": 32, "salt_b64": material,
            "verifier_b64": material, "password_change_required": False,
        }, sort_keys=True) + "\n", encoding="utf-8")
        (staging / "session.key").write_bytes(b"s" * 32)
        (staging / "audit.key").write_bytes(b"a" * 32)
        (staging / "profile.json").write_text(json.dumps({
            "schema": "home-center.deployment-profile.v2", "profile_id": "release-057-systemd-qualification",
            "directory_provider": None,
            "nodes": [{"node_id": "node-release-057-systemd", "hostname": None, "endpoint": None,
                       "roles": ["control-plane"], "required_capabilities": ["inventory.v1"]}],
            "placement": {"minimum_ready_nodes": 1, "maximum_nodes": 1, "allow_single_node": True,
                          "require_distinct_failure_domains": False},
        }, sort_keys=True) + "\n", encoding="utf-8")
        (staging / "config.json").write_text(json.dumps({
            "schema": "home-center.config.v5", "cluster_id": "cluster-release-057-systemd",
            "node_id": "node-release-057-systemd", "node_name": "release-057-systemd", "role": "control-plane",
            "management_address": address, "web_port": web_port, "peer_port": peer_port,
            "state_db": state_db, "backup_dir": "/var/backups/home-center", "web_root": "/opt/home-center/current/web",
            "local_admin_credentials_file": "/etc/home-center/local-admin.json",
            "session_key_file": "/etc/home-center/session.key", "audit_key_file": "/etc/home-center/audit.key",
            "tls_certificate": "/etc/home-center/tls.crt", "tls_private_key": "/etc/home-center/tls.key",
            "cluster_ca": "/etc/home-center/tls.crt", "web_ca": "/etc/home-center/web-ca.crt",
            "deployment_profile": "/etc/home-center/deployment-profile.json", "peers": [],
            "reconcile_interval_seconds": 5, "peer_timeout_seconds": 1,
            "ad_auth": {"enabled": False, "realm": "EXAMPLE.TEST", "kdc_hosts": ["dc.example.test"],
                        "allowed_admin_groups": ["Home Center Admins"], "timeout_seconds": 2,
                        "cache_root": "/var/lib/home-center/ad-auth"},
            "external_access": {"enabled": False, "mode": "trusted-reverse-proxy",
                                "public_hostname": None, "trusted_proxy_addresses": []},
        }, sort_keys=True) + "\n", encoding="utf-8")

        _sudo(
            f"""
home_gid=$(getent group home-center | cut -d: -f3)
install -m 0644 -o root -g root {staging / 'config.json'} /etc/home-center/config.json
install -m 0640 -o root -g "$home_gid" {staging / 'local-admin.json'} /etc/home-center/local-admin.json
install -m 0640 -o root -g "$home_gid" {staging / 'session.key'} /etc/home-center/session.key
install -m 0640 -o root -g "$home_gid" {staging / 'audit.key'} /etc/home-center/audit.key
install -m 0644 -o root -g root {staging / 'profile.json'} /etc/home-center/deployment-profile.json
install -m 0644 -o root -g root {tmp_path / 'tls.crt'} /etc/home-center/tls.crt
install -m 0640 -o root -g "$home_gid" {tmp_path / 'tls.key'} /etc/home-center/tls.key
install -m 0644 -o root -g root {tmp_path / 'web-ca.crt'} /etc/home-center/web-ca.crt
install -m 0644 -o root -g root {stable_extract / 'deploy/systemd/home-center.service'} /etc/systemd/system/home-center.service
install -m 0644 -o root -g root {stable_extract / 'deploy/systemd/home-center-backup.service'} /etc/systemd/system/home-center-backup.service
install -m 0644 -o root -g root {stable_extract / 'deploy/systemd/home-center-backup.timer'} /etc/systemd/system/home-center-backup.timer
systemctl daemon-reload
systemctl enable home-center.service home-center-backup.timer >/dev/null
systemctl start home-center.service
"""
        )
        assert _wait_ready(address, web_port, tls_certificate)["node_id"] == "node-release-057-systemd"

        _sudo(f"""python3 - <<'PY'
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
""")
        protected_paths = (config, credentials, session_key, audit_key)
        preserved = {path.name: _root_sha256(path) for path in protected_paths}

        installed = _run([
            "sudo", "bash", str(candidate_extract / "deploy/install-node.sh"),
            "--artifact", str(candidate_artifact), "--sha256", candidate_digest,
            "--node-name", node_name, "--transaction-id", transaction_id,
            "--expected-current-release", baseline_release, "--expected-current-version", STABLE_VERSION,
            "--expected-current-revision", stable_revision,
        ])
        assert "NODE_DEPLOYMENT=PASS" in installed.stdout
        rollback_point = next(line.split("=", 1)[1] for line in installed.stdout.splitlines() if line.startswith("ROLLBACK_POINT="))
        assert _run(["sudo", "cat", "/opt/home-center/current/VERSION"]).stdout.strip() == CANDIDATE_VERSION
        assert _run(["sudo", "systemctl", "is-active", "home-center.service"]).stdout.strip() == "active"
        assert _wait_ready(address, web_port, tls_certificate)["status"] == "ready"
        assert _state_value(state_db) == "stable-user-state"
        assert preserved == {path.name: _root_sha256(path) for path in protected_paths}

        rolled_back = _run([
            "sudo", "bash", str(candidate_extract / "deploy/rollback-node.sh"), "--rollback-point", rollback_point,
        ])
        assert "NODE_ROLLBACK=PASS" in rolled_back.stdout
        assert _run(["sudo", "cat", "/opt/home-center/current/VERSION"]).stdout.strip() == STABLE_VERSION
        assert _run(["sudo", "systemctl", "is-active", "home-center.service"]).stdout.strip() == "active"
        assert _wait_ready(address, web_port, tls_certificate)["status"] == "ready"
        assert _state_value(state_db) == "stable-user-state"
        assert preserved == {path.name: _root_sha256(path) for path in protected_paths}
    finally:
        _run(["git", "worktree", "remove", "--force", str(candidate_worktree)], cwd=ROOT, check=False)
        _run(["sudo", "systemctl", "disable", "--now", "home-center-backup.timer"], check=False)
        _run(["sudo", "systemctl", "disable", "--now", "home-center.service"], check=False)
        _run(["sudo", "systemctl", "stop", "home-center-backup.service"], check=False)
        _sudo("""
rm -f /etc/systemd/system/home-center.service /etc/systemd/system/home-center-backup.service /etc/systemd/system/home-center-backup.timer
systemctl daemon-reload || true
rm -rf /opt/home-center /etc/home-center /var/lib/home-center /var/lib/home-center-deploy
rm -rf /var/backups/home-center /var/backups/home-center-deploy /run/home-center-locks
""")
        if not had_user:
            _run(["sudo", "userdel", "home-center"], check=False)
