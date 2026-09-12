from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "07e537f415267b010f049ba694a9382a57a3f7fb"
SOURCE_VERSION = "0.56.0"
BASELINE_VERSION = "0.57.0"
CANDIDATE_VERSION = "0.58.0"


def _load_057_helpers():
    path = ROOT / "tests/test_release_057_hosted_systemd_upgrade.py"
    spec = importlib.util.spec_from_file_location("hc_release_057_systemd_helpers", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H057 = _load_057_helpers()


def _run(args: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=check)


def _sudo(script: str) -> subprocess.CompletedProcess[str]:
    return _run(["sudo", "bash", "-ceu", script])


def _build_versioned_artifact(worktree: Path, version: str, output: Path) -> tuple[Path, str, str]:
    init_path = worktree / "product/control-plane/src/home_center/__init__.py"
    init_text = init_path.read_text(encoding="utf-8")
    source_marker = f'__version__ = "{SOURCE_VERSION}"'
    assert source_marker in init_text
    init_path.write_text(init_text.replace(source_marker, f'__version__ = "{version}"', 1), encoding="utf-8")
    _run(["bash", "deploy/scripts/build-deployment-artifact.sh", str(output)], cwd=worktree)
    artifact = output / f"home-center-{version}-linux-amd64.tar.gz"
    digest = Path(f"{artifact}.sha256").read_text(encoding="ascii").split()[0]
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == digest
    revision = _run(["git", "rev-parse", "HEAD"], cwd=worktree).stdout.strip()
    return artifact, digest, revision


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="real systemd 0.57 -> 0.58 qualification runs once on the hosted Python 3.12 leg",
)
def test_release_058_real_systemd_upgrade_health_and_rollback(tmp_path: Path) -> None:
    """Qualify the exact 0.57 -> 0.58 install/health/rollback path under real systemd."""

    H057._assert_systemd_manager()
    address = H057._host_address()
    web_port = H057._free_port(address)
    peer_port = H057._free_port(address)
    while peer_port == web_port:
        peer_port = H057._free_port(address)

    baseline_worktree = tmp_path / "baseline-src"
    candidate_worktree = tmp_path / "candidate-src"
    _run(["git", "worktree", "add", "--detach", str(baseline_worktree), BASE_SHA], cwd=ROOT)
    _run(["git", "worktree", "add", "--detach", str(candidate_worktree), "HEAD"], cwd=ROOT)

    baseline_release = "/opt/home-center/releases/qualification-systemd-0.57.0-for-058"
    state_db = "/var/lib/home-center/qualification-058-systemd.sqlite3"
    transaction_id = "20260912T085000Z-058058058058"
    node_name = socket.gethostname().split(".", 1)[0]
    config = Path("/etc/home-center/config.json")
    credentials = Path("/etc/home-center/local-admin.json")
    session_key = Path("/etc/home-center/session.key")
    audit_key = Path("/etc/home-center/audit.key")
    tls_certificate = Path("/etc/home-center/tls.crt")
    had_user = _run(["id", "-u", "home-center"], check=False).returncode == 0

    try:
        baseline_artifact, _, baseline_revision = _build_versioned_artifact(
            baseline_worktree, BASELINE_VERSION, tmp_path / "baseline-dist"
        )
        candidate_artifact, candidate_digest, candidate_revision = _build_versioned_artifact(
            candidate_worktree, CANDIDATE_VERSION, tmp_path / "candidate-dist"
        )
        assert baseline_revision == BASE_SHA
        assert candidate_revision == _run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()

        baseline_extract = tmp_path / "baseline"
        candidate_extract = tmp_path / "candidate"
        baseline_extract.mkdir()
        candidate_extract.mkdir()
        _run(["tar", "-xzf", str(baseline_artifact), "-C", str(baseline_extract)])
        _run(["tar", "-xzf", str(candidate_artifact), "-C", str(candidate_extract)])
        assert (baseline_extract / "VERSION").read_text(encoding="ascii").strip() == BASELINE_VERSION
        assert (candidate_extract / "VERSION").read_text(encoding="ascii").strip() == CANDIDATE_VERSION
        assert (candidate_extract / "home_center/device_management_enrollment_verification.py").is_file()
        assert (candidate_extract / "home_center/device_management_deenrollment.py").is_file()

        for path in (Path("/opt/home-center/current"), Path("/etc/home-center"), Path("/var/lib/home-center")):
            if path.exists() or path.is_symlink():
                pytest.fail(f"unexpected pre-existing Home Center path: {path}")

        _sudo(
            f"""
if ! id -u home-center >/dev/null 2>&1; then useradd --system --user-group --no-create-home home-center; fi
install -d -m 0755 /opt/home-center/releases {baseline_release}
install -d -m 0750 -o home-center -g home-center /var/lib/home-center /var/backups/home-center
install -d -m 0755 /etc/home-center
tar -xzf {baseline_artifact} -C {baseline_release}
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
            "-subj", "/CN=Home Center 0.58 qualification web CA",
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
            "schema": "home-center.deployment-profile.v2", "profile_id": "release-058-systemd-qualification",
            "directory_provider": None,
            "nodes": [{"node_id": "node-release-058-systemd", "hostname": None, "endpoint": None,
                       "roles": ["control-plane"], "required_capabilities": ["inventory.v1"]}],
            "placement": {"minimum_ready_nodes": 1, "maximum_nodes": 1, "allow_single_node": True,
                          "require_distinct_failure_domains": False},
        }, sort_keys=True) + "\n", encoding="utf-8")
        (staging / "config.json").write_text(json.dumps({
            "schema": "home-center.config.v5", "cluster_id": "cluster-release-058-systemd",
            "node_id": "node-release-058-systemd", "node_name": "release-058-systemd", "role": "control-plane",
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
install -m 0644 -o root -g root {baseline_extract / 'deploy/systemd/home-center.service'} /etc/systemd/system/home-center.service
install -m 0644 -o root -g root {baseline_extract / 'deploy/systemd/home-center-backup.service'} /etc/systemd/system/home-center-backup.service
install -m 0644 -o root -g root {baseline_extract / 'deploy/systemd/home-center-backup.timer'} /etc/systemd/system/home-center-backup.timer
systemctl daemon-reload
systemctl enable home-center.service home-center-backup.timer >/dev/null
systemctl start home-center.service
"""
        )
        assert H057._wait_ready(address, web_port, tls_certificate)["node_id"] == "node-release-058-systemd"
        assert _run(["sudo", "systemctl", "is-enabled", "home-center-backup.timer"]).stdout.strip() == "enabled"

        _sudo(f"""python3 - <<'PY'
import sqlite3
con = sqlite3.connect({state_db!r}, timeout=10)
try:
    con.execute("CREATE TABLE IF NOT EXISTS qualification_systemd (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
    con.execute("INSERT OR REPLACE INTO qualification_systemd(k,v) VALUES ('sentinel','user-state-057')")
    con.commit()
finally:
    con.close()
PY
chown home-center:home-center {state_db}
chmod 0640 {state_db}
""")
        protected_paths = (config, credentials, session_key, audit_key)
        preserved = {path.name: H057._root_sha256(path) for path in protected_paths}

        installed = _run([
            "sudo", "bash", str(candidate_extract / "deploy/install-node.sh"),
            "--artifact", str(candidate_artifact), "--sha256", candidate_digest,
            "--node-name", node_name, "--transaction-id", transaction_id,
            "--expected-current-release", baseline_release, "--expected-current-version", BASELINE_VERSION,
            "--expected-current-revision", baseline_revision,
        ])
        assert "NODE_DEPLOYMENT=PASS" in installed.stdout
        rollback_point = next(line.split("=", 1)[1] for line in installed.stdout.splitlines() if line.startswith("ROLLBACK_POINT="))
        assert _run(["sudo", "cat", "/opt/home-center/current/VERSION"]).stdout.strip() == CANDIDATE_VERSION
        assert _run(["sudo", "cat", "/opt/home-center/current/REVISION"]).stdout.strip() == candidate_revision
        assert _run(["sudo", "systemctl", "is-active", "home-center.service"]).stdout.strip() == "active"
        assert _run(["sudo", "systemctl", "is-enabled", "home-center-backup.timer"]).stdout.strip() == "enabled"
        assert H057._wait_ready(address, web_port, tls_certificate)["status"] == "ready"
        assert H057._state_value(state_db) == "user-state-057"
        assert preserved == {path.name: H057._root_sha256(path) for path in protected_paths}

        rolled_back = _run([
            "sudo", "bash", str(candidate_extract / "deploy/rollback-node.sh"), "--rollback-point", rollback_point,
        ])
        assert "NODE_ROLLBACK=PASS" in rolled_back.stdout
        assert _run(["sudo", "cat", "/opt/home-center/current/VERSION"]).stdout.strip() == BASELINE_VERSION
        assert _run(["sudo", "cat", "/opt/home-center/current/REVISION"]).stdout.strip() == baseline_revision
        assert _run(["sudo", "systemctl", "is-active", "home-center.service"]).stdout.strip() == "active"
        assert _run(["sudo", "systemctl", "is-enabled", "home-center-backup.timer"]).stdout.strip() == "enabled"
        assert H057._wait_ready(address, web_port, tls_certificate)["status"] == "ready"
        assert H057._state_value(state_db) == "user-state-057"
        assert preserved == {path.name: H057._root_sha256(path) for path in protected_paths}
    finally:
        for worktree in (baseline_worktree, candidate_worktree):
            if worktree.exists():
                _run(["git", "worktree", "remove", "--force", str(worktree)], cwd=ROOT, check=False)
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
