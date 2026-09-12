from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "60f4c34f82a8335f9eec36bf2c303bb382efdca6"
SOURCE_VERSION = "0.57.0"
BASELINE_VERSION = "0.57.0"
CANDIDATE_VERSION = "0.58.0"


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


def _build_versioned_artifact(worktree: Path, version: str, output: Path) -> tuple[Path, str, str]:
    init_path = worktree / "product/control-plane/src/home_center/__init__.py"
    init_text = init_path.read_text(encoding="utf-8")
    source_marker = f'__version__ = "{SOURCE_VERSION}"'
    assert source_marker in init_text
    init_path.write_text(init_text.replace(source_marker, f'__version__ = "{version}"', 1), encoding="utf-8")

    _run(["bash", "deploy/scripts/build-deployment-artifact.sh", str(output)], cwd=worktree)
    artifact = output / f"home-center-{version}-linux-amd64.tar.gz"
    sidecar = Path(f"{artifact}.sha256")
    digest = sidecar.read_text(encoding="ascii").split()[0]
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == digest
    revision = _run(["git", "rev-parse", "HEAD"], cwd=worktree).stdout.strip()
    return artifact, digest, revision


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="0.57 -> 0.58 hosted upgrade/rollback drill runs once on the Python 3.12 leg",
)
def test_release_058_hosted_upgrade_from_057_and_rollback(tmp_path: Path) -> None:
    """Exercise the exact 0.58 node artifact from the qualified 0.57 base.

    This is deliberately a filesystem/service-manager-shim qualification.  The
    existing 0.57 lane already owns the real-systemd Stable 0.56 -> 0.57 drill;
    this test adds only the non-duplicate 0.57 -> 0.58 install/rollback boundary.
    """

    baseline_worktree = tmp_path / "baseline-src"
    candidate_worktree = tmp_path / "candidate-src"
    _run(["git", "worktree", "add", "--detach", str(baseline_worktree), BASE_SHA], cwd=ROOT)
    _run(["git", "worktree", "add", "--detach", str(candidate_worktree), "HEAD"], cwd=ROOT)

    baseline_release = "/opt/home-center/releases/qualification-0.57.0-for-058"
    state_db = "/var/lib/home-center/qualification-058-upgrade-state.sqlite3"
    config_path = "/etc/home-center/config.json"
    transaction_id = "20260912T084000Z-058058058058"
    node_name = socket.gethostname().split(".", 1)[0]
    had_user = _run(["id", "-u", "home-center"], check=False).returncode == 0

    try:
        baseline_artifact, _, baseline_revision = _build_versioned_artifact(
            baseline_worktree,
            BASELINE_VERSION,
            tmp_path / "baseline-dist",
        )
        candidate_artifact, candidate_digest, candidate_revision = _build_versioned_artifact(
            candidate_worktree,
            CANDIDATE_VERSION,
            tmp_path / "candidate-dist",
        )
        assert baseline_revision == BASE_SHA
        assert candidate_revision == _run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()

        candidate_extract = tmp_path / "candidate"
        candidate_extract.mkdir()
        _run(["tar", "-xzf", str(candidate_artifact), "-C", str(candidate_extract)])
        assert (candidate_extract / "VERSION").read_text(encoding="ascii").strip() == CANDIDATE_VERSION
        assert (candidate_extract / "REVISION").read_text(encoding="ascii").strip() == candidate_revision
        assert (candidate_extract / "home_center/device_management_enrollment_verification.py").is_file()
        assert (candidate_extract / "home_center/device_management_deenrollment.py").is_file()
        assert (
            candidate_extract
            / "contracts/devices/device-management-enrollment-post-condition-verification-receipt.v1.schema.json"
        ).is_file()
        assert (
            candidate_extract
            / "contracts/devices/device-management-deenrollment-verification-receipt.v1.schema.json"
        ).is_file()

        fake_bin = tmp_path / "fake-bin"
        fake_bin.mkdir()
        fake_systemctl = fake_bin / "systemctl"
        fake_systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            "case \"${1:-}\" in\n"
            "  is-active|is-enabled) exit 0 ;;\n"
            "  stop|start|restart|daemon-reload|enable|disable) exit 0 ;;\n"
            "  *) exit 0 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        fake_systemctl.chmod(0o755)
        fake_path = f"{fake_bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

        _sudo(
            f"""
if ! id -u home-center >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home home-center
fi
rm -rf {baseline_release}
install -d -m 0755 {baseline_release} /opt/home-center/releases /var/lib/home-center /etc/home-center
tar -xzf {baseline_artifact} -C {baseline_release}
rm -f /opt/home-center/current /opt/home-center/.current.new /opt/home-center/.current.rollback
ln -s {baseline_release} /opt/home-center/current
cat > {config_path} <<'JSON'
{{"state_db":"{state_db}","qualification_marker":"preserve-058","bootstrap_password_changed":true}}
JSON
chown root:root {config_path}
chmod 0644 {config_path}
python3 - <<'PY'
import sqlite3
path = {state_db!r}
con = sqlite3.connect(path)
try:
    con.execute("CREATE TABLE IF NOT EXISTS qualification_058 (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
    con.execute("INSERT OR REPLACE INTO qualification_058(k,v) VALUES ('sentinel','user-state-057')")
    con.commit()
finally:
    con.close()
PY
chown home-center:home-center {state_db}
chmod 0640 {state_db}
rm -rf /var/backups/home-center-deploy/{transaction_id}-{node_name}
rm -f /var/lib/home-center-deploy/transactions/{transaction_id}-{node_name}.json
"""
        )
        config_before = _run(["sudo", "sha256sum", config_path]).stdout.split()[0]

        installed = _run(
            [
                "sudo",
                "env",
                f"PATH={fake_path}",
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
                BASELINE_VERSION,
                "--expected-current-revision",
                baseline_revision,
            ]
        )
        assert "NODE_DEPLOYMENT=PASS" in installed.stdout
        rollback_point = next(
            line.split("=", 1)[1]
            for line in installed.stdout.splitlines()
            if line.startswith("ROLLBACK_POINT=")
        )
        target_release = _run(["sudo", "readlink", "-f", "/opt/home-center/current"]).stdout.strip()
        assert _run(["sudo", "cat", f"{target_release}/VERSION"]).stdout.strip() == CANDIDATE_VERSION
        assert _run(["sudo", "cat", f"{target_release}/REVISION"]).stdout.strip() == candidate_revision
        assert _run(["sudo", "test", "-f", f"{target_release}/home_center/device_management_enrollment_verification.py"]).returncode == 0
        assert _run(["sudo", "test", "-f", f"{target_release}/home_center/device_management_deenrollment.py"]).returncode == 0
        assert _run(["sudo", "sha256sum", config_path]).stdout.split()[0] == config_before

        state_value = _sudo(
            f"""python3 - <<'PY'
import sqlite3
con = sqlite3.connect({state_db!r})
try:
    print(con.execute("SELECT v FROM qualification_058 WHERE k='sentinel'").fetchone()[0])
finally:
    con.close()
PY"""
        ).stdout.strip()
        assert state_value == "user-state-057"

        rolled_back = _run(
            [
                "sudo",
                "env",
                f"PATH={fake_path}",
                "bash",
                str(candidate_extract / "deploy/rollback-node.sh"),
                "--rollback-point",
                rollback_point,
            ]
        )
        assert "NODE_ROLLBACK=PASS" in rolled_back.stdout
        assert _run(["sudo", "readlink", "-f", "/opt/home-center/current"]).stdout.strip() == baseline_release
        assert _run(["sudo", "cat", "/opt/home-center/current/VERSION"]).stdout.strip() == BASELINE_VERSION
        assert _run(["sudo", "cat", "/opt/home-center/current/REVISION"]).stdout.strip() == baseline_revision
        assert _run(["sudo", "sha256sum", config_path]).stdout.split()[0] == config_before
        assert _sudo(
            f"""python3 - <<'PY'
import sqlite3
con = sqlite3.connect({state_db!r})
try:
    print(con.execute("SELECT v FROM qualification_058 WHERE k='sentinel'").fetchone()[0])
finally:
    con.close()
PY"""
        ).stdout.strip() == "user-state-057"
    finally:
        for worktree in (baseline_worktree, candidate_worktree):
            if worktree.exists():
                _run(["git", "worktree", "remove", "--force", str(worktree)], cwd=ROOT, check=False)
        _sudo(
            f"""
rm -f /opt/home-center/current /opt/home-center/.current.new /opt/home-center/.current.rollback
rm -rf {baseline_release}
find /opt/home-center/releases -maxdepth 1 -type d -name '0.58.0-*' -exec rm -rf {{}} + 2>/dev/null || true
rm -f {state_db} {state_db}-wal {state_db}-shm {config_path}
rm -rf /var/backups/home-center-deploy/{transaction_id}-{node_name}
rm -f /var/lib/home-center-deploy/transactions/{transaction_id}-{node_name}.json
rm -f /etc/systemd/system/home-center.service /etc/systemd/system/home-center-backup.service /etc/systemd/system/home-center-backup.timer
"""
        )
        if not had_user:
            _run(["sudo", "userdel", "home-center"], check=False)
