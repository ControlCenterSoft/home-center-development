from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
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
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


def _download(url: str, target: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "home-center-release-qualification/0.57"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        target.write_bytes(response.read())


def _sudo_shell(script: str) -> subprocess.CompletedProcess[str]:
    return _run(["sudo", "bash", "-ceu", script])


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="hosted deployment drill runs once on the GitHub Actions Python 3.12 leg",
)
def test_release_057_hosted_upgrade_and_rollback_from_public_stable(tmp_path: Path) -> None:
    """Exercise the real deployment scripts against the public 0.56.0 artifact.

    systemctl itself is replaced by a deterministic shim so this hosted drill
    validates package identity, checksum enforcement, state/config preservation,
    release switching, rollback-point creation and restoration without relying on
    a nested systemd service manager in the GitHub-hosted runner.
    """

    stable_artifact = tmp_path / f"home-center-{STABLE_VERSION}-linux-amd64.tar.gz"
    stable_sidecar = tmp_path / f"{stable_artifact.name}.sha256"
    release_base = f"https://github.com/{STABLE_REPO}/releases/download/v{STABLE_VERSION}"
    _download(f"{release_base}/{stable_artifact.name}", stable_artifact)
    _download(f"{release_base}/{stable_sidecar.name}", stable_sidecar)

    expected_digest = stable_sidecar.read_text(encoding="utf-8").split()[0]
    actual_digest = hashlib.sha256(stable_artifact.read_bytes()).hexdigest()
    assert actual_digest == expected_digest

    stable_extract = tmp_path / "stable"
    stable_extract.mkdir()
    _run(["tar", "-xzf", str(stable_artifact), "-C", str(stable_extract)])
    stable_revision = (stable_extract / "REVISION").read_text(encoding="utf-8").strip()
    assert (stable_extract / "VERSION").read_text(encoding="utf-8").strip() == STABLE_VERSION
    assert len(stable_revision) == 40

    candidate_worktree = tmp_path / "candidate-src"
    _run(["git", "worktree", "add", "--detach", str(candidate_worktree), "HEAD"], cwd=ROOT)
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
        assert hashlib.sha256(candidate_artifact.read_bytes()).hexdigest() == candidate_digest

        candidate_extract = tmp_path / "candidate"
        candidate_extract.mkdir()
        _run(["tar", "-xzf", str(candidate_artifact), "-C", str(candidate_extract)])
        candidate_revision = (candidate_extract / "REVISION").read_text(encoding="utf-8").strip()
        assert (candidate_extract / "VERSION").read_text(encoding="utf-8").strip() == CANDIDATE_VERSION
        assert candidate_revision == _run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()

        fake_bin = tmp_path / "fake-bin"
        fake_bin.mkdir()
        fake_systemctl = fake_bin / "systemctl"
        fake_systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            "case \"${1:-}\" in\n"
            "  is-active) exit 0 ;;\n"
            "  stop|start|daemon-reload|enable) exit 0 ;;\n"
            "  *) exit 0 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        fake_systemctl.chmod(0o755)

        baseline_release = "/opt/home-center/releases/qualification-0.56.0"
        state_db = "/var/lib/home-center/qualification-057-state.sqlite3"
        config_path = "/etc/home-center/config.json"
        transaction_id = "20260912T010000Z-057057057057"
        node_name = socket.gethostname().split(".", 1)[0]
        had_user = subprocess.run(
            ["id", "-u", "home-center"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0

        setup_script = f"""
if ! id -u home-center >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home home-center
fi
rm -rf {baseline_release}
install -d -m 0755 {baseline_release}
tar -xzf {stable_artifact} -C {baseline_release}
install -d -m 0755 /opt/home-center /var/lib/home-center /etc/home-center
rm -f /opt/home-center/current /opt/home-center/.current.new /opt/home-center/.current.rollback
ln -s {baseline_release} /opt/home-center/current
cat > {config_path} <<'JSON'
{{"state_db":"{state_db}","qualification_marker":"preserve-me","bootstrap_password_changed":true}}
JSON
chown root:root {config_path}
chmod 0644 {config_path}
python3 - <<'PY2'
import sqlite3
path = {state_db!r}
con = sqlite3.connect(path)
try:
    con.execute("CREATE TABLE IF NOT EXISTS qualification (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
    con.execute("INSERT OR REPLACE INTO qualification(k,v) VALUES ('sentinel','stable-user-state')")
    con.commit()
finally:
    con.close()
PY2
chown home-center:home-center {state_db}
chmod 0640 {state_db}
rm -rf /var/backups/home-center-deploy/{transaction_id}-{node_name}
rm -f /var/lib/home-center-deploy/transactions/{transaction_id}-{node_name}.json
"""
        _sudo_shell(setup_script)
        config_before = _run(["sudo", "sha256sum", config_path]).stdout.split()[0]

        installed = _run(
            [
                "sudo",
                "env",
                f"PATH={fake_bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
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
        assert _run(["sudo", "sha256sum", config_path]).stdout.split()[0] == config_before

        state_value = _sudo_shell(
            f"""python3 - <<'PY2'
import sqlite3
con = sqlite3.connect({state_db!r})
try:
    print(con.execute("SELECT v FROM qualification WHERE k='sentinel'").fetchone()[0])
finally:
    con.close()
PY2"""
        ).stdout.strip()
        assert state_value == "stable-user-state"

        backup_value = _sudo_shell(
            f"""python3 - <<'PY2'
import sqlite3
con = sqlite3.connect({(rollback_point + '/state.sqlite3')!r})
try:
    print(con.execute("SELECT v FROM qualification WHERE k='sentinel'").fetchone()[0])
finally:
    con.close()
PY2"""
        ).stdout.strip()
        assert backup_value == "stable-user-state"

        rolled_back = _run(
            [
                "sudo",
                "env",
                f"PATH={fake_bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "bash",
                str(candidate_extract / "deploy/rollback-node.sh"),
                "--rollback-point",
                rollback_point,
            ]
        )
        assert "NODE_ROLLBACK=PASS" in rolled_back.stdout
        assert _run(["sudo", "readlink", "-f", "/opt/home-center/current"]).stdout.strip() == baseline_release
        assert _run(["sudo", "cat", "/opt/home-center/current/VERSION"]).stdout.strip() == STABLE_VERSION
        rollback_state = _sudo_shell(
            f"""python3 - <<'PY2'
import sqlite3
con = sqlite3.connect({state_db!r})
try:
    print(con.execute("SELECT v FROM qualification WHERE k='sentinel'").fetchone()[0])
finally:
    con.close()
PY2"""
        ).stdout.strip()
        assert rollback_state == "stable-user-state"
        assert _run(["sudo", "sha256sum", config_path]).stdout.split()[0] == config_before
    finally:
        _run(["git", "worktree", "remove", "--force", str(candidate_worktree)], cwd=ROOT)
        try:
            _sudo_shell(
                """
rm -f /opt/home-center/current /opt/home-center/.current.new /opt/home-center/.current.rollback
rm -rf /opt/home-center/releases/qualification-0.56.0
find /opt/home-center/releases -maxdepth 1 -type d -name '0.57.0-*' -exec rm -rf {} + 2>/dev/null || true
rm -f /var/lib/home-center/qualification-057-state.sqlite3*
rm -f /etc/home-center/config.json
rm -f /etc/systemd/system/home-center.service /etc/systemd/system/home-center-backup.service /etc/systemd/system/home-center-backup.timer
rm -rf /var/backups/home-center-deploy/20260912T010000Z-057057057057-*
rm -f /var/lib/home-center-deploy/transactions/20260912T010000Z-057057057057-*.json
"""
            )
        finally:
            if "had_user" in locals() and not had_user:
                subprocess.run(
                    ["sudo", "userdel", "home-center"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
