from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy/scripts/install-node.sh"
BASELINE_RELEASE = Path("/opt/home-center/releases/qualification-replay-integrity-baseline")
BASELINE_VERSION = "0.55.0"
BASELINE_REVISION = "b" * 40
CURRENT = Path("/opt/home-center/current")
CONFIG = Path("/etc/home-center/config.json")


def _run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=check)


def _sudo(script: str) -> subprocess.CompletedProcess[str]:
    return _run(["sudo", "bash", "-ceu", script])


@pytest.fixture(scope="module")
def candidate_artifact(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str, str, str]:
    out = tmp_path_factory.mktemp("hc057-replay-integrity")
    built = _run(["bash", "deploy/scripts/build-deployment-artifact.sh", str(out)], check=True)
    artifact_line = next(line for line in built.stdout.splitlines() if line.startswith("DEPLOYMENT_ARTIFACT="))
    artifact = Path(artifact_line.split("=", 1)[1])
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    with tarfile.open(artifact, "r:gz") as archive:
        version_member = archive.extractfile("./VERSION")
        revision_member = archive.extractfile("./REVISION")
        assert version_member is not None and revision_member is not None
        version = version_member.read().decode("utf-8").strip()
        revision = revision_member.read().decode("utf-8").strip()
    assert len(revision) == 40
    return artifact, digest, version, revision


def _prepare_baseline() -> None:
    _sudo(
        f"""
install -d -m 0755 /opt/home-center/releases /etc/home-center /var/backups/home-center-deploy /var/lib/home-center-deploy/transactions
rm -rf {BASELINE_RELEASE}
install -d -m 0755 {BASELINE_RELEASE}
printf '%s\n' {BASELINE_VERSION!r} > {BASELINE_RELEASE}/VERSION
printf '%s\n' {BASELINE_REVISION!r} > {BASELINE_RELEASE}/REVISION
rm -f {CURRENT} /opt/home-center/.current.new /opt/home-center/.current.rollback
ln -s {BASELINE_RELEASE} {CURRENT}
printf '%s\n' '{{"state_db":"/var/lib/home-center/nonexistent-replay-integrity.sqlite3"}}' > {CONFIG}
chmod 0644 {CONFIG}
"""
    )


def _cleanup(target_release: Path, transaction_id: str, node_name: str) -> None:
    _sudo(
        f"""
rm -f {CURRENT} /opt/home-center/.current.new /opt/home-center/.current.rollback
rm -rf {BASELINE_RELEASE} {target_release}
rm -rf /var/backups/home-center-deploy/{transaction_id}-{node_name}
rm -f /var/lib/home-center-deploy/transactions/{transaction_id}-{node_name}.json
rm -f {CONFIG}
"""
    )


def _installer_args(
    artifact: Path,
    digest: str,
    transaction_id: str,
    node_name: str,
) -> list[str]:
    return [
        "sudo",
        "bash",
        str(INSTALLER),
        "--artifact",
        str(artifact),
        "--sha256",
        digest,
        "--node-name",
        node_name,
        "--transaction-id",
        transaction_id,
        "--expected-current-release",
        str(BASELINE_RELEASE),
        "--expected-current-version",
        BASELINE_VERSION,
        "--expected-current-revision",
        BASELINE_REVISION,
    ]


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="privileged replay/integrity qualification runs once on the hosted Python 3.12 leg",
)
def test_install_node_rejects_corrupted_preexisting_target_release(
    candidate_artifact: tuple[Path, str, str, str],
) -> None:
    artifact, digest, version, revision = candidate_artifact
    node_name = socket.gethostname().split(".", 1)[0]
    transaction_id = "20260912T061200Z-a1b2c3d4e5f6"
    target_release = Path(f"/opt/home-center/releases/{version}-{revision[:12]}-{digest[:12]}")
    _prepare_baseline()
    try:
        _sudo(
            f"""
rm -rf {target_release}
install -d -m 0755 {target_release}
tar -xzf {artifact} -C {target_release}
printf '\n# qualification tamper\n' >> {target_release}/run.py
"""
        )
        completed = _run(
            _installer_args(artifact, digest, transaction_id, node_name),
            check=False,
        )
        assert completed.returncode == 66
        assert "TARGET_RELEASE_MANIFEST_MISMATCH" in completed.stderr
        assert "NODE_DEPLOYMENT=PASS" not in completed.stdout
        assert _run(["sudo", "readlink", "-f", str(CURRENT)]).stdout.strip() == str(BASELINE_RELEASE)
    finally:
        _cleanup(target_release, transaction_id, node_name)


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="privileged replay/integrity qualification runs once on the hosted Python 3.12 leg",
)
def test_install_node_rejects_reused_transaction_identity_before_mutation(
    candidate_artifact: tuple[Path, str, str, str],
) -> None:
    artifact, digest, version, revision = candidate_artifact
    node_name = socket.gethostname().split(".", 1)[0]
    transaction_id = "20260912T061201Z-f6e5d4c3b2a1"
    target_release = Path(f"/opt/home-center/releases/{version}-{revision[:12]}-{digest[:12]}")
    backup = Path(f"/var/backups/home-center-deploy/{transaction_id}-{node_name}")
    _prepare_baseline()
    try:
        _sudo(f"install -d -m 0700 {backup}")
        completed = _run(
            _installer_args(artifact, digest, transaction_id, node_name),
            check=False,
        )
        assert completed.returncode == 66
        assert "TRANSACTION_ID_ALREADY_USED" in completed.stderr
        assert "NODE_DEPLOYMENT=PASS" not in completed.stdout
        assert _run(["sudo", "readlink", "-f", str(CURRENT)]).stdout.strip() == str(BASELINE_RELEASE)
        assert not target_release.exists()
    finally:
        _cleanup(target_release, transaction_id, node_name)
