from __future__ import annotations

import hashlib
import io
import os
import socket
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy/scripts/install-node.sh"
ROLLBACK = ROOT / "deploy/scripts/rollback-node.sh"


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def _installer_args(artifact: Path, digest: str, *, node_name: str | None = None) -> list[str]:
    return [
        "sudo",
        "bash",
        str(INSTALLER),
        "--artifact",
        str(artifact),
        "--sha256",
        digest,
        "--node-name",
        node_name or socket.gethostname().split(".", 1)[0],
        "--transaction-id",
        "20260912T034700Z-057057057057",
        "--expected-current-release",
        "/opt/home-center/releases/security-boundary-baseline",
        "--expected-current-version",
        "0.56.0",
        "--expected-current-revision",
        "a" * 40,
    ]


def test_install_and_rollback_keep_protected_credentials_outside_release_mutation_scope() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")
    rollback = ROLLBACK.read_text(encoding="utf-8")

    # Upgrade/rollback may read config to discover the state database, but the
    # local-admin verifier and session/audit keys are outside release mutation.
    for protected_name in ("local-admin.json", "session.key", "audit.key"):
        assert protected_name not in installer
        assert protected_name not in rollback

    assert installer.count("/etc/home-center/config.json") == 1
    assert "p=Path('/etc/home-center/config.json')" in installer
    assert "umask 077" in installer
    assert "umask 077" in rollback
    assert 'install -d -m 0700 -o root -g root "$BACKUP" "$TRANSACTION_DIR"' in installer
    assert "os.chmod(tmp,0o600)" in installer


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="privileged installer fail-closed qualification runs once on the hosted Python 3.12 leg",
)
def test_install_node_rejects_checksum_mismatch_before_any_release_switch(tmp_path: Path) -> None:
    artifact = tmp_path / "candidate.tar.gz"
    artifact.write_bytes(b"not-a-release-artifact")

    completed = _run(_installer_args(artifact, "0" * 64))

    assert completed.returncode == 66
    assert "ARTIFACT_CHECKSUM_MISMATCH" in completed.stderr
    assert "NODE_DEPLOYMENT=PASS" not in completed.stdout


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="privileged installer fail-closed qualification runs once on the hosted Python 3.12 leg",
)
def test_install_node_rejects_path_traversal_archive_before_current_release_access(tmp_path: Path) -> None:
    artifact = tmp_path / "path-traversal.tar.gz"
    payload = b"escape"
    with tarfile.open(artifact, "w:gz") as archive:
        member = tarfile.TarInfo("../escape")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

    completed = _run(_installer_args(artifact, digest))

    assert completed.returncode == 66
    assert "UNSAFE_ARCHIVE_PATH" in completed.stderr
    assert "NODE_DEPLOYMENT=PASS" not in completed.stdout
    assert not (tmp_path.parent / "escape").exists()


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="privileged installer fail-closed qualification runs once on the hosted Python 3.12 leg",
)
@pytest.mark.parametrize(
    ("member_type", "link_name"),
    [
        (tarfile.SYMTYPE, "/etc/passwd"),
        (tarfile.LNKTYPE, "../escape"),
        (tarfile.FIFOTYPE, ""),
    ],
)
def test_install_node_rejects_non_regular_archive_entries_before_extraction(
    tmp_path: Path,
    member_type: bytes,
    link_name: str,
) -> None:
    artifact = tmp_path / "unsafe-entry.tar.gz"
    with tarfile.open(artifact, "w:gz") as archive:
        member = tarfile.TarInfo("./deploy/home-center.service")
        member.type = member_type
        member.linkname = link_name
        archive.addfile(member)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

    completed = _run(_installer_args(artifact, digest))

    assert completed.returncode == 66
    assert "UNSAFE_ARCHIVE_ENTRY_TYPE" in completed.stderr
    assert "NODE_DEPLOYMENT=PASS" not in completed.stdout


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="privileged installer fail-closed qualification runs once on the hosted Python 3.12 leg",
)
def test_install_node_rejects_wrong_node_identity_before_checksum_or_mutation(tmp_path: Path) -> None:
    artifact = tmp_path / "candidate.tar.gz"
    artifact.write_bytes(b"identity-boundary")
    actual = socket.gethostname().split(".", 1)[0]
    wrong = "definitely-not-this-runner"
    assert wrong != actual

    completed = _run(_installer_args(artifact, "0" * 64, node_name=wrong))

    assert completed.returncode == 65
    assert "NODE_IDENTITY_MISMATCH" in completed.stderr
    assert "ARTIFACT_CHECKSUM_MISMATCH" not in completed.stderr
    assert "NODE_DEPLOYMENT=PASS" not in completed.stdout
