from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_058_keeps_latest_057_installer_archive_safety_boundary() -> None:
    installer = (ROOT / "deploy/scripts/install-node.sh").read_text(encoding="utf-8")

    # 0.58 must not regress the exact fail-closed installer boundary already
    # qualified for 0.57.  This is intentionally a source gate so a future
    # integration/rebase cannot silently drop duplicate/symlink/hardlink/FIFO
    # rejection while combining the two release lines.
    assert "import tarfile" in installer
    assert "archive.getmembers()" in installer
    assert "len(names) != len(set(names))" in installer
    assert "member.isfile() or member.isdir()" in installer
    assert "UNSAFE_ARCHIVE_ENTRY_TYPE" in installer


def test_058_keeps_sanitized_public_stable_provenance_boundary() -> None:
    exporter = (ROOT / "scripts/export_public_stable_provenance.py").read_text(
        encoding="utf-8"
    )
    schema = (ROOT / "contracts/releases/public-stable-provenance.v2.schema.json").read_text(
        encoding="utf-8"
    )

    assert "home-center.public-stable-provenance.v2" in exporter
    assert "identity_leak" in exporter
    assert "approved_repository" in exporter
    assert "source_identity_sha256" in schema
    assert "release_boundary_identity_sha256" in schema
    assert "approved_repository" not in schema
    assert "approved_revision" not in schema
