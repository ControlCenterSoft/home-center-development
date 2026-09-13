"""Consistent local backup, retention and independent verification."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import tarfile
import tempfile
from pathlib import Path

from .config import load_config
from .store import StateStore
from .util import atomic_write, canonical_json, sha256_file, utc_now


def create_backup(retain: int = 14) -> tuple[Path, Path]:
    config = load_config()
    store = StateStore(config.state_db, config.audit_key_file.read_bytes(), config.cluster_id)
    stamp = utc_now().replace("-", "").replace(":", "")
    config.backup_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(config.backup_dir, 0o700)
    with tempfile.TemporaryDirectory(prefix="home-center-backup-") as raw_tmp:
        tmp = Path(raw_tmp)
        snapshot = tmp / "state.sqlite3"
        store.backup_to(snapshot)
        if not _sqlite_ok(snapshot):
            raise RuntimeError("backup snapshot integrity check failed")
        audit_head = _verify_audit_snapshot(snapshot, config.audit_key_file.read_bytes())
        manifest = {
            "schema": "home-center.backup-manifest.v1",
            "created_at": utc_now(),
            "cluster_id": config.cluster_id,
            "node_id": config.node_id,
            "runtime_version": __import__("home_center").__version__,
            "database_sha256": sha256_file(snapshot),
            "database_bytes": snapshot.stat().st_size,
            "audit_head": audit_head,
            "verification": {"sqlite_integrity": "ok", "audit_chain": "ok"},
        }
        manifest_file = tmp / "manifest.json"
        atomic_write(manifest_file, (canonical_json(manifest) + "\n").encode("utf-8"), 0o600)
        archive = config.backup_dir / f"home-center-{config.node_name}-{stamp}.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as bundle:
            bundle.add(snapshot, arcname="state.sqlite3", recursive=False)
            bundle.add(manifest_file, arcname="manifest.json", recursive=False)
        os.chmod(archive, 0o600)
    manifest["archive_sha256"] = sha256_file(archive)
    manifest["archive_bytes"] = archive.stat().st_size
    sidecar = archive.with_suffix("").with_suffix(".manifest.json")
    atomic_write(sidecar, (canonical_json(manifest) + "\n").encode("utf-8"), 0o600)
    verify_backup(archive, expected_archive_hash=manifest["archive_sha256"], audit_key=config.audit_key_file.read_bytes())
    store.audit(actor="system:backup", action="backup.create", target=config.node_id, outcome="verified", correlation_id=archive.name, details={"archive": archive.name, "archive_sha256": manifest["archive_sha256"]})
    store.close()
    _prune(config.backup_dir, retain)
    return archive, sidecar


def verify_backup(archive: Path, expected_archive_hash: str | None = None, audit_key: bytes | None = None) -> dict:
    archive = archive.resolve()
    if expected_archive_hash and sha256_file(archive) != expected_archive_hash:
        raise RuntimeError("archive checksum mismatch")
    with tempfile.TemporaryDirectory(prefix="home-center-restore-check-") as raw_tmp:
        tmp = Path(raw_tmp)
        with tarfile.open(archive, "r:gz") as bundle:
            names = {member.name for member in bundle.getmembers()}
            if names != {"state.sqlite3", "manifest.json"}:
                raise RuntimeError("unexpected backup members")
            bundle.extractall(tmp, filter="data")
        manifest = json.loads((tmp / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("schema") != "home-center.backup-manifest.v1":
            raise RuntimeError("unsupported backup manifest")
        snapshot = tmp / "state.sqlite3"
        if sha256_file(snapshot) != manifest.get("database_sha256"):
            raise RuntimeError("database checksum mismatch")
        if not _sqlite_ok(snapshot):
            raise RuntimeError("database integrity check failed")
        if audit_key is not None:
            audit_head = _verify_audit_snapshot(snapshot, audit_key)
            if audit_head != manifest.get("audit_head"):
                raise RuntimeError("audit head mismatch")
        return manifest


def _sqlite_ok(path: Path) -> bool:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
        return bool(row and row[0] == "ok")
    finally:
        connection.close()


def _verify_audit_snapshot(path: Path, key: bytes) -> str:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = connection.execute("SELECT event_id, ts, actor, action, target, outcome, correlation_id, details_json, prev_hash, event_hash FROM audit_events ORDER BY seq ASC").fetchall()
    finally:
        connection.close()
    prev = "0" * 64
    for row in rows:
        event_id, ts, actor, action, target, outcome, correlation_id, details_json, prev_hash, event_hash = row
        if prev_hash != prev:
            raise RuntimeError("backup audit prev-hash mismatch")
        payload = {"event_id": event_id, "ts": ts, "actor": actor, "action": action, "target": target, "outcome": outcome, "correlation_id": correlation_id, "details": json.loads(details_json), "prev_hash": prev_hash}
        expected = hmac.new(key, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, event_hash):
            raise RuntimeError("backup audit hash mismatch")
        prev = event_hash
    return prev


def _prune(directory: Path, retain: int) -> None:
    archives = sorted(directory.glob("home-center-*.tar.gz"), key=lambda item: item.stat().st_mtime, reverse=True)
    for old in archives[max(retain, 1):]:
        manifest = old.with_suffix("").with_suffix(".manifest.json")
        old.unlink(missing_ok=True)
        manifest.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Home Center backup utility")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--retain", type=int, default=14)
    verify = sub.add_parser("verify")
    verify.add_argument("archive", type=Path)
    args = parser.parse_args()
    if args.command == "create":
        archive, manifest = create_backup(args.retain)
        print(json.dumps({"ok": True, "archive": str(archive), "manifest": str(manifest)}))
        return 0
    config = load_config()
    result = verify_backup(args.archive, audit_key=config.audit_key_file.read_bytes())
    print(json.dumps({"ok": True, "manifest": result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
