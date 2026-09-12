#!/usr/bin/env python3
"""Exercise Home Center 0.57 on one real target node and capture bounded evidence.

The tool is intentionally target-local and release-specific in semantics but not
in topology. It verifies one immutable candidate artifact, upgrades the current
single-node installation with the candidate's own install script, checks HTTPS
readiness and preservation of protected/user state, exercises the candidate's
rollback script, verifies the original release and state again, and only then
emits the three files consumed by evaluate_target_node_evidence.py.

It never contacts GitHub, never invokes CI, never enables provider execution and
never publishes a release. Evidence files contain hashes and bounded identities,
not configuration contents, credentials, addresses, or secret material.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import sqlite3
import ssl
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

EVIDENCE_SCHEMA = "home-center.target-node-evidence.v1"
ENVIRONMENT_SCHEMA = "home-center.target-node-environment.v1"
TRANSCRIPT_SCHEMA = "home-center.target-node-acceptance-transcript.v1"
PLAN_SCHEMA = "home-center.target-node-acceptance-plan.v1"

_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NODE_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\Z")
_TX_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")

# Runtime-maintained evidence may legitimately change when a service restarts.
# Everything else in the state store is treated as durable user/product state
# for this 0.57 acceptance boundary and must remain semantically identical.
_VOLATILE_SQLITE_TABLES = frozenset({"audit", "cluster_meta", "nodes", "sqlite_sequence"})


class AcceptanceError(RuntimeError):
    """Fail closed on an unsafe or unverified acceptance step."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise AcceptanceError(code)


def _regular_file_sha256(path: Path, *, code: str) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AcceptanceError(code) from exc
    digest = hashlib.sha256()
    try:
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode), code)
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _read_regular_text(path: Path, *, code: str, limit: int = 1024 * 1024) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AcceptanceError(code) from exc
    try:
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode), code)
        _require(info.st_size <= limit, code)
        data = b""
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        _require(len(data) <= limit, code)
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcceptanceError(code) from exc
    finally:
        os.close(fd)


def _write_exclusive(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except OSError as exc:
        raise AcceptanceError("output_unavailable") from exc
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _prepare_output_dir(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        _require(path.is_dir() and not path.is_symlink(), "output_dir_unsafe")
        _require(not any(path.iterdir()), "output_dir_not_empty")
    except OSError as exc:
        raise AcceptanceError("output_dir_unavailable") from exc
    os.chmod(path, 0o700)


def _run(args: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceError("command_execution_failed") from exc


def _command_digest(completed: subprocess.CompletedProcess[str]) -> str:
    return sha256_bytes((completed.stdout + "\0" + completed.stderr).encode("utf-8", errors="replace"))


def _archive_member_bytes(archive: tarfile.TarFile, name: str) -> bytes:
    candidates = (name, f"./{name}")
    for candidate in candidates:
        try:
            member = archive.getmember(candidate)
        except KeyError:
            continue
        _require(member.isfile(), f"candidate_member_invalid:{name}")
        stream = archive.extractfile(member)
        _require(stream is not None, f"candidate_member_invalid:{name}")
        data = stream.read(2 * 1024 * 1024 + 1)
        _require(len(data) <= 2 * 1024 * 1024, f"candidate_member_oversized:{name}")
        return data
    raise AcceptanceError(f"candidate_member_missing:{name}")


def _manifest_map(raw: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcceptanceError("candidate_manifest_invalid") from exc
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        _require(len(parts) == 2 and _SHA256.fullmatch(parts[0]) is not None, "candidate_manifest_invalid")
        name = parts[1].lstrip("*")
        if name.startswith("./"):
            name = name[2:]
        _require(name and name not in result, "candidate_manifest_invalid")
        result[name] = parts[0]
    return result


def inspect_candidate(path: Path, expected_sha256: str, expected_version: str, expected_revision: str) -> dict[str, Any]:
    actual_sha256 = _regular_file_sha256(path, code="candidate_artifact_invalid")
    _require(actual_sha256 == expected_sha256, "candidate_artifact_digest_mismatch")
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            normalized: set[str] = set()
            for member in members:
                name = member.name[2:] if member.name.startswith("./") else member.name
                _require(name not in normalized, "candidate_archive_duplicate_member")
                normalized.add(name)
                _require(not name.startswith("/") and ".." not in Path(name).parts, "candidate_archive_unsafe_path")
                _require(member.isfile() or member.isdir(), "candidate_archive_unsafe_type")
            version = _archive_member_bytes(archive, "VERSION").decode("ascii").strip()
            revision = _archive_member_bytes(archive, "REVISION").decode("ascii").strip()
            manifest = _manifest_map(_archive_member_bytes(archive, "MANIFEST.sha256"))
            for script_name in ("deploy/install-node.sh", "deploy/rollback-node.sh"):
                payload = _archive_member_bytes(archive, script_name)
                _require(manifest.get(script_name) == sha256_bytes(payload), f"candidate_manifest_mismatch:{script_name}")
    except (OSError, tarfile.TarError, UnicodeDecodeError) as exc:
        raise AcceptanceError("candidate_archive_invalid") from exc
    _require(_SEMVER.fullmatch(version) is not None, "candidate_version_invalid")
    _require(_REVISION.fullmatch(revision) is not None, "candidate_revision_invalid")
    _require(version == expected_version, "candidate_version_mismatch")
    _require(revision == expected_revision, "candidate_revision_mismatch")
    return {"version": version, "revision": revision, "sha256": actual_sha256, "manifest": manifest}


def _extract_candidate_scripts(path: Path, destination: Path) -> tuple[Path, Path]:
    destination.mkdir(mode=0o700)
    try:
        with tarfile.open(path, "r:gz") as archive:
            install_payload = _archive_member_bytes(archive, "deploy/install-node.sh")
            rollback_payload = _archive_member_bytes(archive, "deploy/rollback-node.sh")
    except (OSError, tarfile.TarError) as exc:
        raise AcceptanceError("candidate_archive_invalid") from exc
    install = destination / "install-node.sh"
    rollback = destination / "rollback-node.sh"
    install.write_bytes(install_payload)
    rollback.write_bytes(rollback_payload)
    install.chmod(0o700)
    rollback.chmod(0o700)
    return install, rollback


def _load_config(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(_read_regular_text(path, code="config_invalid"))
    except json.JSONDecodeError as exc:
        raise AcceptanceError("config_invalid") from exc
    _require(isinstance(raw, dict), "config_invalid")
    required_str = (
        "node_id",
        "state_db",
        "local_admin_credentials_file",
        "session_key_file",
        "audit_key_file",
        "web_ca",
        "management_address",
    )
    for key in required_str:
        _require(isinstance(raw.get(key), str) and raw[key], f"config_{key}_invalid")
    _require(_NODE_ID.fullmatch(raw["node_id"]) is not None, "config_node_id_invalid")
    _require(type(raw.get("web_port")) is int and 1 <= raw["web_port"] <= 65535, "config_web_port_invalid")
    for key in ("state_db", "local_admin_credentials_file", "session_key_file", "audit_key_file", "web_ca"):
        _require(Path(raw[key]).is_absolute(), f"config_{key}_invalid")
    return raw


def _current_release_identity() -> tuple[str, str, str]:
    current = Path("/opt/home-center/current")
    _require(current.is_symlink(), "current_release_not_symlink")
    resolved = current.resolve(strict=True)
    _require(str(resolved).startswith("/opt/home-center/releases/"), "current_release_invalid")
    _require(resolved.is_dir(), "current_release_invalid")
    version = _read_regular_text(resolved / "VERSION", code="current_version_invalid", limit=256).strip()
    revision = _read_regular_text(resolved / "REVISION", code="current_revision_invalid", limit=256).strip()
    _require(_SEMVER.fullmatch(version) is not None, "current_version_invalid")
    _require(_REVISION.fullmatch(revision) is not None, "current_revision_invalid")
    return str(resolved), version, revision


def _file_bundle_digest(config_path: Path, config: dict[str, Any]) -> str:
    entries: list[tuple[str, str]] = []
    paths = (
        ("config", config_path),
        ("local_admin", Path(config["local_admin_credentials_file"])),
        ("session_key", Path(config["session_key_file"])),
        ("audit_key", Path(config["audit_key_file"])),
    )
    for label, path in paths:
        entries.append((label, _regular_file_sha256(path, code=f"protected_file_invalid:{label}")))
    return sha256_bytes(canonical_json(entries))


def _encode_sql_value(value: object) -> object:
    if value is None:
        return ["null"]
    if isinstance(value, bytes):
        return ["blob", base64.b64encode(value).decode("ascii")]
    if isinstance(value, bool):
        return ["int", "1" if value else "0"]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, float):
        return ["float", value.hex()]
    if isinstance(value, str):
        return ["text", value]
    raise AcceptanceError("sqlite_value_type_unsupported")


def _sqlite_semantic_digest(path: Path) -> tuple[str, tuple[str, ...]]:
    _require(path.is_absolute(), "state_db_path_invalid")
    _require(path.exists() and path.is_file() and not path.is_symlink(), "state_db_invalid")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        tables = [
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            if isinstance(row[0], str) and row[0] not in _VOLATILE_SQLITE_TABLES
        ]
        _require(all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in tables), "state_db_table_name_invalid")
        payload_tables: list[dict[str, object]] = []
        for table in tables:
            schema_row = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            schema = schema_row[0] if schema_row and isinstance(schema_row[0], str) else ""
            quoted = '"' + table.replace('"', '""') + '"'
            encoded_rows = [
                canonical_json([_encode_sql_value(value) for value in row]).decode("ascii").strip()
                for row in connection.execute(f"SELECT * FROM {quoted}")
            ]
            encoded_rows.sort()
            payload_tables.append({"table": table, "schema": schema, "rows": encoded_rows})
        connection.rollback()
    except (sqlite3.Error, OSError) as exc:
        raise AcceptanceError("state_db_read_failed") from exc
    finally:
        if connection is not None:
            connection.close()
    return sha256_bytes(canonical_json(payload_tables)), tuple(tables)


def _systemd_version() -> str:
    completed = _run(["systemctl", "--version"], timeout=15)
    _require(completed.returncode == 0, "systemd_unavailable")
    line = completed.stdout.splitlines()[0].strip() if completed.stdout.splitlines() else ""
    _require(line.startswith("systemd ") and len(line) <= 128, "systemd_version_invalid")
    return line


def _service_active() -> bool:
    return _run(["systemctl", "is-active", "--quiet", "home-center.service"], timeout=15).returncode == 0


def _ready_payload(config: dict[str, Any], ready_host: str | None, expected_version: str, timeout: int) -> dict[str, object]:
    host = ready_host or config["management_address"]
    _require(isinstance(host, str) and host and len(host) <= 253, "ready_host_invalid")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        _require(not address.is_unspecified, "ready_host_unspecified")
    except ValueError:
        _require(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host) is not None, "ready_host_invalid")
    port = int(config["web_port"])
    ca = Path(config["web_ca"])
    _require(ca.exists() and ca.is_file() and not ca.is_symlink(), "web_ca_invalid")
    context = ssl.create_default_context(cafile=str(ca))
    url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    url = f"https://{url_host}:{port}/readyz"
    deadline = time.monotonic() + timeout
    last_code = "readiness_unavailable"
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "home-center-target-acceptance/0.57"})
            with urllib.request.urlopen(request, timeout=5, context=context) as response:
                raw = response.read(65537)
                _require(len(raw) <= 65536, "readiness_response_oversized")
                payload = json.loads(raw)
                if (
                    response.status == 200
                    and isinstance(payload, dict)
                    and payload.get("schema") == "home-center.readiness.v1"
                    and payload.get("status") == "ready"
                    and payload.get("reasons") == []
                    and payload.get("version") == expected_version
                    and payload.get("node_id") == config["node_id"]
                ):
                    return {"schema": payload["schema"], "status": payload["status"], "version": payload["version"], "node_id": payload["node_id"], "reasons": []}
                last_code = "readiness_identity_mismatch"
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, json.JSONDecodeError, AcceptanceError):
            last_code = "readiness_unavailable"
        time.sleep(1)
    raise AcceptanceError(last_code)


def _parse_key_lines(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"NODE_DEPLOYMENT", "NODE_ROLLBACK", "NODE", "VERSION", "REVISION", "RELEASE", "ROLLBACK_POINT"}:
            _require(key not in result, "deployment_output_duplicate_key")
            result[key] = value.strip()
    return result


def _environment_snapshot(*, node_id: str, stable_version: str, stable_revision: str, candidate: dict[str, Any], systemd_version: str, state_tables: tuple[str, ...], protected_digest: str, state_digest: str) -> dict[str, object]:
    return {
        "schema": ENVIRONMENT_SCHEMA,
        "captured_at": utc_now(),
        "target_node_id": node_id,
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "kernel_release": platform.release(),
        "python_version": platform.python_version(),
        "systemd_version": systemd_version,
        "baseline_version": stable_version,
        "baseline_revision": stable_revision,
        "candidate_version": candidate["version"],
        "candidate_revision": candidate["revision"],
        "candidate_artifact_sha256": candidate["sha256"],
        "protected_state_bundle_sha256": protected_digest,
        "durable_state_sha256": state_digest,
        "durable_state_tables": list(state_tables),
    }


def _validate_environment(snapshot: dict[str, object]) -> None:
    _require(snapshot.get("schema") == ENVIRONMENT_SCHEMA, "environment_schema_invalid")
    for key in ("target_node_id", "platform_system", "platform_machine", "kernel_release", "python_version", "systemd_version", "baseline_version", "baseline_revision", "candidate_version", "candidate_revision"):
        value = snapshot.get(key)
        _require(isinstance(value, str) and 0 < len(value) <= 256, f"environment_{key}_invalid")
    for key in ("candidate_artifact_sha256", "protected_state_bundle_sha256", "durable_state_sha256"):
        _require(isinstance(snapshot.get(key), str) and _SHA256.fullmatch(str(snapshot[key])) is not None, f"environment_{key}_invalid")
    tables = snapshot.get("durable_state_tables")
    _require(isinstance(tables, list) and all(isinstance(item, str) for item in tables), "environment_tables_invalid")


def _new_transaction_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(6)


def _plan(candidate: dict[str, Any], stable_release: str, stable_version: str, stable_revision: str, node_id: str) -> dict[str, object]:
    return {
        "schema": PLAN_SCHEMA,
        "candidate_version": candidate["version"],
        "candidate_revision": candidate["revision"],
        "candidate_artifact_sha256": candidate["sha256"],
        "baseline_version": stable_version,
        "baseline_revision": stable_revision,
        "baseline_release_name": Path(stable_release).name,
        "target_node_id": node_id,
        "operations": [
            "verify baseline readiness and protected state",
            "install exact candidate with deploy/install-node.sh",
            "verify candidate readiness and protected state",
            "rollback with deploy/rollback-node.sh",
            "verify original release readiness and protected state",
            "emit content-addressed target-node evidence",
        ],
        "final_expected_state": "original-release-restored",
        "provider_execution": False,
        "external_publication": False,
    }


def capture(args: argparse.Namespace) -> int:
    _require(os.geteuid() == 0, "root_required")
    _require(_SHA256.fullmatch(args.candidate_sha256) is not None, "candidate_sha256_invalid")
    _require(_SEMVER.fullmatch(args.expected_candidate_version) is not None, "candidate_version_invalid")
    _require(_REVISION.fullmatch(args.expected_candidate_revision) is not None, "candidate_revision_invalid")
    _require(_SEMVER.fullmatch(args.expected_current_version) is not None, "current_version_invalid")

    candidate = inspect_candidate(args.candidate_artifact, args.candidate_sha256, args.expected_candidate_version, args.expected_candidate_revision)
    config_path = Path("/etc/home-center/config.json")
    config = _load_config(config_path)
    stable_release, stable_version, stable_revision = _current_release_identity()
    _require(stable_version == args.expected_current_version, "current_version_mismatch")
    if args.expected_current_revision is not None:
        _require(_REVISION.fullmatch(args.expected_current_revision) is not None, "current_revision_invalid")
        _require(stable_revision == args.expected_current_revision, "current_revision_mismatch")
    _require(stable_version != candidate["version"] or stable_revision != candidate["revision"], "candidate_already_current")
    _require(_service_active(), "baseline_service_not_active")

    protected_before = _file_bundle_digest(config_path, config)
    state_db = Path(config["state_db"])
    state_before, state_tables = _sqlite_semantic_digest(state_db)
    systemd_version = _systemd_version()
    _ready_payload(config, args.ready_host, stable_version, args.readiness_timeout)

    if args.plan_only:
        print(canonical_json(_plan(candidate, stable_release, stable_version, stable_revision, config["node_id"])).decode("utf-8"), end="")
        return 0

    _prepare_output_dir(args.output_dir)
    environment = _environment_snapshot(node_id=config["node_id"], stable_version=stable_version, stable_revision=stable_revision, candidate=candidate, systemd_version=systemd_version, state_tables=state_tables, protected_digest=protected_before, state_digest=state_before)
    _validate_environment(environment)
    environment_path = args.output_dir / "target-environment.json"
    _write_exclusive(environment_path, canonical_json(environment))
    environment_sha256 = _regular_file_sha256(environment_path, code="environment_output_invalid")

    transaction_id = _new_transaction_id()
    _require(_TX_ID.fullmatch(transaction_id) is not None, "transaction_id_invalid")
    started_at = utc_now()
    steps: list[dict[str, object]] = [
        {"step": "baseline_readiness", "status": "pass", "version": stable_version},
        {"step": "baseline_state", "status": "pass", "protected_state_bundle_sha256": protected_before, "durable_state_sha256": state_before},
    ]
    rollback_point: str | None = None
    install_completed = False
    rollback_completed = False
    failure: BaseException | None = None

    with tempfile.TemporaryDirectory(prefix="home-center-target-acceptance-") as temp_raw:
        install_script, rollback_script = _extract_candidate_scripts(args.candidate_artifact, Path(temp_raw) / "candidate-scripts")
        try:
            install = _run([
                str(install_script), "--artifact", str(args.candidate_artifact), "--sha256", args.candidate_sha256,
                "--node-name", socket.gethostname().split(".", 1)[0], "--transaction-id", transaction_id,
                "--expected-current-release", stable_release, "--expected-current-version", stable_version,
                "--expected-current-revision", stable_revision,
            ], timeout=args.mutation_timeout)
            install_fields = _parse_key_lines(install.stdout)
            steps.append({"step": "install_candidate", "status": "pass" if install.returncode == 0 else "fail", "returncode": install.returncode, "output_sha256": _command_digest(install)})
            _require(install.returncode == 0 and install_fields.get("NODE_DEPLOYMENT") == "PASS", "candidate_install_failed")
            _require(install_fields.get("VERSION") == candidate["version"], "candidate_install_version_mismatch")
            _require(install_fields.get("REVISION") == candidate["revision"], "candidate_install_revision_mismatch")
            rollback_point = install_fields.get("ROLLBACK_POINT")
            _require(isinstance(rollback_point, str) and rollback_point.startswith("/var/backups/home-center-deploy/"), "rollback_point_invalid")
            install_completed = True

            current_release, current_version, current_revision = _current_release_identity()
            _require(current_version == candidate["version"] and current_revision == candidate["revision"], "candidate_current_identity_mismatch")
            _require(install_fields.get("RELEASE") == current_release, "candidate_release_path_mismatch")
            _require(_service_active(), "candidate_service_not_active")
            _ready_payload(config, args.ready_host, candidate["version"], args.readiness_timeout)
            steps.append({"step": "candidate_readiness", "status": "pass", "version": candidate["version"]})

            protected_candidate = _file_bundle_digest(config_path, config)
            state_candidate, candidate_tables = _sqlite_semantic_digest(state_db)
            _require(candidate_tables == state_tables, "candidate_state_table_drift")
            _require(protected_candidate == protected_before, "candidate_protected_state_changed")
            _require(state_candidate == state_before, "candidate_durable_state_changed")
            steps.append({"step": "candidate_state_preservation", "status": "pass", "protected_state_bundle_sha256": protected_candidate, "durable_state_sha256": state_candidate})

            rollback = _run([str(rollback_script), "--rollback-point", rollback_point], timeout=args.mutation_timeout)
            rollback_fields = _parse_key_lines(rollback.stdout)
            steps.append({"step": "rollback", "status": "pass" if rollback.returncode == 0 else "fail", "returncode": rollback.returncode, "output_sha256": _command_digest(rollback)})
            _require(rollback.returncode == 0 and rollback_fields.get("NODE_ROLLBACK") == "PASS", "rollback_failed")
            rollback_completed = True

            restored_release, restored_version, restored_revision = _current_release_identity()
            _require(restored_release == stable_release, "rollback_release_mismatch")
            _require(restored_version == stable_version and restored_revision == stable_revision, "rollback_identity_mismatch")
            _require(_service_active(), "rollback_service_not_active")
            _ready_payload(config, args.ready_host, stable_version, args.readiness_timeout)
            steps.append({"step": "rollback_readiness", "status": "pass", "version": stable_version})

            protected_after = _file_bundle_digest(config_path, config)
            state_after, after_tables = _sqlite_semantic_digest(state_db)
            _require(after_tables == state_tables, "rollback_state_table_drift")
            _require(protected_after == protected_before, "rollback_protected_state_changed")
            _require(state_after == state_before, "rollback_durable_state_changed")
            steps.append({"step": "rollback_state_preservation", "status": "pass", "protected_state_bundle_sha256": protected_after, "durable_state_sha256": state_after})
        except BaseException as exc:
            failure = exc
        finally:
            if install_completed and not rollback_completed and rollback_point is not None:
                emergency = _run([str(rollback_script), "--rollback-point", rollback_point], timeout=args.mutation_timeout)
                steps.append({"step": "emergency_rollback", "status": "pass" if emergency.returncode == 0 else "fail", "returncode": emergency.returncode, "output_sha256": _command_digest(emergency)})
                if emergency.returncode != 0:
                    print("TARGET_NODE_ACCEPTANCE=CRITICAL_ROLLBACK_FAILED", file=sys.stderr)
                    raise AcceptanceError("emergency_rollback_failed") from failure

    if failure is not None:
        raise failure

    transcript = {
        "schema": TRANSCRIPT_SCHEMA, "version": candidate["version"], "revision": candidate["revision"],
        "candidate_artifact_sha256": candidate["sha256"], "target_node_id": config["node_id"],
        "baseline_version": stable_version, "baseline_revision": stable_revision,
        "target_environment_sha256": environment_sha256, "started_at": started_at, "completed_at": utc_now(),
        "final_state": "original-release-restored", "provider_execution_exercised": False,
        "external_publication_exercised": False, "steps": steps,
    }
    transcript_path = args.output_dir / "target-transcript.json"
    _write_exclusive(transcript_path, canonical_json(transcript))
    transcript_sha256 = _regular_file_sha256(transcript_path, code="transcript_output_invalid")

    evidence = {
        "schema": EVIDENCE_SCHEMA, "version": candidate["version"], "revision": candidate["revision"],
        "candidate_artifact_sha256": candidate["sha256"], "target_node_id": config["node_id"],
        "target_environment_sha256": environment_sha256,
        "target_execution_transcript_sha256": transcript_sha256,
        "install_or_upgrade_exercised": True, "health_ready": True,
        "user_state_preserved": True, "rollback_exercised": True,
    }
    evidence_path = args.output_dir / "target-node-evidence.json"
    _write_exclusive(evidence_path, canonical_json(evidence))

    print(
        "TARGET_NODE_ACCEPTANCE=PASS "
        f"version={candidate['version']} revision={candidate['revision']} "
        f"candidate_artifact_sha256={candidate['sha256']} "
        f"target_environment_sha256={environment_sha256} "
        f"target_execution_transcript_sha256={transcript_sha256}"
    )
    print(f"EVIDENCE_DIR={args.output_dir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Exercise exact Home Center candidate on one real target node and capture bounded evidence.")
    parser.add_argument("--candidate-artifact", required=True, type=Path)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--expected-candidate-version", required=True)
    parser.add_argument("--expected-candidate-revision", required=True)
    parser.add_argument("--expected-current-version", required=True)
    parser.add_argument("--expected-current-revision")
    parser.add_argument("--ready-host", help="TLS hostname/IP used only for local readiness verification; not written to evidence")
    parser.add_argument("--output-dir", type=Path, default=Path("./home-center-target-node-evidence"))
    parser.add_argument("--readiness-timeout", type=int, default=60)
    parser.add_argument("--mutation-timeout", type=int, default=300)
    parser.add_argument("--plan-only", action="store_true", help="validate exact inputs/baseline and print a mutation-free plan only")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        _require(5 <= args.readiness_timeout <= 300, "readiness_timeout_invalid")
        _require(30 <= args.mutation_timeout <= 1800, "mutation_timeout_invalid")
        return capture(args)
    except AcceptanceError as exc:
        print(f"TARGET_NODE_ACCEPTANCE=ERROR code={exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("TARGET_NODE_ACCEPTANCE=ERROR code=interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
