#!/usr/bin/env python3
"""Real single-target acceptance capture for the Home Center 0.57 candidate.

The helper is target-local and runner-free. It never contacts GitHub, enables a
provider, or publishes a release. A successful run upgrades the current node to
one exact artifact, verifies readiness and protected state, rolls back to the
original release, verifies the original state again, and only then emits the
closed target-node evidence consumed by evaluate_target_node_evidence.py.
"""
from __future__ import annotations

import argparse, base64, hashlib, ipaddress, json, os, platform, re, secrets
import socket, sqlite3, ssl, stat, subprocess, sys, tarfile, tempfile, time
import urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path
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
_VOLATILE_SQLITE_TABLES = frozenset({"audit", "cluster_meta", "nodes", "sqlite_sequence"})

class AcceptanceError(RuntimeError):
    pass

def _require(ok: bool, code: str) -> None:
    if not ok: raise AcceptanceError(code)

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()

def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _regular_file_sha256(path: Path, *, code: str) -> str:
    flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
    try: fd = os.open(path, flags)
    except OSError as exc: raise AcceptanceError(code) from exc
    digest = hashlib.sha256()
    try:
        _require(stat.S_ISREG(os.fstat(fd).st_mode), code)
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk: break
            digest.update(chunk)
    finally: os.close(fd)
    return digest.hexdigest()

def _read_regular_text(path: Path, *, code: str, limit: int = 1024 * 1024) -> str:
    flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
    try: fd = os.open(path, flags)
    except OSError as exc: raise AcceptanceError(code) from exc
    try:
        info = os.fstat(fd); _require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, code)
        data = b""
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk: break
            data += chunk; _require(len(data) <= limit, code)
        return data.decode()
    except UnicodeDecodeError as exc: raise AcceptanceError(code) from exc
    finally: os.close(fd)

def _write_exclusive(path: Path, payload: bytes) -> None:
    try: fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc: raise AcceptanceError("output_unavailable") from exc
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(payload); out.flush(); os.fsync(out.fileno())
    except Exception:
        try: path.unlink(missing_ok=True)
        except OSError: pass
        raise

def _prepare_output_dir(path: Path) -> None:
    try: path.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        _require(path.is_dir() and not path.is_symlink() and not any(path.iterdir()), "output_dir_not_empty")
    except OSError as exc: raise AcceptanceError("output_dir_unavailable") from exc
    os.chmod(path, 0o700)

def _run(args: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    try: return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc: raise AcceptanceError("command_execution_failed") from exc

def _command_digest(result: subprocess.CompletedProcess[str]) -> str:
    return sha256_bytes((result.stdout + "\0" + result.stderr).encode(errors="replace"))

def _archive_member_bytes(archive: tarfile.TarFile, name: str) -> bytes:
    for candidate in (name, "./" + name):
        try: member = archive.getmember(candidate)
        except KeyError: continue
        _require(member.isfile(), "candidate_member_invalid:" + name)
        stream = archive.extractfile(member); _require(stream is not None, "candidate_member_invalid:" + name)
        data = stream.read(2 * 1024 * 1024 + 1); _require(len(data) <= 2 * 1024 * 1024, "candidate_member_oversized:" + name)
        return data
    raise AcceptanceError("candidate_member_missing:" + name)

def _manifest_map(raw: bytes) -> dict[str, str]:
    try: lines = raw.decode().splitlines()
    except UnicodeDecodeError as exc: raise AcceptanceError("candidate_manifest_invalid") from exc
    result: dict[str, str] = {}
    for line in lines:
        if not line.strip(): continue
        parts = line.split(maxsplit=1)
        _require(len(parts) == 2 and _SHA256.fullmatch(parts[0]) is not None, "candidate_manifest_invalid")
        name = parts[1].lstrip("*"); name = name[2:] if name.startswith("./") else name
        _require(name and name not in result, "candidate_manifest_invalid"); result[name] = parts[0]
    return result

def inspect_candidate(path: Path, expected_sha256: str, expected_version: str, expected_revision: str) -> dict[str, Any]:
    actual = _regular_file_sha256(path, code="candidate_artifact_invalid")
    _require(actual == expected_sha256, "candidate_artifact_digest_mismatch")
    try:
        with tarfile.open(path, "r:gz") as archive:
            names: set[str] = set()
            for member in archive.getmembers():
                name = member.name[2:] if member.name.startswith("./") else member.name
                _require(name not in names, "candidate_archive_duplicate_member"); names.add(name)
                _require(not name.startswith("/") and ".." not in Path(name).parts, "candidate_archive_unsafe_path")
                _require(member.isfile() or member.isdir(), "candidate_archive_unsafe_type")
            version = _archive_member_bytes(archive, "VERSION").decode("ascii").strip()
            revision = _archive_member_bytes(archive, "REVISION").decode("ascii").strip()
            manifest = _manifest_map(_archive_member_bytes(archive, "MANIFEST.sha256"))
            for script in ("deploy/install-node.sh", "deploy/rollback-node.sh"):
                _require(manifest.get(script) == sha256_bytes(_archive_member_bytes(archive, script)), "candidate_manifest_mismatch:" + script)
    except (OSError, tarfile.TarError, UnicodeDecodeError) as exc: raise AcceptanceError("candidate_archive_invalid") from exc
    _require(version == expected_version and _SEMVER.fullmatch(version) is not None, "candidate_version_mismatch")
    _require(revision == expected_revision and _REVISION.fullmatch(revision) is not None, "candidate_revision_mismatch")
    return {"version": version, "revision": revision, "sha256": actual, "manifest": manifest}

def _extract_candidate_scripts(path: Path, dest: Path) -> tuple[Path, Path]:
    dest.mkdir(mode=0o700)
    with tarfile.open(path, "r:gz") as archive:
        install_data = _archive_member_bytes(archive, "deploy/install-node.sh")
        rollback_data = _archive_member_bytes(archive, "deploy/rollback-node.sh")
    install, rollback = dest / "install-node.sh", dest / "rollback-node.sh"
    install.write_bytes(install_data); rollback.write_bytes(rollback_data); install.chmod(0o700); rollback.chmod(0o700)
    return install, rollback

def _load_config(path: Path) -> dict[str, Any]:
    try: raw = json.loads(_read_regular_text(path, code="config_invalid"))
    except json.JSONDecodeError as exc: raise AcceptanceError("config_invalid") from exc
    _require(isinstance(raw, dict), "config_invalid")
    for key in ("node_id", "state_db", "local_admin_credentials_file", "session_key_file", "audit_key_file", "web_ca", "management_address"):
        _require(isinstance(raw.get(key), str) and raw[key], "config_" + key + "_invalid")
    _require(_NODE_ID.fullmatch(raw["node_id"]) is not None, "config_node_id_invalid")
    _require(type(raw.get("web_port")) is int and 1 <= raw["web_port"] <= 65535, "config_web_port_invalid")
    for key in ("state_db", "local_admin_credentials_file", "session_key_file", "audit_key_file", "web_ca"):
        _require(Path(raw[key]).is_absolute(), "config_" + key + "_invalid")
    return raw

def _current_release_identity() -> tuple[str, str, str]:
    current = Path("/opt/home-center/current"); _require(current.is_symlink(), "current_release_not_symlink")
    release = current.resolve(strict=True); _require(str(release).startswith("/opt/home-center/releases/") and release.is_dir(), "current_release_invalid")
    version = _read_regular_text(release / "VERSION", code="current_version_invalid", limit=256).strip()
    revision = _read_regular_text(release / "REVISION", code="current_revision_invalid", limit=256).strip()
    _require(_SEMVER.fullmatch(version) is not None and _REVISION.fullmatch(revision) is not None, "current_identity_invalid")
    return str(release), version, revision

def _file_bundle_digest(config_path: Path, config: dict[str, Any]) -> str:
    pairs = [("config", config_path), ("local_admin", Path(config["local_admin_credentials_file"])), ("session_key", Path(config["session_key_file"])), ("audit_key", Path(config["audit_key_file"]))]
    return sha256_bytes(canonical_json([(label, _regular_file_sha256(path, code="protected_file_invalid:" + label)) for label, path in pairs]))

def _encode_sql_value(value: object) -> object:
    if value is None: return ["null"]
    if isinstance(value, bytes): return ["blob", base64.b64encode(value).decode("ascii")]
    if isinstance(value, int): return ["int", str(value)]
    if isinstance(value, float): return ["float", value.hex()]
    if isinstance(value, str): return ["text", value]
    raise AcceptanceError("sqlite_value_type_unsupported")

def _sqlite_semantic_digest(path: Path) -> tuple[str, tuple[str, ...]]:
    _require(path.is_absolute() and path.is_file() and not path.is_symlink(), "state_db_invalid")
    con: sqlite3.Connection | None = None
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10); con.execute("PRAGMA query_only=ON"); con.execute("BEGIN")
        tables = [row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name") if isinstance(row[0], str) and row[0] not in _VOLATILE_SQLITE_TABLES]
        _require(all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", t) for t in tables), "state_db_table_name_invalid")
        encoded_tables = []
        for table in tables:
            schema_row = con.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            quoted = '"' + table.replace('"', '""') + '"'
            rows = [canonical_json([_encode_sql_value(v) for v in row]).decode("ascii").strip() for row in con.execute(f"SELECT * FROM {quoted}")]; rows.sort()
            encoded_tables.append({"table": table, "schema": schema_row[0] if schema_row and isinstance(schema_row[0], str) else "", "rows": rows})
        con.rollback(); return sha256_bytes(canonical_json(encoded_tables)), tuple(tables)
    except (sqlite3.Error, OSError) as exc: raise AcceptanceError("state_db_read_failed") from exc
    finally:
        if con is not None: con.close()

def _systemd_version() -> str:
    result = _run(["systemctl", "--version"], timeout=15); _require(result.returncode == 0 and bool(result.stdout.splitlines()), "systemd_unavailable")
    line = result.stdout.splitlines()[0].strip(); _require(line.startswith("systemd ") and len(line) <= 128, "systemd_version_invalid"); return line

def _service_active() -> bool:
    return _run(["systemctl", "is-active", "--quiet", "home-center.service"], timeout=15).returncode == 0

def _ready_payload(config: dict[str, Any], ready_host: str | None, expected_version: str, timeout: int) -> dict[str, object]:
    host = ready_host or config["management_address"]; _require(isinstance(host, str) and 0 < len(host) <= 253, "ready_host_invalid")
    try: _require(not ipaddress.ip_address(host.strip("[]")).is_unspecified, "ready_host_unspecified")
    except ValueError: _require(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host) is not None, "ready_host_invalid")
    ca = Path(config["web_ca"]); _require(ca.is_file() and not ca.is_symlink(), "web_ca_invalid")
    context = ssl.create_default_context(cafile=str(ca)); url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    url = f"https://{url_host}:{int(config['web_port'])}/readyz"; deadline = time.monotonic() + timeout; last = "readiness_unavailable"
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "home-center-target-acceptance/0.57"})
            with urllib.request.urlopen(req, timeout=5, context=context) as response:
                raw = response.read(65537); _require(len(raw) <= 65536, "readiness_response_oversized"); payload = json.loads(raw)
                if response.status == 200 and isinstance(payload, dict) and payload.get("schema") == "home-center.readiness.v1" and payload.get("status") == "ready" and payload.get("reasons") == [] and payload.get("version") == expected_version and payload.get("node_id") == config["node_id"]:
                    return {"schema": payload["schema"], "status": "ready", "version": expected_version, "node_id": payload["node_id"], "reasons": []}
                last = "readiness_identity_mismatch"
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, json.JSONDecodeError, AcceptanceError): last = "readiness_unavailable"
        time.sleep(1)
    raise AcceptanceError(last)

def _parse_key_lines(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line: continue
        key, value = line.split("=", 1)
        if key in {"NODE_DEPLOYMENT", "NODE_ROLLBACK", "NODE", "VERSION", "REVISION", "RELEASE", "ROLLBACK_POINT"}:
            _require(key not in result, "deployment_output_duplicate_key"); result[key] = value.strip()
    return result

def _new_transaction_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(6)

def _rollback_point_from_transaction(transaction_id: str, node_name: str) -> str | None:
    if _TX_ID.fullmatch(transaction_id) is None or _NODE_ID.fullmatch(node_name) is None: return None
    path = Path("/var/lib/home-center-deploy/transactions") / f"{transaction_id}-{node_name}.json"
    try: raw = json.loads(_read_regular_text(path, code="transaction_record_invalid", limit=65536))
    except (AcceptanceError, json.JSONDecodeError): return None
    point = raw.get("rollback_point") if isinstance(raw, dict) and raw.get("schema") == "home-center.node-deployment.v1" else None
    return point if isinstance(point, str) and point.startswith("/var/backups/home-center-deploy/") else None

def _environment_snapshot(node_id: str, stable_version: str, stable_revision: str, candidate: dict[str, Any], systemd_version: str, tables: tuple[str, ...], protected: str, state: str) -> dict[str, object]:
    return {"schema": ENVIRONMENT_SCHEMA, "captured_at": utc_now(), "target_node_id": node_id, "platform_system": platform.system(), "platform_machine": platform.machine(), "kernel_release": platform.release(), "python_version": platform.python_version(), "systemd_version": systemd_version, "baseline_version": stable_version, "baseline_revision": stable_revision, "candidate_version": candidate["version"], "candidate_revision": candidate["revision"], "candidate_artifact_sha256": candidate["sha256"], "protected_state_bundle_sha256": protected, "durable_state_sha256": state, "durable_state_tables": list(tables)}

def _plan(candidate: dict[str, Any], stable_release: str, stable_version: str, stable_revision: str, node_id: str) -> dict[str, object]:
    return {"schema": PLAN_SCHEMA, "candidate_version": candidate["version"], "candidate_revision": candidate["revision"], "candidate_artifact_sha256": candidate["sha256"], "baseline_version": stable_version, "baseline_revision": stable_revision, "baseline_release_name": Path(stable_release).name, "target_node_id": node_id, "operations": ["verify baseline readiness and protected state", "install exact candidate with deploy/install-node.sh", "verify candidate readiness and protected state", "rollback with deploy/rollback-node.sh", "verify original release readiness and protected state", "emit content-addressed target-node evidence"], "final_expected_state": "original-release-restored", "provider_execution": False, "external_publication": False}

def capture(args: argparse.Namespace) -> int:
    _require(os.geteuid() == 0, "root_required"); _require(_SHA256.fullmatch(args.candidate_sha256) is not None, "candidate_sha256_invalid")
    _require(_SEMVER.fullmatch(args.expected_candidate_version) is not None and _REVISION.fullmatch(args.expected_candidate_revision) is not None, "candidate_identity_invalid")
    _require(_SEMVER.fullmatch(args.expected_current_version) is not None, "current_version_invalid")
    candidate = inspect_candidate(args.candidate_artifact, args.candidate_sha256, args.expected_candidate_version, args.expected_candidate_revision)
    config_path = Path("/etc/home-center/config.json"); config = _load_config(config_path)
    stable_release, stable_version, stable_revision = _current_release_identity(); _require(stable_version == args.expected_current_version, "current_version_mismatch")
    if args.expected_current_revision is not None:
        _require(_REVISION.fullmatch(args.expected_current_revision) is not None and stable_revision == args.expected_current_revision, "current_revision_mismatch")
    _require((stable_version, stable_revision) != (candidate["version"], candidate["revision"]), "candidate_already_current"); _require(_service_active(), "baseline_service_not_active")
    protected_before = _file_bundle_digest(config_path, config); state_db = Path(config["state_db"]); state_before, state_tables = _sqlite_semantic_digest(state_db)
    systemd_version = _systemd_version(); _ready_payload(config, args.ready_host, stable_version, args.readiness_timeout)
    if args.plan_only:
        print(canonical_json(_plan(candidate, stable_release, stable_version, stable_revision, config["node_id"])).decode(), end=""); return 0

    _prepare_output_dir(args.output_dir)
    environment = _environment_snapshot(config["node_id"], stable_version, stable_revision, candidate, systemd_version, state_tables, protected_before, state_before)
    environment_path = args.output_dir / "target-environment.json"; _write_exclusive(environment_path, canonical_json(environment)); environment_sha = _regular_file_sha256(environment_path, code="environment_output_invalid")
    tx = _new_transaction_id(); _require(_TX_ID.fullmatch(tx) is not None, "transaction_id_invalid"); started = utc_now()
    steps: list[dict[str, object]] = [{"step":"baseline_readiness","status":"pass","version":stable_version},{"step":"baseline_state","status":"pass","protected_state_bundle_sha256":protected_before,"durable_state_sha256":state_before}]
    point: str | None = None; install_completed = False; rollback_completed = False; failure: BaseException | None = None; node_name = socket.gethostname().split(".",1)[0]
    with tempfile.TemporaryDirectory(prefix="home-center-target-acceptance-") as temp:
        install_script, rollback_script = _extract_candidate_scripts(args.candidate_artifact, Path(temp)/"scripts")
        try:
            install = _run([str(install_script),"--artifact",str(args.candidate_artifact),"--sha256",args.candidate_sha256,"--node-name",node_name,"--transaction-id",tx,"--expected-current-release",stable_release,"--expected-current-version",stable_version,"--expected-current-revision",stable_revision], timeout=args.mutation_timeout)
            steps.append({"step":"install_candidate","status":"pass" if install.returncode==0 else "fail","returncode":install.returncode,"output_sha256":_command_digest(install)})
            if install.returncode == 0: install_completed = True
            fields = _parse_key_lines(install.stdout); _require(install.returncode==0 and fields.get("NODE_DEPLOYMENT")=="PASS", "candidate_install_failed")
            _require(fields.get("VERSION")==candidate["version"] and fields.get("REVISION")==candidate["revision"], "candidate_install_identity_mismatch")
            point = fields.get("ROLLBACK_POINT") or _rollback_point_from_transaction(tx,node_name); _require(isinstance(point,str) and point.startswith("/var/backups/home-center-deploy/"), "rollback_point_invalid")
            current_release, current_version, current_revision = _current_release_identity(); _require((current_version,current_revision)==(candidate["version"],candidate["revision"]) and fields.get("RELEASE")==current_release, "candidate_current_identity_mismatch")
            _require(_service_active(), "candidate_service_not_active"); _ready_payload(config,args.ready_host,candidate["version"],args.readiness_timeout); steps.append({"step":"candidate_readiness","status":"pass","version":candidate["version"]})
            protected_candidate = _file_bundle_digest(config_path,config); state_candidate,candidate_tables = _sqlite_semantic_digest(state_db)
            _require(candidate_tables==state_tables and protected_candidate==protected_before and state_candidate==state_before, "candidate_user_state_changed")
            steps.append({"step":"candidate_state_preservation","status":"pass","protected_state_bundle_sha256":protected_candidate,"durable_state_sha256":state_candidate})
            rollback = _run([str(rollback_script),"--rollback-point",point], timeout=args.mutation_timeout); rb = _parse_key_lines(rollback.stdout); steps.append({"step":"rollback","status":"pass" if rollback.returncode==0 else "fail","returncode":rollback.returncode,"output_sha256":_command_digest(rollback)})
            _require(rollback.returncode==0 and rb.get("NODE_ROLLBACK")=="PASS", "rollback_failed"); rollback_completed=True
            restored_release, restored_version, restored_revision = _current_release_identity(); _require((restored_release,restored_version,restored_revision)==(stable_release,stable_version,stable_revision), "rollback_identity_mismatch")
            _require(_service_active(), "rollback_service_not_active"); _ready_payload(config,args.ready_host,stable_version,args.readiness_timeout); steps.append({"step":"rollback_readiness","status":"pass","version":stable_version})
            protected_after = _file_bundle_digest(config_path,config); state_after,after_tables = _sqlite_semantic_digest(state_db); _require(after_tables==state_tables and protected_after==protected_before and state_after==state_before, "rollback_user_state_changed")
            steps.append({"step":"rollback_state_preservation","status":"pass","protected_state_bundle_sha256":protected_after,"durable_state_sha256":state_after})
        except BaseException as exc: failure=exc
        finally:
            if install_completed and not rollback_completed:
                point = point or _rollback_point_from_transaction(tx,node_name)
                if point is None:
                    print("TARGET_NODE_ACCEPTANCE=CRITICAL_ROLLBACK_POINT_UNAVAILABLE",file=sys.stderr); raise AcceptanceError("emergency_rollback_point_unavailable") from failure
                emergency = _run([str(rollback_script),"--rollback-point",point],timeout=args.mutation_timeout); steps.append({"step":"emergency_rollback","status":"pass" if emergency.returncode==0 else "fail","returncode":emergency.returncode,"output_sha256":_command_digest(emergency)})
                if emergency.returncode != 0:
                    print("TARGET_NODE_ACCEPTANCE=CRITICAL_ROLLBACK_FAILED",file=sys.stderr); raise AcceptanceError("emergency_rollback_failed") from failure
    if failure is not None: raise failure

    transcript = {"schema":TRANSCRIPT_SCHEMA,"version":candidate["version"],"revision":candidate["revision"],"candidate_artifact_sha256":candidate["sha256"],"target_node_id":config["node_id"],"baseline_version":stable_version,"baseline_revision":stable_revision,"target_environment_sha256":environment_sha,"started_at":started,"completed_at":utc_now(),"final_state":"original-release-restored","provider_execution_exercised":False,"external_publication_exercised":False,"steps":steps}
    transcript_path=args.output_dir/"target-transcript.json"; _write_exclusive(transcript_path,canonical_json(transcript)); transcript_sha=_regular_file_sha256(transcript_path,code="transcript_output_invalid")
    evidence={"schema":EVIDENCE_SCHEMA,"version":candidate["version"],"revision":candidate["revision"],"candidate_artifact_sha256":candidate["sha256"],"target_node_id":config["node_id"],"target_environment_sha256":environment_sha,"target_execution_transcript_sha256":transcript_sha,"install_or_upgrade_exercised":True,"health_ready":True,"user_state_preserved":True,"rollback_exercised":True}
    _write_exclusive(args.output_dir/"target-node-evidence.json",canonical_json(evidence))
    print(f"TARGET_NODE_ACCEPTANCE=PASS version={candidate['version']} revision={candidate['revision']} candidate_artifact_sha256={candidate['sha256']} target_environment_sha256={environment_sha} target_execution_transcript_sha256={transcript_sha}"); print(f"EVIDENCE_DIR={args.output_dir}"); return 0

def build_parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description="Exercise an exact Home Center candidate on one real target node and capture bounded evidence.")
    p.add_argument("--candidate-artifact",required=True,type=Path); p.add_argument("--candidate-sha256",required=True); p.add_argument("--expected-candidate-version",required=True); p.add_argument("--expected-candidate-revision",required=True); p.add_argument("--expected-current-version",required=True); p.add_argument("--expected-current-revision"); p.add_argument("--ready-host",help="TLS hostname/IP for local readiness verification only; never written to evidence"); p.add_argument("--output-dir",type=Path,default=Path("./home-center-target-node-evidence")); p.add_argument("--readiness-timeout",type=int,default=60); p.add_argument("--mutation-timeout",type=int,default=300); p.add_argument("--plan-only",action="store_true"); return p

def main() -> int:
    args=build_parser().parse_args()
    try:
        _require(5<=args.readiness_timeout<=300,"readiness_timeout_invalid"); _require(30<=args.mutation_timeout<=1800,"mutation_timeout_invalid"); return capture(args)
    except AcceptanceError as exc:
        print(f"TARGET_NODE_ACCEPTANCE=ERROR code={exc}",file=sys.stderr); return 2
    except KeyboardInterrupt:
        print("TARGET_NODE_ACCEPTANCE=ERROR code=interrupted",file=sys.stderr); return 130

if __name__ == "__main__": raise SystemExit(main())
