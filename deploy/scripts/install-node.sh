#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

# Compatibility wrapper for hardened rolling upgrades.
# deployment-profile.json is persistent node-local state. Legacy 0.22
# installations stored it below /opt/home-center/current; migrate that file
# atomically to /etc/home-center/deployment-profile.json before switching releases.
ARGS=("$@")
ARTIFACT=""
SHA256=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact) ARTIFACT=${2:-}; shift 2 ;;
    --sha256) SHA256=${2:-}; shift 2 ;;
    *) shift ;;
  esac
done

[[ -n "$ARTIFACT" && -f "$ARTIFACT" && ! -L "$ARTIFACT" ]] || { echo ARTIFACT_REQUIRED >&2; exit 64; }
[[ "$SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo SHA256_REQUIRED >&2; exit 64; }
actual_sha256=$(sha256sum "$ARTIFACT" | awk '{print $1}')
[[ "$actual_sha256" == "$SHA256" ]] || { echo ARTIFACT_CHECKSUM_MISMATCH >&2; exit 66; }

CONFIG=/etc/home-center/config.json
DEPLOYMENT_PROFILE=/etc/home-center/deployment-profile.json
python3 - "$CONFIG" "$DEPLOYMENT_PROFILE" <<'PY'
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

config_path = Path(sys.argv[1])
persistent = Path(sys.argv[2])
legacy = Path("/opt/home-center/current/deployment-profile.json")

def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(66)

def load_object(path: Path, unsafe_marker: str) -> tuple[dict, os.stat_result, bytes]:
    try:
        if path.is_symlink():
            fail(unsafe_marker)
        st = path.stat()
        if not stat.S_ISREG(st.st_mode):
            fail(unsafe_marker)
        data = path.read_bytes()
        value = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail(unsafe_marker)
    if not isinstance(value, dict):
        fail(unsafe_marker)
    return value, st, data

def atomic_write(path: Path, data: bytes, st: os.stat_result) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), stat.S_IMODE(st.st_mode))
            os.fchown(stream.fileno(), st.st_uid, st.st_gid)
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass

config_raw, config_stat, _ = load_object(config_path, "CONFIG_UNSAFE")
value = config_raw.get("deployment_profile")
if not isinstance(value, str) or not value.startswith("/"):
    fail("DEPLOYMENT_PROFILE_UNSAFE")
configured = Path(value)

if configured == legacy:
    _, source_stat, source_data = load_object(legacy, "DEPLOYMENT_PROFILE_UNSAFE")
    if persistent.exists() or persistent.is_symlink():
        _, _, persistent_data = load_object(persistent, "DEPLOYMENT_PROFILE_UNSAFE")
        if persistent_data != source_data:
            fail("DEPLOYMENT_PROFILE_CONFLICT")
    else:
        atomic_write(persistent, source_data, source_stat)

    config_raw["deployment_profile"] = str(persistent)
    config_bytes = (
        json.dumps(config_raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    atomic_write(config_path, config_bytes, config_stat)
    print("DEPLOYMENT_PROFILE_MIGRATION=PASS")
elif configured == persistent:
    load_object(persistent, "DEPLOYMENT_PROFILE_UNSAFE")
    print("DEPLOYMENT_PROFILE_MIGRATION=ALREADY_PERSISTENT")
else:
    load_object(configured, "DEPLOYMENT_PROFILE_UNSAFE")
    print("DEPLOYMENT_PROFILE_MIGRATION=EXTERNAL_PATH")
PY

CORE=$(mktemp)
cleanup() { rm -f -- "$CORE"; }
trap cleanup EXIT
if ! tar -xOf "$ARTIFACT" ./deploy/install-node-core.sh >"$CORE"; then
  echo INSTALLER_CORE_MISSING >&2
  exit 66
fi
[[ -s "$CORE" ]] || { echo INSTALLER_CORE_EMPTY >&2; exit 66; }
chmod 0500 "$CORE"
bash -n "$CORE" || { echo INSTALLER_CORE_SYNTAX_INVALID >&2; exit 66; }

set +e
bash "$CORE" "${ARGS[@]}"
rc=$?
set -e
exit "$rc"
