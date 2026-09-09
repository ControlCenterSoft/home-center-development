#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

# Compatibility wrapper for hardened rolling upgrades.
# /etc/home-center/deployment-profile.json is persistent node-local state:
# upgrades validate it when present and preserve it in place. The signed
# deployment artifact carries the immutable installer core used below.
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

DEPLOYMENT_PROFILE=/etc/home-center/deployment-profile.json
if [[ -e "$DEPLOYMENT_PROFILE" || -L "$DEPLOYMENT_PROFILE" ]]; then
  [[ -f "$DEPLOYMENT_PROFILE" && ! -L "$DEPLOYMENT_PROFILE" ]] || { echo DEPLOYMENT_PROFILE_UNSAFE >&2; exit 66; }
  python3 - "$DEPLOYMENT_PROFILE" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(66)
if not isinstance(value, dict):
    raise SystemExit(66)
PY
fi

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
