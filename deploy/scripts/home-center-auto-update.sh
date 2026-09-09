#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

API_URL="${HOME_CENTER_RELEASE_API:-https://api.github.com/repos/ControlCenterSoft/home-center/releases/latest}"
COORDINATOR="${HOME_CENTER_UPDATE_COORDINATOR:-}"
PEER="${HOME_CENTER_UPDATE_PEER:-}"
STATE_DIR="${HOME_CENTER_UPDATE_STATE_DIR:-/var/lib/home-center-auto-update}"
LOCK_FILE="${STATE_DIR}/update.lock"
BLOCKED_FILE="${STATE_DIR}/blocked.sha256"
CURRENT_LINK="/opt/home-center/current"

log() {
  printf '%s home-center-auto-update[%s]: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$*"
}

fail() {
  log "ERROR: $*"
  exit 1
}

[[ "$(id -u)" -eq 0 ]] || fail "root required"
[[ "$COORDINATOR" =~ ^[A-Za-z0-9._-]+$ ]] || fail "invalid or missing coordinator"
[[ "$PEER" =~ ^[A-Za-z0-9._-]+$ ]] || fail "invalid or missing peer"

node="$(hostname -s)"
if [[ "$node" != "${COORDINATOR%%.*}" && "$(hostname -f 2>/dev/null || hostname)" != "$COORDINATOR" ]]; then
  log "standby timer check: coordinator is ${COORDINATOR}; no cluster mutation on ${node}"
  exit 0
fi

for cmd in curl python3 tar sha256sum flock ssh systemctl; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command missing: $cmd"
done

install -d -m 0700 -o root -g root "$STATE_DIR"
exec 9>"$LOCK_FILE"
flock -n 9 || { log "another update check is running; skip"; exit 0; }

[[ -L "$CURRENT_LINK" ]] || fail "current release is not a symlink"
current_release="$(readlink -f "$CURRENT_LINK")"
[[ "$current_release" == /opt/home-center/releases/* && -d "$current_release" ]] || fail "invalid current release"
[[ -f "$current_release/VERSION" && -f "$current_release/REVISION" ]] || fail "current release identity missing"
current_version="$(tr -d '\r\n' <"$current_release/VERSION")"
current_revision="$(tr -d '\r\n' <"$current_release/REVISION")"
[[ "$current_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid current version"
[[ "$current_revision" =~ ^[0-9a-f]{40}$ ]] || fail "invalid current revision"
systemctl is-active --quiet home-center.service || fail "local Home Center service is not active"

peer_identity="$(
  ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes "$PEER" \
    'set -eu; p=$(readlink -f /opt/home-center/current); test -n "$p" -a -f "$p/VERSION" -a -f "$p/REVISION"; printf "%s %s %s\n" "$p" "$(tr -d "\r\n" <"$p/VERSION")" "$(tr -d "\r\n" <"$p/REVISION")"; systemctl is-active --quiet home-center.service' \
  2>/dev/null
)" || fail "peer identity/readiness probe failed"
read -r peer_release peer_version peer_revision <<<"$peer_identity"
[[ "$peer_release" == /opt/home-center/releases/* ]] || fail "invalid peer release path"
[[ "$peer_version" == "$current_version" && "$peer_revision" == "$current_revision" ]] || fail "cluster version/revision drift; automatic update blocked"

tmp="$(mktemp -d "${STATE_DIR}/run.XXXXXX")"
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT

release_json="$tmp/release.json"
curl --fail --silent --show-error --location \
  --connect-timeout 10 --max-time 30 --retry 2 \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  "$API_URL" -o "$release_json"

read -r target_version artifact_url checksum_url api_digest < <(
python3 - "$release_json" <<'PY'
import json, re, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if data.get("draft") is not False or data.get("prerelease") is not False:
    raise SystemExit("release_not_stable")
tag = data.get("tag_name")
m = re.fullmatch(r"v([0-9]+\.[0-9]+\.[0-9]+)", tag or "")
if not m:
    raise SystemExit("invalid_release_tag")
version = m.group(1)
artifact_name = f"home-center-{version}-linux-amd64.tar.gz"
checksum_name = artifact_name + ".sha256"
assets = data.get("assets")
if not isinstance(assets, list):
    raise SystemExit("invalid_assets")
by_name = {}
for asset in assets:
    name = asset.get("name")
    if isinstance(name, str):
        by_name.setdefault(name, []).append(asset)
if len(by_name.get(artifact_name, [])) != 1 or len(by_name.get(checksum_name, [])) != 1:
    raise SystemExit("required_release_assets_missing_or_ambiguous")
artifact = by_name[artifact_name][0]
checksum = by_name[checksum_name][0]
prefix = f"https://github.com/ControlCenterSoft/home-center/releases/download/v{version}/"
artifact_url = artifact.get("browser_download_url", "")
checksum_url = checksum.get("browser_download_url", "")
if artifact_url != prefix + artifact_name or checksum_url != prefix + checksum_name:
    raise SystemExit("unexpected_release_asset_url")
digest = artifact.get("digest", "")
dm = re.fullmatch(r"sha256:([0-9a-f]{64})", digest or "")
if not dm:
    raise SystemExit("github_asset_digest_missing")
print(version, artifact_url, checksum_url, dm.group(1))
PY
) || fail "release metadata validation failed"

set +e
python3 - "$current_version" "$target_version" <<'PY'
import re, sys
def version(value):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise SystemExit(2)
    return tuple(map(int, value.split(".")))
cur, target = map(version, sys.argv[1:3])
raise SystemExit(0 if target > cur else 10)
PY
cmp_rc=$?
set -e
if [[ "$cmp_rc" -eq 10 ]]; then
  log "no update: current=${current_version}, published=${target_version}"
  exit 0
elif [[ "$cmp_rc" -ne 0 ]]; then
  fail "version comparison failed"
fi

artifact="$tmp/home-center-${target_version}-linux-amd64.tar.gz"
checksum="$tmp/home-center-${target_version}-linux-amd64.tar.gz.sha256"
curl --fail --silent --show-error --location --connect-timeout 10 --max-time 120 --retry 2 "$artifact_url" -o "$artifact"
curl --fail --silent --show-error --location --connect-timeout 10 --max-time 30 --retry 2 "$checksum_url" -o "$checksum"

side_digest="$(awk 'NR==1 {print $1}' "$checksum")"
[[ "$side_digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid checksum sidecar"
[[ "$side_digest" == "$api_digest" ]] || fail "GitHub asset digest and checksum sidecar disagree"
actual_digest="$(sha256sum "$artifact" | awk '{print $1}')"
[[ "$actual_digest" == "$side_digest" ]] || fail "artifact checksum mismatch"

archive_version="$(tar -xOf "$artifact" ./VERSION 2>/dev/null | tr -d '\r\n')" || fail "VERSION missing from artifact"
archive_revision="$(tar -xOf "$artifact" ./REVISION 2>/dev/null | tr -d '\r\n')" || fail "REVISION missing from artifact"
[[ "$archive_version" == "$target_version" ]] || fail "release tag/artifact version mismatch"
[[ "$archive_revision" =~ ^[0-9a-f]{40}$ ]] || fail "invalid artifact revision"

if [[ -f "$BLOCKED_FILE" ]] && [[ "$(tr -d '\r\n' <"$BLOCKED_FILE")" == "$actual_digest" ]]; then
  log "release ${target_version} is quarantined after an earlier failed rollout; waiting for a different release or operator clearance"
  exit 0
fi

for path in ./deploy/bootstrap-hm-dm.sh ./deploy/install-node.sh ./deploy/rollback-node.sh; do
  tar -tzf "$artifact" | grep -Fxq "$path" || fail "required deployment entry missing: $path"
done

bootstrap="$tmp/bootstrap.sh"
installer="$tmp/install-node.sh"
rollback="$tmp/rollback-node.sh"
tar -xOf "$artifact" ./deploy/bootstrap-hm-dm.sh >"$bootstrap"
tar -xOf "$artifact" ./deploy/install-node.sh >"$installer"
tar -xOf "$artifact" ./deploy/rollback-node.sh >"$rollback"
chmod 0500 "$bootstrap" "$installer" "$rollback"
bash -n "$bootstrap"
bash -n "$installer"
bash -n "$rollback"

log "admitting stable release ${target_version} (${actual_digest:0:12}); rolling order is peer first, coordinator second"
set +e
bash "$bootstrap" \
  --artifact "$artifact" \
  --sha256 "$actual_digest" \
  --installer "$installer" \
  --rollback "$rollback"
rollout_rc=$?
set -e

if [[ "$rollout_rc" -ne 0 ]]; then
  printf '%s\n' "$actual_digest" >"${BLOCKED_FILE}.tmp"
  chmod 0600 "${BLOCKED_FILE}.tmp"
  mv -f "${BLOCKED_FILE}.tmp" "$BLOCKED_FILE"
  log "rollout failed rc=${rollout_rc}; digest quarantined to prevent repeated mutation attempts"
  exit "$rollout_rc"
fi

local_after="$(tr -d '\r\n' </opt/home-center/current/VERSION)"
peer_after="$(ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes "$PEER" 'tr -d "\r\n" </opt/home-center/current/VERSION; systemctl is-active --quiet home-center.service' 2>/dev/null)" || fail "peer post-update verification failed"
[[ "$local_after" == "$target_version" && "$peer_after" == "$target_version" ]] || fail "post-update version parity failed"
systemctl is-active --quiet home-center.service || fail "local service inactive after update"

rm -f "$BLOCKED_FILE"
python3 - "$STATE_DIR/state.json" "$target_version" "$archive_revision" "$actual_digest" <<'PY'
import json, os, sys, tempfile
from datetime import datetime, timezone
path, version, revision, digest = sys.argv[1:]
data = {
    "schema": "home-center.auto-update.state.v1",
    "last_success_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "version": version,
    "revision": revision,
    "sha256": digest,
}
directory = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(prefix=".state.", dir=directory, text=True)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
finally:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
PY

log "cluster update completed: ${current_version} -> ${target_version}"
