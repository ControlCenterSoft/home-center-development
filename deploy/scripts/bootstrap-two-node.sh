#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: $0 --artifact PATH --sha256 HEX --installer PATH --rollback PATH --coordinator HOSTNAME --peer HOSTNAME" >&2
  exit 64
}

ARTIFACT="" SHA256="" INSTALLER="" ROLLBACK="" COORDINATOR="" PEER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact) ARTIFACT=${2:-}; shift 2 ;;
    --sha256) SHA256=${2:-}; shift 2 ;;
    --installer) INSTALLER=${2:-}; shift 2 ;;
    --rollback) ROLLBACK=${2:-}; shift 2 ;;
    --coordinator) COORDINATOR=${2:-}; shift 2 ;;
    --peer) PEER=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo ROOT_REQUIRED >&2; exit 65; }
[[ -f "$ARTIFACT" && ! -L "$ARTIFACT" ]] || usage
[[ -f "$INSTALLER" && ! -L "$INSTALLER" ]] || usage
[[ -f "$ROLLBACK" && ! -L "$ROLLBACK" ]] || usage
[[ "$SHA256" =~ ^[0-9a-f]{64}$ ]] || usage
[[ "$COORDINATOR" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$ ]] || usage
[[ "$PEER" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$ ]] || usage
[[ "$COORDINATOR" != "$PEER" ]] || { echo CLUSTER_NODE_IDENTITIES_MUST_DIFFER >&2; exit 64; }
[[ "$(hostname -s)" == "${COORDINATOR%%.*}" ]] || { echo COORDINATOR_IDENTITY_MISMATCH >&2; exit 65; }
[[ "$(sha256sum "$ARTIFACT" | awk '{print $1}')" == "$SHA256" ]] || { echo ARTIFACT_CHECKSUM_MISMATCH >&2; exit 66; }
bash -n "$INSTALLER"
bash -n "$ROLLBACK"

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes "$PEER")
SCP=(scp -q -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes)

local_release=$(readlink -f /opt/home-center/current)
[[ "$local_release" == /opt/home-center/releases/* && -d "$local_release" ]] || { echo LOCAL_RELEASE_INVALID >&2; exit 66; }
local_version=$(tr -d '\r\n' <"$local_release/VERSION")
local_revision=$(tr -d '\r\n' <"$local_release/REVISION")
[[ "$local_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo LOCAL_VERSION_INVALID >&2; exit 66; }
[[ "$local_revision" =~ ^[0-9a-f]{40}$ ]] || { echo LOCAL_REVISION_INVALID >&2; exit 66; }
systemctl is-active --quiet home-center.service || { echo LOCAL_SERVICE_NOT_ACTIVE >&2; exit 70; }

peer_identity=$("${SSH[@]}" '
  set -Eeuo pipefail
  test "$(hostname -s)" = "'"${PEER%%.*}"'" || exit 65
  release=$(readlink -f /opt/home-center/current)
  test -n "$release" -a -d "$release" -a -f "$release/VERSION" -a -f "$release/REVISION"
  systemctl is-active --quiet home-center.service
  printf "%s\t%s\t%s\n" "$release" "$(tr -d "\r\n" <"$release/VERSION")" "$(tr -d "\r\n" <"$release/REVISION")"
') || { echo PEER_PREFLIGHT_FAILED >&2; exit 70; }
IFS=$'\t' read -r peer_release peer_version peer_revision <<<"$peer_identity"
[[ "$peer_release" == /opt/home-center/releases/* ]] || { echo PEER_RELEASE_INVALID >&2; exit 66; }
[[ "$peer_version" == "$local_version" && "$peer_revision" == "$local_revision" ]] || { echo CLUSTER_RELEASE_DRIFT >&2; exit 66; }

target_version=$(tar -xOf "$ARTIFACT" ./VERSION | tr -d '\r\n')
target_revision=$(tar -xOf "$ARTIFACT" ./REVISION | tr -d '\r\n')
[[ "$target_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo TARGET_VERSION_INVALID >&2; exit 66; }
[[ "$target_revision" =~ ^[0-9a-f]{40}$ ]] || { echo TARGET_REVISION_INVALID >&2; exit 66; }

transaction_id="$(date -u +%Y%m%dT%H%M%SZ)-$(python3 - <<'PY'
import secrets
print(secrets.token_hex(6))
PY
)"
remote_dir="/tmp/home-center-rollout-${transaction_id}"
remote_artifact="$remote_dir/artifact.tar.gz"
remote_installer="$remote_dir/install-node.sh"
remote_rollback_script="$remote_dir/rollback-node.sh"
remote_backup="/var/backups/home-center-deploy/${transaction_id}-${PEER%%.*}"
local_backup="/var/backups/home-center-deploy/${transaction_id}-${COORDINATOR%%.*}"

peer_deployed=0
local_deployed=0
cleanup_remote() {
  "${SSH[@]}" "rm -rf -- '$remote_dir'" >/dev/null 2>&1 || true
}
trap cleanup_remote EXIT

"${SSH[@]}" "install -d -m 0700 '$remote_dir'"
"${SCP[@]}" "$ARTIFACT" "$PEER:$remote_artifact"
"${SCP[@]}" "$INSTALLER" "$PEER:$remote_installer"
"${SCP[@]}" "$ROLLBACK" "$PEER:$remote_rollback_script"

set +e
peer_output=$("${SSH[@]}" "
  set -Eeuo pipefail
  chmod 0600 '$remote_artifact'
  chmod 0700 '$remote_installer' '$remote_rollback_script'
  sudo -n bash '$remote_installer' \\
    --artifact '$remote_artifact' \\
    --sha256 '$SHA256' \\
    --node-name '${PEER%%.*}' \\
    --transaction-id '$transaction_id' \\
    --expected-current-release '$peer_release' \\
    --expected-current-version '$peer_version' \\
    --expected-current-revision '$peer_revision'
" 2>&1)
peer_rc=$?
set -e
printf '%s\n' "$peer_output"
if [[ "$peer_rc" -ne 0 ]]; then
  echo PEER_DEPLOYMENT_FAILED >&2
  exit "$peer_rc"
fi
peer_deployed=1

if ! "${SSH[@]}" "test \"\$(tr -d '\r\n' </opt/home-center/current/VERSION)\" = '$target_version' && systemctl is-active --quiet home-center.service"; then
  "${SSH[@]}" "sudo -n bash '$remote_rollback_script' --rollback-point '$remote_backup'" || true
  echo PEER_POST_DEPLOYMENT_VERIFICATION_FAILED >&2
  exit 70
fi

set +e
local_output=$(bash "$INSTALLER" \
  --artifact "$ARTIFACT" \
  --sha256 "$SHA256" \
  --node-name "${COORDINATOR%%.*}" \
  --transaction-id "$transaction_id" \
  --expected-current-release "$local_release" \
  --expected-current-version "$local_version" \
  --expected-current-revision "$local_revision" 2>&1)
local_rc=$?
set -e
printf '%s\n' "$local_output"
if [[ "$local_rc" -ne 0 ]]; then
  if [[ "$peer_deployed" -eq 1 ]]; then
    "${SSH[@]}" "sudo -n bash '$remote_rollback_script' --rollback-point '$remote_backup'" || true
  fi
  echo COORDINATOR_DEPLOYMENT_FAILED >&2
  exit "$local_rc"
fi
local_deployed=1

final_ok=1
[[ "$(tr -d '\r\n' </opt/home-center/current/VERSION)" == "$target_version" ]] || final_ok=0
systemctl is-active --quiet home-center.service || final_ok=0
"${SSH[@]}" "test \"\$(tr -d '\r\n' </opt/home-center/current/VERSION)\" = '$target_version' && systemctl is-active --quiet home-center.service" || final_ok=0

if [[ "$final_ok" -ne 1 ]]; then
  [[ "$local_deployed" -eq 1 ]] && bash "$ROLLBACK" --rollback-point "$local_backup" || true
  [[ "$peer_deployed" -eq 1 ]] && "${SSH[@]}" "sudo -n bash '$remote_rollback_script' --rollback-point '$remote_backup'" || true
  echo CLUSTER_POST_DEPLOYMENT_VERIFICATION_FAILED >&2
  exit 70
fi

printf 'CLUSTER_ROLLOUT=PASS\n'
printf 'VERSION=%s\n' "$target_version"
printf 'REVISION=%s\n' "$target_revision"
printf 'TRANSACTION_ID=%s\n' "$transaction_id"
