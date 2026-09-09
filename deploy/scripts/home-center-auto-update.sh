#!/usr/bin/env bash
set -Eeuo pipefail

umask 027

SYNC_SCRIPT="${HOME_CENTER_SYNC_SCRIPT:-/opt/home-center/scripts/home-center-sync.sh}"
COORDINATOR="${HOME_CENTER_UPDATE_COORDINATOR:-}"
LOCK_FILE="${HOME_CENTER_UPDATE_LOCK_FILE:-/run/lock/home-center-auto-update.lock}"
MAX_RUNTIME="${HOME_CENTER_UPDATE_TIMEOUT_SECONDS:-2700}"

log() {
    printf '%s home-center-auto-update[%s]: %s\n' \
        "$(date --iso-8601=seconds)" "$$" "$*"
}

fail() {
    log "ERROR: $*"
    exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "must run as root"
[[ -n "${COORDINATOR}" ]] || fail "HOME_CENTER_UPDATE_COORDINATOR is not configured"
[[ "${MAX_RUNTIME}" =~ ^[1-9][0-9]*$ ]] || fail "HOME_CENTER_UPDATE_TIMEOUT_SECONDS must be a positive integer"
command -v flock >/dev/null 2>&1 || fail "flock is required"
[[ -x "${SYNC_SCRIPT}" ]] || fail "sync script is not executable: ${SYNC_SCRIPT}"

node_short="$(hostname -s)"
node_fqdn="$(hostname -f 2>/dev/null || hostname)"
coordinator_short="${COORDINATOR%%.*}"

# Install the same unit on every node, but allow only the configured coordinator
# to orchestrate the cluster-wide rolling update. The existing sync script keeps
# ownership of release verification, backup, health checks, rollback, and node order.
if [[ "${node_short}" != "${coordinator_short}" && "${node_fqdn}" != "${COORDINATOR}" ]]; then
    exit 0
fi

install -d -m 0755 "$(dirname "${LOCK_FILE}")"
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
    log "another update run already holds ${LOCK_FILE}; skipping"
    exit 0
fi

log "starting cluster update check via ${SYNC_SCRIPT}"
set +e
if command -v timeout >/dev/null 2>&1; then
    timeout --foreground --signal=TERM --kill-after=30s "${MAX_RUNTIME}" "${SYNC_SCRIPT}"
    rc=$?
else
    "${SYNC_SCRIPT}"
    rc=$?
fi
set -e

if [[ "${rc}" -ne 0 ]]; then
    log "cluster update check failed with exit code ${rc}"
    exit "${rc}"
fi

log "cluster update check completed successfully"
