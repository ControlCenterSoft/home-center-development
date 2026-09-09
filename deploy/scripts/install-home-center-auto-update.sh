#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage: install-home-center-auto-update.sh --coordinator HOSTNAME [--sync-script PATH]

Installs the same periodic update unit on a Home Center node. Only HOSTNAME
will execute the cluster-wide rolling update; other nodes keep the timer
installed but their service exits without mutation.
EOF
}

COORDINATOR=""
SYNC_SCRIPT="/opt/home-center/scripts/home-center-sync.sh"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --coordinator)
            [[ $# -ge 2 ]] || { usage >&2; exit 64; }
            COORDINATOR="$2"
            shift 2
            ;;
        --sync-script)
            [[ $# -ge 2 ]] || { usage >&2; exit 64; }
            SYNC_SCRIPT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 64
            ;;
    esac
done

[[ "${EUID}" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ -n "${COORDINATOR}" ]] || { echo "--coordinator is required" >&2; exit 64; }
[[ "${COORDINATOR}" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid coordinator hostname" >&2; exit 64; }
[[ "${SYNC_SCRIPT}" == /* ]] || { echo "--sync-script must be an absolute path" >&2; exit 64; }
[[ -x "${SYNC_SCRIPT}" ]] || { echo "sync script is not executable: ${SYNC_SCRIPT}" >&2; exit 1; }

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
SERVICE_SOURCE="${REPO_ROOT}/deploy/systemd/home-center-auto-update.service"
TIMER_SOURCE="${REPO_ROOT}/deploy/systemd/home-center-auto-update.timer"
WRAPPER_SOURCE="${SCRIPT_DIR}/home-center-auto-update.sh"

for source in "${SERVICE_SOURCE}" "${TIMER_SOURCE}" "${WRAPPER_SOURCE}"; do
    [[ -f "${source}" ]] || { echo "missing deployment file: ${source}" >&2; exit 1; }
done

install -m 0755 "${WRAPPER_SOURCE}" /usr/local/sbin/home-center-auto-update
install -m 0644 "${SERVICE_SOURCE}" /etc/systemd/system/home-center-auto-update.service
install -m 0644 "${TIMER_SOURCE}" /etc/systemd/system/home-center-auto-update.timer
install -d -m 0755 /etc/home-center

ENV_TMP="$(mktemp)"
trap 'rm -f "${ENV_TMP}"' EXIT
cat >"${ENV_TMP}" <<EOF
HOME_CENTER_UPDATE_COORDINATOR=${COORDINATOR}
HOME_CENTER_SYNC_SCRIPT=${SYNC_SCRIPT}
HOME_CENTER_UPDATE_TIMEOUT_SECONDS=2700
EOF
install -m 0644 "${ENV_TMP}" /etc/home-center/auto-update.env

systemctl daemon-reload
systemctl enable --now home-center-auto-update.timer
systemctl start home-center-auto-update.service

systemctl --no-pager --full status home-center-auto-update.timer || true
systemctl --no-pager --full status home-center-auto-update.service || true
