#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage: install-home-center-auto-update.sh --coordinator HOSTNAME --peer HOSTNAME

Installs the same periodic updater on a Home Center node. Only the configured
coordinator performs the cluster-wide rolling update. Topology bindings are
written only to a root-owned local environment file.
EOF
}

COORDINATOR=""
PEER=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --coordinator)
            [[ $# -ge 2 ]] || { usage >&2; exit 64; }
            COORDINATOR="$2"
            shift 2
            ;;
        --peer)
            [[ $# -ge 2 ]] || { usage >&2; exit 64; }
            PEER="$2"
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
[[ "${COORDINATOR}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$ ]] || { echo "--coordinator is required and must be a hostname" >&2; exit 64; }
[[ "${PEER}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$ ]] || { echo "--peer is required and must be a hostname" >&2; exit 64; }
[[ "${COORDINATOR}" != "${PEER}" ]] || { echo "coordinator and peer must differ" >&2; exit 64; }

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
SERVICE_SOURCE="${REPO_ROOT}/deploy/systemd/home-center-auto-update.service"
TIMER_SOURCE="${REPO_ROOT}/deploy/systemd/home-center-auto-update.timer"
UPDATER_SOURCE="${SCRIPT_DIR}/home-center-auto-update.sh"

for source in "${SERVICE_SOURCE}" "${TIMER_SOURCE}" "${UPDATER_SOURCE}"; do
    [[ -f "${source}" ]] || { echo "missing deployment file: ${source}" >&2; exit 1; }
done

bash -n "${UPDATER_SOURCE}"
install -m 0755 "${UPDATER_SOURCE}" /usr/local/sbin/home-center-auto-update
install -m 0644 "${SERVICE_SOURCE}" /etc/systemd/system/home-center-auto-update.service
install -m 0644 "${TIMER_SOURCE}" /etc/systemd/system/home-center-auto-update.timer
install -d -m 0755 /etc/home-center

ENV_TMP="$(mktemp)"
trap 'rm -f "${ENV_TMP}"' EXIT
cat >"${ENV_TMP}" <<EOF
HOME_CENTER_UPDATE_COORDINATOR=${COORDINATOR}
HOME_CENTER_UPDATE_PEER=${PEER}
HOME_CENTER_RELEASES_API=https://api.github.com/repos/ControlCenterSoft/home-center-stable/releases?per_page=30
EOF
install -m 0600 "${ENV_TMP}" /etc/home-center/auto-update.env

systemctl daemon-reload
systemctl enable --now home-center-auto-update.timer
systemctl start home-center-auto-update.service
systemctl --no-pager --full status home-center-auto-update.timer || true
systemctl --no-pager --full status home-center-auto-update.service || true
