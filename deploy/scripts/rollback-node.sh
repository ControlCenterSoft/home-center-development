#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

usage() { echo "usage: $0 --rollback-point PATH" >&2; exit 64; }
ROLLBACK_POINT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rollback-point) ROLLBACK_POINT=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$(id -u)" -eq 0 ]] || { echo ROOT_REQUIRED >&2; exit 65; }
[[ "$ROLLBACK_POINT" == /var/backups/home-center-deploy/* && -d "$ROLLBACK_POINT" && ! -L "$ROLLBACK_POINT" ]] || usage
[[ -f "$ROLLBACK_POINT/previous.release" ]] || { echo ROLLBACK_IDENTITY_MISSING >&2; exit 66; }
previous=$(tr -d '\r\n' <"$ROLLBACK_POINT/previous.release")
[[ "$previous" == /opt/home-center/releases/* && -d "$previous" && ! -L "$previous" ]] || { echo PREVIOUS_RELEASE_INVALID >&2; exit 66; }
[[ -f "$previous/VERSION" && -f "$previous/REVISION" ]] || { echo PREVIOUS_IDENTITY_MISSING >&2; exit 66; }

LOCK_DIR=/run/home-center-locks
install -d -m 0700 -o root -g root "$LOCK_DIR"
exec 9>"$LOCK_DIR/node-mutation.lock"
flock -n 9 || { echo HOME_CENTER_NODE_MUTATION_ALREADY_RUNNING >&2; exit 75; }

systemctl stop home-center.service || true
if [[ -f "$ROLLBACK_POINT/state-db.path" && -f "$ROLLBACK_POINT/state.sqlite3" ]]; then
  state_db=$(tr -d '\r\n' <"$ROLLBACK_POINT/state-db.path")
  [[ "$state_db" == /* ]] || { echo STATE_DB_PATH_INVALID >&2; exit 66; }
  install -m 0640 -o home-center -g home-center "$ROLLBACK_POINT/state.sqlite3" "$state_db"
  rm -f "${state_db}-wal" "${state_db}-shm"
fi
for unit in home-center.service home-center-backup.service home-center-backup.timer; do
  if [[ -f "$ROLLBACK_POINT/$unit.existed" && -f "$ROLLBACK_POINT/$unit" ]]; then
    install -m 0644 -o root -g root "$ROLLBACK_POINT/$unit" "/etc/systemd/system/$unit"
  fi
done
rm -f /opt/home-center/.current.rollback
ln -s "$previous" /opt/home-center/.current.rollback
mv -Tf /opt/home-center/.current.rollback /opt/home-center/current
systemctl daemon-reload
systemctl start home-center.service
systemctl is-active --quiet home-center.service || { echo ROLLBACK_SERVICE_NOT_ACTIVE >&2; exit 70; }

printf 'NODE_ROLLBACK=PASS\n'
printf 'RELEASE=%s\n' "$previous"
printf 'VERSION=%s\n' "$(tr -d '\r\n' <"$previous/VERSION")"
