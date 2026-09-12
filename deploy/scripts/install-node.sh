#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: $0 --artifact PATH --sha256 HEX --node-name NAME --transaction-id ID --expected-current-release PATH --expected-current-version VERSION --expected-current-revision SHA" >&2
  exit 64
}

ARTIFACT="" SHA256="" NODE_NAME="" TRANSACTION_ID=""
EXPECTED_CURRENT_RELEASE="" EXPECTED_CURRENT_VERSION="" EXPECTED_CURRENT_REVISION=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact) ARTIFACT=${2:-}; shift 2 ;;
    --sha256) SHA256=${2:-}; shift 2 ;;
    --node-name) NODE_NAME=${2:-}; shift 2 ;;
    --transaction-id) TRANSACTION_ID=${2:-}; shift 2 ;;
    --expected-current-release) EXPECTED_CURRENT_RELEASE=${2:-}; shift 2 ;;
    --expected-current-version) EXPECTED_CURRENT_VERSION=${2:-}; shift 2 ;;
    --expected-current-revision) EXPECTED_CURRENT_REVISION=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo ROOT_REQUIRED >&2; exit 65; }
[[ -f "$ARTIFACT" && ! -L "$ARTIFACT" ]] || usage
[[ "$SHA256" =~ ^[0-9a-f]{64}$ ]] || usage
[[ "$NODE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$ ]] || usage
[[ "$TRANSACTION_ID" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$ ]] || usage
[[ "$EXPECTED_CURRENT_RELEASE" == /opt/home-center/releases/* ]] || usage
[[ "$EXPECTED_CURRENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
[[ "$EXPECTED_CURRENT_REVISION" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "$(hostname -s)" == "$NODE_NAME" ]] || { echo NODE_IDENTITY_MISMATCH >&2; exit 65; }
[[ "$(sha256sum "$ARTIFACT" | awk '{print $1}')" == "$SHA256" ]] || { echo ARTIFACT_CHECKSUM_MISMATCH >&2; exit 66; }

archive_list=$(tar -tzf "$ARTIFACT")
if grep -Eq '(^/|(^|/)\.\.(/|$))' <<<"$archive_list"; then
  echo UNSAFE_ARCHIVE_PATH >&2
  exit 66
fi
if ! python3 - "$ARTIFACT" <<'PY'
import sys
import tarfile

try:
    with tarfile.open(sys.argv[1], "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise SystemExit(1)
        if any(not (member.isfile() or member.isdir()) for member in members):
            raise SystemExit(1)
except (OSError, tarfile.TarError):
    raise SystemExit(1)
PY
then
  echo UNSAFE_ARCHIVE_ENTRY_TYPE >&2
  exit 66
fi
for required in ./VERSION ./REVISION ./MANIFEST.sha256 ./run.py ./home_center ./web ./deploy/home-center.service; do
  grep -Eq "^${required//./\.}(/|$)" <<<"$archive_list" || { echo "REQUIRED_ENTRY_MISSING:$required" >&2; exit 66; }
done

VERSION=$(tar -xOf "$ARTIFACT" ./VERSION | tr -d '\r\n')
REVISION=$(tar -xOf "$ARTIFACT" ./REVISION | tr -d '\r\n')
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo INVALID_VERSION >&2; exit 66; }
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || { echo INVALID_REVISION >&2; exit 66; }

CURRENT=/opt/home-center/current
[[ -L "$CURRENT" ]] || { echo CURRENT_RELEASE_NOT_SYMLINK >&2; exit 66; }
previous=$(readlink -f "$CURRENT")
[[ "$previous" == "$EXPECTED_CURRENT_RELEASE" && -d "$previous" ]] || { echo CURRENT_RELEASE_CHANGED >&2; exit 66; }
[[ -f "$previous/VERSION" && -f "$previous/REVISION" ]] || { echo CURRENT_IDENTITY_MISSING >&2; exit 66; }
previous_version=$(tr -d '\r\n' <"$previous/VERSION")
previous_revision=$(tr -d '\r\n' <"$previous/REVISION")
[[ "$previous_version" == "$EXPECTED_CURRENT_VERSION" && "$previous_revision" == "$EXPECTED_CURRENT_REVISION" ]] || { echo CURRENT_IDENTITY_CHANGED >&2; exit 66; }

LOCK_DIR=/run/home-center-locks
LOCK_FILE=$LOCK_DIR/node-mutation.lock
install -d -m 0700 -o root -g root "$LOCK_DIR"
exec 9>"$LOCK_FILE"
flock -n 9 || { echo HOME_CENTER_NODE_MUTATION_ALREADY_RUNNING >&2; exit 75; }

RELEASE=/opt/home-center/releases/${VERSION}-${REVISION:0:12}-${SHA256:0:12}
BACKUP=/var/backups/home-center-deploy/${TRANSACTION_ID}-${NODE_NAME}
TRANSACTION_DIR=/var/lib/home-center-deploy/transactions
TRANSACTION_FILE=$TRANSACTION_DIR/${TRANSACTION_ID}-${NODE_NAME}.json
STAGE=$(mktemp -d /opt/home-center/releases/.stage.XXXXXX)
cleanup() { rm -rf -- "$STAGE"; }
trap cleanup EXIT
install -d -m 0700 -o root -g root "$BACKUP" "$TRANSACTION_DIR"

printf '%s\n' "$previous" >"$BACKUP/previous.release"
printf '%s\n' "$previous_version" >"$BACKUP/previous.version"
printf '%s\n' "$previous_revision" >"$BACKUP/previous.revision"
for unit in home-center.service home-center-backup.service home-center-backup.timer; do
  if [[ -f "/etc/systemd/system/$unit" && ! -L "/etc/systemd/system/$unit" ]]; then
    cp -a "/etc/systemd/system/$unit" "$BACKUP/$unit"
    : >"$BACKUP/$unit.existed"
  fi
done

state_db=$(python3 - <<'PY'
import json
from pathlib import Path
p=Path('/etc/home-center/config.json')
raw=json.loads(p.read_text(encoding='utf-8'))
value=raw.get('state_db')
if not isinstance(value, str) or not value.startswith('/'):
    raise SystemExit(66)
print(value)
PY
)
if [[ -f "$state_db" && ! -L "$state_db" ]]; then
  printf '%s\n' "$state_db" >"$BACKUP/state-db.path"
  python3 - "$state_db" "$BACKUP/state.sqlite3" <<'PY'
import sqlite3, sys
source, target=sys.argv[1:]
src=sqlite3.connect(f'file:{source}?mode=ro', uri=True, timeout=10)
dst=sqlite3.connect(target, timeout=10)
try:
    src.backup(dst)
    dst.commit()
finally:
    dst.close(); src.close()
PY
  chmod 0600 "$BACKUP/state.sqlite3"
fi

tar -xzf "$ARTIFACT" -C "$STAGE"
(
  cd "$STAGE"
  sha256sum -c MANIFEST.sha256 >/dev/null
)
[[ "$(tr -d '\r\n' <"$STAGE/VERSION")" == "$VERSION" ]] || { echo STAGED_VERSION_MISMATCH >&2; exit 66; }
[[ "$(tr -d '\r\n' <"$STAGE/REVISION")" == "$REVISION" ]] || { echo STAGED_REVISION_MISMATCH >&2; exit 66; }

rollback() {
  set +e
  systemctl stop home-center.service >/dev/null 2>&1 || true
  if [[ -f "$BACKUP/state-db.path" && -f "$BACKUP/state.sqlite3" ]]; then
    restore_state=$(cat "$BACKUP/state-db.path")
    install -m 0640 -o home-center -g home-center "$BACKUP/state.sqlite3" "$restore_state" >/dev/null 2>&1 || true
    rm -f "${restore_state}-wal" "${restore_state}-shm" >/dev/null 2>&1 || true
  fi
  for unit in home-center.service home-center-backup.service home-center-backup.timer; do
    if [[ -f "$BACKUP/$unit.existed" ]]; then
      install -m 0644 -o root -g root "$BACKUP/$unit" "/etc/systemd/system/$unit" >/dev/null 2>&1 || true
    fi
  done
  ln -sfn "$previous" /opt/home-center/.current.rollback
  mv -Tf /opt/home-center/.current.rollback "$CURRENT" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl start home-center.service >/dev/null 2>&1 || true
  set -e
}

if [[ ! -e "$RELEASE" ]]; then
  chown -R root:root "$STAGE"
  find "$STAGE" -type d -exec chmod 0755 {} +
  find "$STAGE" -type f -exec chmod 0644 {} +
  chmod 0755 "$STAGE/deploy/install-node.sh" "$STAGE/deploy/rollback-node.sh" "$STAGE/deploy/bootstrap-two-node.sh"
  mv "$STAGE" "$RELEASE"
  STAGE=$(mktemp -d /opt/home-center/releases/.stage.XXXXXX)
else
  [[ -d "$RELEASE" && ! -L "$RELEASE" ]] || { echo TARGET_RELEASE_PATH_UNSAFE >&2; exit 66; }
fi

systemctl stop home-center.service
install -m 0644 -o root -g root "$RELEASE/deploy/home-center.service" /etc/systemd/system/home-center.service
if [[ -f "$RELEASE/deploy/home-center-backup.service" ]]; then
  install -m 0644 -o root -g root "$RELEASE/deploy/home-center-backup.service" /etc/systemd/system/home-center-backup.service
fi
if [[ -f "$RELEASE/deploy/home-center-backup.timer" ]]; then
  install -m 0644 -o root -g root "$RELEASE/deploy/home-center-backup.timer" /etc/systemd/system/home-center-backup.timer
fi
ln -s "$RELEASE" /opt/home-center/.current.new
mv -Tf /opt/home-center/.current.new "$CURRENT"
systemctl daemon-reload
systemctl enable home-center.service >/dev/null
if [[ -f /etc/systemd/system/home-center-backup.timer ]]; then
  systemctl enable --now home-center-backup.timer >/dev/null || { rollback; echo BACKUP_TIMER_ACTIVATION_FAILED >&2; exit 70; }
fi

if ! systemctl start home-center.service; then
  rollback
  echo SERVICE_START_FAILED >&2
  exit 70
fi

ready=0
for _ in $(seq 1 15); do
  if systemctl is-active --quiet home-center.service; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then
  rollback
  echo SERVICE_READINESS_FAILED >&2
  exit 70
fi

if [[ "$(readlink -f "$CURRENT")" != "$RELEASE" ]]; then
  rollback
  echo CURRENT_SWITCH_VERIFICATION_FAILED >&2
  exit 70
fi

python3 - "$TRANSACTION_FILE" "$NODE_NAME" "$previous" "$RELEASE" "$BACKUP" "$SHA256" <<'PY'
import json, os, sys, tempfile
from datetime import datetime, timezone
path,node,source,target,backup,digest=sys.argv[1:]
data={
 'schema':'home-center.node-deployment.v1',
 'node':node,
 'source_release':source,
 'target_release':target,
 'rollback_point':backup,
 'sha256':digest,
 'completed_at':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
 'status':'succeeded',
}
os.makedirs(os.path.dirname(path), exist_ok=True)
fd,tmp=tempfile.mkstemp(prefix='.transaction.', dir=os.path.dirname(path), text=True)
try:
    with os.fdopen(fd,'w',encoding='utf-8') as f:
        json.dump(data,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp,0o600); os.replace(tmp,path)
finally:
    try: os.unlink(tmp)
    except FileNotFoundError: pass
PY

printf 'NODE_DEPLOYMENT=PASS\n'
printf 'NODE=%s\n' "$NODE_NAME"
printf 'VERSION=%s\n' "$VERSION"
printf 'REVISION=%s\n' "$REVISION"
printf 'RELEASE=%s\n' "$RELEASE"
printf 'ROLLBACK_POINT=%s\n' "$BACKUP"
