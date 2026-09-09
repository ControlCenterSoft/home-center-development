#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
OUT=${1:-"$ROOT/dist"}
SOURCE_VERSION=$(python3 - "$ROOT/product/control-plane/src/home_center/__init__.py" <<'PY'
import re, sys
text=open(sys.argv[1], encoding='utf-8').read()
m=re.search(r'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"$', text, re.M)
if not m:
    raise SystemExit('version_not_found')
print(m.group(1))
PY
)
VERSION=${HOME_CENTER_VERSION:-$SOURCE_VERSION}
[[ "$VERSION" == "$SOURCE_VERSION" ]] || { echo VERSION_OVERRIDE_MISMATCH >&2; exit 66; }
REVISION=${HOME_CENTER_REVISION:-$(git -C "$ROOT" rev-parse HEAD)}
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || { echo REVISION_NOT_IMMUTABLE >&2; exit 66; }
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$REVISION" ]] || { echo RELEASE_REVISION_NOT_HEAD >&2; exit 66; }
if [[ "${HOME_CENTER_RELEASE_BUILD:-0}" == 1 ]]; then
  [[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || { echo RELEASE_WORKTREE_NOT_CLEAN >&2; exit 66; }
elif [[ "${HOME_CENTER_RELEASE_BUILD:-0}" != 0 ]]; then
  echo RELEASE_BUILD_MODE_REJECTED >&2
  exit 66
fi
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" show -s --format=%ct "$REVISION")}
[[ "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]{8,11}$ ]] || { echo SOURCE_DATE_EPOCH_REJECTED >&2; exit 66; }

STAGE=$(mktemp -d)
trap 'rm -rf -- "$STAGE"' EXIT
mkdir -p "$OUT" "$STAGE/home_center" "$STAGE/web" "$STAGE/contracts" "$STAGE/deploy"

cp -a "$ROOT/product/control-plane/src/home_center/." "$STAGE/home_center/"
find "$STAGE/home_center" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find "$STAGE/home_center" -type d -name __pycache__ -prune -exec rm -rf {} +
cp -a "$ROOT/product/web/static/." "$STAGE/web/"
cp -a "$ROOT/contracts/." "$STAGE/contracts/"
cp "$ROOT/deploy/runtime/run.py" "$ROOT/deploy/runtime/backup-run.py" "$STAGE/"
cp "$ROOT/deploy/scripts/install-node.sh" \
   "$ROOT/deploy/scripts/install-node-core.sh" \
   "$ROOT/deploy/scripts/rollback-node.sh" \
   "$ROOT/deploy/scripts/bootstrap-two-node.sh" \
   "$STAGE/deploy/"
cp "$ROOT/deploy/systemd/home-center.service" \
   "$ROOT/deploy/systemd/home-center-backup.service" \
   "$ROOT/deploy/systemd/home-center-backup.timer" \
   "$STAGE/deploy/"

printf '%s\n' "$VERSION" >"$STAGE/VERSION"
printf '%s\n' "$REVISION" >"$STAGE/REVISION"
cat >"$STAGE/DEPLOYMENT-ARTIFACT.json" <<EOF
{"schema":"home-center.deployment-artifact.v1","version":"$VERSION","revision":"$REVISION","topology_bindings":"external"}
EOF

# Deployment artifacts must never embed a concrete environment or secret material.
if grep -RIEq --exclude='MANIFEST.sha256' \
  'S-1-5-21-[0-9]+-[0-9]+-[0-9]+|(^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})([^0-9]|$)|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' \
  "$STAGE"; then
  echo DEPLOYMENT_ARTIFACT_PRIVACY_BOUNDARY_REJECTED >&2
  exit 66
fi

find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/deploy/install-node.sh" "$STAGE/deploy/rollback-node.sh" "$STAGE/deploy/bootstrap-two-node.sh"

(
  cd "$STAGE"
  find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum >MANIFEST.sha256
)

ARCHIVE="$OUT/home-center-${VERSION}-linux-amd64.tar.gz"
SIDECAR="$ARCHIVE.sha256"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  -C "$STAGE" -cf - . | gzip -n -9 >"$ARCHIVE"
(
  cd "$OUT"
  sha256sum "$(basename "$ARCHIVE")" >"$(basename "$SIDECAR")"
)

printf 'DEPLOYMENT_ARTIFACT=%s\n' "$ARCHIVE"
printf 'DEPLOYMENT_SHA256=%s\n' "$(sha256sum "$ARCHIVE" | awk '{print $1}')"
printf 'DEPLOYMENT_BYTES=%s\n' "$(stat -c %s "$ARCHIVE")"
