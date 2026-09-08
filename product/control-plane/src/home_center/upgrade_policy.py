# Reusable Home Center semantic-version upgrade policy.
#
# Version compatibility is deliberately separate from artifact integrity.
# Deployment still verifies release paths, revisions, target artifact digests,
# backups, rollback, PKI, replication and protected-service sentinels.

from __future__ import annotations

import re

_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class UpgradePolicyError(ValueError):
    pass


def parse_version(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise UpgradePolicyError("upgrade_version_rejected")
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise UpgradePolicyError("upgrade_version_rejected")
    return tuple(int(part) for part in match.groups())


def is_upgrade_allowed(source_version: str, target_version: str) -> bool:
    # X.0.0 bridges every older semantic version. Other releases accept every
    # older version in their own major line.
    try:
        source = parse_version(source_version)
        target = parse_version(target_version)
    except UpgradePolicyError:
        return False
    if source >= target:
        return False
    if target[1] == 0 and target[2] == 0:
        return True
    return source[0] == target[0]
