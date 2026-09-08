# Переиспользуемая политика обновления Home Center на основе semantic version.
#
# Совместимость версий намеренно отделена от целостности артефактов.
# Deployment по-прежнему проверяет пути релиза, revisions, digest целевого артефакта,
# резервные копии, rollback, PKI, репликацию и sentinel-проверки защищённых сервисов.

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
    # Переход на X.0.0 разрешён с любой более старой semantic version. Остальные
    # релизы принимают любую более старую версию в пределах своей major-линейки.
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
