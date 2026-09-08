"""Планирование обновления по точной идентичности без полномочий на загрузку или установку."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
PRODUCTION_ACTIVATION_ENABLED = False


class UpgradeEngineError(ValueError):
    pass


def _version(value: str) -> tuple[int, int, int]:
    if SEMVER.fullmatch(value) is None:
        raise UpgradeEngineError("invalid_version")
    return tuple(int(item) for item in value.split("."))  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class ReleaseIdentity:
    version: str
    revision: str
    artifact_sha256: str

    def validate(self) -> None:
        _version(self.version)
        if HEX40.fullmatch(self.revision) is None or HEX64.fullmatch(self.artifact_sha256) is None:
            raise UpgradeEngineError("invalid_release_identity")

    def to_dict(self) -> dict[str, str]:
        return {
            "version": self.version,
            "revision": self.revision,
            "artifact_sha256": self.artifact_sha256,
        }


@dataclass(frozen=True, slots=True)
class UpgradePlan:
    current: ReleaseIdentity
    target: ReleaseIdentity
    state: str
    steps: tuple[str, ...]
    production_activation_enabled: bool = False
    schema: str = field(default="home-center.upgrade-plan.v1", init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "current": self.current.to_dict(),
            "target": self.target.to_dict(),
            "state": self.state,
            "steps": list(self.steps),
            "production_activation_enabled": self.production_activation_enabled,
        }


class UpgradeEngine:
    def plan(self, *, current: ReleaseIdentity, target: ReleaseIdentity) -> UpgradePlan:
        current.validate()
        target.validate()
        if _version(target.version) <= _version(current.version):
            raise UpgradeEngineError("target_not_newer")
        return UpgradePlan(
            current=current,
            target=target,
            state="planned",
            steps=("preflight", "backup", "verify", "canary", "soak", "rollout", "accept"),
        )
