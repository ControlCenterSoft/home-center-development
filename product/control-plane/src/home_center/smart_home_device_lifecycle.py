"""Plan-only Smart Home device lifecycle foundation for Home Center 0.66.

The module combines the current 0.65 ZigBee/MQTT observation with local Home Center
metadata to produce truthful Cozy/Full read models and exact-bound rename/room-move
plans. It never performs a provider command, pairing/unpairing, infrastructure
mutation, external publication or automatic recovery.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import re

from .util import canonical_json
from .zigbee_mqtt import EvidenceState, SmartHomeDeviceObservation, ZigbeeMqttInventorySnapshot

DEVICE_STATE_SCHEMA = "home-center.smart-home-device-state.v1"
DEVICE_CHANGE_PLAN_SCHEMA = "home-center.smart-home-device-change-plan.v1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_NAME = re.compile(r"[^\x00-\x1f\x7f]{1,96}\Z")
MAX_DIAGNOSTICS = 16

_CAPABILITY_FAMILY = {
    "light": "lighting",
    "switch": "switch",
    "sensor": "sensor",
    "temperature": "climate",
    "humidity": "climate",
    "thermostat": "climate",
    "climate": "climate",
    "lock": "security",
    "contact": "security",
    "motion": "security",
    "cover": "cover",
    "blind": "cover",
    "media": "media",
    "speaker": "media",
}


class SmartHomeLifecycleError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DeviceHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STALE = "stale"
    UNKNOWN = "unknown"


class DeviceChangeKind(StrEnum):
    RENAME = "rename"
    MOVE_ROOM = "move-room"


@dataclass(frozen=True, slots=True)
class SmartHomeLocalProfile:
    device_id: str
    generation: int
    display_name: str
    room_id: str | None

    def __post_init__(self) -> None:
        _require_id(self.device_id, "smart_home_profile_device_id_invalid")
        if type(self.generation) is not int or self.generation < 1:
            raise SmartHomeLifecycleError("smart_home_profile_generation_invalid")
        _require_name(self.display_name, "smart_home_profile_name_invalid")
        if self.room_id is not None:
            _require_id(self.room_id, "smart_home_profile_room_id_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "device_id": self.device_id,
            "generation": self.generation,
            "display_name": self.display_name,
            "room_id": self.room_id,
        }


@dataclass(frozen=True, slots=True)
class SmartHomeDeviceState:
    device_id: str
    inventory_sha256: str
    profile_generation: int
    display_name: str
    room_id: str | None
    observed_room_id: str | None
    capabilities: tuple[str, ...]
    capability_families: tuple[str, ...]
    health: DeviceHealth
    diagnostics: tuple[str, ...]
    drift_detected: bool
    observed_at_epoch: int
    battery_percent: int | None
    link_quality: int | None
    schema: str = field(default=DEVICE_STATE_SCHEMA, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "device_id": self.device_id,
            "inventory_sha256": self.inventory_sha256,
            "profile_generation": self.profile_generation,
            "display_name": self.display_name,
            "room_id": self.room_id,
            "observed_room_id": self.observed_room_id,
            "capabilities": list(self.capabilities),
            "capability_families": list(self.capability_families),
            "health": self.health.value,
            "diagnostics": list(self.diagnostics),
            "drift_detected": self.drift_detected,
            "observed_at_epoch": self.observed_at_epoch,
            "battery_percent": self.battery_percent,
            "link_quality": self.link_quality,
            "mutation_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class SmartHomeDeviceChangePlan:
    plan_id: str
    change: DeviceChangeKind
    device_id: str
    inventory_sha256: str
    expected_profile_generation: int
    before_display_name: str
    before_room_id: str | None
    target_display_name: str
    target_room_id: str | None
    explicit_confirmation_required: bool
    recovery_snapshot_required: bool
    schema: str = field(default=DEVICE_CHANGE_PLAN_SCHEMA, init=False)
    execution_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    device_state_mutation_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "change": self.change.value,
            "device_id": self.device_id,
            "inventory_sha256": self.inventory_sha256,
            "expected_profile_generation": self.expected_profile_generation,
            "before": {"display_name": self.before_display_name, "room_id": self.before_room_id},
            "target": {"display_name": self.target_display_name, "room_id": self.target_room_id},
            "explicit_confirmation_required": self.explicit_confirmation_required,
            "recovery_snapshot_required": self.recovery_snapshot_required,
            "execution_authorized": False,
            "provider_execution_authorized": False,
            "device_state_mutation_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _require_id(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise SmartHomeLifecycleError(code)
    return value


def _require_name(value: object, code: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None or value != value.strip():
        raise SmartHomeLifecycleError(code)
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _find_observation(snapshot: ZigbeeMqttInventorySnapshot, device_id: str) -> SmartHomeDeviceObservation:
    if not isinstance(snapshot, ZigbeeMqttInventorySnapshot):
        raise SmartHomeLifecycleError("smart_home_inventory_invalid")
    _require_id(device_id, "smart_home_device_id_invalid")
    matches = [item for item in snapshot.devices if item.device_id == device_id]
    if len(matches) != 1:
        raise SmartHomeLifecycleError("smart_home_device_not_found" if not matches else "smart_home_device_duplicate")
    return matches[0]


def _families(capabilities: tuple[str, ...]) -> tuple[str, ...]:
    families: set[str] = set()
    for capability in capabilities:
        root = re.split(r"[._-]", capability, maxsplit=1)[0]
        families.add(_CAPABILITY_FAMILY.get(root, "other"))
    return tuple(sorted(families))


def build_device_state(*, snapshot: ZigbeeMqttInventorySnapshot, profile: SmartHomeLocalProfile) -> SmartHomeDeviceState:
    if not isinstance(profile, SmartHomeLocalProfile):
        raise SmartHomeLifecycleError("smart_home_profile_invalid")
    observation = _find_observation(snapshot, profile.device_id)

    diagnostics: list[str] = []
    if snapshot.state is EvidenceState.UNAVAILABLE or observation.evidence_state is EvidenceState.UNAVAILABLE:
        health = DeviceHealth.UNKNOWN
        diagnostics.append("state-unavailable")
    elif snapshot.state is EvidenceState.STALE or observation.evidence_state is EvidenceState.STALE:
        health = DeviceHealth.STALE
        diagnostics.append("state-stale")
    else:
        health = DeviceHealth.HEALTHY
        if observation.battery_percent is not None and observation.battery_percent <= 10:
            diagnostics.append("low-battery")
        if observation.link_quality is not None and observation.link_quality <= 30:
            diagnostics.append("weak-link")
        if diagnostics:
            health = DeviceHealth.DEGRADED

    drift = (
        snapshot.state is EvidenceState.CURRENT
        and observation.evidence_state is EvidenceState.CURRENT
        and profile.room_id != observation.room_id
    )
    if drift:
        diagnostics.append("room-drift")
        if health is DeviceHealth.HEALTHY:
            health = DeviceHealth.DEGRADED

    diagnostics = sorted(set(diagnostics))
    if len(diagnostics) > MAX_DIAGNOSTICS:
        raise SmartHomeLifecycleError("smart_home_diagnostics_too_many")

    return SmartHomeDeviceState(
        device_id=profile.device_id,
        inventory_sha256=snapshot.inventory_sha256,
        profile_generation=profile.generation,
        display_name=profile.display_name,
        room_id=profile.room_id,
        observed_room_id=observation.room_id,
        capabilities=observation.capabilities,
        capability_families=_families(observation.capabilities),
        health=health,
        diagnostics=tuple(diagnostics),
        drift_detected=drift,
        observed_at_epoch=observation.observed_at_epoch,
        battery_percent=observation.battery_percent,
        link_quality=observation.link_quality,
    )


def build_change_plan(
    *,
    snapshot: ZigbeeMqttInventorySnapshot,
    profile: SmartHomeLocalProfile,
    change: DeviceChangeKind,
    target_display_name: str | None = None,
    target_room_id: str | None = None,
) -> SmartHomeDeviceChangePlan:
    if not isinstance(profile, SmartHomeLocalProfile):
        raise SmartHomeLifecycleError("smart_home_profile_invalid")
    if snapshot.state is not EvidenceState.CURRENT:
        raise SmartHomeLifecycleError("smart_home_change_inventory_not_current")
    observation = _find_observation(snapshot, profile.device_id)
    if observation.evidence_state is not EvidenceState.CURRENT:
        raise SmartHomeLifecycleError("smart_home_change_device_not_current")
    if not isinstance(change, DeviceChangeKind):
        raise SmartHomeLifecycleError("smart_home_change_kind_invalid")

    next_name = profile.display_name
    next_room = profile.room_id
    if change is DeviceChangeKind.RENAME:
        if target_room_id is not None:
            raise SmartHomeLifecycleError("smart_home_rename_room_forbidden")
        next_name = _require_name(target_display_name, "smart_home_target_name_invalid")
        if next_name == profile.display_name:
            raise SmartHomeLifecycleError("smart_home_change_noop")
    else:
        if target_display_name is not None:
            raise SmartHomeLifecycleError("smart_home_move_name_forbidden")
        next_room = _require_id(target_room_id, "smart_home_target_room_invalid") if target_room_id is not None else None
        if next_room == profile.room_id:
            raise SmartHomeLifecycleError("smart_home_change_noop")

    material = {
        "change": change.value,
        "device_id": profile.device_id,
        "inventory_sha256": snapshot.inventory_sha256,
        "expected_profile_generation": profile.generation,
        "before": {"display_name": profile.display_name, "room_id": profile.room_id},
        "target": {"display_name": next_name, "room_id": next_room},
        "explicit_confirmation_required": True,
        "recovery_snapshot_required": True,
    }
    return SmartHomeDeviceChangePlan(
        plan_id="hc66-change-" + _digest(material)[:24],
        change=change,
        device_id=profile.device_id,
        inventory_sha256=snapshot.inventory_sha256,
        expected_profile_generation=profile.generation,
        before_display_name=profile.display_name,
        before_room_id=profile.room_id,
        target_display_name=next_name,
        target_room_id=next_room,
        explicit_confirmation_required=True,
        recovery_snapshot_required=True,
    )


def project_cozy(state: SmartHomeDeviceState) -> dict[str, object]:
    if not isinstance(state, SmartHomeDeviceState):
        raise SmartHomeLifecycleError("smart_home_cozy_state_invalid")
    message = {
        DeviceHealth.HEALTHY: "Устройство работает нормально",
        DeviceHealth.DEGRADED: "Устройство требует внимания",
        DeviceHealth.STALE: "Данные об устройстве устарели",
        DeviceHealth.UNKNOWN: "Не удалось подтвердить состояние устройства",
    }[state.health]
    return {
        "schema": "home-center.cozy-smart-home-device.v1",
        "device_id": state.device_id,
        "name": state.display_name,
        "room_id": state.room_id,
        "status": state.health.value,
        "message": message,
        "capability_families": list(state.capability_families),
        "attention_required": state.health is not DeviceHealth.HEALTHY,
        "mutation_authorized": False,
    }


def project_full(state: SmartHomeDeviceState) -> dict[str, object]:
    if not isinstance(state, SmartHomeDeviceState):
        raise SmartHomeLifecycleError("smart_home_full_state_invalid")
    result = state.to_dict()
    result["schema"] = "home-center.full-smart-home-device.v1"
    return result


__all__ = [
    "DEVICE_CHANGE_PLAN_SCHEMA",
    "DEVICE_STATE_SCHEMA",
    "DeviceChangeKind",
    "DeviceHealth",
    "SmartHomeDeviceChangePlan",
    "SmartHomeDeviceState",
    "SmartHomeLifecycleError",
    "SmartHomeLocalProfile",
    "build_change_plan",
    "build_device_state",
    "project_cozy",
    "project_full",
]
