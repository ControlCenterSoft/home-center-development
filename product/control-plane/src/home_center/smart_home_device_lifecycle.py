"""Fail-closed Smart Home device lifecycle foundation for Home Center 0.66.

The 0.66 foundation consumes the exact ZigBee/MQTT inventory introduced in 0.65 and
builds read-only lifecycle/drift evidence plus plan-only rename/room-assignment changes.
It deliberately performs no provider call, pairing, device mutation, configuration
restore, infrastructure mutation, or external publication.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import re

from .util import canonical_json
from .zigbee_mqtt import EvidenceState, SmartHomeDeviceObservation, ZigbeeMqttInventorySnapshot

SCHEMA_DESIRED_STATE = "home-center.smart-home-device-desired-state.v1"
SCHEMA_LIFECYCLE_VIEW = "home-center.smart-home-device-lifecycle-view.v1"
SCHEMA_CHANGE_PLAN = "home-center.smart-home-device-change-plan.v1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_DISPLAY_NAME = 96
MAX_DRIFT_REASONS = 16


class SmartHomeDeviceLifecycleError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DeviceLifecycleHealth(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


class DeviceDriftState(StrEnum):
    IN_SYNC = "in-sync"
    DRIFTED = "drifted"
    UNKNOWN = "unknown"


class DeviceChangeKind(StrEnum):
    RENAME = "rename"
    ASSIGN_ROOM = "assign-room"


@dataclass(frozen=True, slots=True)
class SmartHomeDeviceDesiredState:
    device_id: str
    generation: int
    display_name: str
    room_id: str | None
    expected_capabilities: tuple[str, ...]
    configuration_sha256: str | None = None
    schema: str = field(default=SCHEMA_DESIRED_STATE, init=False)

    def __post_init__(self) -> None:
        _require_id(self.device_id, "device_id")
        if type(self.generation) is not int or self.generation < 1:
            raise SmartHomeDeviceLifecycleError("device_desired_generation_invalid")
        _require_display_name(self.display_name)
        if self.room_id is not None:
            _require_id(self.room_id, "room_id")
        if not isinstance(self.expected_capabilities, tuple) or not self.expected_capabilities:
            raise SmartHomeDeviceLifecycleError("device_expected_capabilities_required")
        if tuple(sorted(set(self.expected_capabilities))) != self.expected_capabilities:
            raise SmartHomeDeviceLifecycleError("device_expected_capabilities_not_canonical")
        if self.configuration_sha256 is not None:
            _require_sha256(self.configuration_sha256, "device_configuration_digest_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "device_id": self.device_id,
            "generation": self.generation,
            "display_name": self.display_name,
            "room_id": self.room_id,
            "expected_capabilities": list(self.expected_capabilities),
            "configuration_sha256": self.configuration_sha256,
        }


@dataclass(frozen=True, slots=True)
class SmartHomeDeviceLifecycleView:
    device_id: str
    coordinator_id: str
    inventory_sha256: str
    desired_generation: int
    health: DeviceLifecycleHealth
    drift_state: DeviceDriftState
    drift_reasons: tuple[str, ...]
    observed_room_id: str | None
    desired_room_id: str | None
    observed_capabilities: tuple[str, ...]
    expected_capabilities: tuple[str, ...]
    battery_percent: int | None
    link_quality: int | None
    configuration_verification_available: bool
    schema: str = field(default=SCHEMA_LIFECYCLE_VIEW, init=False)
    lifecycle_mutation_authorized: bool = field(default=False, init=False)
    configuration_restore_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "device_id": self.device_id,
            "coordinator_id": self.coordinator_id,
            "inventory_sha256": self.inventory_sha256,
            "desired_generation": self.desired_generation,
            "health": self.health.value,
            "drift_state": self.drift_state.value,
            "drift_reasons": list(self.drift_reasons),
            "observed_room_id": self.observed_room_id,
            "desired_room_id": self.desired_room_id,
            "observed_capabilities": list(self.observed_capabilities),
            "expected_capabilities": list(self.expected_capabilities),
            "battery_percent": self.battery_percent,
            "link_quality": self.link_quality,
            "configuration_verification_available": self.configuration_verification_available,
            "lifecycle_mutation_authorized": False,
            "configuration_restore_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class SmartHomeDeviceChangePlan:
    plan_id: str
    change_kind: DeviceChangeKind
    device_id: str
    coordinator_id: str
    inventory_sha256: str
    desired_generation: int
    expected_observed_room_id: str | None
    proposed_display_name: str | None
    proposed_room_id: str | None
    schema: str = field(default=SCHEMA_CHANGE_PLAN, init=False)
    explicit_confirmation_required: bool = field(default=True, init=False)
    execution_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "change_kind": self.change_kind.value,
            "device_id": self.device_id,
            "coordinator_id": self.coordinator_id,
            "inventory_sha256": self.inventory_sha256,
            "desired_generation": self.desired_generation,
            "expected_observed_room_id": self.expected_observed_room_id,
            "proposed_display_name": self.proposed_display_name,
            "proposed_room_id": self.proposed_room_id,
            "explicit_confirmation_required": True,
            "execution_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _require_id(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise SmartHomeDeviceLifecycleError(f"{field_name}_invalid")
    return value


def _require_sha256(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SmartHomeDeviceLifecycleError(f"{field_name}_invalid")
    return value


def _require_display_name(value: object) -> str:
    if not isinstance(value, str):
        raise SmartHomeDeviceLifecycleError("device_display_name_invalid")
    normalized = value.strip()
    if normalized != value or not normalized or len(normalized) > MAX_DISPLAY_NAME:
        raise SmartHomeDeviceLifecycleError("device_display_name_invalid")
    if _CONTROL.search(value):
        raise SmartHomeDeviceLifecycleError("device_display_name_invalid")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _find_device(snapshot: ZigbeeMqttInventorySnapshot, device_id: str) -> SmartHomeDeviceObservation:
    _require_id(device_id, "device_id")
    matches = [item for item in snapshot.devices if item.device_id == device_id]
    if len(matches) != 1:
        raise SmartHomeDeviceLifecycleError("device_not_uniquely_observed")
    return matches[0]


def build_lifecycle_view(
    *,
    snapshot: ZigbeeMqttInventorySnapshot,
    desired: SmartHomeDeviceDesiredState,
) -> SmartHomeDeviceLifecycleView:
    if not isinstance(snapshot, ZigbeeMqttInventorySnapshot):
        raise SmartHomeDeviceLifecycleError("device_inventory_invalid")
    if not isinstance(desired, SmartHomeDeviceDesiredState):
        raise SmartHomeDeviceLifecycleError("device_desired_state_invalid")
    device = _find_device(snapshot, desired.device_id)

    if snapshot.state is EvidenceState.UNAVAILABLE or device.evidence_state is EvidenceState.UNAVAILABLE:
        health = DeviceLifecycleHealth.UNAVAILABLE
        drift_state = DeviceDriftState.UNKNOWN
        reasons = ("actual_state_unavailable",)
    elif snapshot.state is EvidenceState.STALE or device.evidence_state is EvidenceState.STALE:
        health = DeviceLifecycleHealth.STALE
        drift_state = DeviceDriftState.UNKNOWN
        reasons = ("actual_state_stale",)
    else:
        health = DeviceLifecycleHealth.CURRENT
        drift: list[str] = []
        if device.room_id != desired.room_id:
            drift.append("room_mismatch")
        if device.capabilities != desired.expected_capabilities:
            drift.append("capability_mismatch")
        if desired.configuration_sha256 is not None:
            drift.append("configuration_verification_unavailable")
        reasons = tuple(drift[:MAX_DRIFT_REASONS])
        drift_state = DeviceDriftState.DRIFTED if reasons else DeviceDriftState.IN_SYNC

    return SmartHomeDeviceLifecycleView(
        device_id=device.device_id,
        coordinator_id=device.coordinator_id,
        inventory_sha256=snapshot.inventory_sha256,
        desired_generation=desired.generation,
        health=health,
        drift_state=drift_state,
        drift_reasons=reasons,
        observed_room_id=device.room_id,
        desired_room_id=desired.room_id,
        observed_capabilities=device.capabilities,
        expected_capabilities=desired.expected_capabilities,
        battery_percent=device.battery_percent,
        link_quality=device.link_quality,
        configuration_verification_available=False,
    )


def build_device_change_plan(
    *,
    snapshot: ZigbeeMqttInventorySnapshot,
    desired: SmartHomeDeviceDesiredState,
    change_kind: DeviceChangeKind,
    proposed_display_name: str | None = None,
    proposed_room_id: str | None = None,
) -> SmartHomeDeviceChangePlan:
    if not isinstance(snapshot, ZigbeeMqttInventorySnapshot):
        raise SmartHomeDeviceLifecycleError("device_change_inventory_invalid")
    if snapshot.state is not EvidenceState.CURRENT:
        raise SmartHomeDeviceLifecycleError("device_change_inventory_not_current")
    if not isinstance(desired, SmartHomeDeviceDesiredState):
        raise SmartHomeDeviceLifecycleError("device_change_desired_state_invalid")
    if not isinstance(change_kind, DeviceChangeKind):
        raise SmartHomeDeviceLifecycleError("device_change_kind_invalid")
    device = _find_device(snapshot, desired.device_id)
    if device.evidence_state is not EvidenceState.CURRENT:
        raise SmartHomeDeviceLifecycleError("device_change_device_not_current")

    if change_kind is DeviceChangeKind.RENAME:
        if proposed_room_id is not None:
            raise SmartHomeDeviceLifecycleError("device_change_room_forbidden_for_rename")
        if proposed_display_name is None:
            raise SmartHomeDeviceLifecycleError("device_change_display_name_required")
        _require_display_name(proposed_display_name)
    else:
        if proposed_display_name is not None:
            raise SmartHomeDeviceLifecycleError("device_change_name_forbidden_for_room_assignment")
        if proposed_room_id is None:
            raise SmartHomeDeviceLifecycleError("device_change_room_required")
        _require_id(proposed_room_id, "proposed_room_id")
        if proposed_room_id == device.room_id:
            raise SmartHomeDeviceLifecycleError("device_change_room_already_current")

    payload = {
        "change_kind": change_kind.value,
        "device_id": device.device_id,
        "coordinator_id": device.coordinator_id,
        "inventory_sha256": snapshot.inventory_sha256,
        "desired_generation": desired.generation,
        "expected_observed_room_id": device.room_id,
        "proposed_display_name": proposed_display_name,
        "proposed_room_id": proposed_room_id,
    }
    return SmartHomeDeviceChangePlan(
        plan_id=f"hc66-change-{_digest(payload)[:24]}",
        change_kind=change_kind,
        device_id=device.device_id,
        coordinator_id=device.coordinator_id,
        inventory_sha256=snapshot.inventory_sha256,
        desired_generation=desired.generation,
        expected_observed_room_id=device.room_id,
        proposed_display_name=proposed_display_name,
        proposed_room_id=proposed_room_id,
    )
