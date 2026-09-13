"""Plan-only ZigBee/MQTT foundation for Home Center 0.65.

This module models bounded, content-addressed coordinator/device observations and
non-authorizing pairing/unpairing/backup plans. It deliberately grants no provider,
device, infrastructure, external-publication or HA authority.

A physical coordinator is never presented as highly available. All observed state is
freshness-bound and unknown/stale evidence fails closed instead of being rendered as
healthy/current.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import re
from typing import Iterable

from .util import canonical_json

SCHEMA_INVENTORY = "home-center.zigbee-mqtt-inventory-snapshot.v1"
SCHEMA_OPERATION_PLAN = "home-center.zigbee-mqtt-operation-plan.v1"
SCHEMA_BACKUP_PLAN = "home-center.zigbee-mqtt-backup-plan.v1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}\Z")
_CAPABILITY = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,7}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

MAX_CAPABILITIES_PER_DEVICE = 32
MAX_DEVICES = 512
MAX_FRESHNESS_SECONDS = 3600
MAX_PAIRING_WINDOW_SECONDS = 300


class ZigbeeMqttFoundationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CoordinatorKind(StrEnum):
    ZIGBEE = "zigbee"
    MQTT_BRIDGE = "mqtt-bridge"


class CoordinatorTransport(StrEnum):
    USB = "usb"
    SERIAL = "serial"
    TCP = "tcp"
    MQTT = "mqtt"


class EvidenceState(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


class PairingOperation(StrEnum):
    PAIR = "pair"
    UNPAIR = "unpair"


@dataclass(frozen=True, slots=True)
class CoordinatorObservation:
    coordinator_id: str
    kind: CoordinatorKind
    transport: CoordinatorTransport
    observed_at_epoch: int
    firmware_version: str | None = None
    endpoint_fingerprint_sha256: str | None = None
    evidence_state: EvidenceState = EvidenceState.CURRENT
    ha_supported: bool = field(default=False, init=False)
    automatic_failover_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _require_id(self.coordinator_id, "coordinator_id")
        if type(self.observed_at_epoch) is not int or self.observed_at_epoch < 0:
            raise ZigbeeMqttFoundationError("coordinator_observed_at_invalid")
        if self.firmware_version is not None and (
            not isinstance(self.firmware_version, str)
            or _VERSION.fullmatch(self.firmware_version) is None
        ):
            raise ZigbeeMqttFoundationError("coordinator_firmware_version_invalid")
        if self.endpoint_fingerprint_sha256 is not None and (
            not isinstance(self.endpoint_fingerprint_sha256, str)
            or _SHA256.fullmatch(self.endpoint_fingerprint_sha256) is None
        ):
            raise ZigbeeMqttFoundationError("coordinator_endpoint_fingerprint_invalid")
        if self.evidence_state is EvidenceState.UNAVAILABLE and (
            self.firmware_version is not None or self.endpoint_fingerprint_sha256 is not None
        ):
            raise ZigbeeMqttFoundationError("coordinator_unavailable_contains_evidence")

    @property
    def physical_single_coordinator(self) -> bool:
        return self.transport in {CoordinatorTransport.USB, CoordinatorTransport.SERIAL}

    def to_dict(self) -> dict[str, object]:
        return {
            "coordinator_id": self.coordinator_id,
            "kind": self.kind.value,
            "transport": self.transport.value,
            "observed_at_epoch": self.observed_at_epoch,
            "firmware_version": self.firmware_version,
            "endpoint_fingerprint_sha256": self.endpoint_fingerprint_sha256,
            "evidence_state": self.evidence_state.value,
            "physical_single_coordinator": self.physical_single_coordinator,
            "ha_supported": False,
            "automatic_failover_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class SmartHomeDeviceObservation:
    device_id: str
    coordinator_id: str
    observed_at_epoch: int
    capabilities: tuple[str, ...]
    room_id: str | None = None
    battery_percent: int | None = None
    link_quality: int | None = None
    evidence_state: EvidenceState = EvidenceState.CURRENT

    def __post_init__(self) -> None:
        _require_id(self.device_id, "device_id")
        _require_id(self.coordinator_id, "coordinator_id")
        if self.room_id is not None:
            _require_id(self.room_id, "room_id")
        if type(self.observed_at_epoch) is not int or self.observed_at_epoch < 0:
            raise ZigbeeMqttFoundationError("device_observed_at_invalid")
        if not isinstance(self.capabilities, tuple) or not self.capabilities:
            raise ZigbeeMqttFoundationError("device_capabilities_required")
        if len(self.capabilities) > MAX_CAPABILITIES_PER_DEVICE:
            raise ZigbeeMqttFoundationError("device_capabilities_too_many")
        normalized = tuple(sorted(set(self.capabilities)))
        if normalized != self.capabilities:
            raise ZigbeeMqttFoundationError("device_capabilities_not_canonical")
        for capability in self.capabilities:
            if not isinstance(capability, str) or _CAPABILITY.fullmatch(capability) is None:
                raise ZigbeeMqttFoundationError("device_capability_invalid")
        if self.battery_percent is not None and (
            type(self.battery_percent) is not int or not 0 <= self.battery_percent <= 100
        ):
            raise ZigbeeMqttFoundationError("device_battery_invalid")
        if self.link_quality is not None and (
            type(self.link_quality) is not int or not 0 <= self.link_quality <= 255
        ):
            raise ZigbeeMqttFoundationError("device_link_quality_invalid")
        if self.evidence_state is EvidenceState.UNAVAILABLE and any(
            value is not None for value in (self.room_id, self.battery_percent, self.link_quality)
        ):
            raise ZigbeeMqttFoundationError("device_unavailable_contains_telemetry")

    def to_dict(self) -> dict[str, object]:
        return {
            "device_id": self.device_id,
            "coordinator_id": self.coordinator_id,
            "observed_at_epoch": self.observed_at_epoch,
            "capabilities": list(self.capabilities),
            "room_id": self.room_id,
            "battery_percent": self.battery_percent,
            "link_quality": self.link_quality,
            "evidence_state": self.evidence_state.value,
        }


@dataclass(frozen=True, slots=True)
class ZigbeeMqttInventorySnapshot:
    coordinator: CoordinatorObservation
    devices: tuple[SmartHomeDeviceObservation, ...]
    generated_at_epoch: int
    freshness_seconds: int
    inventory_sha256: str
    state: EvidenceState
    schema: str = field(default=SCHEMA_INVENTORY, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    pairing_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "coordinator": self.coordinator.to_dict(),
            "devices": [device.to_dict() for device in self.devices],
            "generated_at_epoch": self.generated_at_epoch,
            "freshness_seconds": self.freshness_seconds,
            "inventory_sha256": self.inventory_sha256,
            "state": self.state.value,
            "mutation_authorized": False,
            "pairing_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class ZigbeeMqttOperationPlan:
    plan_id: str
    operation: PairingOperation
    coordinator_id: str
    inventory_sha256: str
    expected_device_id: str | None
    pairing_window_seconds: int | None
    physical_confirmation_required: bool
    backup_required_before_execution: bool
    schema: str = field(default=SCHEMA_OPERATION_PLAN, init=False)
    execution_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    device_state_mutation_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "operation": self.operation.value,
            "coordinator_id": self.coordinator_id,
            "inventory_sha256": self.inventory_sha256,
            "expected_device_id": self.expected_device_id,
            "pairing_window_seconds": self.pairing_window_seconds,
            "physical_confirmation_required": self.physical_confirmation_required,
            "backup_required_before_execution": self.backup_required_before_execution,
            "execution_authorized": False,
            "provider_execution_authorized": False,
            "device_state_mutation_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class ZigbeeMqttBackupPlan:
    plan_id: str
    coordinator_id: str
    inventory_sha256: str
    reason: str
    schema: str = field(default=SCHEMA_BACKUP_PLAN, init=False)
    backup_execution_authorized: bool = field(default=False, init=False)
    restore_execution_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "coordinator_id": self.coordinator_id,
            "inventory_sha256": self.inventory_sha256,
            "reason": self.reason,
            "backup_execution_authorized": False,
            "restore_execution_authorized": False,
            "external_publication_authorized": False,
        }


def _require_id(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ZigbeeMqttFoundationError(f"{field_name}_invalid")
    return value


def _content_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def build_inventory_snapshot(
    *,
    coordinator: CoordinatorObservation,
    devices: Iterable[SmartHomeDeviceObservation],
    now_epoch: int,
    freshness_seconds: int,
) -> ZigbeeMqttInventorySnapshot:
    if not isinstance(coordinator, CoordinatorObservation):
        raise ZigbeeMqttFoundationError("inventory_coordinator_invalid")
    if type(now_epoch) is not int or now_epoch < 0:
        raise ZigbeeMqttFoundationError("inventory_now_invalid")
    if type(freshness_seconds) is not int or not 1 <= freshness_seconds <= MAX_FRESHNESS_SECONDS:
        raise ZigbeeMqttFoundationError("inventory_freshness_invalid")
    device_items = tuple(devices)
    if len(device_items) > MAX_DEVICES:
        raise ZigbeeMqttFoundationError("inventory_devices_too_many")
    if any(not isinstance(device, SmartHomeDeviceObservation) for device in device_items):
        raise ZigbeeMqttFoundationError("inventory_device_invalid")
    device_items = tuple(sorted(device_items, key=lambda item: item.device_id))
    if len({item.device_id for item in device_items}) != len(device_items):
        raise ZigbeeMqttFoundationError("inventory_duplicate_device")
    if any(item.coordinator_id != coordinator.coordinator_id for item in device_items):
        raise ZigbeeMqttFoundationError("inventory_coordinator_binding_mismatch")
    if coordinator.observed_at_epoch > now_epoch or any(
        item.observed_at_epoch > now_epoch for item in device_items
    ):
        raise ZigbeeMqttFoundationError("inventory_future_evidence")

    states = [coordinator.evidence_state, *(item.evidence_state for item in device_items)]
    ages = [
        now_epoch - coordinator.observed_at_epoch,
        *(now_epoch - item.observed_at_epoch for item in device_items),
    ]
    if EvidenceState.UNAVAILABLE in states:
        state = EvidenceState.UNAVAILABLE
    elif EvidenceState.STALE in states or any(age > freshness_seconds for age in ages):
        state = EvidenceState.STALE
    else:
        state = EvidenceState.CURRENT

    digest_payload = {
        "coordinator": coordinator.to_dict(),
        "devices": [item.to_dict() for item in device_items],
        "generated_at_epoch": now_epoch,
        "freshness_seconds": freshness_seconds,
        "state": state.value,
    }
    return ZigbeeMqttInventorySnapshot(
        coordinator=coordinator,
        devices=device_items,
        generated_at_epoch=now_epoch,
        freshness_seconds=freshness_seconds,
        inventory_sha256=_content_sha256(digest_payload),
        state=state,
    )


def build_operation_plan(
    *,
    snapshot: ZigbeeMqttInventorySnapshot,
    operation: PairingOperation,
    expected_device_id: str | None = None,
    pairing_window_seconds: int | None = None,
) -> ZigbeeMqttOperationPlan:
    if not isinstance(snapshot, ZigbeeMqttInventorySnapshot):
        raise ZigbeeMqttFoundationError("operation_snapshot_invalid")
    if snapshot.state is not EvidenceState.CURRENT:
        raise ZigbeeMqttFoundationError("operation_inventory_not_current")
    if not isinstance(operation, PairingOperation):
        raise ZigbeeMqttFoundationError("operation_invalid")
    if operation is PairingOperation.PAIR:
        if expected_device_id is not None:
            _require_id(expected_device_id, "expected_device_id")
        if (
            type(pairing_window_seconds) is not int
            or not 1 <= pairing_window_seconds <= MAX_PAIRING_WINDOW_SECONDS
        ):
            raise ZigbeeMqttFoundationError("pairing_window_invalid")
        physical_confirmation_required = snapshot.coordinator.physical_single_coordinator
    else:
        _require_id(expected_device_id, "expected_device_id")
        if not any(item.device_id == expected_device_id for item in snapshot.devices):
            raise ZigbeeMqttFoundationError("unpair_device_not_observed")
        if pairing_window_seconds is not None:
            raise ZigbeeMqttFoundationError("unpair_pairing_window_forbidden")
        physical_confirmation_required = False

    payload = {
        "operation": operation.value,
        "coordinator_id": snapshot.coordinator.coordinator_id,
        "inventory_sha256": snapshot.inventory_sha256,
        "expected_device_id": expected_device_id,
        "pairing_window_seconds": pairing_window_seconds,
        "physical_confirmation_required": physical_confirmation_required,
        "backup_required_before_execution": True,
    }
    return ZigbeeMqttOperationPlan(
        plan_id=f"hc65-op-{_content_sha256(payload)[:24]}",
        operation=operation,
        coordinator_id=snapshot.coordinator.coordinator_id,
        inventory_sha256=snapshot.inventory_sha256,
        expected_device_id=expected_device_id,
        pairing_window_seconds=pairing_window_seconds,
        physical_confirmation_required=physical_confirmation_required,
        backup_required_before_execution=True,
    )


def build_backup_plan(
    *,
    snapshot: ZigbeeMqttInventorySnapshot,
    reason: str,
) -> ZigbeeMqttBackupPlan:
    if not isinstance(snapshot, ZigbeeMqttInventorySnapshot):
        raise ZigbeeMqttFoundationError("backup_snapshot_invalid")
    if snapshot.state is not EvidenceState.CURRENT:
        raise ZigbeeMqttFoundationError("backup_inventory_not_current")
    if reason not in {"pre-pair", "pre-unpair", "manual"}:
        raise ZigbeeMqttFoundationError("backup_reason_invalid")
    payload = {
        "coordinator_id": snapshot.coordinator.coordinator_id,
        "inventory_sha256": snapshot.inventory_sha256,
        "reason": reason,
    }
    return ZigbeeMqttBackupPlan(
        plan_id=f"hc65-backup-{_content_sha256(payload)[:24]}",
        coordinator_id=snapshot.coordinator.coordinator_id,
        inventory_sha256=snapshot.inventory_sha256,
        reason=reason,
    )


def project_cozy(snapshot: ZigbeeMqttInventorySnapshot) -> dict[str, object]:
    if not isinstance(snapshot, ZigbeeMqttInventorySnapshot):
        raise ZigbeeMqttFoundationError("cozy_snapshot_invalid")
    if snapshot.state is EvidenceState.CURRENT:
        status = "Устройства умного дома доступны"
    elif snapshot.state is EvidenceState.STALE:
        status = "Данные об устройствах устарели"
    else:
        status = "Не удалось подтвердить состояние устройств"
    return {
        "schema": "home-center.cozy-zigbee-mqtt-summary.v1",
        "status": snapshot.state.value,
        "title": "Умный дом",
        "message": status,
        "device_count": len(snapshot.devices) if snapshot.state is not EvidenceState.UNAVAILABLE else None,
        "attention_required": snapshot.state is not EvidenceState.CURRENT,
        "ha_limitation": (
            "Один физический координатор"
            if snapshot.coordinator.physical_single_coordinator
            else "Отказоустойчивость не подтверждена"
        ),
        "mutation_authorized": False,
    }


def project_full(snapshot: ZigbeeMqttInventorySnapshot) -> dict[str, object]:
    if not isinstance(snapshot, ZigbeeMqttInventorySnapshot):
        raise ZigbeeMqttFoundationError("full_snapshot_invalid")
    return {
        "schema": "home-center.full-zigbee-mqtt-summary.v1",
        "state": snapshot.state.value,
        "inventory_sha256": snapshot.inventory_sha256,
        "coordinator": snapshot.coordinator.to_dict(),
        "devices": [item.to_dict() for item in snapshot.devices],
        "ha_supported": False,
        "automatic_failover_authorized": False,
        "mutation_authorized": False,
    }


__all__ = [
    "CoordinatorKind",
    "CoordinatorObservation",
    "CoordinatorTransport",
    "EvidenceState",
    "PairingOperation",
    "SmartHomeDeviceObservation",
    "ZigbeeMqttBackupPlan",
    "ZigbeeMqttFoundationError",
    "ZigbeeMqttInventorySnapshot",
    "ZigbeeMqttOperationPlan",
    "build_backup_plan",
    "build_inventory_snapshot",
    "build_operation_plan",
    "project_cozy",
    "project_full",
]
