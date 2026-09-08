"""Deterministic local-first Device Registry for Home Center 0.17."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping


SCHEMA = "home-center.device-registry.v1"
ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
RFC3339_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
MAX_DEVICES = 4096


class DeviceRegistryError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DeviceKind(StrEnum):
    SENSOR = "sensor"
    SWITCH = "switch"
    LIGHT = "light"
    OUTLET = "outlet"
    THERMOSTAT = "thermostat"
    COORDINATOR = "coordinator"
    MEDIA = "media"
    OTHER = "other"


class DeviceState(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


def _closed(value: object, keys: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise DeviceRegistryError(code)
    return value


def _id(value: object, code: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or ID.fullmatch(value) is None:
        raise DeviceRegistryError(code)
    return value


def _timestamp(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or RFC3339_TIMESTAMP.fullmatch(value) is None
        or value.endswith("-00:00")
    ):
        raise DeviceRegistryError(code)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.utcoffset() is None:
            raise ValueError("timezone offset is required")
        canonical = parsed.astimezone(timezone.utc).isoformat()
    except (OverflowError, ValueError) as exc:
        raise DeviceRegistryError(code) from exc
    return canonical.replace("+00:00", "Z")


def _capabilities(value: object) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > 128
        or any(
            not isinstance(item, str) or CAPABILITY.fullmatch(item) is None
            for item in value
        )
    ):
        raise DeviceRegistryError("invalid_capabilities")
    if len(value) != len(set(value)):
        raise DeviceRegistryError("duplicate_capability")
    return tuple(sorted(value))


def _permission_refs(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 128:
        raise DeviceRegistryError("invalid_permission_refs")
    refs = [_id(item, "invalid_permission_ref") for item in value]
    if len(refs) != len(set(refs)):
        raise DeviceRegistryError("duplicate_permission_ref")
    return tuple(sorted(ref for ref in refs if ref is not None))


@dataclass(frozen=True, slots=True)
class DeviceEvent:
    event_type: str
    occurred_at: str


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    device_id: str
    name: str
    kind: DeviceKind
    state: DeviceState
    location_id: str | None
    owner_subject: str | None
    permission_refs: tuple[str, ...]
    capabilities: tuple[str, ...]
    last_observed_at: str
    last_event: DeviceEvent | None


@dataclass(frozen=True, slots=True)
class DeviceRegistry:
    observed_at: str
    devices: tuple[DeviceRecord, ...]
    schema: str = field(default=SCHEMA, init=False)
    source: str = field(default="local-trusted", init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "observed_at": self.observed_at,
            "source": self.source,
            "production_mutation_enabled": False,
            "devices": [
                {
                    "device_id": device.device_id,
                    "name": device.name,
                    "kind": device.kind.value,
                    "state": device.state.value,
                    "location_id": device.location_id,
                    "owner_subject": device.owner_subject,
                    "permission_refs": list(device.permission_refs),
                    "capabilities": list(device.capabilities),
                    "last_observed_at": device.last_observed_at,
                    "last_event": None
                    if device.last_event is None
                    else {
                        "event_type": device.last_event.event_type,
                        "occurred_at": device.last_event.occurred_at,
                    },
                    "command_authority": False,
                }
                for device in self.devices
            ],
        }


def normalize_device_registry(value: Mapping[str, Any]) -> DeviceRegistry:
    document = _closed(
        value,
        {"schema", "observed_at", "source", "devices"},
        "invalid_registry_shape",
    )
    if document.get("schema") != SCHEMA or document.get("source") != "local-trusted":
        raise DeviceRegistryError("unsupported_registry")
    raw_devices = document.get("devices")
    if not isinstance(raw_devices, list) or len(raw_devices) > MAX_DEVICES:
        raise DeviceRegistryError("invalid_devices")

    devices: list[DeviceRecord] = []
    seen: set[str] = set()
    for raw in raw_devices:
        row = _closed(
            raw,
            {
                "device_id",
                "name",
                "kind",
                "state",
                "location_id",
                "owner_subject",
                "permission_refs",
                "capabilities",
                "last_observed_at",
                "last_event",
            },
            "invalid_device_shape",
        )
        device_id = _id(row.get("device_id"), "invalid_device_id")
        if device_id is None:
            raise DeviceRegistryError("invalid_device_id")
        if device_id in seen:
            raise DeviceRegistryError("duplicate_device_id")
        seen.add(device_id)

        name = row.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise DeviceRegistryError("invalid_device_name")
        try:
            kind = DeviceKind(row.get("kind"))
            state = DeviceState(row.get("state"))
        except (TypeError, ValueError) as exc:
            raise DeviceRegistryError("invalid_device_enum") from exc

        event = None
        if row.get("last_event") is not None:
            event_value = _closed(
                row["last_event"],
                {"event_type", "occurred_at"},
                "invalid_event_shape",
            )
            event_type = _id(event_value.get("event_type"), "invalid_event_type")
            if event_type is None:
                raise DeviceRegistryError("invalid_event_type")
            event = DeviceEvent(
                event_type,
                _timestamp(event_value.get("occurred_at"), "invalid_event_time"),
            )

        devices.append(
            DeviceRecord(
                device_id=device_id,
                name=name.strip(),
                kind=kind,
                state=state,
                location_id=_id(row.get("location_id"), "invalid_location_id", optional=True),
                owner_subject=_id(
                    row.get("owner_subject"), "invalid_owner_subject", optional=True
                ),
                permission_refs=_permission_refs(row.get("permission_refs")),
                capabilities=_capabilities(row.get("capabilities")),
                last_observed_at=_timestamp(
                    row.get("last_observed_at"), "invalid_last_observed_at"
                ),
                last_event=event,
            )
        )

    return DeviceRegistry(
        _timestamp(document.get("observed_at"), "invalid_observed_at"),
        tuple(sorted(devices, key=lambda item: item.device_id)),
    )
