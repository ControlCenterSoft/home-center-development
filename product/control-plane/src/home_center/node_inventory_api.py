"""Typed, read-only API view over persisted node capability facts."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol

from .util import utc_now


NODE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{2,63}$")
NODE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
ROLE_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
CAPABILITY_ID = re.compile(r"^[a-z0-9][a-z0-9.-]+\.v[0-9]+$")
SERVICE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@_.:-]{0,127}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
NODE_STATUSES = frozenset({"ready", "unreachable"})
SERVICE_STATES = frozenset({"active", "inactive", "failed", "activating", "deactivating", "unknown"})
MAX_NODES = 64
MAX_CAPABILITIES = 128
MAX_SERVICES = 128
MAX_CPU_COUNT = 4096
MAX_BYTES = 2**63 - 1


class NodeInventoryError(ValueError):
    """Stable fail-closed rejection code for inconsistent persisted facts."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NodeInventoryStore(Protocol):
    def nodes(self) -> list[dict[str, Any]]: ...


def _mapping(value: object, *, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise NodeInventoryError(code)
    return value


def _text(
    value: object,
    *,
    code: str,
    minimum: int = 1,
    maximum: int = 128,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise NodeInventoryError(code)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise NodeInventoryError(code)
    if any(ord(character) < 32 for character in value):
        raise NodeInventoryError(code)
    return value


def _integer(value: object, *, minimum: int, maximum: int, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise NodeInventoryError(code)
    return value


def _timestamp(value: object, *, code: str) -> str:
    if not isinstance(value, str) or not 10 <= len(value) <= 40:
        raise NodeInventoryError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NodeInventoryError(code) from exc
    if parsed.tzinfo is None:
        raise NodeInventoryError(code)
    return value


def _address(value: object) -> str:
    if not isinstance(value, str) or value != value.strip() or "%" in value:
        raise NodeInventoryError("invalid_management_address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise NodeInventoryError("invalid_management_address") from exc
    if address.is_unspecified or address.is_multicast:
        raise NodeInventoryError("invalid_management_address")
    return str(address)


def _services(value: object) -> list[dict[str, str]]:
    source = _mapping(value, code="invalid_services")
    if len(source) > MAX_SERVICES:
        raise NodeInventoryError("too_many_services")
    services: list[dict[str, str]] = []
    for service_id, state in source.items():
        normalized_id = _text(service_id, code="invalid_service_id", pattern=SERVICE_ID)
        if not isinstance(state, str) or state not in SERVICE_STATES:
            raise NodeInventoryError("invalid_service_state")
        services.append({"id": normalized_id, "state": state})
    services.sort(key=lambda item: item["id"].casefold())
    return services


def _capabilities(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_CAPABILITIES:
        raise NodeInventoryError("invalid_capabilities")
    capabilities = [
        _text(item, code="invalid_capability_id", pattern=CAPABILITY_ID)
        for item in value
    ]
    if len(capabilities) != len(set(capabilities)):
        raise NodeInventoryError("duplicate_capability_id")
    return sorted(capabilities)


def _node(row: Mapping[str, Any]) -> dict[str, Any]:
    node_id = _text(row.get("node_id"), code="invalid_node_id", pattern=NODE_ID)
    name = _text(row.get("name"), code="invalid_node_name", pattern=NODE_NAME)
    role = _text(row.get("role"), code="invalid_node_role", pattern=ROLE_ID, maximum=32)
    status = row.get("status")
    if not isinstance(status, str) or status not in NODE_STATUSES:
        raise NodeInventoryError("invalid_node_status")
    management_address = _address(row.get("address"))

    capability = _mapping(row.get("capabilities"), code="missing_node_capability")
    if capability.get("schema") != "home-center.node-capability.v1":
        raise NodeInventoryError("unsupported_node_capability")
    identity = _mapping(capability.get("node"), code="missing_node_identity")
    if (
        identity.get("id") != node_id
        or identity.get("name") != name
        or identity.get("role") != role
        or identity.get("address") != row.get("address")
    ):
        raise NodeInventoryError("node_identity_mismatch")

    operating_system = _mapping(capability.get("operating_system"), code="missing_operating_system")
    hardware = _mapping(capability.get("hardware"), code="missing_hardware")
    storage = _mapping(capability.get("storage"), code="missing_storage")
    root = _mapping(storage.get("root"), code="missing_root_storage")

    total_bytes = _integer(
        root.get("total_bytes"), minimum=1, maximum=MAX_BYTES, code="invalid_storage_total"
    )
    used_bytes = _integer(
        root.get("used_bytes"), minimum=0, maximum=MAX_BYTES, code="invalid_storage_used"
    )
    free_bytes = _integer(
        root.get("free_bytes"), minimum=0, maximum=MAX_BYTES, code="invalid_storage_free"
    )
    if used_bytes > total_bytes or free_bytes > total_bytes or used_bytes + free_bytes > total_bytes:
        raise NodeInventoryError("inconsistent_storage_capacity")

    return {
        "id": node_id,
        "name": name,
        "role": role,
        "status": status,
        "management_address": management_address,
        "observed_at": _timestamp(capability.get("observed_at"), code="invalid_observed_at"),
        "operating_system": {
            "id": _text(operating_system.get("id"), code="invalid_operating_system_id"),
            "version": _text(
                operating_system.get("version"), code="invalid_operating_system_version"
            ),
            "kernel": _text(operating_system.get("kernel"), code="invalid_kernel", maximum=256),
            "architecture": _text(
                operating_system.get("architecture"), code="invalid_architecture", maximum=64
            ),
        },
        "hardware": {
            "cpu_count": _integer(
                hardware.get("cpu_count"),
                minimum=1,
                maximum=MAX_CPU_COUNT,
                code="invalid_cpu_count",
            ),
            "memory_bytes": _integer(
                hardware.get("memory_bytes"),
                minimum=1,
                maximum=MAX_BYTES,
                code="invalid_memory_bytes",
            ),
        },
        "storage": {
            "root": {
                "total_bytes": total_bytes,
                "used_bytes": used_bytes,
                "free_bytes": free_bytes,
            }
        },
        "services": _services(capability.get("services")),
        "capabilities": _capabilities(capability.get("capabilities")),
    }


class NodeInventoryService:
    """Build a deterministic public view without exposing machine fingerprints."""

    def __init__(
        self,
        store: NodeInventoryStore,
        *,
        product_version: str,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._store = store
        self._clock = clock
        self._product_version = _text(
            product_version, code="invalid_product_version", pattern=VERSION, maximum=64
        )

    def snapshot(self) -> dict[str, Any]:
        raw_nodes = self._store.nodes()
        if not isinstance(raw_nodes, list):
            raise NodeInventoryError("invalid_node_list")
        if len(raw_nodes) > MAX_NODES:
            raise NodeInventoryError("too_many_nodes")
        nodes = [_node(_mapping(row, code="invalid_node")) for row in raw_nodes]
        nodes.sort(key=lambda item: (item["name"].casefold(), item["id"]))

        node_ids = [item["id"] for item in nodes]
        node_names = [item["name"].casefold() for item in nodes]
        if len(node_ids) != len(set(node_ids)) or len(node_names) != len(set(node_names)):
            raise NodeInventoryError("duplicate_node_identity")

        ready_nodes = sum(item["status"] == "ready" for item in nodes)
        unreachable_nodes = sum(item["status"] == "unreachable" for item in nodes)
        if not nodes:
            state = "empty"
        elif ready_nodes == len(nodes):
            state = "healthy"
        else:
            state = "degraded"
        capabilities = sorted({item for node in nodes for item in node["capabilities"]})
        if len(capabilities) > MAX_CAPABILITIES:
            raise NodeInventoryError("too_many_capabilities")
        return {
            "schema": "home-center.infrastructure-inventory-list.v1",
            "version": self._product_version,
            "generated_at": _timestamp(self._clock(), code="invalid_generated_at"),
            "state": state,
            "production_mutation_enabled": False,
            "summary": {
                "total_nodes": len(nodes),
                "ready_nodes": ready_nodes,
                "unreachable_nodes": unreachable_nodes,
            },
            "capabilities": capabilities,
            "nodes": nodes,
        }
