"""Trusted read-only cluster capacity snapshots for Home Center 0.13."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Iterable, Mapping


NODE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{2,63}$")
NODE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
CAPABILITY = re.compile(r"^[a-z0-9][a-z0-9.-]+\.v[0-9]+$")
ROLE_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
VALID_STATUSES = frozenset({"ready", "unreachable"})
MAX_CAPABILITIES = 128
MAX_CPU_COUNT = 4096
MAX_BYTES = 2**63 - 1


class ResourceSnapshotError(ValueError):
    """A stable rejection code for malformed or inconsistent resource facts."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _text(value: object, *, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ResourceSnapshotError(code)
    return value


def _integer(value: object, *, minimum: int, maximum: int, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ResourceSnapshotError(code)
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or not 10 <= len(value) <= 40:
        raise ResourceSnapshotError("invalid_observed_at")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResourceSnapshotError("invalid_observed_at") from exc
    if parsed.tzinfo is None:
        raise ResourceSnapshotError("invalid_observed_at")
    return value


def _mapping(value: object, *, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ResourceSnapshotError(code)
    return value


def _capacity_node(row: Mapping[str, Any]) -> dict[str, Any]:
    node_id = _text(row.get("node_id"), pattern=NODE_ID, code="invalid_node_id")
    name = _text(row.get("name"), pattern=NODE_NAME, code="invalid_node_name")
    role = row.get("role")
    if not isinstance(role, str) or ROLE_ID.fullmatch(role) is None:
        raise ResourceSnapshotError("invalid_node_role")
    status = row.get("status")
    if status not in VALID_STATUSES:
        raise ResourceSnapshotError("invalid_node_status")

    capability = _mapping(row.get("capabilities"), code="missing_node_capability")
    if capability.get("schema") != "home-center.node-capability.v1":
        raise ResourceSnapshotError("unsupported_node_capability")
    observed_at = _timestamp(capability.get("observed_at"))

    identity = _mapping(capability.get("node"), code="missing_capability_identity")
    if (
        identity.get("id") != node_id
        or identity.get("name") != name
        or identity.get("role") != role
        or identity.get("address") != row.get("address")
    ):
        raise ResourceSnapshotError("node_identity_mismatch")

    hardware = _mapping(capability.get("hardware"), code="missing_hardware_capacity")
    cpu_count = _integer(hardware.get("cpu_count"), minimum=1, maximum=MAX_CPU_COUNT, code="invalid_cpu_count")
    memory_bytes = _integer(hardware.get("memory_bytes"), minimum=1, maximum=MAX_BYTES, code="invalid_memory_bytes")

    storage = _mapping(capability.get("storage"), code="missing_storage_capacity")
    root = _mapping(storage.get("root"), code="missing_root_storage_capacity")
    total_bytes = _integer(root.get("total_bytes"), minimum=1, maximum=MAX_BYTES, code="invalid_storage_total")
    used_bytes = _integer(root.get("used_bytes"), minimum=0, maximum=MAX_BYTES, code="invalid_storage_used")
    free_bytes = _integer(root.get("free_bytes"), minimum=0, maximum=MAX_BYTES, code="invalid_storage_free")
    if used_bytes > total_bytes or free_bytes > total_bytes or used_bytes + free_bytes > total_bytes:
        raise ResourceSnapshotError("inconsistent_storage_capacity")

    raw_capabilities = capability.get("capabilities")
    if not isinstance(raw_capabilities, list) or len(raw_capabilities) > MAX_CAPABILITIES:
        raise ResourceSnapshotError("invalid_capability_list")
    capabilities: list[str] = []
    for item in raw_capabilities:
        capabilities.append(_text(item, pattern=CAPABILITY, code="invalid_capability_id"))
    if len(set(capabilities)) != len(capabilities):
        raise ResourceSnapshotError("duplicate_capability_id")

    return {
        "node_id": node_id,
        "name": name,
        "role": role,
        "status": status,
        "observed_at": observed_at,
        "cpu_count": cpu_count,
        "memory_bytes": memory_bytes,
        "root_storage": {
            "total_bytes": total_bytes,
            "used_bytes": used_bytes,
            "free_bytes": free_bytes,
        },
        "capabilities": sorted(capabilities),
    }


def build_resource_snapshot(
    *,
    cluster_id: str,
    expected_nodes: int,
    nodes: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a deterministic, secret-free snapshot from persisted capabilities."""

    if not isinstance(cluster_id, str) or not 3 <= len(cluster_id) <= 128:
        raise ResourceSnapshotError("invalid_cluster_id")
    if not isinstance(expected_nodes, int) or isinstance(expected_nodes, bool) or not 1 <= expected_nodes <= 64:
        raise ResourceSnapshotError("invalid_expected_nodes")

    items = [_capacity_node(row) for row in nodes]
    items.sort(key=lambda item: (item["name"].casefold(), item["node_id"]))
    if len(items) > 64:
        raise ResourceSnapshotError("too_many_nodes")
    ids = [item["node_id"] for item in items]
    names = [item["name"].casefold() for item in items]
    if len(set(ids)) != len(ids) or len(set(names)) != len(names):
        raise ResourceSnapshotError("duplicate_node_identity")

    ready_nodes = sum(item["status"] == "ready" for item in items)
    planning_ready = len(items) == expected_nodes and ready_nodes == expected_nodes
    totals = {
        "observed_nodes": len(items),
        "expected_nodes": expected_nodes,
        "ready_nodes": ready_nodes,
        "cpu_count": sum(item["cpu_count"] for item in items),
        "memory_bytes": sum(item["memory_bytes"] for item in items),
        "root_storage_total_bytes": sum(item["root_storage"]["total_bytes"] for item in items),
        "root_storage_used_bytes": sum(item["root_storage"]["used_bytes"] for item in items),
        "root_storage_free_bytes": sum(item["root_storage"]["free_bytes"] for item in items),
    }
    if any(value > MAX_BYTES for key, value in totals.items() if key.endswith("_bytes")):
        raise ResourceSnapshotError("aggregate_capacity_overflow")

    return {
        "schema": "home-center.resource-snapshot.v1",
        "cluster_id": cluster_id,
        "state": "ready" if planning_ready else "degraded",
        "planning_ready": planning_ready,
        "production_mutation_enabled": False,
        "totals": totals,
        "nodes": items,
    }
