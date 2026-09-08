"""Trusted resource preflight for plan-only Home Center 0.13 intents."""

from __future__ import annotations

from typing import Any, Mapping

from .core.intent_engine import IntentKind, IntentRequest


GIB = 1024**3
MIB = 1024**2
MAX_NODES = 64


class IntentPreflightError(ValueError):
    """The trusted resource snapshot is malformed or semantically inconsistent."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _mapping(value: object, *, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IntentPreflightError(code)
    return value


def _integer(value: object, *, minimum: int, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise IntentPreflightError(code)
    return value


def _ready_nodes(snapshot: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if snapshot.get("schema") != "home-center.resource-snapshot.v1":
        raise IntentPreflightError("unsupported_resource_snapshot")
    if snapshot.get("production_mutation_enabled") is not False:
        raise IntentPreflightError("resource_snapshot_mutation_boundary_rejected")
    planning_ready = snapshot.get("planning_ready")
    if not isinstance(planning_ready, bool):
        raise IntentPreflightError("invalid_resource_planning_state")
    nodes = snapshot.get("nodes")
    if not isinstance(nodes, list) or len(nodes) > MAX_NODES:
        raise IntentPreflightError("invalid_resource_nodes")
    ready: list[Mapping[str, Any]] = []
    for value in nodes:
        node = _mapping(value, code="invalid_resource_node")
        status = node.get("status")
        if status not in {"ready", "unreachable"}:
            raise IntentPreflightError("invalid_resource_node_status")
        if status == "ready":
            ready.append(node)
    return ready


def _capacity(node: Mapping[str, Any]) -> tuple[int, int, int]:
    cpu_count = _integer(node.get("cpu_count"), minimum=1, code="invalid_resource_cpu")
    memory_bytes = _integer(node.get("memory_bytes"), minimum=1, code="invalid_resource_memory")
    root_storage = _mapping(node.get("root_storage"), code="invalid_resource_storage")
    free_bytes = _integer(root_storage.get("free_bytes"), minimum=0, code="invalid_resource_storage_free")
    return cpu_count, memory_bytes, free_bytes


def resource_preflight(request: IntentRequest, snapshot: Mapping[str, Any]) -> tuple[str, ...]:
    """Return deterministic blockers using trusted cluster resource facts only."""

    if request.kind not in {
        IntentKind.STORAGE_SHARE_CREATE,
        IntentKind.VIRTUALIZATION_WORKLOAD_CREATE,
    }:
        return ()

    ready = _ready_nodes(snapshot)
    if snapshot.get("planning_ready") is not True:
        return ("cluster_resources_not_ready",)

    parameters = request.parameters
    high_availability = parameters["high_availability"]
    if not isinstance(high_availability, bool):
        raise IntentPreflightError("invalid_preflight_ha_flag")
    required_nodes = 2 if high_availability else 1
    if len(ready) < required_nodes:
        return ("cluster_resources_not_ready",)

    if request.kind is IntentKind.STORAGE_SHARE_CREATE:
        capacity_gib = _integer(parameters["capacity_gib"], minimum=1, code="invalid_preflight_storage_capacity")
        required_storage_bytes = capacity_gib * GIB
        storage_eligible = sum(_capacity(node)[2] >= required_storage_bytes for node in ready)
        if storage_eligible < required_nodes:
            return ("insufficient_storage_capacity",)
        return ()

    vcpu = _integer(parameters["vcpu"], minimum=1, code="invalid_preflight_vcpu")
    memory_mib = _integer(parameters["memory_mib"], minimum=1, code="invalid_preflight_memory")
    disk_gib = _integer(parameters["disk_gib"], minimum=1, code="invalid_preflight_disk")
    required_memory_bytes = memory_mib * MIB
    required_storage_bytes = disk_gib * GIB

    capacities = [_capacity(node) for node in ready]
    blockers: list[str] = []
    if sum(cpu >= vcpu for cpu, _, _ in capacities) < required_nodes:
        blockers.append("insufficient_cpu_capacity")
    if sum(memory >= required_memory_bytes for _, memory, _ in capacities) < required_nodes:
        blockers.append("insufficient_memory_capacity")
    if sum(storage >= required_storage_bytes for _, _, storage in capacities) < required_nodes:
        blockers.append("insufficient_storage_capacity")
    if blockers:
        return tuple(blockers)

    combined_eligible = sum(
        cpu >= vcpu and memory >= required_memory_bytes and storage >= required_storage_bytes
        for cpu, memory, storage in capacities
    )
    if combined_eligible < required_nodes:
        return ("insufficient_combined_capacity",)
    return ()
