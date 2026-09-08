"""Deterministic, read-only infrastructure inventory normalization for Home Center 0.15."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Mapping

SCHEMA = "home-center.infrastructure-inventory.v2"
NODE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{2,63}$")
NODE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
ROLE_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
RESOURCE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$")
CAPABILITY_ID = re.compile(r"^[a-z0-9][a-z0-9.-]+\.v[0-9]+$")
ARCHITECTURES = frozenset({"x86_64", "amd64", "aarch64", "arm64"})
STORAGE_KINDS = frozenset({"hdd", "ssd", "nvme", "emmc", "virtual", "unknown"})
NETWORK_KINDS = frozenset({"ethernet", "wifi", "virtual", "bridge", "bond", "unknown"})
CARRIER_STATES = frozenset({"up", "down", "unknown"})
VIRTUALIZATION_TECHNOLOGIES = frozenset({"none", "intel-vt-x", "amd-v", "hypervisor"})
MAX_CPU_COUNT = 4096
MAX_BYTES = 2**63 - 1
MAX_SPEED_MBPS = 1_000_000
MAX_ITEMS = 128

class InfrastructureInventoryError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

def _mapping(value: object, *, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping): raise InfrastructureInventoryError(code)
    return value

def _closed(value: object, *, keys: frozenset[str], code: str) -> Mapping[str, Any]:
    result = _mapping(value, code=code)
    if frozenset(result) != keys: raise InfrastructureInventoryError(code)
    return result

def _text(value: object, *, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None: raise InfrastructureInventoryError(code)
    return value

def _integer(value: object, *, minimum: int, maximum: int, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum: raise InfrastructureInventoryError(code)
    return value

def _boolean(value: object, *, code: str) -> bool:
    if type(value) is not bool: raise InfrastructureInventoryError(code)
    return value

def _timestamp(value: object) -> str:
    if not isinstance(value, str) or not 10 <= len(value) <= 40: raise InfrastructureInventoryError("invalid_observed_at")
    try: parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc: raise InfrastructureInventoryError("invalid_observed_at") from exc
    if parsed.tzinfo is None: raise InfrastructureInventoryError("invalid_observed_at")
    return value

def _storage(raw: object) -> list[dict[str, object]]:
    if not isinstance(raw, list) or len(raw) > MAX_ITEMS: raise InfrastructureInventoryError("invalid_storage_list")
    items=[]; seen=set()
    for value in raw:
        row=_closed(value,keys=frozenset({"id","kind","total_bytes","removable"}),code="invalid_storage_shape")
        resource_id=_text(row.get("id"),pattern=RESOURCE_ID,code="invalid_storage_id")
        if resource_id.casefold() in seen: raise InfrastructureInventoryError("duplicate_storage_id")
        seen.add(resource_id.casefold())
        kind=row.get("kind")
        if kind not in STORAGE_KINDS: raise InfrastructureInventoryError("invalid_storage_kind")
        items.append({"id":resource_id,"kind":kind,"total_bytes":_integer(row.get("total_bytes"),minimum=1,maximum=MAX_BYTES,code="invalid_storage_capacity"),"removable":_boolean(row.get("removable"),code="invalid_storage_removable")})
    items.sort(key=lambda item:str(item["id"]).casefold()); return items

def _network(raw: object) -> list[dict[str, object]]:
    if not isinstance(raw, list) or len(raw) > MAX_ITEMS: raise InfrastructureInventoryError("invalid_network_list")
    items=[]; seen=set()
    for value in raw:
        row=_closed(value,keys=frozenset({"id","kind","speed_mbps","carrier"}),code="invalid_network_shape")
        resource_id=_text(row.get("id"),pattern=RESOURCE_ID,code="invalid_network_id")
        if resource_id.casefold() in seen: raise InfrastructureInventoryError("duplicate_network_id")
        seen.add(resource_id.casefold()); kind=row.get("kind"); carrier=row.get("carrier")
        if kind not in NETWORK_KINDS: raise InfrastructureInventoryError("invalid_network_kind")
        if carrier not in CARRIER_STATES: raise InfrastructureInventoryError("invalid_network_carrier")
        items.append({"id":resource_id,"kind":kind,"speed_mbps":_integer(row.get("speed_mbps"),minimum=0,maximum=MAX_SPEED_MBPS,code="invalid_network_speed"),"carrier":carrier})
    items.sort(key=lambda item:str(item["id"]).casefold()); return items

def _capabilities(raw: object) -> list[str]:
    if not isinstance(raw, list) or len(raw) > MAX_ITEMS: raise InfrastructureInventoryError("invalid_capability_list")
    values=[_text(value,pattern=CAPABILITY_ID,code="invalid_capability_id") for value in raw]
    if len(set(values)) != len(values): raise InfrastructureInventoryError("duplicate_capability_id")
    return sorted(values)

def normalize_infrastructure_inventory(facts: Mapping[str, Any]) -> dict[str, Any]:
    document=_closed(facts,keys=frozenset({"schema","observed_at","source","node","hardware","storage","network","capabilities"}),code="invalid_inventory_shape")
    if document.get("schema") != SCHEMA: raise InfrastructureInventoryError("unsupported_inventory_schema")
    if document.get("source") != "local-trusted": raise InfrastructureInventoryError("unsupported_inventory_source")
    node=_closed(document.get("node"),keys=frozenset({"id","name","role"}),code="invalid_node_shape")
    hardware=_closed(document.get("hardware"),keys=frozenset({"architecture","cpu_count","memory_bytes","virtualization"}),code="invalid_hardware_shape")
    virtualization=_closed(hardware.get("virtualization"),keys=frozenset({"supported","technology"}),code="invalid_virtualization_shape")
    architecture=hardware.get("architecture")
    if architecture not in ARCHITECTURES: raise InfrastructureInventoryError("invalid_architecture")
    supported=_boolean(virtualization.get("supported"),code="invalid_virtualization_supported"); technology=virtualization.get("technology")
    if technology not in VIRTUALIZATION_TECHNOLOGIES: raise InfrastructureInventoryError("invalid_virtualization_technology")
    if supported != (technology != "none"): raise InfrastructureInventoryError("inconsistent_virtualization_state")
    return {"schema":SCHEMA,"observed_at":_timestamp(document.get("observed_at")),"source":"local-trusted","production_mutation_enabled":False,"node":{"id":_text(node.get("id"),pattern=NODE_ID,code="invalid_node_id"),"name":_text(node.get("name"),pattern=NODE_NAME,code="invalid_node_name"),"role":_text(node.get("role"),pattern=ROLE_ID,code="invalid_node_role")},"hardware":{"architecture":architecture,"cpu_count":_integer(hardware.get("cpu_count"),minimum=1,maximum=MAX_CPU_COUNT,code="invalid_cpu_count"),"memory_bytes":_integer(hardware.get("memory_bytes"),minimum=1,maximum=MAX_BYTES,code="invalid_memory_bytes"),"virtualization":{"supported":supported,"technology":technology}},"storage":_storage(document.get("storage")),"network":_network(document.get("network")),"capabilities":_capabilities(document.get("capabilities"))}
