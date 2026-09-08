"""Side-effect-free Proxmox discovery adapter for Home Center 0.16."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Mapping

from .compute_framework import ComputePlan, ComputePlanner, ComputeProviderDescriptor, ComputeProviderKind, ComputeResourceKind, ComputeResourceRequest

SCHEMA = "home-center.proxmox-discovery.v1"
ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
CAP = re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
MAX_ITEMS = 1024

class ProxmoxProviderError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code); self.code = code

class Health(StrEnum):
    HEALTHY = "healthy"; DEGRADED = "degraded"; UNAVAILABLE = "unavailable"
class AuthState(StrEnum):
    AVAILABLE = "available"; UNAVAILABLE = "unavailable"
class NodeState(StrEnum):
    ONLINE = "online"; DEGRADED = "degraded"; OFFLINE = "offline"
class ResourceState(StrEnum):
    RUNNING = "running"; STOPPED = "stopped"; SUSPENDED = "suspended"; UNKNOWN = "unknown"

def _closed(v: object, keys: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(v, Mapping) or set(v) != keys: raise ProxmoxProviderError(code)
    return v

def _id(v: object, code: str) -> str:
    if not isinstance(v, str) or ID.fullmatch(v) is None: raise ProxmoxProviderError(code)
    return v

def _int(v: object, lo: int, hi: int, code: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi: raise ProxmoxProviderError(code)
    return v

def _bool(v: object, code: str) -> bool:
    if type(v) is not bool: raise ProxmoxProviderError(code)
    return v

def _enum(v: object, kind: type[StrEnum], code: str) -> StrEnum:
    if not isinstance(v, str): raise ProxmoxProviderError(code)
    try: return kind(v)
    except ValueError as exc: raise ProxmoxProviderError(code) from exc

def _caps(v: object) -> tuple[str, ...]:
    if not isinstance(v, list) or len(v) > 64: raise ProxmoxProviderError("invalid_capabilities")
    if any(not isinstance(x, str) or CAP.fullmatch(x) is None for x in v): raise ProxmoxProviderError("invalid_capability")
    if len(v) != len(set(v)): raise ProxmoxProviderError("duplicate_capability")
    return tuple(sorted(v))

def _timestamp(v: object) -> str:
    if not isinstance(v, str): raise ProxmoxProviderError("invalid_observed_at")
    try: parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as exc: raise ProxmoxProviderError("invalid_observed_at") from exc
    if parsed.tzinfo is None: raise ProxmoxProviderError("invalid_observed_at")
    return v

@dataclass(frozen=True, slots=True)
class Node:
    node_id: str; state: NodeState; cpu_total: int; cpu_available: int
    memory_total_mib: int; memory_available_mib: int
    storage_total_gib: int; storage_available_gib: int; capabilities: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class Resource:
    resource_id: str; node_id: str; kind: ComputeResourceKind; state: ResourceState
    vcpu: int; memory_mib: int; disk_gib: int

@dataclass(frozen=True, slots=True)
class ProxmoxDiscovery:
    observed_at: str; provider_id: str; profile_id: str; reported_health: Health; auth_state: AuthState
    cluster_id: str; quorate: bool; nodes: tuple[Node, ...]; resources: tuple[Resource, ...]
    schema: str = field(default=SCHEMA, init=False); source: str = field(default="proxmox-trusted", init=False)
    production_mutation_enabled: bool = field(default=False, init=False)
    @property
    def healthy(self) -> bool:
        return self.reported_health is Health.HEALTHY and self.auth_state is AuthState.AVAILABLE and self.quorate and any(n.state is NodeState.ONLINE for n in self.nodes)
    @property
    def capabilities(self) -> tuple[str, ...]:
        values = {c for n in self.nodes if n.state is NodeState.ONLINE for c in n.capabilities}
        if not self.quorate: values.discard("compute.ha.v1")
        return tuple(sorted(values))
    @property
    def available_capacity(self) -> tuple[int,int,int]:
        online = [n for n in self.nodes if n.state is NodeState.ONLINE]
        return sum(n.cpu_available for n in online), sum(n.memory_available_mib for n in online), sum(n.storage_available_gib for n in online)
    def descriptor(self) -> ComputeProviderDescriptor:
        return ComputeProviderDescriptor.create(provider_id=self.provider_id, kind=ComputeProviderKind.PROXMOX, healthy=self.healthy, capabilities=self.capabilities)
    def plan_create(self, request: ComputeResourceRequest) -> ComputePlan:
        cpu, mem, disk = self.available_capacity
        return ComputePlanner().plan_create(self.descriptor(), request, available_cpu=cpu, available_memory_mib=mem, available_storage_gib=disk)

def normalize_proxmox_discovery(value: Mapping[str, Any]) -> ProxmoxDiscovery:
    d = _closed(value,{"schema","observed_at","source","provider","cluster","nodes","resources"},"invalid_discovery_shape")
    if d.get("schema") != SCHEMA: raise ProxmoxProviderError("unsupported_discovery_schema")
    if d.get("source") != "proxmox-trusted": raise ProxmoxProviderError("unsupported_discovery_source")
    p = _closed(d.get("provider"),{"provider_id","profile_id","reported_health","auth_state"},"invalid_provider_shape")
    c = _closed(d.get("cluster"),{"cluster_id","quorate"},"invalid_cluster_shape")
    raw_nodes=d.get("nodes")
    if not isinstance(raw_nodes,list) or not 1 <= len(raw_nodes) <= MAX_ITEMS: raise ProxmoxProviderError("invalid_nodes")
    nodes=[]; node_ids=set()
    for raw in raw_nodes:
        n=_closed(raw,{"node_id","state","cpu_total","cpu_available","memory_total_mib","memory_available_mib","storage_total_gib","storage_available_gib","capabilities"},"invalid_node_shape")
        nid=_id(n.get("node_id"),"invalid_node_id")
        if nid in node_ids: raise ProxmoxProviderError("duplicate_node_id")
        node_ids.add(nid)
        ct=_int(n.get("cpu_total"),1,4096,"invalid_cpu_total"); ca=_int(n.get("cpu_available"),0,4096,"invalid_cpu_available")
        mt=_int(n.get("memory_total_mib"),256,4_194_304,"invalid_memory_total"); ma=_int(n.get("memory_available_mib"),0,4_194_304,"invalid_memory_available")
        st=_int(n.get("storage_total_gib"),1,1_048_576,"invalid_storage_total"); sa=_int(n.get("storage_available_gib"),0,1_048_576,"invalid_storage_available")
        if ca>ct or ma>mt or sa>st: raise ProxmoxProviderError("capacity_exceeds_total")
        nodes.append(Node(nid,_enum(n.get("state"),NodeState,"invalid_node_state"),ct,ca,mt,ma,st,sa,_caps(n.get("capabilities"))))
    raw_resources=d.get("resources")
    if not isinstance(raw_resources,list) or len(raw_resources)>MAX_ITEMS: raise ProxmoxProviderError("invalid_resources")
    resources=[]; resource_ids=set()
    for raw in raw_resources:
        r=_closed(raw,{"resource_id","node_id","kind","state","vcpu","memory_mib","disk_gib"},"invalid_resource_shape")
        rid=_id(r.get("resource_id"),"invalid_resource_id"); nid=_id(r.get("node_id"),"invalid_resource_node_id")
        if rid in resource_ids: raise ProxmoxProviderError("duplicate_resource_id")
        if nid not in node_ids: raise ProxmoxProviderError("unknown_resource_node")
        resource_ids.add(rid)
        try: kind=ComputeResourceKind(r.get("kind"))
        except (TypeError,ValueError) as exc: raise ProxmoxProviderError("invalid_resource_kind") from exc
        if kind not in {ComputeResourceKind.VM,ComputeResourceKind.LXC}: raise ProxmoxProviderError("unsupported_resource_kind")
        resources.append(Resource(rid,nid,kind,_enum(r.get("state"),ResourceState,"invalid_resource_state"),_int(r.get("vcpu"),1,256,"invalid_resource_vcpu"),_int(r.get("memory_mib"),256,4_194_304,"invalid_resource_memory"),_int(r.get("disk_gib"),1,1_048_576,"invalid_resource_disk")))
    return ProxmoxDiscovery(_timestamp(d.get("observed_at")),_id(p.get("provider_id"),"invalid_provider_id"),_id(p.get("profile_id"),"invalid_profile_id"),_enum(p.get("reported_health"),Health,"invalid_provider_health"),_enum(p.get("auth_state"),AuthState,"invalid_auth_state"),_id(c.get("cluster_id"),"invalid_cluster_id"),_bool(c.get("quorate"),"invalid_quorate"),tuple(sorted(nodes,key=lambda n:n.node_id)),tuple(sorted(resources,key=lambda r:r.resource_id)))
