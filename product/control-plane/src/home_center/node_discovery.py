"""Deterministic, read-only node discovery from trusted inventory documents."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from .infrastructure_inventory import InfrastructureInventoryError, normalize_infrastructure_inventory
SCHEMA="home-center.node-discovery.v1"; SCOPE_ID=re.compile(r"^[a-z0-9][a-z0-9.-]{2,63}$"); ARCHITECTURE_CANONICAL={"amd64":"x86_64","x86_64":"x86_64","aarch64":"arm64","arm64":"arm64"}; MAX_NODES=64
class NodeDiscoveryError(ValueError):
    def __init__(self,code:str)->None: super().__init__(code); self.code=code
def _timestamp(value:object,*,code:str)->datetime:
    if not isinstance(value,str) or not 10<=len(value)<=40: raise NodeDiscoveryError(code)
    try: parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc: raise NodeDiscoveryError(code) from exc
    if parsed.tzinfo is None: raise NodeDiscoveryError(code)
    return parsed.astimezone(timezone.utc)
def _render(value:datetime)->str: return value.astimezone(timezone.utc).isoformat(timespec="microseconds" if value.microsecond else "seconds").replace("+00:00","Z")
def discover_nodes(*,scope_id:str,accepted_after:str,accepted_before:str,inventories:Iterable[Mapping[str,Any]])->dict[str,Any]:
    if not isinstance(scope_id,str) or SCOPE_ID.fullmatch(scope_id) is None: raise NodeDiscoveryError("invalid_scope_id")
    start=_timestamp(accepted_after,code="invalid_accepted_after"); end=_timestamp(accepted_before,code="invalid_accepted_before")
    if start>end: raise NodeDiscoveryError("invalid_observation_window")
    if isinstance(inventories,(str,bytes,Mapping)): raise NodeDiscoveryError("invalid_inventory_list")
    values=list(inventories)
    if len(values)>MAX_NODES: raise NodeDiscoveryError("too_many_nodes")
    nodes=[]; ids=set(); names=set()
    for value in values:
        try: inv=normalize_infrastructure_inventory(value)
        except InfrastructureInventoryError as exc: raise NodeDiscoveryError(f"invalid_inventory:{exc.code}") from exc
        observed=_timestamp(inv["observed_at"],code="invalid_inventory_observed_at")
        if observed<start: raise NodeDiscoveryError("observation_before_window")
        if observed>end: raise NodeDiscoveryError("observation_after_window")
        node=inv["node"]; nid=node["id"]; nname=node["name"]
        if nid in ids: raise NodeDiscoveryError("duplicate_node_id")
        if nname.casefold() in names: raise NodeDiscoveryError("duplicate_node_name")
        ids.add(nid); names.add(nname.casefold()); hw=inv["hardware"]
        nodes.append({"id":nid,"name":nname,"state":"discovered","observed_at":_render(observed),"architecture":ARCHITECTURE_CANONICAL[hw["architecture"]],"cpu_count":hw["cpu_count"],"memory_bytes":hw["memory_bytes"],"storage_device_count":len(inv["storage"]),"network_interface_count":len(inv["network"]),"virtualization_supported":hw["virtualization"]["supported"],"capabilities":list(inv["capabilities"])})
    nodes.sort(key=lambda item:(item["name"].casefold(),item["id"]))
    return {"schema":SCHEMA,"scope_id":scope_id,"accepted_after":_render(start),"accepted_before":_render(end),"state":"candidates-found" if nodes else "empty","candidate_count":len(nodes),"role_assignment_enabled":False,"enrollment_enabled":False,"production_mutation_enabled":False,"nodes":nodes}
