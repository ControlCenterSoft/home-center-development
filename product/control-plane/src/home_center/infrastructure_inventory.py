"""Read-only infrastructure inventory normalization for discovery."""
from __future__ import annotations
import re
from datetime import datetime
from typing import Any, Mapping
SCHEMA="home-center.infrastructure-inventory.v2"
NODE_ID=re.compile(r"^[a-z0-9][a-z0-9.-]{2,63}$"); NODE_NAME=re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$"); ROLE_ID=re.compile(r"^[a-z][a-z0-9-]{1,31}$"); RESOURCE_ID=re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$"); CAPABILITY_ID=re.compile(r"^[a-z0-9][a-z0-9.-]+\.v[0-9]+$")
ARCHITECTURES={"x86_64","amd64","aarch64","arm64"}; STORAGE_KINDS={"hdd","ssd","nvme","emmc","virtual","unknown"}; NETWORK_KINDS={"ethernet","wifi","virtual","bridge","bond","unknown"}; CARRIER_STATES={"up","down","unknown"}; VIRTUALIZATION_TECHNOLOGIES={"none","intel-vt-x","amd-v","hypervisor"}
class InfrastructureInventoryError(ValueError):
    def __init__(self,code:str)->None: super().__init__(code); self.code=code
def _closed(value:object,keys:set[str],code:str)->Mapping[str,Any]:
    if not isinstance(value,Mapping) or set(value)!=keys: raise InfrastructureInventoryError(code)
    return value
def _text(value:object,pattern:re.Pattern[str],code:str)->str:
    if not isinstance(value,str) or pattern.fullmatch(value) is None: raise InfrastructureInventoryError(code)
    return value
def _integer(value:object,minimum:int,maximum:int,code:str)->int:
    if not isinstance(value,int) or isinstance(value,bool) or not minimum<=value<=maximum: raise InfrastructureInventoryError(code)
    return value
def _timestamp(value:object)->str:
    if not isinstance(value,str): raise InfrastructureInventoryError("invalid_observed_at")
    try: parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc: raise InfrastructureInventoryError("invalid_observed_at") from exc
    if parsed.tzinfo is None: raise InfrastructureInventoryError("invalid_observed_at")
    return value
def normalize_infrastructure_inventory(facts:Mapping[str,Any])->dict[str,Any]:
    doc=_closed(facts,{"schema","observed_at","source","node","hardware","storage","network","capabilities"},"invalid_inventory_shape")
    if doc["schema"]!=SCHEMA or doc["source"]!="local-trusted": raise InfrastructureInventoryError("unsupported_inventory")
    node=_closed(doc["node"],{"id","name","role"},"invalid_node_shape"); hardware=_closed(doc["hardware"],{"architecture","cpu_count","memory_bytes","virtualization"},"invalid_hardware_shape"); virt=_closed(hardware["virtualization"],{"supported","technology"},"invalid_virtualization_shape")
    if hardware["architecture"] not in ARCHITECTURES or virt["technology"] not in VIRTUALIZATION_TECHNOLOGIES or bool(virt["supported"])!=(virt["technology"]!="none"): raise InfrastructureInventoryError("invalid_hardware")
    storage=[]
    for row in doc["storage"]:
        row=_closed(row,{"id","kind","total_bytes","removable"},"invalid_storage_shape"); kind=row["kind"]
        if kind not in STORAGE_KINDS: raise InfrastructureInventoryError("invalid_storage_kind")
        storage.append({"id":_text(row["id"],RESOURCE_ID,"invalid_storage_id"),"kind":kind,"total_bytes":_integer(row["total_bytes"],1,2**63-1,"invalid_storage_capacity"),"removable":bool(row["removable"])})
    network=[]
    for row in doc["network"]:
        row=_closed(row,{"id","kind","speed_mbps","carrier"},"invalid_network_shape")
        if row["kind"] not in NETWORK_KINDS or row["carrier"] not in CARRIER_STATES: raise InfrastructureInventoryError("invalid_network")
        network.append({"id":_text(row["id"],RESOURCE_ID,"invalid_network_id"),"kind":row["kind"],"speed_mbps":_integer(row["speed_mbps"],0,1_000_000,"invalid_network_speed"),"carrier":row["carrier"]})
    caps=sorted(_text(v,CAPABILITY_ID,"invalid_capability_id") for v in doc["capabilities"])
    return {"schema":SCHEMA,"observed_at":_timestamp(doc["observed_at"]),"source":"local-trusted","production_mutation_enabled":False,"node":{"id":_text(node["id"],NODE_ID,"invalid_node_id"),"name":_text(node["name"],NODE_NAME,"invalid_node_name"),"role":_text(node["role"],ROLE_ID,"invalid_node_role")},"hardware":{"architecture":hardware["architecture"],"cpu_count":_integer(hardware["cpu_count"],1,4096,"invalid_cpu_count"),"memory_bytes":_integer(hardware["memory_bytes"],1,2**63-1,"invalid_memory_bytes"),"virtualization":{"supported":bool(virt["supported"]),"technology":virt["technology"]}},"storage":sorted(storage,key=lambda x:str(x["id"]).casefold()),"network":sorted(network,key=lambda x:str(x["id"]).casefold()),"capabilities":caps}
