"""Local-first infrastructure-neutral Device Registry with RFC3339 normalization."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Mapping, Any
ID=re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$"); CAP=re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$"); TS=re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$")
class DeviceRegistryError(ValueError): pass
class DeviceKind(StrEnum): SENSOR="sensor"; SWITCH="switch"; LIGHT="light"; OUTLET="outlet"; THERMOSTAT="thermostat"; COORDINATOR="coordinator"; MEDIA="media"; OTHER="other"
class DeviceState(StrEnum): ONLINE="online"; OFFLINE="offline"; DEGRADED="degraded"; UNKNOWN="unknown"
def _time(value:str)->str:
    if not isinstance(value,str) or TS.fullmatch(value) is None or value.endswith("-00:00"): raise DeviceRegistryError("invalid_timestamp")
    parsed=datetime.fromisoformat(value[:-1]+"+00:00" if value.endswith("Z") else value)
    if parsed.utcoffset() is None: raise DeviceRegistryError("invalid_timestamp")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00","Z")
@dataclass(frozen=True,slots=True)
class DeviceRecord:
    device_id:str; name:str; kind:DeviceKind; state:DeviceState; capabilities:tuple[str,...]; last_observed_at:str; location_id:str|None=None; owner_subject:str|None=None; permission_refs:tuple[str,...]=()
    def __post_init__(self)->None:
        if ID.fullmatch(self.device_id) is None or not self.name.strip(): raise DeviceRegistryError("invalid_device_identity")
        if any(CAP.fullmatch(v) is None for v in self.capabilities): raise DeviceRegistryError("invalid_capability")
        object.__setattr__(self,"last_observed_at",_time(self.last_observed_at))
@dataclass(frozen=True,slots=True)
class DeviceRegistry:
    observed_at:str; devices:tuple[DeviceRecord,...]; production_mutation_enabled:bool=False; schema:str=field(default="home-center.device-registry.v1",init=False)
    def __post_init__(self)->None:
        object.__setattr__(self,"observed_at",_time(self.observed_at))
        if len({d.device_id for d in self.devices})!=len(self.devices): raise DeviceRegistryError("duplicate_device_id")
def normalize_device_registry(value:Mapping[str,Any])->DeviceRegistry:
    if set(value)!={"schema","observed_at","source","devices"} or value.get("schema")!="home-center.device-registry.v1" or value.get("source")!="local-trusted": raise DeviceRegistryError("invalid_registry")
    records=[]
    for raw in value["devices"]:
        records.append(DeviceRecord(raw["device_id"],raw["name"],DeviceKind(raw["kind"]),DeviceState(raw["state"]),tuple(sorted(raw.get("capabilities",()))),raw["last_observed_at"],raw.get("location_id"),raw.get("owner_subject"),tuple(sorted(raw.get("permission_refs",())))))
    return DeviceRegistry(value["observed_at"],tuple(sorted(records,key=lambda d:d.device_id)))
