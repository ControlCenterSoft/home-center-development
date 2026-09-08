"""Provider-neutral ZigBee discovery and pairing planning boundary."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import StrEnum
ID=re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
CAP=re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
class ZigbeeError(ValueError):
    def __init__(self,code:str)->None: super().__init__(code); self.code=code
class ProviderHealth(StrEnum): HEALTHY="healthy"; DEGRADED="degraded"; UNAVAILABLE="unavailable"
@dataclass(frozen=True,slots=True)
class ZigbeeProviderSnapshot:
    provider_id:str; coordinator_id:str; health:ProviderHealth; permit_join:bool; capabilities:tuple[str,...]; known_devices:tuple[str,...]=()
    def __post_init__(self)->None:
        if ID.fullmatch(self.provider_id) is None or ID.fullmatch(self.coordinator_id) is None: raise ZigbeeError("invalid_provider_identity")
        if any(CAP.fullmatch(v) is None for v in self.capabilities): raise ZigbeeError("invalid_capability")
        if any(ID.fullmatch(v) is None for v in self.known_devices): raise ZigbeeError("invalid_device_id")
@dataclass(frozen=True,slots=True)
class PairingRequest:
    operation_id:str; provider_id:str; requested_device_id:str|None=None; timeout_seconds:int=120
    def __post_init__(self)->None:
        if ID.fullmatch(self.operation_id) is None or ID.fullmatch(self.provider_id) is None: raise ZigbeeError("invalid_request_identity")
        if self.requested_device_id is not None and ID.fullmatch(self.requested_device_id) is None: raise ZigbeeError("invalid_device_id")
        if not 10<=self.timeout_seconds<=900: raise ZigbeeError("invalid_timeout")
@dataclass(frozen=True,slots=True)
class PairingPlan:
    operation_id:str; provider_id:str; state:str; steps:tuple[str,...]; blockers:tuple[str,...]; production_mutation_enabled:bool=False
    schema:str=field(default="home-center.zigbee-pairing-plan.v1",init=False)
class ZigbeePlanner:
    REQUIRED="zigbee.pairing.v1"
    def plan_pairing(self,request:PairingRequest,snapshot:ZigbeeProviderSnapshot)->PairingPlan:
        blockers=[]
        if request.provider_id!=snapshot.provider_id: blockers.append("provider_identity_mismatch")
        if snapshot.health is not ProviderHealth.HEALTHY: blockers.append("provider_not_healthy")
        if self.REQUIRED not in snapshot.capabilities: blockers.append("pairing_capability_missing")
        if request.requested_device_id and request.requested_device_id in snapshot.known_devices: blockers.append("device_already_registered")
        steps=("validate-provider","request-permit-join","observe-device","validate-capabilities","register-device","close-permit-join")
        return PairingPlan(request.operation_id,request.provider_id,"blocked" if blockers else "planned",steps if not blockers else (),tuple(blockers))
