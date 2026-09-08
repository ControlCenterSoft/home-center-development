"""Plan-only LXC lifecycle for provider-backed infrastructure."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import StrEnum
from .compute_framework import ComputePlanner, ComputeProviderDescriptor, ComputeResourceKind, ComputeResourceRequest
ID=re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
class LxcLifecycleError(ValueError):
    def __init__(self,code:str)->None: super().__init__(code); self.code=code
class LxcState(StrEnum): STOPPED="stopped"; RUNNING="running"; FROZEN="frozen"; ABSENT="absent"
class LxcAction(StrEnum): CREATE="create"; START="start"; STOP="stop"; FREEZE="freeze"; DELETE="delete"
@dataclass(frozen=True,slots=True)
class LxcSnapshot:
    container_id:str; provider_id:str; state:LxcState; vcpu:int; memory_mib:int; disk_gib:int
@dataclass(frozen=True,slots=True)
class LxcLifecycleRequest:
    operation_id:str; container_id:str; action:LxcAction; vcpu:int|None=None; memory_mib:int|None=None; disk_gib:int|None=None; high_availability:bool=False
    def __post_init__(self)->None:
        if ID.fullmatch(self.operation_id) is None or ID.fullmatch(self.container_id) is None: raise LxcLifecycleError("invalid_request_identity")
        if self.action is LxcAction.CREATE and None in (self.vcpu,self.memory_mib,self.disk_gib): raise LxcLifecycleError("create_resources_required")
@dataclass(frozen=True,slots=True)
class LxcLifecyclePlan:
    operation_id:str; container_id:str; action:LxcAction; state:str; provider_id:str|None; steps:tuple[str,...]; blockers:tuple[str,...]; production_mutation_enabled:bool=False
    schema:str=field(default="home-center.lxc-lifecycle-plan.v1",init=False)
class LxcLifecyclePlanner:
    def plan(self,request:LxcLifecycleRequest,*,provider:ComputeProviderDescriptor,snapshot:LxcSnapshot|None=None,available_cpu:int=0,available_memory_mib:int=0,available_storage_gib:int=0)->LxcLifecyclePlan:
        blockers=[]
        if request.action is LxcAction.CREATE:
            if snapshot is not None and snapshot.state is not LxcState.ABSENT: blockers.append("container_already_exists")
            resource=ComputeResourceRequest(request.container_id,ComputeResourceKind.LXC,int(request.vcpu),int(request.memory_mib),int(request.disk_gib),request.high_availability)
            compute=ComputePlanner().plan_create(provider,resource,available_cpu=available_cpu,available_memory_mib=available_memory_mib,available_storage_gib=available_storage_gib)
            blockers.extend(compute.blockers); steps=("validate-provider","reserve-capacity","create-container","verify-state")
        else:
            if snapshot is None or snapshot.state is LxcState.ABSENT: blockers.append("container_not_found")
            elif snapshot.provider_id!=provider.provider_id: blockers.append("provider_identity_mismatch")
            else:
                allowed={LxcAction.START:{LxcState.STOPPED},LxcAction.STOP:{LxcState.RUNNING,LxcState.FROZEN},LxcAction.FREEZE:{LxcState.RUNNING},LxcAction.DELETE:{LxcState.STOPPED}}
                if snapshot.state not in allowed[request.action]: blockers.append("invalid_state_transition")
            steps=("validate-current-state",f"{request.action.value}-container","verify-state")
        return LxcLifecyclePlan(request.operation_id,request.container_id,request.action,"blocked" if blockers else "planned",provider.provider_id,tuple(steps),tuple(blockers))
