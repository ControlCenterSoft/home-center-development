"""Plan-only virtual-machine lifecycle for provider-backed infrastructure."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import StrEnum
from .compute_framework import ComputePlanner, ComputeProviderDescriptor, ComputeResourceKind, ComputeResourceRequest
ID=re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
class VmLifecycleError(ValueError):
    def __init__(self,code:str)->None: super().__init__(code); self.code=code
class VmState(StrEnum): STOPPED="stopped"; RUNNING="running"; SUSPENDED="suspended"; ABSENT="absent"
class VmAction(StrEnum): CREATE="create"; START="start"; STOP="stop"; SUSPEND="suspend"; DELETE="delete"
@dataclass(frozen=True,slots=True)
class VmSnapshot:
    vm_id:str; provider_id:str; state:VmState; vcpu:int; memory_mib:int; disk_gib:int
    def __post_init__(self)->None:
        if ID.fullmatch(self.vm_id) is None or ID.fullmatch(self.provider_id) is None: raise VmLifecycleError("invalid_vm_identity")
@dataclass(frozen=True,slots=True)
class VmLifecycleRequest:
    operation_id:str; vm_id:str; action:VmAction; vcpu:int|None=None; memory_mib:int|None=None; disk_gib:int|None=None; high_availability:bool=False
    def __post_init__(self)->None:
        if ID.fullmatch(self.operation_id) is None or ID.fullmatch(self.vm_id) is None: raise VmLifecycleError("invalid_request_identity")
        if self.action is VmAction.CREATE:
            if None in (self.vcpu,self.memory_mib,self.disk_gib): raise VmLifecycleError("create_resources_required")
@dataclass(frozen=True,slots=True)
class VmLifecyclePlan:
    operation_id:str; vm_id:str; action:VmAction; state:str; provider_id:str|None; steps:tuple[str,...]; blockers:tuple[str,...]; production_mutation_enabled:bool=False
    schema:str=field(default="home-center.vm-lifecycle-plan.v1",init=False)
    def to_dict(self)->dict[str,object]: return {"schema":self.schema,"operation_id":self.operation_id,"vm_id":self.vm_id,"action":self.action.value,"state":self.state,"provider_id":self.provider_id,"steps":list(self.steps),"blockers":list(self.blockers),"production_mutation_enabled":False}
class VmLifecyclePlanner:
    def plan(self,request:VmLifecycleRequest,*,provider:ComputeProviderDescriptor,snapshot:VmSnapshot|None=None,available_cpu:int=0,available_memory_mib:int=0,available_storage_gib:int=0)->VmLifecyclePlan:
        blockers=[]; steps=[]
        if request.action is VmAction.CREATE:
            if snapshot is not None and snapshot.state is not VmState.ABSENT: blockers.append("vm_already_exists")
            resource=ComputeResourceRequest(request.vm_id,ComputeResourceKind.VM,int(request.vcpu),int(request.memory_mib),int(request.disk_gib),request.high_availability)
            compute=ComputePlanner().plan_create(provider,resource,available_cpu=available_cpu,available_memory_mib=available_memory_mib,available_storage_gib=available_storage_gib)
            blockers.extend(compute.blockers); steps=("validate-provider","reserve-capacity","create-vm","verify-state")
        else:
            if snapshot is None or snapshot.state is VmState.ABSENT: blockers.append("vm_not_found")
            elif snapshot.provider_id!=provider.provider_id: blockers.append("provider_identity_mismatch")
            else:
                allowed={VmAction.START:{VmState.STOPPED},VmAction.STOP:{VmState.RUNNING,VmState.SUSPENDED},VmAction.SUSPEND:{VmState.RUNNING},VmAction.DELETE:{VmState.STOPPED}}
                if snapshot.state not in allowed[request.action]: blockers.append("invalid_state_transition")
            steps=("validate-current-state",f"{request.action.value}-vm","verify-state")
        return VmLifecyclePlan(request.operation_id,request.vm_id,request.action,"blocked" if blockers else "planned",provider.provider_id,tuple(steps),tuple(blockers))
