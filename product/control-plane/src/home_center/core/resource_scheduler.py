"""Deterministic resource placement across arbitrary compute providers."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from .compute_framework import ComputeProviderDescriptor, ComputeResourceKind, ComputeResourceRequest
ID=re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
@dataclass(frozen=True,slots=True)
class ProviderCapacity:
    provider:ComputeProviderDescriptor; cpu:int; memory_mib:int; storage_gib:int; failure_domain:str|None=None; labels:tuple[str,...]=()
@dataclass(frozen=True,slots=True)
class PlacementRequest:
    request_id:str; resource:ComputeResourceRequest; preferred_providers:tuple[str,...]=(); required_labels:tuple[str,...]=(); avoid_failure_domains:tuple[str,...]=()
    def __post_init__(self)->None:
        if ID.fullmatch(self.request_id) is None: raise ValueError("invalid_request_id")
@dataclass(frozen=True,slots=True)
class PlacementPlan:
    request_id:str; state:str; provider_id:str|None; score:int|None; blockers:tuple[str,...]; production_mutation_enabled:bool=False
    schema:str=field(default="home-center.resource-placement-plan.v1",init=False)
class ResourceScheduler:
    def plan(self,request:PlacementRequest,providers:tuple[ProviderCapacity,...])->PlacementPlan:
        ranked=[]
        for item in providers:
            p=item.provider
            if not p.healthy: continue
            required={ComputeResourceKind.VM:"compute.vm.v1",ComputeResourceKind.LXC:"compute.lxc.v1",ComputeResourceKind.PHYSICAL:"compute.physical.v1"}[request.resource.kind]
            if required not in p.capabilities: continue
            if request.resource.high_availability and "compute.ha.v1" not in p.capabilities: continue
            if item.cpu<request.resource.vcpu or item.memory_mib<request.resource.memory_mib or item.storage_gib<request.resource.disk_gib: continue
            if not set(request.required_labels).issubset(item.labels): continue
            if item.failure_domain and item.failure_domain in request.avoid_failure_domains: continue
            score=0
            if p.provider_id in request.preferred_providers: score+=1000-len(request.preferred_providers)*5
            score+=min(item.cpu-request.resource.vcpu,100)
            score+=min((item.memory_mib-request.resource.memory_mib)//256,100)
            score+=min(item.storage_gib-request.resource.disk_gib,100)
            ranked.append((score,p.provider_id))
        if not ranked: return PlacementPlan(request.request_id,"blocked",None,None,("no_eligible_provider",))
        ranked.sort(key=lambda row:(-row[0],row[1]))
        score,provider_id=ranked[0]
        return PlacementPlan(request.request_id,"planned",provider_id,score,())
