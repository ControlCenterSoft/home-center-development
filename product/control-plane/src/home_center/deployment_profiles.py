"""Infrastructure-neutral deployment profiles for arbitrary supported topologies."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Iterable

IDENTIFIER=re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
HOSTNAME=re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
CAPABILITY=re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")

class DeploymentProfileError(ValueError):
    def __init__(self,code:str)->None: super().__init__(code); self.code=code

@dataclass(frozen=True,slots=True)
class NodeRequirement:
    node_id:str
    hostname:str|None=None
    endpoint:str|None=None
    roles:tuple[str,...]=()
    required_capabilities:tuple[str,...]=()
    labels:tuple[str,...]=()
    def __post_init__(self)->None:
        if IDENTIFIER.fullmatch(self.node_id) is None: raise DeploymentProfileError("invalid_node_id")
        if self.hostname is not None and HOSTNAME.fullmatch(self.hostname) is None: raise DeploymentProfileError("invalid_hostname")
        if self.endpoint is not None and not 3<=len(self.endpoint)<=512: raise DeploymentProfileError("invalid_endpoint")
        if any(IDENTIFIER.fullmatch(v) is None for v in self.roles+self.labels): raise DeploymentProfileError("invalid_node_metadata")
        if any(CAPABILITY.fullmatch(v) is None for v in self.required_capabilities): raise DeploymentProfileError("invalid_capability")

@dataclass(frozen=True,slots=True)
class PlacementPolicy:
    minimum_ready_nodes:int=1
    maximum_nodes:int=64
    allow_single_node:bool=True
    require_distinct_failure_domains:bool=False
    def __post_init__(self)->None:
        if not 1<=self.minimum_ready_nodes<=self.maximum_nodes<=64: raise DeploymentProfileError("invalid_node_bounds")
        if not isinstance(self.allow_single_node,bool) or not isinstance(self.require_distinct_failure_domains,bool): raise DeploymentProfileError("invalid_placement_policy")
        if not self.allow_single_node and self.minimum_ready_nodes<2: raise DeploymentProfileError("single_node_policy_conflict")

@dataclass(frozen=True,slots=True)
class DeploymentProfile:
    profile_id:str
    nodes:tuple[NodeRequirement,...]
    placement:PlacementPolicy=field(default_factory=PlacementPolicy)
    directory_provider:str|None=None
    production_mutation_enabled:bool=False
    schema:str=field(default="home-center.deployment-profile.v2",init=False)
    def __post_init__(self)->None:
        if IDENTIFIER.fullmatch(self.profile_id) is None: raise DeploymentProfileError("invalid_profile_id")
        if not 1<=len(self.nodes)<=self.placement.maximum_nodes: raise DeploymentProfileError("invalid_node_count")
        if len({n.node_id for n in self.nodes})!=len(self.nodes): raise DeploymentProfileError("duplicate_node_id")
        if self.directory_provider is not None and IDENTIFIER.fullmatch(self.directory_provider) is None: raise DeploymentProfileError("invalid_directory_provider")
        if self.production_mutation_enabled: raise DeploymentProfileError("mutation_not_certified")

@dataclass(frozen=True,slots=True)
class DiscoveredNode:
    node_id:str
    capabilities:tuple[str,...]
    healthy:bool
    failure_domain:str|None=None

@dataclass(frozen=True,slots=True)
class DeploymentPlan:
    profile_id:str
    state:str
    assignments:tuple[tuple[str,str],...]
    blockers:tuple[str,...]
    production_mutation_enabled:bool=False
    schema:str=field(default="home-center.deployment-plan.v1",init=False)
    def to_dict(self)->dict[str,object]:
        return {"schema":self.schema,"profile_id":self.profile_id,"state":self.state,"assignments":[{"requirement":a,"node":b} for a,b in self.assignments],"blockers":list(self.blockers),"production_mutation_enabled":False}

class DeploymentPlanner:
    """Match a desired profile to discovered nodes without fixed infrastructure assumptions."""
    def plan(self,profile:DeploymentProfile,discovered:Iterable[DiscoveredNode])->DeploymentPlan:
        candidates=tuple(sorted(discovered,key=lambda n:n.node_id))
        if len(candidates)>profile.placement.maximum_nodes: return DeploymentPlan(profile.profile_id,"blocked",(),("too_many_discovered_nodes",))
        assignments=[]; used=set(); blockers=[]; domains=set()
        for requirement in profile.nodes:
            match=None
            for node in candidates:
                if node.node_id in used or not node.healthy: continue
                if not set(requirement.required_capabilities).issubset(node.capabilities): continue
                match=node; break
            if match is None:
                blockers.append(f"unsatisfied:{requirement.node_id}"); continue
            assignments.append((requirement.node_id,match.node_id)); used.add(match.node_id)
            if match.failure_domain: domains.add(match.failure_domain)
        if len(assignments)<profile.placement.minimum_ready_nodes: blockers.append("minimum_ready_nodes_not_met")
        if profile.placement.require_distinct_failure_domains and len(domains)<min(len(assignments),profile.placement.minimum_ready_nodes): blockers.append("failure_domain_policy_not_met")
        return DeploymentPlan(profile.profile_id,"blocked" if blockers else "planned",tuple(assignments),tuple(blockers))
