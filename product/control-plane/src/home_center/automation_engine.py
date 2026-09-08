"""Deterministic plan-only automation engine."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping
ID=re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
CAP=re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
class AutomationError(ValueError):
    def __init__(self,code:str)->None: super().__init__(code); self.code=code
class TriggerKind(StrEnum): DEVICE_EVENT="device-event"; SCHEDULE="schedule"; STATE_CHANGE="state-change"; MANUAL="manual"
@dataclass(frozen=True,slots=True)
class Trigger:
    kind:TriggerKind; source_id:str; event:str
    def __post_init__(self)->None:
        if ID.fullmatch(self.source_id) is None or ID.fullmatch(self.event) is None: raise AutomationError("invalid_trigger")
@dataclass(frozen=True,slots=True)
class PlannedAction:
    target_id:str; capability:str; command:str; parameters:Mapping[str,object]=field(default_factory=dict)
    def __post_init__(self)->None:
        if ID.fullmatch(self.target_id) is None or CAP.fullmatch(self.capability) is None or ID.fullmatch(self.command) is None: raise AutomationError("invalid_action")
        forbidden={"password","secret","token","private_key","credential"}
        if forbidden.intersection(self.parameters): raise AutomationError("secret_parameter_rejected")
@dataclass(frozen=True,slots=True)
class AutomationRule:
    rule_id:str; enabled:bool; trigger:Trigger; actions:tuple[PlannedAction,...]; required_permissions:tuple[str,...]=()
    def __post_init__(self)->None:
        if ID.fullmatch(self.rule_id) is None or not self.actions or len(self.actions)>64: raise AutomationError("invalid_rule")
        if any(ID.fullmatch(v) is None for v in self.required_permissions): raise AutomationError("invalid_permission")
@dataclass(frozen=True,slots=True)
class AutomationPlan:
    rule_id:str; state:str; steps:tuple[dict[str,object],...]; blockers:tuple[str,...]; production_mutation_enabled:bool=False
    schema:str=field(default="home-center.automation-plan.v1",init=False)
class AutomationPlanner:
    def plan(self,rule:AutomationRule,*,trigger:Trigger,permissions:tuple[str,...],available_capabilities:Mapping[str,tuple[str,...]])->AutomationPlan:
        blockers=[]
        if not rule.enabled: blockers.append("rule_disabled")
        if trigger!=rule.trigger: blockers.append("trigger_not_matched")
        granted=set(permissions)
        if not set(rule.required_permissions).issubset(granted): blockers.append("permission_denied")
        steps=[]
        for sequence,action in enumerate(rule.actions,1):
            caps=set(available_capabilities.get(action.target_id,()))
            if action.capability not in caps: blockers.append(f"capability_unavailable:{action.target_id}")
            steps.append({"sequence":sequence,"target_id":action.target_id,"capability":action.capability,"command":action.command,"parameters":dict(action.parameters),"requires_execution_authority":True})
        return AutomationPlan(rule.rule_id,"blocked" if blockers else "planned",tuple(steps) if not blockers else (),tuple(blockers))
