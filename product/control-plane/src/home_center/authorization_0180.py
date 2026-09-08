"""Provider-neutral identity and RBAC evaluation for Home Center 0.18."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import StrEnum
ID=re.compile(r"^[a-z][a-z0-9_.:@-]{1,191}$")
PERM=re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
class AuthorizationError(ValueError):
    def __init__(self,code:str)->None: super().__init__(code); self.code=code
class SubjectProvider(StrEnum): LOCAL="local"; AD="ad"
@dataclass(frozen=True,slots=True)
class SubjectRef:
    provider:SubjectProvider; subject_id:str
    def __post_init__(self)->None:
        if ID.fullmatch(self.subject_id) is None: raise AuthorizationError("invalid_subject")
@dataclass(frozen=True,slots=True)
class Role:
    role_id:str; permissions:tuple[str,...]
    def __post_init__(self)->None:
        if ID.fullmatch(self.role_id) is None: raise AuthorizationError("invalid_role")
        if any(PERM.fullmatch(v) is None for v in self.permissions): raise AuthorizationError("invalid_permission")
@dataclass(frozen=True,slots=True)
class Binding:
    subject:SubjectRef; role_id:str; scope_id:str="global"
    def __post_init__(self)->None:
        if ID.fullmatch(self.role_id) is None or ID.fullmatch(self.scope_id) is None: raise AuthorizationError("invalid_binding")
@dataclass(frozen=True,slots=True)
class AuthorizationPolicy:
    policy_id:str; roles:tuple[Role,...]; bindings:tuple[Binding,...]; default_deny:bool=True; production_mutation_enabled:bool=False
    schema:str=field(default="home-center.authorization-policy.v1",init=False)
    def __post_init__(self)->None:
        if ID.fullmatch(self.policy_id) is None: raise AuthorizationError("invalid_policy_id")
        if not self.default_deny: raise AuthorizationError("default_deny_required")
        if len({r.role_id for r in self.roles})!=len(self.roles): raise AuthorizationError("duplicate_role")
@dataclass(frozen=True,slots=True)
class EffectiveAccess:
    subject:SubjectRef; scope_id:str; permissions:tuple[str,...]; decision_source:tuple[str,...]; schema:str=field(default="home-center.effective-access.v1",init=False)
class AuthorizationEngine:
    def evaluate(self,policy:AuthorizationPolicy,subject:SubjectRef,*,scope_id:str="global")->EffectiveAccess:
        roles={r.role_id:r for r in policy.roles}; permissions=set(); sources=[]
        for binding in policy.bindings:
            if binding.subject!=subject or binding.scope_id not in {scope_id,"global"}: continue
            role=roles.get(binding.role_id)
            if role is None: raise AuthorizationError("binding_role_not_found")
            permissions.update(role.permissions); sources.append(role.role_id)
        return EffectiveAccess(subject,scope_id,tuple(sorted(permissions)),tuple(sorted(sources)))
    def authorize(self,access:EffectiveAccess,permission:str)->bool:
        if PERM.fullmatch(permission) is None: raise AuthorizationError("invalid_permission")
        return permission in access.permissions
