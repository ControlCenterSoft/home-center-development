"""Provider-neutral, plan-only identity and RBAC evaluation for Home Center 0.18."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


ID = re.compile(r"^[a-z][a-z0-9_.:@-]{1,191}$")
PERMISSION = re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
MAX_ROLES = 256
MAX_BINDINGS = 4096
MAX_PERMISSIONS = 256


class AuthorizationError(ValueError):
    """Stable authorization-boundary rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SubjectProvider(StrEnum):
    LOCAL = "local"
    AD = "ad"


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and ID.fullmatch(value) is not None


def _valid_permission(value: object) -> bool:
    return isinstance(value, str) and PERMISSION.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class SubjectRef:
    provider: SubjectProvider
    subject_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.provider, SubjectProvider):
            raise AuthorizationError("invalid_subject_provider")
        if not _valid_id(self.subject_id):
            raise AuthorizationError("invalid_subject")

    def to_dict(self) -> dict[str, str]:
        return {"provider": self.provider.value, "subject_id": self.subject_id}


@dataclass(frozen=True, slots=True)
class Role:
    role_id: str
    permissions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _valid_id(self.role_id):
            raise AuthorizationError("invalid_role")
        if type(self.permissions) is not tuple or len(self.permissions) > MAX_PERMISSIONS:
            raise AuthorizationError("invalid_permissions")
        if any(not _valid_permission(value) for value in self.permissions):
            raise AuthorizationError("invalid_permission")
        if len(set(self.permissions)) != len(self.permissions):
            raise AuthorizationError("duplicate_permission")

    def to_dict(self) -> dict[str, Any]:
        return {"role_id": self.role_id, "permissions": list(self.permissions)}


@dataclass(frozen=True, slots=True)
class Binding:
    subject: SubjectRef
    role_id: str
    scope_id: str = "global"

    def __post_init__(self) -> None:
        if not isinstance(self.subject, SubjectRef):
            raise AuthorizationError("invalid_binding_subject")
        if not _valid_id(self.role_id) or not _valid_id(self.scope_id):
            raise AuthorizationError("invalid_binding")

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject.to_dict(),
            "role_id": self.role_id,
            "scope_id": self.scope_id,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationPolicy:
    policy_id: str
    roles: tuple[Role, ...]
    bindings: tuple[Binding, ...]
    default_deny: bool = True
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.authorization-policy.v1", init=False)

    def __post_init__(self) -> None:
        if not _valid_id(self.policy_id):
            raise AuthorizationError("invalid_policy_id")
        if self.default_deny is not True:
            raise AuthorizationError("default_deny_required")
        if self.production_mutation_enabled is not False:
            raise AuthorizationError("production_mutation_forbidden")
        if type(self.roles) is not tuple or len(self.roles) > MAX_ROLES:
            raise AuthorizationError("invalid_roles")
        if type(self.bindings) is not tuple or len(self.bindings) > MAX_BINDINGS:
            raise AuthorizationError("invalid_bindings")
        if any(not isinstance(role, Role) for role in self.roles):
            raise AuthorizationError("invalid_role")
        if any(not isinstance(binding, Binding) for binding in self.bindings):
            raise AuthorizationError("invalid_binding")
        role_ids = {role.role_id for role in self.roles}
        if len(role_ids) != len(self.roles):
            raise AuthorizationError("duplicate_role")
        if len(set(self.bindings)) != len(self.bindings):
            raise AuthorizationError("duplicate_binding")
        if any(binding.role_id not in role_ids for binding in self.bindings):
            raise AuthorizationError("binding_role_not_found")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "roles": [role.to_dict() for role in self.roles],
            "bindings": [binding.to_dict() for binding in self.bindings],
            "default_deny": self.default_deny,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


@dataclass(frozen=True, slots=True)
class EffectiveAccess:
    subject: SubjectRef
    scope_id: str
    permissions: tuple[str, ...]
    decision_source: tuple[str, ...]
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.effective-access.v1", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.subject, SubjectRef):
            raise AuthorizationError("invalid_subject")
        if not _valid_id(self.scope_id):
            raise AuthorizationError("invalid_scope_id")
        if type(self.permissions) is not tuple or len(self.permissions) > MAX_PERMISSIONS:
            raise AuthorizationError("invalid_permissions")
        if any(not _valid_permission(value) for value in self.permissions):
            raise AuthorizationError("invalid_permission")
        if len(set(self.permissions)) != len(self.permissions):
            raise AuthorizationError("duplicate_permission")
        if tuple(sorted(self.permissions)) != self.permissions:
            raise AuthorizationError("noncanonical_permissions")
        if type(self.decision_source) is not tuple or len(self.decision_source) > MAX_ROLES:
            raise AuthorizationError("invalid_decision_source")
        if any(not _valid_id(value) for value in self.decision_source):
            raise AuthorizationError("invalid_decision_source")
        if len(set(self.decision_source)) != len(self.decision_source):
            raise AuthorizationError("duplicate_decision_source")
        if tuple(sorted(self.decision_source)) != self.decision_source:
            raise AuthorizationError("noncanonical_decision_source")
        if self.production_mutation_enabled is not False:
            raise AuthorizationError("production_mutation_forbidden")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "subject": self.subject.to_dict(),
            "scope_id": self.scope_id,
            "permissions": list(self.permissions),
            "decision_source": list(self.decision_source),
            "production_mutation_enabled": self.production_mutation_enabled,
        }


class AuthorizationEngine:
    """Evaluate immutable policy facts without granting execution authority."""

    def evaluate(
        self,
        policy: AuthorizationPolicy,
        subject: SubjectRef,
        *,
        scope_id: str = "global",
    ) -> EffectiveAccess:
        if not isinstance(policy, AuthorizationPolicy):
            raise AuthorizationError("invalid_policy")
        if not isinstance(subject, SubjectRef):
            raise AuthorizationError("invalid_subject")
        if not _valid_id(scope_id):
            raise AuthorizationError("invalid_scope_id")

        roles = {role.role_id: role for role in policy.roles}
        permissions: set[str] = set()
        sources: set[str] = set()
        for binding in policy.bindings:
            if binding.subject != subject or binding.scope_id not in {scope_id, "global"}:
                continue
            role = roles[binding.role_id]
            permissions.update(role.permissions)
            sources.add(role.role_id)
        return EffectiveAccess(
            subject=subject,
            scope_id=scope_id,
            permissions=tuple(sorted(permissions)),
            decision_source=tuple(sorted(sources)),
        )

    def authorize(self, access: EffectiveAccess, permission: str) -> bool:
        if not isinstance(access, EffectiveAccess):
            raise AuthorizationError("invalid_effective_access")
        if not _valid_permission(permission):
            raise AuthorizationError("invalid_permission")
        return permission in access.permissions
