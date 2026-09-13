"""Lazy production composition for the Home Center 0.62 identity provisioning API.

The HTTP-facing service may only compose on top of the qualification-gated safe
identity runtime. No provider is registered automatically; concrete providers
still require exact qualification evidence and explicit server-side registration.
"""
from __future__ import annotations

from .role_identity_provisioning_api_runtime import RoleIdentityProvisioningApiRuntimeService
from .role_identity_provisioning_runtime_safe import SafeRoleIdentityProvisioningRuntimeService

_SERVICE_ATTR = "_role_identity_provisioning_api_service"


def role_identity_provisioning_api_for_runtime(runtime: object) -> RoleIdentityProvisioningApiRuntimeService:
    existing = getattr(runtime, _SERVICE_ATTR, None)
    if isinstance(existing, RoleIdentityProvisioningApiRuntimeService):
        return existing
    store = getattr(runtime, "store", None)
    execution = getattr(runtime, "role_identity_provisioning", None)
    if store is None or not isinstance(execution, SafeRoleIdentityProvisioningRuntimeService):
        raise RuntimeError("identity_api_safe_runtime_composition_unavailable")
    service = RoleIdentityProvisioningApiRuntimeService(store, execution)
    setattr(runtime, _SERVICE_ATTR, service)
    return service
