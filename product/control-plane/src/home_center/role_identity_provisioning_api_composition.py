"""Lazy composition helper for the Home Center 0.62 identity provisioning API.

The production Runtime already owns the durable identity execution service. This
helper composes the HTTP-facing service without activating any provider adapter;
qualified providers still have to be registered explicitly against exact evidence.
"""
from __future__ import annotations

from .role_identity_provisioning_api_runtime import RoleIdentityProvisioningApiRuntimeService

_SERVICE_ATTR = "_role_identity_provisioning_api_service"


def role_identity_provisioning_api_for_runtime(runtime: object) -> RoleIdentityProvisioningApiRuntimeService:
    existing = getattr(runtime, _SERVICE_ATTR, None)
    if isinstance(existing, RoleIdentityProvisioningApiRuntimeService):
        return existing
    store = getattr(runtime, "store", None)
    execution = getattr(runtime, "role_identity_provisioning", None)
    if store is None or execution is None:
        raise RuntimeError("identity_api_runtime_composition_unavailable")
    service = RoleIdentityProvisioningApiRuntimeService(store, execution)
    setattr(runtime, _SERVICE_ATTR, service)
    return service
