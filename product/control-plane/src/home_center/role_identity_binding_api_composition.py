"""Lazy production composition for the Home Center 0.62 identity-binding API."""
from __future__ import annotations

from .role_identity_binding_api_runtime import RoleIdentityBindingApiRuntimeService
from .role_identity_binding_transition import RoleIdentityBindingTransitionService
from .role_identity_provisioning_runtime_safe import SafeRoleIdentityProvisioningRuntimeService

_SERVICE_ATTR = "_role_identity_binding_api_service"


def role_identity_binding_api_for_runtime(runtime: object) -> RoleIdentityBindingApiRuntimeService:
    existing = getattr(runtime, _SERVICE_ATTR, None)
    if isinstance(existing, RoleIdentityBindingApiRuntimeService):
        return existing
    store = getattr(runtime, "store", None)
    execution = getattr(runtime, "role_identity_provisioning", None)
    binding = getattr(runtime, "role_identity_binding", None)
    if (
        store is None
        or not isinstance(execution, SafeRoleIdentityProvisioningRuntimeService)
        or not isinstance(binding, RoleIdentityBindingTransitionService)
    ):
        raise RuntimeError("identity_binding_api_safe_runtime_composition_unavailable")
    service = RoleIdentityBindingApiRuntimeService(store, binding)
    setattr(runtime, _SERVICE_ATTR, service)
    return service
