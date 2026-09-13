"""Production-safe Home Center runtime composition.

This composition keeps the generic Runtime reusable for tests and internal composition while
ensuring the actual server process exposes identity provisioning only through the qualification-
bound provider registry. No provider is registered automatically.
"""
from __future__ import annotations

from .role_identity_provisioning_api_runtime import RoleIdentityProvisioningApiService
from .role_identity_provisioning_runtime_safe import SafeRoleIdentityProvisioningRuntimeService
from .runtime import Runtime


class ProductionRuntime(Runtime):
    """Server runtime with fail-closed identity provider admission."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.role_identity_provisioning = SafeRoleIdentityProvisioningRuntimeService(self.store)
        self.role_identity_provisioning_api = RoleIdentityProvisioningApiService(
            self.store,
            self.role_identity_provisioning,
            self.role_identity_binding,
        )
