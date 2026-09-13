from __future__ import annotations

import inspect

from home_center.role_identity_provisioning_runtime import RoleIdentityProvisioningRuntimeService
from home_center.role_identity_provisioning_runtime_safe import SafeRoleIdentityProvisioningRuntimeService
from home_center.runtime import Runtime


def test_safe_identity_runtime_is_a_narrowing_of_the_qualified_execution_service() -> None:
    assert issubclass(SafeRoleIdentityProvisioningRuntimeService, RoleIdentityProvisioningRuntimeService)


def test_production_runtime_composes_the_safe_identity_registry_not_generic_registration() -> None:
    source = inspect.getsource(Runtime.__init__)
    assert "self.role_identity_provisioning = SafeRoleIdentityProvisioningRuntimeService(self.store)" in source
    assert "self.role_identity_provisioning = RoleIdentityProvisioningRuntimeService(self.store)" not in source
