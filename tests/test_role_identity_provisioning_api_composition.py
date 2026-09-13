from __future__ import annotations

from types import SimpleNamespace

import pytest

from home_center.role_identity_provisioning_api_composition import role_identity_provisioning_api_for_runtime
from home_center.role_identity_provisioning_runtime import RoleIdentityProvisioningRuntimeService
from home_center.role_identity_provisioning_runtime_safe import SafeRoleIdentityProvisioningRuntimeService
from home_center.store import StateStore


def _store(tmp_path):
    return StateStore(tmp_path / "state.db", audit_key=b"q" * 32, cluster_id="cluster-test")


def test_api_composition_requires_safe_qualified_registry(tmp_path) -> None:
    store = _store(tmp_path)
    generic = SimpleNamespace(store=store, role_identity_provisioning=RoleIdentityProvisioningRuntimeService(store))
    with pytest.raises(RuntimeError, match="identity_api_safe_runtime_composition_unavailable"):
        role_identity_provisioning_api_for_runtime(generic)

    safe = SimpleNamespace(store=store, role_identity_provisioning=SafeRoleIdentityProvisioningRuntimeService(store))
    first = role_identity_provisioning_api_for_runtime(safe)
    second = role_identity_provisioning_api_for_runtime(safe)
    assert first is second
    store.close()
