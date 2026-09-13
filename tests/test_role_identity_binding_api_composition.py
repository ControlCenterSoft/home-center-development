from pathlib import Path

import pytest

from home_center.role_identity_binding_api_composition import role_identity_binding_api_for_runtime
from home_center.role_identity_binding_api_runtime import RoleIdentityBindingApiRuntimeService
from home_center.role_identity_binding_transition import RoleIdentityBindingTransitionService
from home_center.store import StateStore


class _Runtime:
    def __init__(self, store: StateStore) -> None:
        self.store = store
        self.role_identity_binding = RoleIdentityBindingTransitionService(store)


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", audit_key=b"q" * 32, cluster_id="cluster-test")


def test_binding_api_composes_only_from_qualified_binding_runtime(tmp_path: Path) -> None:
    store = _store(tmp_path)
    runtime = _Runtime(store)

    first = role_identity_binding_api_for_runtime(runtime)
    second = role_identity_binding_api_for_runtime(runtime)

    assert isinstance(first, RoleIdentityBindingApiRuntimeService)
    assert first is second
    assert first.binding is runtime.role_identity_binding
    store.close()


def test_binding_api_composition_fails_closed_without_binding_runtime(tmp_path: Path) -> None:
    store = _store(tmp_path)

    class _UnsafeRuntime:
        pass

    runtime = _UnsafeRuntime()
    runtime.store = store
    runtime.role_identity_binding = object()

    with pytest.raises(RuntimeError, match="identity_binding_api_runtime_composition_unavailable"):
        role_identity_binding_api_for_runtime(runtime)
    store.close()
