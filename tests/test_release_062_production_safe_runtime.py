from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_production_server_uses_safe_runtime_composition() -> None:
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(encoding="utf-8")
    production = (ROOT / "product/control-plane/src/home_center/runtime_safe.py").read_text(encoding="utf-8")

    assert "from .runtime_safe import ProductionRuntime as Runtime" in server
    assert "from .runtime import Runtime" not in server
    assert "class ProductionRuntime(Runtime):" in production
    assert "SafeRoleIdentityProvisioningRuntimeService(self.store)" in production
    assert "register_adapter(" not in production


def test_production_safe_composition_does_not_register_provider_implicitly() -> None:
    production = (ROOT / "product/control-plane/src/home_center/runtime_safe.py").read_text(encoding="utf-8")

    assert "register_qualified_adapter" not in production
    assert "provider_id=" not in production
    assert "credential" not in production.lower()
