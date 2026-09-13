from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_production_server_uses_v10_qr_handler() -> None:
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(encoding="utf-8")
    api_v10 = (ROOT / "product/control-plane/src/home_center/api_v10.py").read_text(encoding="utf-8")

    assert "from .api_v10 import RuntimeRequestHandlerV10" in server
    assert "from .api_v9 import RuntimeRequestHandlerV9" not in server
    assert "HomeCenterServer(config.web_bind, RuntimeRequestHandlerV10, runtime)" in server
    assert "class RuntimeRequestHandlerV10(RuntimeRequestHandlerV9):" in api_v10
    assert '"/api/v1/household/qr-onboarding/issue"' in api_v10
    assert '"/api/v1/household/qr-onboarding/plan"' in api_v10
    assert '"/api/v1/household/qr-onboarding/consume"' in api_v10
    assert '"/api/v1/household/qr-onboarding/revoke"' in api_v10


def test_production_runtime_composes_canonical_qr_repository() -> None:
    production = (ROOT / "product/control-plane/src/home_center/runtime_safe.py").read_text(
        encoding="utf-8"
    )
    store = (ROOT / "product/control-plane/src/home_center/store.py").read_text(encoding="utf-8")

    assert "self.qr_onboarding = QrOnboardingRuntimeService(" in production
    assert "SQLiteQrOnboardingRuntimeRepository(" in production
    assert "self.store._connection" in production
    assert "self.store._lock" in production
    assert "CREATE TABLE IF NOT EXISTS qr_onboarding_runtime (" in store
    assert "CREATE TABLE IF NOT EXISTS qr_onboarding_runtime_operations (" in store


def test_qr_http_activation_preserves_bounded_effect_boundary() -> None:
    api_v10 = (ROOT / "product/control-plane/src/home_center/api_v10.py").read_text(encoding="utf-8")
    runtime = (ROOT / "product/control-plane/src/home_center/qr_onboarding_runtime.py").read_text(
        encoding="utf-8"
    )

    assert "_same_origin_post_allowed" in api_v10
    assert "_require_actor" in api_v10
    assert "max_bytes=8192" in api_v10
    assert '"typed-guest-access-change-job"' in runtime
    assert '"typed-device-binding-change-job"' in runtime
    assert '"onboarding_effect_verified": False' in runtime
    assert '"provider_execution_authorized": False' in runtime
    assert '"infrastructure_mutation_authorized": False' in runtime
    assert '"external_publication_authorized": False' in runtime
