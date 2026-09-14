from __future__ import annotations

from pathlib import Path

from home_center.api_v11 import RuntimeRequestHandlerV11
from home_center.api_v12 import RuntimeRequestHandlerV12
from home_center.qr_onboarding_runtime import (
    QrOnboardingRuntimeService,
    SQLiteQrOnboardingRuntimeRepository,
)
from home_center.store import StateStore


ROOT = Path(__file__).resolve().parents[1]


def test_canonical_server_wraps_v11_qr_handler_with_v12_ha_boundary() -> None:
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(encoding="utf-8")
    assert issubclass(RuntimeRequestHandlerV12, RuntimeRequestHandlerV11)
    assert "from .api_v12 import RuntimeRequestHandlerV12" in server
    assert "HomeCenterServer(config.web_bind, RuntimeRequestHandlerV12, runtime)" in server
    assert "RuntimeRequestHandlerV10" not in server
    assert "from .runtime_safe import ProductionRuntime as Runtime" in server


def test_production_runtime_wires_qr_to_canonical_state_store_without_self_migration() -> None:
    production = (ROOT / "product/control-plane/src/home_center/runtime_safe.py").read_text(encoding="utf-8")
    assert "SQLiteQrOnboardingRuntimeRepository" in production
    assert "self.store._connection" in production
    assert "self.store._lock" in production
    assert "self.qr_onboarding = QrOnboardingRuntimeService(" in production
    assert "self.qr_effect_source = QrOnboardingEffectSourceService(qr_repository)" in production
    assert "self.qr_effect_admission = QrOnboardingEffectAdmissionService(self.store)" in production
    assert "self.qr_effect_execution = QrOnboardingEffectExecutionService(self.store)" in production
    assert "QrOnboardingProductStateAdapter(self.store)" in production
    assert "self.qr_effect_worker = QrOnboardingEffectWorkerService(self.store, self.qr_effect_execution)" in production
    assert "executescript" not in production
    assert "schema_sql" not in production


def test_canonical_state_store_schema_accepts_production_qr_repository(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.db", b"q" * 32, "cluster-test")
    try:
        repository = SQLiteQrOnboardingRuntimeRepository(store._connection, store._lock)  # noqa: SLF001
        service = QrOnboardingRuntimeService(repository)
        assert service.repository is repository
        with store._lock:  # noqa: SLF001
            tables = {
                row[0]
                for row in store._connection.execute(  # noqa: SLF001
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        assert "qr_onboarding_runtime" in tables
        assert "qr_onboarding_runtime_operations" in tables
        assert store.integrity_check()
        store.verify_audit_chain()
    finally:
        store.close()
