from __future__ import annotations

from pathlib import Path

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_qr_product_state_adapter_is_mandatory_release_artifact_member() -> None:
    assert "home_center/qr_onboarding_product_state.py" in REQUIRED_MEMBERS
    assert (ROOT / "product/control-plane/src/home_center/qr_onboarding_product_state.py").is_file()


def test_production_runtime_registers_product_state_effect_adapter_without_provider_authority() -> None:
    runtime = (ROOT / "product/control-plane/src/home_center/runtime_safe.py").read_text(encoding="utf-8")
    adapter = (ROOT / "product/control-plane/src/home_center/qr_onboarding_product_state.py").read_text(
        encoding="utf-8"
    )
    assert "QrOnboardingProductStateAdapter" in runtime
    assert "QrOnboardingEffectExecutionService" in runtime
    assert '"provider_execution_authorized": False' in adapter
    assert '"infrastructure_mutation_authorized": False' in adapter
    assert '"external_publication_authorized": False' in adapter
