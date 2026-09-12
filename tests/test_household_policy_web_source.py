from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "product" / "web" / "static" / "index.html"
CLIENT = ROOT / "product" / "web" / "static" / "household-policy.js"
STYLE = ROOT / "product" / "web" / "static" / "household-policy.css"


def test_cozy_policy_ui_requires_preview_then_explicit_confirmation() -> None:
    index = INDEX.read_text(encoding="utf-8")
    client = CLIENT.read_text(encoding="utf-8")

    assert 'id="policy-composer-card"' in index
    assert 'id="policy-plan-form"' in index
    assert 'id="policy-preview"' in index
    assert 'id="policy-confirm-button"' in index
    assert "Показать правила" in index
    assert "Применить правила" in index
    assert "До нажатия «Применить правила» ничего не меняется" in index

    assert "'/api/v1/household/policies/plan'" in client
    assert "'/api/v1/household/policies/confirm'" in client
    assert "home-center.household-policy-plan-request.v1" in client
    assert "home-center.household-policy-confirm-request.v1" in client
    assert "confirmed: true" in client
    assert "desired_state_materialized !== true" in client


def test_policy_client_renders_text_without_html_injection_and_exposes_exact_technical_view() -> None:
    client = CLIENT.read_text(encoding="utf-8")
    style = STYLE.read_text(encoding="utf-8")

    assert "textContent = String(value)" in client
    assert "textContent = JSON.stringify(full.technical_policy" in client
    assert "innerHTML" not in client
    assert "presentation?.same_policy_evidence !== true" in client
    assert ".policy-technical" in style


def test_policy_ui_does_not_call_provider_or_execution_routes() -> None:
    client = CLIENT.read_text(encoding="utf-8")

    assert "/provider" not in client
    assert "/execution" not in client
    assert "/jobs" not in client
