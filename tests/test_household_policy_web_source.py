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


def test_policy_client_renders_text_without_html_injection_and_exposes_exact_full_evidence() -> None:
    index = INDEX.read_text(encoding="utf-8")
    client = CLIENT.read_text(encoding="utf-8")
    style = STYLE.read_text(encoding="utf-8")

    assert 'id="full-policy-inspector"' in index
    assert 'id="full-policy-evidence"' in index
    assert "тот же `bundle_id`" in index
    assert "textContent = String(value)" in client
    assert "textContent = JSON.stringify(full.technical_policy" in client
    assert "fullEvidence.textContent = JSON.stringify" in client
    assert "bundle_id: full.bundle_id" in client
    assert "proposal_id: full.proposal_id" in client
    assert "expected_desired_state_generation: full.expected_desired_state_generation" in client
    assert "innerHTML" not in client
    assert "presentation?.same_policy_evidence !== true" in client
    assert ".policy-technical" in style


def test_full_policy_ui_uses_verified_history_and_separate_explicit_rollback_confirmation() -> None:
    index = INDEX.read_text(encoding="utf-8")
    client = CLIENT.read_text(encoding="utf-8")
    style = STYLE.read_text(encoding="utf-8")

    assert 'id="policy-history-list"' in index
    assert 'id="policy-rollback-confirm"' in index
    assert 'id="policy-rollback-confirm-button"' in index
    assert 'id="policy-rollback-cancel-button"' in index
    assert "Подтвердить возврат" in index
    assert "не запускает управление устройствами" in index
    assert "/api/v1/household/policies/history?resource_key=" in client
    assert "'/api/v1/household/policies/rollback'" in client
    assert "home-center.household-policy-rollback-request.v1" in client
    assert "expected_generation: latestHistory.current_generation" in client
    assert "expected_bundle_id: latestHistory.current_bundle_id" in client
    assert "confirmed: true" in client
    assert ".policy-history-item" in style


def test_policy_ui_does_not_call_provider_execution_or_job_routes() -> None:
    client = CLIENT.read_text(encoding="utf-8")

    assert "/provider" not in client
    assert "/execution" not in client
    assert "/jobs" not in client
