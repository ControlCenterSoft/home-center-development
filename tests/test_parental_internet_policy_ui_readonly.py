from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_existing_family_policy_ui_reads_parental_saved_state_without_mutation_controls() -> None:
    ui = (ROOT / "product/web/static/policy-effective-state.js").read_text(encoding="utf-8")
    assert "const PARENTAL_ENDPOINT = '/api/v1/household/parental-internet/desired';" in ui
    assert "parental(member, 'cozy')" in ui
    assert "parental(member, 'full')" in ui
    assert "Правила сохранены, но фактическое применение ещё не подтверждено." in ui
    assert "provider_execution_authorized=false; external_publication_authorized=false" in ui
    assert "decision-preview" not in ui
    assert "parental-internet/plan" not in ui
    assert "parental-internet/confirm" not in ui
    assert "parental-internet/execute" not in ui


def test_cozy_parental_projection_does_not_render_private_rule_lists() -> None:
    ui = (ROOT / "product/web/static/policy-effective-state.js").read_text(encoding="utf-8")
    cozy_start = ui.index("function appendParentalCozy")
    full_start = ui.index("function appendParentalFull")
    cozy = ui[cozy_start:full_start]
    assert "allow_domains" not in cozy
    assert "deny_domains" not in cozy
    assert "allow_categories" not in cozy
    assert "deny_categories" not in cozy
    assert "daily_quota_minutes" in cozy
    assert "weekly_quota_minutes" in cozy
    assert "continuous_session_minutes" in cozy


def test_full_parental_projection_reports_counts_not_domain_values() -> None:
    ui = (ROOT / "product/web/static/policy-effective-state.js").read_text(encoding="utf-8")
    full_start = ui.index("function appendParentalFull")
    card_start = ui.index("function cozyCard", full_start)
    full = ui[full_start:card_start]
    assert "policy.allow_domains.length" in full
    assert "policy.deny_domains.length" in full
    assert "policy.allow_categories.length" in full
    assert "policy.deny_categories.length" in full
    assert "JSON.stringify(policy.allow_domains)" not in full
    assert "JSON.stringify(policy.deny_domains)" not in full
