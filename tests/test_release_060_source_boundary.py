from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_release_060_notes_preserve_current_stable_and_non_rc_status() -> None:
    notes = (ROOT / "docs/releases/0.60.0.md").read_text(encoding="utf-8")
    assert "Status: source development; not Release Candidate and not Public Stable." in notes
    assert "текущий официальный Public Stable остаётся Home Center 0.59.0" in notes
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == "0.59.0"


def test_release_060_notes_do_not_turn_provider_acceptance_into_success() -> None:
    notes = (ROOT / "docs/releases/0.60.0.md").read_text(encoding="utf-8")
    assert "Provider command acceptance также не является enforcement success" in notes
    assert "`enforcement_verified=false`" in notes
    assert "`reconciliation_required=true`" in notes
    assert "`dns_policy_applied=false`" in notes
    assert "`proxy_policy_applied=false`" in notes
    assert "Concrete production adapter не регистрируется" in notes


def test_release_060_notes_keep_commercial_and_ha_claims_separate() -> None:
    notes = (ROOT / "docs/releases/0.60.0.md").read_text(encoding="utf-8")
    assert "Commercial launch clearance" in notes
    assert "multi-node HA/automatic failover" in notes
    assert "не заявляются" in notes
