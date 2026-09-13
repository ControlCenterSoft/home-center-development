from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_release_060_notes_define_bounded_official_release_identity() -> None:
    notes = (ROOT / "docs/releases/0.60.0.md").read_text(encoding="utf-8")
    assert notes.startswith("# Home Center 0.60.0\n\nStatus: official release.")
    assert "Release profile: `single-node-core`." in notes
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == "0.60.0"


def test_release_060_notes_do_not_turn_provider_acceptance_into_success() -> None:
    notes = (ROOT / "docs/releases/0.60.0.md").read_text(encoding="utf-8")
    assert "Provider command acceptance также не является enforcement success" in notes
    assert "`enforcement_verified=false`" in notes
    assert "`reconciliation_required=true`" in notes
    assert "`dns_policy_applied=false`" in notes
    assert "`proxy_policy_applied=false`" in notes
    assert "Concrete production adapter должен проходить отдельную exact-bound qualification" in notes


def test_release_060_notes_keep_commercial_and_ha_claims_separate() -> None:
    notes = (ROOT / "docs/releases/0.60.0.md").read_text(encoding="utf-8")
    assert "commercial launch clearance" in notes
    assert "Multi-node HA / automatic failover" in notes
    assert "не заявляются" in notes
