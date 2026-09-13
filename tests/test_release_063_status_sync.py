from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_063_status_is_exact_candidate_not_stable() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "Status: qualification candidate; not Public Stable." in notes
    assert "durable typed effect Job admission" in notes
    assert "authoritative product-state read-back" in notes
    assert "HTTP success and `succeeded` permitted only after an exact verified post-condition match" in notes
    assert "no implicit retry/reinvocation after ambiguous execution" in notes
    assert "0.62.1 → 0.63.0 install/upgrade → 0.62.1 rollback" in notes


def test_release_063_closed_section_contains_effect_execution_and_readback() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "authenticated same-origin `/effect/admit` and `/effect/run` HTTP boundaries" in notes
    assert "server-authoritative parent revalidation" in notes
    assert "authoritative terminal invitation-state source" in notes
    assert "restart-safe effect worker" in notes
    assert "authoritative product-state read-back" in notes
    assert "replay/restart semantics that do not duplicate an already executed effect" in notes
    assert "reproducible-artifact qualification" in notes
    assert "commercial-engineering qualification" in notes


def test_release_063_keeps_commercial_and_ha_claims_separate_from_technical_stable() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "Concrete provider/HA/commercial-launch claims remain separate qualification boundaries" in notes
    assert "Technical Public Stable qualification must remain distinct" in notes
    assert "multi-node HA/automatic failover" in notes
    assert "commercial launch clearance unclaimed" in notes
