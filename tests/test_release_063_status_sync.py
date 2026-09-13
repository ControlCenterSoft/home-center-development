from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_063_status_is_official_after_verified_effect_path_completion() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "Status: official release." in notes
    assert "durable typed effect Job admission" in notes
    assert "restart-safe effect worker semantics" in notes
    assert "authoritative post-condition read-back" in notes
    assert "post_condition_verified=true" in notes
    assert "authenticated same-origin V11 HTTP routes" in notes
    assert "Home Center 0.62.1 → 0.63.0" in notes


def test_release_063_notes_record_all_previously_pending_functional_gates_as_closed() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    for required in (
        "additive canonical StateStore migration",
        "authenticated same-origin issue/plan/consume/revoke HTTP routes",
        "privacy-minimized receipt-only Audit persistence",
        "restart and backup/restore preservation",
        "exact effect handoff",
        "durable typed effect Job admission",
        "concrete bounded product-state effect adapters",
        "restart-safe effect worker semantics",
        "authoritative post-condition read-back",
        "transport-neutral explicit effect `admit` and `run` API contracts",
        "authenticated same-origin V11 HTTP routes",
    ):
        assert required in notes


def test_release_063_keeps_commercial_provider_and_ha_claims_separate_from_technical_stable() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "Concrete provider execution remains fail-closed unless separately qualified" in notes
    assert "HA/automatic failover is not claimed" in notes
    assert "Commercial-launch clearance remains a separate business/legal boundary" in notes
    assert "Technical Public Stable qualification must remain distinct" in notes
