from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_063_status_remains_non_stable_until_effect_readback_is_verified() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "Status: source preparation only; not Release Candidate and not Public Stable." in notes
    assert "durable non-executing typed effect Job admission" in notes
    assert "execution_authorized=false" in notes
    assert "post_condition_verified=false" in notes
    assert "effect_success_claimed=false" in notes
    assert "actual typed guest-access/device-binding/access-revocation effect execution path" in notes
    assert "authoritative read-back" in notes
    assert "0.62.1 → 0.63.0 install/upgrade" in notes


def test_release_063_status_no_longer_lists_already_closed_qr_gates_as_pending() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    closed_section = notes.split("## Closed runner-dependent gates on the current source line", 1)[1].split(
        "## Still required before 0.63 can be promoted", 1
    )[0]
    assert "canonical migration" in closed_section
    assert "authenticated HTTP boundary" in closed_section
    assert "production wiring" in closed_section
    assert "Audit chain" in closed_section
    assert "backup/restart recovery" in closed_section
    assert "durable typed effect Job admission" in closed_section
    assert "release-artifact membership" in closed_section
    assert "commercial-engineering boundary" in closed_section


def test_release_063_keeps_commercial_and_ha_claims_separate_from_technical_stable() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "Concrete provider/HA/commercial-launch claims remain separate qualification boundaries" in notes
    assert "Technical Public Stable qualification must remain distinct" in notes
