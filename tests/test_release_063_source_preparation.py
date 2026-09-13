from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _contract(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def test_063_source_preparation_does_not_preempt_release_identity() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == "0.60.0"
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "not Release Candidate and not Public Stable" in notes
    assert "Public Stable 0.60.0" in notes


def test_063_runtime_and_validation_sources_are_present() -> None:
    assert (ROOT / "product/control-plane/src/home_center/qr_onboarding.py").is_file()
    assert (ROOT / "product/control-plane/src/home_center/qr_onboarding_validation.py").is_file()


def test_063_contracts_are_closed() -> None:
    for name in (
        "qr-onboarding-invitation.v1.schema.json",
        "qr-onboarding-payload.v1.schema.json",
        "qr-onboarding-redemption-plan.v1.schema.json",
    ):
        assert _contract(name)["additionalProperties"] is False


def test_063_notes_preserve_no_admin_credential_boundary() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "must never contain a long-lived administrative credential" in notes
    assert "Revoked, expired, consumed or code-mismatched invitations fail closed" in notes
