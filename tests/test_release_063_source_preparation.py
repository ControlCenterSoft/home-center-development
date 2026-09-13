from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _contract(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def test_063_source_preparation_does_not_preempt_release_identity() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() != "0.63.0"
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "not Release Candidate and not Public Stable" in notes
    assert "Public Stable at this preparation pass: Home Center 0.61.2" in notes
    assert "must be transplanted/reconciled" in notes


def test_063_runtime_and_validation_sources_are_present() -> None:
    for relative in (
        "product/control-plane/src/home_center/qr_onboarding.py",
        "product/control-plane/src/home_center/qr_onboarding_validation.py",
        "product/control-plane/src/home_center/qr_onboarding_runtime.py",
    ):
        assert (ROOT / relative).is_file()


def test_063_contracts_are_closed() -> None:
    for name in (
        "qr-onboarding-invitation.v1.schema.json",
        "qr-onboarding-payload.v1.schema.json",
        "qr-onboarding-redemption-plan.v1.schema.json",
        "qr-onboarding-runtime-record.v1.schema.json",
        "qr-onboarding-operation-receipt.v1.schema.json",
    ):
        assert _contract(name)["additionalProperties"] is False


def test_063_notes_preserve_no_admin_credential_and_no_false_success_boundaries() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "must never contain a long-lived administrative credential" in notes
    assert "fail closed" in notes
    assert "onboarding_effect_verified=false" in notes
    assert "do **not** create an account" in notes
