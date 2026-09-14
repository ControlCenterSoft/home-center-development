from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.63.0"


def _contract(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def test_063_release_identity_remains_historical_stable_boundary() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "# Home Center 0.63.0" in notes
    assert "Status: official release." in notes
    assert "Home Center 0.62.1 → 0.63.0" in notes


def test_063_release_notes_are_official_bounded_and_truthful() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "Status: official release." in notes
    assert "Release profile: `single-node-core`." in notes
    assert "Home Center 0.62.1 → 0.63.0" in notes
    assert "Technical Public Stable qualification must remain distinct" in notes
    assert "Commercial-launch clearance remains a separate business/legal boundary" in notes
    assert "HA/automatic failover is not claimed" in notes


def test_063_complete_qr_runtime_effect_and_http_sources_are_present() -> None:
    for relative in (
        "product/control-plane/src/home_center/qr_onboarding.py",
        "product/control-plane/src/home_center/qr_onboarding_validation.py",
        "product/control-plane/src/home_center/qr_onboarding_runtime.py",
        "product/control-plane/src/home_center/qr_onboarding_api.py",
        "product/control-plane/src/home_center/qr_onboarding_audit.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_handoff.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_verification.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_source.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_admission.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_execution.py",
        "product/control-plane/src/home_center/qr_onboarding_product_state.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_worker.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_api.py",
        "product/control-plane/src/home_center/api_v10.py",
        "product/control-plane/src/home_center/api_v11.py",
    ):
        assert (ROOT / relative).is_file()


def test_063_request_contracts_are_closed() -> None:
    for name in (
        "qr-onboarding-invitation.v1.schema.json",
        "qr-onboarding-payload.v1.schema.json",
        "qr-onboarding-redemption-plan.v1.schema.json",
        "qr-onboarding-runtime-record.v1.schema.json",
        "qr-onboarding-operation-receipt.v1.schema.json",
        "qr-onboarding-audit-details.v1.schema.json",
        "qr-onboarding-api-issue-request.v1.schema.json",
        "qr-onboarding-api-plan-request.v1.schema.json",
        "qr-onboarding-api-consume-request.v1.schema.json",
        "qr-onboarding-api-revoke-request.v1.schema.json",
        "qr-onboarding-effect-api-admit-request.v1.schema.json",
        "qr-onboarding-effect-api-run-request.v1.schema.json",
    ):
        assert _contract(name)["additionalProperties"] is False


def test_063_notes_preserve_no_admin_credential_and_verified_success_boundaries() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "must never contain a long-lived administrative credential" in notes
    assert "fails closed" in notes
    assert "post_condition_verified=true" in notes
    assert "second explicit parent confirmation" in notes
    assert "authenticated same-origin V11 HTTP routes" in notes
    assert "never automatically re-executed" in notes
