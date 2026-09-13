from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _contract(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def test_063_exact_candidate_identity_is_consistent() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == "0.63.0"
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == "0.63.0"
    runtime_init = (ROOT / "product/control-plane/src/home_center/__init__.py").read_text(encoding="utf-8")
    assert '__version__ = "0.63.0"' in runtime_init
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    assert '<small id="version">0.63.0</small>' in html
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "Status: qualification candidate; not Public Stable." in notes
    assert "Authoritative Public Stable: Home Center 0.62.1" in notes
    assert "candidate identity is exactly **0.63.0**" in notes


def test_063_runtime_validation_api_and_audit_sources_are_present() -> None:
    for relative in (
        "product/control-plane/src/home_center/qr_onboarding.py",
        "product/control-plane/src/home_center/qr_onboarding_validation.py",
        "product/control-plane/src/home_center/qr_onboarding_runtime.py",
        "product/control-plane/src/home_center/qr_onboarding_api.py",
        "product/control-plane/src/home_center/qr_onboarding_audit.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_handoff.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_verification.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_admission.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_execution.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_source.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_worker.py",
        "product/control-plane/src/home_center/qr_onboarding_effect_api.py",
    ):
        assert (ROOT / relative).is_file()


def test_063_contracts_are_closed() -> None:
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
    ):
        assert _contract(name)["additionalProperties"] is False


def test_063_notes_preserve_no_admin_credential_and_no_false_success_boundaries() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "must never contain a long-lived administrative credential" in notes
    assert "fail closed" in notes
    assert "onboarding_effect_verified=false" in notes
    assert "do **not** create an account" in notes
    assert "authenticated same-origin HTTP" in notes
    assert "Provider or command acceptance is never treated as onboarding success" in notes
