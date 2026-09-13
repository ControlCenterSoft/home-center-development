from __future__ import annotations

import json
from pathlib import Path

from scripts.qualify_release_artifact import REQUIRED_MEMBERS

ROOT = Path(__file__).resolve().parents[1]


def _contract(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def test_063_effect_handoff_runtime_is_required_in_reproducible_wheel() -> None:
    assert {
        "home_center/qr_onboarding_effect_handoff.py",
        "home_center/qr_onboarding_effect_verification.py",
        "home_center/qr_onboarding_effect_admission.py",
    } <= REQUIRED_MEMBERS


def test_063_effect_handoff_contracts_are_closed_and_non_authorizing() -> None:
    handoff = _contract("qr-onboarding-effect-handoff.v1.schema.json")
    verification = _contract("qr-onboarding-effect-verification-request.v1.schema.json")
    assert handoff["additionalProperties"] is False
    assert verification["additionalProperties"] is False
    for name in (
        "effect_execution_authorized",
        "account_creation_authorized",
        "device_registration_authorized",
        "managed_state_change_authorized",
        "provider_execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert handoff["properties"][name] == {"const": False}
    assert verification["properties"]["authoritative_readback_required"] == {"const": True}
    assert verification["properties"]["post_condition_verified"] == {"const": False}
    assert verification["properties"]["effect_success_claimed"] == {"const": False}
    assert verification["properties"]["provider_execution_authorized"] == {"const": False}
    assert verification["properties"]["infrastructure_mutation_authorized"] == {"const": False}
    assert verification["properties"]["external_publication_authorized"] == {"const": False}


def test_063_effect_handoff_does_not_preempt_release_identity_or_open_execution() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() != "0.63.0"
    handoff_source = (
        ROOT / "product/control-plane/src/home_center/qr_onboarding_effect_handoff.py"
    ).read_text(encoding="utf-8")
    verification_source = (
        ROOT / "product/control-plane/src/home_center/qr_onboarding_effect_verification.py"
    ).read_text(encoding="utf-8")
    admission_source = (
        ROOT / "product/control-plane/src/home_center/qr_onboarding_effect_admission.py"
    ).read_text(encoding="utf-8")
    assert 'effect_execution_authorized: bool = field(default=False' in handoff_source
    assert 'post_condition_verified: bool = field(default=False' in verification_source
    assert 'effect_success_claimed: bool = field(default=False' in verification_source
    assert '"execution_authorized": False' in admission_source
    assert '"post_condition_verified": False' in admission_source
    assert '"effect_success_claimed": False' in admission_source
