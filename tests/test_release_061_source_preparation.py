from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _contract(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def test_061_source_preparation_does_not_preempt_release_identity() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == "0.60.0"
    notes = (ROOT / "docs/releases/0.61.0.md").read_text(encoding="utf-8")
    assert "Status: source development; not Release Candidate and not Public Stable." in notes
    assert "Provider selection is not VPN activation." in notes


def test_061_vpn_runtime_source_is_present() -> None:
    for relative in (
        "product/control-plane/src/home_center/vpn_egress_policy.py",
        "product/control-plane/src/home_center/vpn_egress_policy_api.py",
        "product/control-plane/src/home_center/vpn_egress_policy_validation.py",
    ):
        assert (ROOT / relative).is_file()


def test_061_contracts_are_closed_and_non_authorizing() -> None:
    for name in (
        "vpn-egress-provider-candidate.v1.schema.json",
        "vpn-egress-policy.v1.schema.json",
        "vpn-egress-observation.v1.schema.json",
        "vpn-egress-route-decision.v1.schema.json",
    ):
        schema = _contract(name)
        assert schema["additionalProperties"] is False
        props = schema["properties"]
        assert props["execution_authorized"] == {"const": False}
        assert props["infrastructure_mutation_authorized"] == {"const": False}
        assert props["external_publication_authorized"] == {"const": False}


def test_061_parental_precedence_and_kill_switch_are_explicit() -> None:
    policy = _contract("vpn-egress-policy.v1.schema.json")
    props = policy["properties"]
    assert props["parental_deny_has_priority"] == {"const": True}
    assert set(props["dns_strategy"]["enum"]) == {"provider", "parental", "system"}
    assert set(props["fallback_mode"]["enum"]) == {"deny", "direct"}
    serialized = json.dumps(policy, sort_keys=True)
    assert '"kill_switch"' in serialized
    assert '"fallback_mode"' in serialized


def test_061_architecture_keeps_execution_for_later_typed_boundary() -> None:
    architecture = (ROOT / "docs/architecture/0.61-vpn-egress-policy-foundation.md").read_text(
        encoding="utf-8"
    )
    assert "parental DENY has absolute precedence" in architecture
    assert "no generic shell" in architecture
    assert "post-condition read-back" in architecture
