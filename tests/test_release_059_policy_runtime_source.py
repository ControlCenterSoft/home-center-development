from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts/household"
SOURCE = ROOT / "product/control-plane/src/home_center"


def _contract(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def test_059_confirmation_contract_is_closed_and_never_grants_mutation_authority() -> None:
    schema = _contract("household-policy-confirmation.v1.schema.json")
    assert schema["additionalProperties"] is False
    properties = schema["properties"]
    assert properties["desired_state_write_ready"] == {"const": True}
    assert properties["desired_state_write_authorized"] == {"const": False}
    assert properties["infrastructure_mutation_authorized"] == {"const": False}
    assert properties["external_publication_authorized"] == {"const": False}


def test_059_apply_contracts_are_closed_and_provider_neutral() -> None:
    request = _contract("household-policy-apply-request.v1.schema.json")
    receipt = _contract("household-policy-apply-receipt.v1.schema.json")
    assert request["additionalProperties"] is False
    assert receipt["additionalProperties"] is False
    properties = receipt["properties"]
    assert properties["desired_state_materialized"] == {"const": True}
    assert properties["provider_execution_authorized"] == {"const": False}
    assert properties["infrastructure_mutation_authorized"] == {"const": False}
    assert properties["external_publication_authorized"] == {"const": False}


def test_059_runtime_is_confirmation_gated_and_has_explicit_recovery_state() -> None:
    source = (SOURCE / "household_policy_runtime.py").read_text(encoding="utf-8")
    assert '"confirming"' in source
    assert '"recovery_required": True' in source
    assert "revalidate_policy_composition_proposal" in source
    assert "household.policy.confirm.recover" in source
    assert "desired_state_write_authorized: bool = field(default=False" in source


def test_059_desired_state_writer_uses_cas_and_never_executes_providers() -> None:
    source = (SOURCE / "household_policy_desired_state.py").read_text(encoding="utf-8")
    lower = source.lower()
    assert "begin immediate" in lower
    assert "expected_desired_state_generation" in source
    assert "household.policy.desired-state.apply.begin" in source
    assert "household.policy.desired-state.apply.complete" in source
    assert "finalized-existing-write" in source
    for forbidden in (
        "provideradapter(",
        "subprocess",
        "os.system",
        "socket.",
        "requests.",
        "urllib.request",
        '"external_publication_authorized": true',
        '"infrastructure_mutation_authorized": true',
    ):
        assert forbidden not in lower


def test_059_release_notes_remain_non_release_and_state_runner_qualification_is_pending() -> None:
    notes = (ROOT / "docs/releases/0.59.0.md").read_text(encoding="utf-8")
    assert "не Release Candidate и не Public Stable" in notes
    assert "Desired State writer" in notes
    assert "compare-and-set" in notes
    assert "runner-зависимую qualification" in notes
