from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts/household"


def _contract(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def test_059_policy_contracts_are_closed_and_confirmation_gated() -> None:
    bundle = _contract("household-policy-bundle.v1.schema.json")
    proposal = _contract("household-policy-composition-proposal.v1.schema.json")

    assert bundle["additionalProperties"] is False
    assert proposal["additionalProperties"] is False
    assert proposal["properties"]["confirmation_required"] == {"const": True}
    assert proposal["properties"]["desired_state_write_authorized"] == {"const": False}
    assert proposal["properties"]["infrastructure_mutation_authorized"] == {"const": False}
    assert proposal["properties"]["external_publication_authorized"] == {"const": False}


def test_059_proposal_binds_household_and_desired_state_versions() -> None:
    proposal = _contract("household-policy-composition-proposal.v1.schema.json")
    required = set(proposal["required"])
    assert {
        "snapshot_id",
        "resource_version",
        "generation",
        "expected_desired_state_generation",
        "expected_desired_state_bundle_id",
    } <= required


def test_059_bundle_exposes_cozy_explanation_and_exact_technical_policy() -> None:
    bundle = _contract("household-policy-bundle.v1.schema.json")
    required = set(bundle["required"])
    assert {"technical_policy", "explanation", "desired_state_resource_key"} <= required
    technical = bundle["properties"]["technical_policy"]
    assert technical["additionalProperties"] is False
    assert technical["properties"]["external_publication_allowed"] == {"const": False}
    assert technical["properties"]["production_mutation_enabled"] == {"const": False}


def test_059_foundation_does_not_pull_later_policy_features_or_runtime_mutation() -> None:
    module = (ROOT / "product/control-plane/src/home_center/household_policy_composer.py").read_text(encoding="utf-8")
    lower = module.lower()
    for forbidden in (
        "statestore",
        ".set_meta(",
        "create_action_job",
        "provideradapter",
        "quota",
        "schedule",
        "allowlist",
        "denylist",
        "vpn_provider",
        "account_provision",
    ):
        assert forbidden not in lower


def test_059_notes_remain_non_release_and_list_runtime_gates() -> None:
    notes = (ROOT / "docs/releases/0.59.0.md").read_text(encoding="utf-8")
    assert "не Release Candidate и не Public Stable" in notes
    assert "durable plan/confirm runtime" in notes
    assert "optimistic concurrency" in notes
    assert "Audit" in notes
