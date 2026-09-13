from __future__ import annotations

import json
from pathlib import Path

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_059_release_notes_remain_historical_and_truthful() -> None:
    notes = (ROOT / "docs/releases/0.59.0.md").read_text(encoding="utf-8")
    assert notes.startswith("# Home Center 0.59.0\n\nStatus: official release.")
    assert "`single-node-core`" in notes
    assert "multi-node HA / automatic failover" in notes
    assert "concrete production backend/provider execution" in notes
    assert "commercial launch clearance" in notes
    assert "backend acceptance не означает enforcement success" in notes
    assert "Automatic backend retry" in notes
    assert "0.58.0 → 0.59.0" in notes


def test_release_059_policy_runtime_remains_required_in_reproducible_wheel() -> None:
    assert {
        "home_center/api_v6.py",
        "home_center/api_v7.py",
        "home_center/api_v8.py",
        "home_center/household_policy_api.py",
        "home_center/household_policy_composer.py",
        "home_center/household_policy_effective_state.py",
        "home_center/household_policy_enforcement_admission.py",
        "home_center/household_policy_enforcement_qualification_binding.py",
        "home_center/household_policy_enforcement_reconciliation_snapshot.py",
        "home_center/household_policy_enforcement_runtime.py",
        "home_center/household_policy_reconciliation.py",
        "home_center/household_policy_reconciliation_api_runtime.py",
        "home_center/household_policy_reconciliation_recovery.py",
        "home_center/household_policy_reconciliation_runtime.py",
        "home_center/household_policy_runtime.py",
        "home_center/household_policy_verification_state.py",
        "home_center/household_policy_verification_transition.py",
        "home_center/policy_backend_qualification.py",
        "home_center/release_promotion_gate.py",
        "home_center/target_node_qualification.py",
        "home_center/technical_stable_profile.py",
    } <= REQUIRED_MEMBERS


def test_release_059_enforcement_openapi_preserves_fail_closed_authority() -> None:
    document = json.loads(
        (ROOT / "contracts/openapi/home-center-household-policy-enforcement.v1.openapi.json").read_text(
            encoding="utf-8"
        )
    )
    assert document["openapi"] == "3.1.0"
    assert "Backend acceptance never constitutes verified enforcement" in document["info"]["description"]
    paths = document["paths"]
    required = {
        "/api/v1/household/policy/enforcement/plan",
        "/api/v1/household/policy/enforcement/confirm",
        "/api/v1/household/policy/enforcement/execute",
    }
    assert required <= set(paths)
    for path in required:
        operation = paths[path]["post"]
        assert operation["security"] == [{"sessionCookie": []}]
        assert operation["requestBody"]["required"] is True
    confirm_description = paths["/api/v1/household/policy/enforcement/confirm"]["post"]["responses"]["200"]["description"]
    execute = paths["/api/v1/household/policy/enforcement/execute"]["post"]
    assert "no automatic retry or success claim is authorized" in confirm_description
    assert "does not authorize retry after an ambiguous backend outcome" in execute["parameters"][0]["description"]
    assert "remain unverified and require reconciliation" in execute["responses"]["200"]["description"]
    assert "backend outcome ambiguous" in execute["responses"]["503"]["description"]
