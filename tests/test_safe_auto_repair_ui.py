from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_ui import (
    RecommendationUiError,
    RecommendationUiState,
    project_history_row,
    project_recommendation,
)

ROOT = Path(__file__).resolve().parents[1]


def recommendation(*, eligible: bool):
    candidate = RepairCandidate(
        household_id="home-1",
        resource_id="derived-index-1",
        resource_generation=7,
        evidence_sha256="a" * 64,
        action=RepairAction.REBUILD_DERIVED_INDEX,
        risk=RepairRisk.LOW,
        recovery_proven=eligible,
        post_condition_verifiable=True,
    )
    policy = SafeRepairPolicy(
        policy_id="safe-default",
        policy_sha256="b" * 64,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
        allowed_risks=frozenset({RepairRisk.LOW}),
    )
    return evaluate_safe_auto_repair(candidate=candidate, policy=policy)


def test_cozy_projection_never_claims_completed_repair() -> None:
    projection = project_recommendation(recommendation(eligible=True))
    assert projection.state is RecommendationUiState.ELIGIBLE
    assert projection.automatic_repair_eligible is True
    payload = projection.to_dict()
    assert payload["execution_available"] is False
    assert payload["repair_completed"] is False
    assert payload["execution_authorized"] is False
    assert "ещё не выполнялось" in payload["cozy_summary"]


def test_blocked_projection_explains_recovery_blocker() -> None:
    projection = project_recommendation(recommendation(eligible=False))
    assert projection.state is RecommendationUiState.BLOCKED
    assert projection.automatic_repair_eligible is False
    assert projection.blocker_messages == ("Не подтверждён безопасный путь восстановления",)
    assert projection.execution_available is False


def test_history_projection_preserves_timestamp_and_false_authority() -> None:
    item = recommendation(eligible=True).to_dict()
    projected = project_history_row({"recommendation": item, "recorded_at_epoch": 1234})
    assert projected.recorded_at_epoch == 1234
    assert projected.automatic_repair_eligible is True
    assert projected.to_dict()["repair_completed"] is False


def test_history_projection_fails_closed_on_authority_tampering() -> None:
    item = recommendation(eligible=True).to_dict()
    item["execution_authorized"] = True
    with pytest.raises(RecommendationUiError, match="recommendation_history_authority_invalid"):
        project_history_row({"recommendation": item, "recorded_at_epoch": 1234})


def test_history_projection_rejects_inconsistent_eligibility() -> None:
    item = recommendation(eligible=False).to_dict()
    item["eligible_for_auto_repair"] = True
    with pytest.raises(RecommendationUiError, match="recommendation_history_eligibility_conflict"):
        project_history_row({"recommendation": item, "recorded_at_epoch": 1234})


def test_public_ui_schema_accepts_current_projection() -> None:
    schema = json.loads(
        (ROOT / "contracts/automation/safe-auto-repair-ui.v1.schema.json").read_text(encoding="utf-8")
    )
    for eligible in (True, False):
        jsonschema.Draft202012Validator(schema).validate(
            project_recommendation(recommendation(eligible=eligible)).to_dict()
        )


def test_public_ui_schema_rejects_false_success() -> None:
    schema = json.loads(
        (ROOT / "contracts/automation/safe-auto-repair-ui.v1.schema.json").read_text(encoding="utf-8")
    )
    payload = project_recommendation(recommendation(eligible=True)).to_dict()
    payload["repair_completed"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(payload)
