from __future__ import annotations

import pytest

from home_center.safe_auto_repair import RepairAction
from home_center.safe_auto_repair_adapter import (
    PostConditionState,
    SafeRepairAdapterError,
    SafeRepairAdapterRequest,
    SafeRepairAdapterResult,
    SafeRepairPostConditionObservation,
)
from home_center.safe_auto_repair_job import RepairExecutionOutcome


REQUEST = {
    "job_id": "hcrpj-" + "a" * 24,
    "recommendation_id": "hcrpr-" + "b" * 24,
    "recommendation_sha256": "c" * 64,
    "household_id": "household-1",
    "resource_id": "derived-index-1",
    "resource_generation": 7,
    "source_evidence_sha256": "d" * 64,
    "action": RepairAction.REBUILD_DERIVED_INDEX,
}


def _request(**changes: object) -> SafeRepairAdapterRequest:
    payload = dict(REQUEST)
    payload.update(changes)
    return SafeRepairAdapterRequest(**payload)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("job_id", "job-1", "safe_repair_adapter_job_id_invalid"),
        (
            "recommendation_id",
            "recommendation-1",
            "safe_repair_adapter_recommendation_id_invalid",
        ),
        ("household_id", "", "safe_repair_adapter_household_id_invalid"),
        ("resource_id", "bad/resource", "safe_repair_adapter_resource_id_invalid"),
    ),
)
def test_adapter_request_rejects_identity_drift(field: str, value: str, code: str) -> None:
    with pytest.raises(SafeRepairAdapterError, match=code):
        _request(**{field: value})


def test_adapter_result_rejects_unbound_job_or_recommendation_identity() -> None:
    with pytest.raises(SafeRepairAdapterError, match="safe_repair_adapter_result_job_id_invalid"):
        SafeRepairAdapterResult(
            job_id="wrong",
            recommendation_id=REQUEST["recommendation_id"],
            action=RepairAction.REBUILD_DERIVED_INDEX,
            outcome=RepairExecutionOutcome.ACCEPTED,
            effect_receipt_sha256="e" * 64,
        )

    with pytest.raises(
        SafeRepairAdapterError,
        match="safe_repair_adapter_result_recommendation_id_invalid",
    ):
        SafeRepairAdapterResult(
            job_id=REQUEST["job_id"],
            recommendation_id="wrong",
            action=RepairAction.REBUILD_DERIVED_INDEX,
            outcome=RepairExecutionOutcome.ACCEPTED,
            effect_receipt_sha256="e" * 64,
        )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("job_id", "wrong", "safe_repair_post_condition_job_id_invalid"),
        (
            "recommendation_id",
            "wrong",
            "safe_repair_post_condition_recommendation_id_invalid",
        ),
        ("household_id", "bad household", "safe_repair_post_condition_household_id_invalid"),
        ("resource_id", "bad/resource", "safe_repair_post_condition_resource_id_invalid"),
    ),
)
def test_post_condition_rejects_identity_drift(field: str, value: str, code: str) -> None:
    payload: dict[str, object] = {
        "job_id": REQUEST["job_id"],
        "recommendation_id": REQUEST["recommendation_id"],
        "household_id": REQUEST["household_id"],
        "resource_id": REQUEST["resource_id"],
        "observed_generation": 7,
        "observation_sha256": "f" * 64,
        "state": PostConditionState.MATCHED,
    }
    payload[field] = value
    with pytest.raises(SafeRepairAdapterError, match=code):
        SafeRepairPostConditionObservation(**payload)  # type: ignore[arg-type]


def test_valid_adapter_identity_contract_still_round_trips() -> None:
    request = _request()
    result = SafeRepairAdapterResult(
        job_id=request.job_id,
        recommendation_id=request.recommendation_id,
        action=request.action,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="e" * 64,
    )
    observation = SafeRepairPostConditionObservation(
        job_id=request.job_id,
        recommendation_id=request.recommendation_id,
        household_id=request.household_id,
        resource_id=request.resource_id,
        observed_generation=request.resource_generation,
        observation_sha256="f" * 64,
        state=PostConditionState.MATCHED,
    )

    request_payload = request.to_dict()
    assert request_payload["credential_value_access_authorized"] is False
    assert request_payload["provider_execution_authorized"] is False
    assert request_payload["generic_infrastructure_mutation_authorized"] is False
    assert request_payload["external_publication_authorized"] is False
    assert result.to_dict()["post_condition_verified"] is False
    assert observation.verified is True
