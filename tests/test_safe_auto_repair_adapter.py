from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.safe_auto_repair import RepairAction
from home_center.safe_auto_repair_adapter import (
    SafeAutoRepairAdapterCapabilities,
    SafeAutoRepairAdapterError,
    SafeAutoRepairAdapterRegistry,
    SafeAutoRepairApplyRequest,
    SafeAutoRepairApplyResult,
    SafeAutoRepairObservation,
    SafeAutoRepairReadbackRequest,
    SafeRepairApplyOutcome,
    SafeRepairObservationState,
)


ROOT = Path(__file__).resolve().parents[1]


def _capabilities(actions: frozenset[RepairAction] | None = None) -> SafeAutoRepairAdapterCapabilities:
    return SafeAutoRepairAdapterCapabilities(
        adapter_id="local.derived-state",
        adapter_version="1.0.0",
        supported_actions=actions or frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
        supports_readback=True,
        supports_rollback=True,
    )


def _apply_request() -> SafeAutoRepairApplyRequest:
    return SafeAutoRepairApplyRequest(
        job_id="hcrpj-1234567890abcdef12345678",
        adapter_id="local.derived-state",
        adapter_version="1.0.0",
        recommendation_id="hcrpr-1234567890abcdef12345678",
        recommendation_sha256="a" * 64,
        household_id="home-main",
        resource_id="household-derived-index",
        resource_generation=7,
        source_evidence_sha256="b" * 64,
        action=RepairAction.REBUILD_DERIVED_INDEX,
        policy_id="safe-default",
        policy_sha256="c" * 64,
    )


def _readback_request() -> SafeAutoRepairReadbackRequest:
    return SafeAutoRepairReadbackRequest(
        adapter_id="local.derived-state",
        adapter_version="1.0.0",
        operation_id="repair-op-1",
        recommendation_id="hcrpr-1234567890abcdef12345678",
        recommendation_sha256="a" * 64,
        resource_id="household-derived-index",
        expected_generation=7,
        action=RepairAction.REBUILD_DERIVED_INDEX,
    )


class _Adapter:
    def __init__(self, capabilities: SafeAutoRepairAdapterCapabilities) -> None:
        self.capabilities = capabilities
        self.apply_calls = 0
        self.readback_calls = 0

    def apply(self, request: SafeAutoRepairApplyRequest) -> SafeAutoRepairApplyResult:
        self.apply_calls += 1
        assert request.action in self.capabilities.supported_actions
        return SafeAutoRepairApplyResult(
            adapter_id=self.capabilities.adapter_id,
            adapter_version=self.capabilities.adapter_version,
            operation_id="repair-op-1",
            outcome=SafeRepairApplyOutcome.ACCEPTED,
        )

    def read_back(self, request: SafeAutoRepairReadbackRequest) -> SafeAutoRepairObservation:
        self.readback_calls += 1
        return SafeAutoRepairObservation(
            adapter_id=self.capabilities.adapter_id,
            adapter_version=self.capabilities.adapter_version,
            operation_id=request.operation_id,
            recommendation_id=request.recommendation_id,
            recommendation_sha256=request.recommendation_sha256,
            resource_id=request.resource_id,
            observed_generation=request.expected_generation,
            action=request.action,
            state=SafeRepairObservationState.SATISFIED,
            actual_evidence_sha256="d" * 64,
            blocker=None,
        )


def test_capabilities_are_bounded_and_require_readback() -> None:
    capabilities = _capabilities()
    payload = capabilities.to_dict()
    assert payload["supported_actions"] == ["rebuild-derived-index"]
    assert payload["supports_readback"] is True
    assert payload["credential_value_access_required"] is False
    assert payload["provider_execution_required"] is False
    assert payload["infrastructure_mutation_required"] is False
    assert payload["external_publication_required"] is False

    with pytest.raises(SafeAutoRepairAdapterError, match="safe_repair_adapter_readback_required"):
        SafeAutoRepairAdapterCapabilities(
            adapter_id="local.invalid",
            adapter_version="1.0.0",
            supported_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
            supports_readback=False,
        )


def test_registry_is_explicit_fail_closed_and_rejects_action_collision() -> None:
    registry = SafeAutoRepairAdapterRegistry()
    with pytest.raises(SafeAutoRepairAdapterError, match="safe_repair_adapter_unavailable"):
        registry.require(RepairAction.REBUILD_DERIVED_INDEX)

    first = _Adapter(_capabilities())
    registry.register(first)
    assert registry.require(RepairAction.REBUILD_DERIVED_INDEX) is first

    with pytest.raises(SafeAutoRepairAdapterError, match="safe_repair_adapter_action_already_registered"):
        registry.register(_Adapter(_capabilities()))


def test_apply_request_grants_only_exact_typed_local_adapter_execution() -> None:
    payload = _apply_request().to_dict()
    assert payload["adapter_execution_authorized"] is True
    assert payload["credential_value_access_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False
    assert payload["post_condition_verified"] is False


def test_adapter_acceptance_is_not_success_and_never_authorizes_retry() -> None:
    result = SafeAutoRepairApplyResult(
        adapter_id="local.derived-state",
        adapter_version="1.0.0",
        operation_id="repair-op-1",
        outcome=SafeRepairApplyOutcome.ACCEPTED,
    )
    payload = result.to_dict()
    assert payload["outcome"] == "accepted"
    assert payload["post_condition_verified"] is False
    assert payload["readback_required"] is True
    assert payload["automatic_retry_authorized"] is False

    ambiguous = SafeAutoRepairApplyResult(
        adapter_id="local.derived-state",
        adapter_version="1.0.0",
        operation_id="repair-op-ambiguous",
        outcome=SafeRepairApplyOutcome.AMBIGUOUS,
    )
    assert ambiguous.to_dict()["automatic_retry_authorized"] is False


def test_readback_is_strictly_non_mutating_and_observation_is_not_verification() -> None:
    request = _readback_request()
    request_payload = request.to_dict()
    assert request_payload["adapter_mutation_authorized"] is False
    assert request_payload["provider_execution_authorized"] is False
    assert request_payload["infrastructure_mutation_authorized"] is False
    assert request_payload["external_publication_authorized"] is False

    adapter = _Adapter(_capabilities())
    observation = adapter.read_back(request)
    payload = observation.to_dict()
    assert payload["state"] == "satisfied"
    assert payload["post_condition_verified"] is False
    assert payload["adapter_mutation_performed"] is False
    assert payload["provider_execution_performed"] is False
    assert payload["infrastructure_mutation_performed"] is False
    assert payload["external_publication_performed"] is False


def test_unknown_and_not_satisfied_observations_fail_closed() -> None:
    with pytest.raises(SafeAutoRepairAdapterError, match="safe_repair_adapter_observation_blocker_required"):
        SafeAutoRepairObservation(
            adapter_id="local.derived-state",
            adapter_version="1.0.0",
            operation_id="repair-op-2",
            recommendation_id="hcrpr-1234567890abcdef12345678",
            recommendation_sha256="a" * 64,
            resource_id="household-derived-index",
            observed_generation=7,
            action=RepairAction.REBUILD_DERIVED_INDEX,
            state=SafeRepairObservationState.UNKNOWN,
            actual_evidence_sha256=None,
            blocker=None,
        )

    with pytest.raises(SafeAutoRepairAdapterError, match="safe_repair_adapter_actual_evidence_invalid"):
        SafeAutoRepairObservation(
            adapter_id="local.derived-state",
            adapter_version="1.0.0",
            operation_id="repair-op-3",
            recommendation_id="hcrpr-1234567890abcdef12345678",
            recommendation_sha256="a" * 64,
            resource_id="household-derived-index",
            observed_generation=7,
            action=RepairAction.REBUILD_DERIVED_INDEX,
            state=SafeRepairObservationState.NOT_SATISFIED,
            actual_evidence_sha256=None,
            blocker="mismatch",
        )


def test_adapter_contracts_validate_against_closed_json_schemas() -> None:
    documents = {
        "safe-auto-repair-adapter-capabilities.v1.schema.json": _capabilities().to_dict(),
        "safe-auto-repair-adapter-apply-request.v1.schema.json": _apply_request().to_dict(),
        "safe-auto-repair-adapter-apply-result.v1.schema.json": SafeAutoRepairApplyResult(
            adapter_id="local.derived-state",
            adapter_version="1.0.0",
            operation_id="repair-op-1",
            outcome=SafeRepairApplyOutcome.ACCEPTED,
        ).to_dict(),
        "safe-auto-repair-adapter-readback-request.v1.schema.json": _readback_request().to_dict(),
        "safe-auto-repair-adapter-observation.v1.schema.json": _Adapter(_capabilities()).read_back(
            _readback_request()
        ).to_dict(),
    }
    for filename, payload in documents.items():
        schema = json.loads((ROOT / "contracts/automation" / filename).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(payload)
