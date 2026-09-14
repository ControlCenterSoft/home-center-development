from __future__ import annotations

import pytest

from home_center.safe_auto_repair import (
    RepairAction,
    RepairBlocker,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_candidate_source import (
    DerivedStateObservation,
    DerivedStateSource,
    DerivedStateStatus,
    SafeRepairCandidateSourceError,
    derive_safe_repair_candidate,
)


def observation(**overrides: object) -> DerivedStateObservation:
    values: dict[str, object] = {
        "household_id": "household-1",
        "resource_id": "derived-index-1",
        "resource_generation": 7,
        "source": DerivedStateSource.STATE_STORE_DERIVED_INDEX,
        "status": DerivedStateStatus.STALE,
        "expected_content_sha256": "a" * 64,
        "actual_content_sha256": "b" * 64,
        "observed_at_epoch": 1_789_394_400,
        "recovery_evidence_sha256": "c" * 64,
    }
    values.update(overrides)
    return DerivedStateObservation(**values)  # type: ignore[arg-type]


def test_stale_server_state_produces_exact_low_risk_candidate() -> None:
    first = derive_safe_repair_candidate(observation())
    replay = derive_safe_repair_candidate(observation())

    assert first is not None
    assert replay is not None
    assert first == replay
    assert first.action is RepairAction.REBUILD_DERIVED_INDEX
    assert first.resource_generation == 7
    assert first.recovery_proven is True
    assert first.post_condition_verifiable is True
    assert first.provider_execution_required is False
    assert first.infrastructure_mutation_required is False
    assert first.external_publication_required is False


def test_current_or_unknown_state_never_produces_candidate() -> None:
    current = observation(
        status=DerivedStateStatus.CURRENT,
        actual_content_sha256="a" * 64,
    )
    unknown = observation(
        status=DerivedStateStatus.UNKNOWN,
        actual_content_sha256=None,
    )

    assert derive_safe_repair_candidate(current) is None
    assert derive_safe_repair_candidate(unknown) is None


def test_missing_local_read_model_maps_only_to_closed_refresh_action() -> None:
    candidate = derive_safe_repair_candidate(
        observation(
            source=DerivedStateSource.STATE_STORE_LOCAL_READ_MODEL,
            status=DerivedStateStatus.MISSING,
            actual_content_sha256=None,
        )
    )

    assert candidate is not None
    assert candidate.action is RepairAction.REFRESH_LOCAL_READ_MODEL


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        (
            {
                "status": DerivedStateStatus.CURRENT,
                "actual_content_sha256": "b" * 64,
            },
            "safe_repair_source_current_digest_mismatch",
        ),
        (
            {
                "status": DerivedStateStatus.STALE,
                "actual_content_sha256": "a" * 64,
            },
            "safe_repair_source_stale_digest_match",
        ),
        (
            {
                "status": DerivedStateStatus.MISSING,
                "actual_content_sha256": "b" * 64,
            },
            "safe_repair_source_missing_actual_digest_present",
        ),
    ],
)
def test_inconsistent_server_observations_fail_closed(
    overrides: dict[str, object], code: str
) -> None:
    with pytest.raises(SafeRepairCandidateSourceError, match=code):
        observation(**overrides)


def test_recovery_is_never_inferred_from_staleness() -> None:
    candidate = derive_safe_repair_candidate(
        observation(recovery_evidence_sha256=None)
    )
    assert candidate is not None
    assert candidate.recovery_proven is False

    policy = SafeRepairPolicy(
        policy_id="policy-1",
        policy_sha256="d" * 64,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
    )
    recommendation = evaluate_safe_auto_repair(candidate=candidate, policy=policy)
    assert recommendation.eligible_for_auto_repair is False
    assert recommendation.blockers == (RepairBlocker.RECOVERY_NOT_PROVEN,)


def test_observation_evidence_carries_no_mutation_authority() -> None:
    material = observation().evidence_material()
    assert material["execution_authorized"] is False
    assert material["credential_value_access_authorized"] is False
    assert material["provider_execution_authorized"] is False
    assert material["generic_infrastructure_mutation_authorized"] is False
    assert material["external_publication_authorized"] is False


def test_generation_or_expected_digest_changes_candidate_identity() -> None:
    original = derive_safe_repair_candidate(observation())
    newer = derive_safe_repair_candidate(observation(resource_generation=8))
    changed = derive_safe_repair_candidate(
        observation(expected_content_sha256="e" * 64)
    )

    assert original is not None
    assert newer is not None
    assert changed is not None
    assert original.evidence_sha256 != newer.evidence_sha256
    assert original.evidence_sha256 != changed.evidence_sha256


def test_untyped_source_cannot_expand_candidate_authority() -> None:
    with pytest.raises(SafeRepairCandidateSourceError, match="safe_repair_source_kind_invalid"):
        observation(source="provider-health")
