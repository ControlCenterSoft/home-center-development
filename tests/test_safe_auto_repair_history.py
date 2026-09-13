from __future__ import annotations

import sqlite3

import pytest

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_history import (
    SQLiteSafeAutoRepairHistoryRepository,
    SafeAutoRepairHistoryError,
)


def recommendation(*, generation: int = 1, risk: RepairRisk = RepairRisk.LOW):
    candidate = RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=generation,
        evidence_sha256="a" * 64,
        action=RepairAction.REBUILD_DERIVED_INDEX,
        risk=risk,
        recovery_proven=True,
        post_condition_verifiable=True,
    )
    policy = SafeRepairPolicy(
        policy_id="policy-1",
        policy_sha256="b" * 64,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
        allowed_risks=frozenset({RepairRisk.LOW}),
    )
    return evaluate_safe_auto_repair(candidate=candidate, policy=policy)


def repository() -> SQLiteSafeAutoRepairHistoryRepository:
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteSafeAutoRepairHistoryRepository.schema_sql())
    return SQLiteSafeAutoRepairHistoryRepository(connection)


def test_history_append_and_exact_replay_are_idempotent() -> None:
    repo = repository()
    item = recommendation()
    assert repo.append(item, recorded_at_epoch=100) is True
    assert repo.append(item, recorded_at_epoch=200) is False
    stored = repo.get(item.recommendation_id)
    assert stored is not None
    assert stored["recorded_at_epoch"] == 100
    assert stored["recommendation"] == item.to_dict()


def test_history_is_bounded_to_household_and_resource() -> None:
    repo = repository()
    first = recommendation(generation=1)
    second = recommendation(generation=2)
    repo.append(first, recorded_at_epoch=100)
    repo.append(second, recorded_at_epoch=200)
    recent = repo.recent(household_id="household-1", resource_id="derived-index-1")
    assert [item["recommendation"]["recommendation_id"] for item in recent] == [
        second.recommendation_id,
        first.recommendation_id,
    ]
    assert repo.recent(household_id="other-household") == []


def test_history_preserves_blocked_recommendation_without_creating_authority() -> None:
    repo = repository()
    blocked = recommendation(risk=RepairRisk.HIGH)
    assert blocked.eligible_for_auto_repair is False
    repo.append(blocked, recorded_at_epoch=100)
    stored = repo.get(blocked.recommendation_id)
    assert stored is not None
    payload = stored["recommendation"]
    assert payload["eligible_for_auto_repair"] is False
    assert payload["execution_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False


def test_history_rejects_unbounded_query_limit() -> None:
    repo = repository()
    with pytest.raises(SafeAutoRepairHistoryError, match="safe_auto_repair_history_limit_invalid"):
        repo.recent(household_id="household-1", limit=0)
    with pytest.raises(SafeAutoRepairHistoryError, match="safe_auto_repair_history_limit_invalid"):
        repo.recent(household_id="household-1", limit=201)


def test_history_adapter_does_not_self_migrate() -> None:
    connection = sqlite3.connect(":memory:")
    repo = SQLiteSafeAutoRepairHistoryRepository(connection)
    with pytest.raises(sqlite3.OperationalError):
        repo.append(recommendation(), recorded_at_epoch=100)
