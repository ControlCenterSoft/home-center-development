from __future__ import annotations

import sqlite3

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_history import SQLiteSafeAutoRepairHistoryRepository
from home_center.safe_auto_repair_job_store import SQLiteSafeAutoRepairJobRepository
from home_center.safe_auto_repair_read_api import SafeRepairHistoryReadService


def test_history_read_is_household_scoped_bounded_and_read_only() -> None:
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteSafeAutoRepairHistoryRepository.schema_sql())
    connection.executescript(SQLiteSafeAutoRepairJobRepository.schema_sql())
    history = SQLiteSafeAutoRepairHistoryRepository(connection)
    jobs = SQLiteSafeAutoRepairJobRepository(connection)

    candidate = RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=1,
        evidence_sha256="a" * 64,
        action=RepairAction.REBUILD_DERIVED_INDEX,
        risk=RepairRisk.LOW,
        recovery_proven=True,
        post_condition_verifiable=True,
    )
    policy = SafeRepairPolicy(
        policy_id="policy-1",
        policy_sha256="b" * 64,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
    )
    recommendation = evaluate_safe_auto_repair(candidate=candidate, policy=policy)
    assert history.append(recommendation, recorded_at_epoch=90) is True

    service = SafeRepairHistoryReadService(history, jobs)
    result = service.list(household_id="household-1", resource_id="derived-index-1")
    assert result["mutation_authorized"] is False
    assert result["execution_authorized"] is False
    assert result["provider_execution_authorized"] is False
    assert result["infrastructure_mutation_authorized"] is False
    assert result["external_publication_authorized"] is False
    assert len(result["items"]) == 1
    assert result["items"][0]["status"] == "suggested"
    assert service.list(household_id="other-household")["items"] == []
    connection.close()
