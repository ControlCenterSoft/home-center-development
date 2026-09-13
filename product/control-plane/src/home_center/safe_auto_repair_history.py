"""Durable, append-only history for Home Center 0.64 repair recommendations.

The history stores only bounded recommendation evidence. It never persists a command,
provider payload, credential, repair output, or execution authority. Schema installation
is owned by the canonical StateStore migration path; this adapter exposes schema_sql()
for qualification but never self-migrates.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Iterable

from .safe_auto_repair import SafeAutoRepairRecommendation
from .util import canonical_json

_HISTORY_DDL = """
CREATE TABLE IF NOT EXISTS safe_auto_repair_recommendations (
    recommendation_id TEXT PRIMARY KEY,
    household_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_generation INTEGER NOT NULL CHECK(resource_generation >= 0),
    evidence_sha256 TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    eligible_for_auto_repair INTEGER NOT NULL CHECK(eligible_for_auto_repair IN (0,1)),
    recommendation_json TEXT NOT NULL,
    recorded_at_epoch INTEGER NOT NULL CHECK(recorded_at_epoch >= 0)
);
CREATE INDEX IF NOT EXISTS idx_safe_auto_repair_history_household_resource
ON safe_auto_repair_recommendations(household_id, resource_id, recorded_at_epoch DESC);
"""


class SafeAutoRepairHistoryError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SQLiteSafeAutoRepairHistoryRepository:
    """Persist and read immutable recommendation evidence."""

    def __init__(self, connection: sqlite3.Connection, lock: threading.RLock | None = None) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("safe_auto_repair_history_connection_invalid")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._lock = lock or threading.RLock()

    @staticmethod
    def schema_sql() -> str:
        return _HISTORY_DDL

    def append(self, recommendation: SafeAutoRepairRecommendation, *, recorded_at_epoch: int) -> bool:
        if not isinstance(recommendation, SafeAutoRepairRecommendation):
            raise TypeError("safe_auto_repair_recommendation_invalid")
        if type(recorded_at_epoch) is not int or recorded_at_epoch < 0:
            raise SafeAutoRepairHistoryError("safe_auto_repair_recorded_at_invalid")
        payload = recommendation.to_dict()
        encoded = canonical_json(payload)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT recommendation_json, recorded_at_epoch FROM safe_auto_repair_recommendations WHERE recommendation_id=?",
                    (recommendation.recommendation_id,),
                ).fetchone()
                if existing is not None:
                    if existing["recommendation_json"] != encoded:
                        raise SafeAutoRepairHistoryError("safe_auto_repair_history_identity_conflict")
                    self._connection.commit()
                    return False
                self._connection.execute(
                    """INSERT INTO safe_auto_repair_recommendations(
                    recommendation_id,household_id,resource_id,resource_generation,evidence_sha256,
                    policy_id,policy_sha256,eligible_for_auto_repair,recommendation_json,recorded_at_epoch
                    ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (
                        recommendation.recommendation_id,
                        recommendation.candidate.household_id,
                        recommendation.candidate.resource_id,
                        recommendation.candidate.resource_generation,
                        recommendation.candidate.evidence_sha256,
                        recommendation.policy_id,
                        recommendation.policy_sha256,
                        1 if recommendation.eligible_for_auto_repair else 0,
                        encoded,
                        recorded_at_epoch,
                    ),
                )
                self._connection.commit()
                return True
            except Exception:
                self._connection.rollback()
                raise

    def get(self, recommendation_id: str) -> dict[str, object] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT recommendation_json,recorded_at_epoch FROM safe_auto_repair_recommendations WHERE recommendation_id=?",
                (recommendation_id,),
            ).fetchone()
        if row is None:
            return None
        return self._decode(row)

    def recent(
        self,
        *,
        household_id: str,
        resource_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, object]]:
        if type(limit) is not int or limit < 1 or limit > 200:
            raise SafeAutoRepairHistoryError("safe_auto_repair_history_limit_invalid")
        query = (
            "SELECT recommendation_json,recorded_at_epoch FROM safe_auto_repair_recommendations "
            "WHERE household_id=?"
        )
        params: list[object] = [household_id]
        if resource_id is not None:
            query += " AND resource_id=?"
            params.append(resource_id)
        query += " ORDER BY recorded_at_epoch DESC,recommendation_id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._connection.execute(query, tuple(params)).fetchall()
        return [self._decode(row) for row in rows]

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, object]:
        payload = json.loads(row["recommendation_json"])
        if not isinstance(payload, dict):
            raise SafeAutoRepairHistoryError("safe_auto_repair_history_payload_invalid")
        if payload.get("execution_authorized") is not False:
            raise SafeAutoRepairHistoryError("safe_auto_repair_history_execution_authority_invalid")
        if payload.get("provider_execution_authorized") is not False:
            raise SafeAutoRepairHistoryError("safe_auto_repair_history_provider_authority_invalid")
        if payload.get("infrastructure_mutation_authorized") is not False:
            raise SafeAutoRepairHistoryError("safe_auto_repair_history_infrastructure_authority_invalid")
        if payload.get("external_publication_authorized") is not False:
            raise SafeAutoRepairHistoryError("safe_auto_repair_history_publication_authority_invalid")
        return {
            "recommendation": payload,
            "recorded_at_epoch": int(row["recorded_at_epoch"]),
        }
