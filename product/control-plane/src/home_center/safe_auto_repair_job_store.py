"""Durable SQLite persistence boundary for Home Center 0.64 safe-repair Jobs.

The repository persists only the bounded typed Job projection. It never stores the raw
idempotency key, provider payloads, credentials, commands or generic execution authority.
Schema installation remains owned by the canonical StateStore migration path; this
adapter exposes schema_sql() for qualification and deliberately does not self-migrate.
"""
from __future__ import annotations

import json
import sqlite3
import threading

from .safe_auto_repair_job import RepairJobState, SafeAutoRepairJob
from .util import canonical_json

_JOB_DDL = """
CREATE TABLE IF NOT EXISTS safe_auto_repair_jobs (
    job_id TEXT PRIMARY KEY,
    admission_id TEXT NOT NULL,
    recommendation_id TEXT NOT NULL,
    recommendation_sha256 TEXT NOT NULL,
    idempotency_key_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('admitted','running','verifying','succeeded','failed','reconcile-required')),
    job_json TEXT NOT NULL,
    created_at_epoch INTEGER NOT NULL CHECK(created_at_epoch >= 0),
    updated_at_epoch INTEGER NOT NULL CHECK(updated_at_epoch >= created_at_epoch),
    UNIQUE(admission_id, idempotency_key_sha256)
);
CREATE INDEX IF NOT EXISTS idx_safe_auto_repair_jobs_recommendation
ON safe_auto_repair_jobs(recommendation_id, updated_at_epoch DESC);
"""


class SafeAutoRepairJobStoreError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SQLiteSafeAutoRepairJobRepository:
    """Persist exact typed Job snapshots with optimistic state/timestamp CAS."""

    def __init__(self, connection: sqlite3.Connection, lock: threading.RLock | None = None) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("safe_repair_job_store_connection_invalid")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._lock = lock or threading.RLock()

    @staticmethod
    def schema_sql() -> str:
        return _JOB_DDL

    def create(self, job: SafeAutoRepairJob) -> bool:
        if not isinstance(job, SafeAutoRepairJob):
            raise TypeError("safe_repair_job_store_job_invalid")
        encoded = canonical_json(job.to_dict())
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT job_json FROM safe_auto_repair_jobs WHERE job_id=?",
                    (job.job_id,),
                ).fetchone()
                if existing is not None:
                    if existing["job_json"] != encoded:
                        raise SafeAutoRepairJobStoreError("safe_repair_job_store_identity_conflict")
                    self._connection.commit()
                    return False
                self._connection.execute(
                    """INSERT INTO safe_auto_repair_jobs(
                    job_id,admission_id,recommendation_id,recommendation_sha256,
                    idempotency_key_sha256,state,job_json,created_at_epoch,updated_at_epoch
                    ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        job.job_id,
                        job.admission_id,
                        job.recommendation_id,
                        job.recommendation_sha256,
                        job.idempotency_key_sha256,
                        job.state.value,
                        encoded,
                        job.created_at_epoch,
                        job.updated_at_epoch,
                    ),
                )
                self._connection.commit()
                return True
            except sqlite3.IntegrityError as exc:
                self._connection.rollback()
                raise SafeAutoRepairJobStoreError("safe_repair_job_store_idempotency_conflict") from exc
            except Exception:
                self._connection.rollback()
                raise

    def get(self, job_id: str) -> SafeAutoRepairJob | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT job_json FROM safe_auto_repair_jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
        return self._decode(row["job_json"]) if row is not None else None

    def recent_for_recommendation(
        self, *, recommendation_id: str, limit: int = 50
    ) -> list[SafeAutoRepairJob]:
        if type(limit) is not int or limit < 1 or limit > 200:
            raise SafeAutoRepairJobStoreError("safe_repair_job_store_limit_invalid")
        with self._lock:
            rows = self._connection.execute(
                """SELECT job_json FROM safe_auto_repair_jobs
                WHERE recommendation_id=?
                ORDER BY updated_at_epoch DESC,job_id DESC LIMIT ?""",
                (recommendation_id, limit),
            ).fetchall()
        return [self._decode(row["job_json"]) for row in rows]

    def compare_and_set(
        self,
        *,
        expected_state: RepairJobState,
        expected_updated_at_epoch: int,
        updated: SafeAutoRepairJob,
    ) -> SafeAutoRepairJob:
        if not isinstance(expected_state, RepairJobState):
            raise TypeError("safe_repair_job_store_expected_state_invalid")
        if type(expected_updated_at_epoch) is not int or expected_updated_at_epoch < 0:
            raise SafeAutoRepairJobStoreError("safe_repair_job_store_expected_timestamp_invalid")
        if not isinstance(updated, SafeAutoRepairJob):
            raise TypeError("safe_repair_job_store_job_invalid")
        encoded = canonical_json(updated.to_dict())
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current_row = self._connection.execute(
                    "SELECT * FROM safe_auto_repair_jobs WHERE job_id=?",
                    (updated.job_id,),
                ).fetchone()
                if current_row is None:
                    raise SafeAutoRepairJobStoreError("safe_repair_job_store_not_found")
                current = self._decode(current_row["job_json"])
                if (
                    current.admission_id != updated.admission_id
                    or current.recommendation_id != updated.recommendation_id
                    or current.recommendation_sha256 != updated.recommendation_sha256
                    or current.idempotency_key_sha256 != updated.idempotency_key_sha256
                ):
                    raise SafeAutoRepairJobStoreError("safe_repair_job_store_identity_conflict")
                if current.state is not expected_state or current.updated_at_epoch != expected_updated_at_epoch:
                    raise SafeAutoRepairJobStoreError("safe_repair_job_store_stale")
                cursor = self._connection.execute(
                    """UPDATE safe_auto_repair_jobs
                    SET state=?,job_json=?,updated_at_epoch=?
                    WHERE job_id=? AND state=? AND updated_at_epoch=?""",
                    (
                        updated.state.value,
                        encoded,
                        updated.updated_at_epoch,
                        updated.job_id,
                        expected_state.value,
                        expected_updated_at_epoch,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SafeAutoRepairJobStoreError("safe_repair_job_store_stale")
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        stored = self.get(updated.job_id)
        if stored is None:
            raise SafeAutoRepairJobStoreError("safe_repair_job_store_readback_failed")
        if stored != updated:
            raise SafeAutoRepairJobStoreError("safe_repair_job_store_readback_mismatch")
        return stored

    @staticmethod
    def _decode(encoded: str) -> SafeAutoRepairJob:
        payload = json.loads(encoded)
        if not isinstance(payload, dict) or payload.get("schema") != "home-center.safe-auto-repair-job.v1":
            raise SafeAutoRepairJobStoreError("safe_repair_job_store_payload_invalid")
        for field in (
            "raw_idempotency_key_persisted",
            "automatic_retry_authorized",
            "execution_authorized",
            "provider_execution_authorized",
            "infrastructure_mutation_authorized",
            "external_publication_authorized",
        ):
            if payload.get(field) is not False:
                raise SafeAutoRepairJobStoreError("safe_repair_job_store_authority_invalid")
        try:
            return SafeAutoRepairJob(
                job_id=payload["job_id"],
                admission_id=payload["admission_id"],
                recommendation_id=payload["recommendation_id"],
                recommendation_sha256=payload["recommendation_sha256"],
                idempotency_key_sha256=payload["idempotency_key_sha256"],
                state=RepairJobState(payload["state"]),
                created_at_epoch=payload["created_at_epoch"],
                updated_at_epoch=payload["updated_at_epoch"],
                effect_receipt_sha256=payload.get("effect_receipt_sha256"),
                post_condition_evidence_sha256=payload.get("post_condition_evidence_sha256"),
                post_condition_verified=payload["post_condition_verified"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SafeAutoRepairJobStoreError("safe_repair_job_store_payload_invalid") from exc
