"""Additive Home Center 0.64 safe-repair Job migration extension.

Recommendation history is already the canonical immutable migration v5 on the
current 0.64 line. This extension adds only the durable bounded Job table as v6.
Repositories still never self-migrate; production composition applies this migration
to the canonical StateStore database before exposing the read-only history surface.
"""
from __future__ import annotations

import sqlite3
import threading
from typing import Protocol

from .safe_auto_repair_job_store import SQLiteSafeAutoRepairJobRepository
from .util import utc_now

SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION = 6
SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL = SQLiteSafeAutoRepairJobRepository.schema_sql()


class _StateStoreLike(Protocol):
    _connection: sqlite3.Connection
    _lock: threading.RLock


class SafeAutoRepairJobMigrationError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _verify_schema(connection: sqlite3.Connection) -> None:
    table = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='safe_auto_repair_jobs'"
    ).fetchone()
    index = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' "
        "AND name='idx_safe_auto_repair_jobs_recommendation'"
    ).fetchone()
    if table is None or index is None:
        raise SafeAutoRepairJobMigrationError("safe_repair_job_migration_schema_missing")
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(safe_auto_repair_jobs)").fetchall()
    }
    required = {
        "job_id",
        "admission_id",
        "recommendation_id",
        "recommendation_sha256",
        "idempotency_key_sha256",
        "state",
        "job_json",
        "created_at_epoch",
        "updated_at_epoch",
    }
    if columns != required:
        raise SafeAutoRepairJobMigrationError("safe_repair_job_migration_schema_invalid")


def apply_safe_auto_repair_job_migration(store: _StateStoreLike) -> None:
    """Apply v6 once, preserving the already-qualified v5 history migration."""

    connection = getattr(store, "_connection", None)
    lock = getattr(store, "_lock", None)
    if not isinstance(connection, sqlite3.Connection) or lock is None:
        raise TypeError("safe_repair_job_migration_store_invalid")

    with lock, connection:
        current = {
            int(row[0])
            for row in connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        }
        if 5 not in current:
            raise SafeAutoRepairJobMigrationError("safe_repair_job_migration_history_v5_required")
        if SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION not in current:
            connection.executescript(SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION, utc_now()),
            )
        _verify_schema(connection)


__all__ = [
    "SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL",
    "SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION",
    "SafeAutoRepairJobMigrationError",
    "apply_safe_auto_repair_job_migration",
]
