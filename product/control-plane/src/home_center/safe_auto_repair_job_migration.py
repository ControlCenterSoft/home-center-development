"""Canonical migration payload for Home Center 0.64 durable safe-repair Jobs."""
from __future__ import annotations

from .safe_auto_repair_migration import SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION

SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION = SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION + 1

SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL = """
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


def normalized_migration_sql() -> str:
    """Return deterministic SQL text for migration identity qualification."""
    return "\n".join(line.rstrip() for line in SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL.strip().splitlines()) + "\n"
