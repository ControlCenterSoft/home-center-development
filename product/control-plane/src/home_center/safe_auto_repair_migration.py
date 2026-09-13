"""Canonical Home Center 0.64 recommendation-history migration payload."""
from __future__ import annotations

SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION = 5

SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL = """
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


def normalized_migration_sql() -> str:
    """Return deterministic SQL text for migration identity checks."""
    return "\n".join(line.rstrip() for line in SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL.strip().splitlines()) + "\n"
