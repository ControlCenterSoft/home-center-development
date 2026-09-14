"""Deterministic authoritative-state snapshots for manual HA failover.

Only product state that must follow the active writer is mirrored here. Node
observations, the local Audit chain and schema-migration history deliberately
remain node-local.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from .util import canonical_json, sha256_bytes

SNAPSHOT_SCHEMA = "home-center.authoritative-state.v2"


@dataclass(frozen=True, slots=True)
class TableSpec:
    columns: tuple[str, ...]
    order_by: str


AUTHORITATIVE_TABLES: dict[str, TableSpec] = {
    "cluster_meta": TableSpec(("key", "value_json", "updated_at"), "key"),
    "desired_state": TableSpec(("resource_key", "generation", "value_json", "updated_at"), "resource_key"),
    "jobs": TableSpec(
        (
            "job_id", "job_type", "state", "initiator", "reason", "preflight_json",
            "result_json", "evidence_json", "recovery_json", "created_at", "updated_at",
        ),
        "job_id",
    ),
    "action_job_metadata": TableSpec(
        ("job_id", "actor", "action_id", "idempotency_key", "request_hash", "steps_json"),
        "job_id",
    ),
    "home_service_instances": TableSpec(
        (
            "instance_id", "service_id", "target_node_id", "state", "generation",
            "resource_version", "configuration_revision_id", "external_publication_enabled", "updated_at",
        ),
        "instance_id",
    ),
    "home_service_instance_transitions": TableSpec(
        ("instance_id", "idempotency_key", "request_hash", "result_json", "created_at"),
        "instance_id,idempotency_key",
    ),
    "qr_onboarding_runtime": TableSpec(
        (
            "runtime_record_id", "invitation_id", "household_id", "household_snapshot_id",
            "household_resource_version", "household_generation", "target_member_id", "invitation_json",
            "invitation_evidence_sha256", "token_sha256", "state", "version", "created_at_epoch",
            "expires_at_epoch", "consumed_at_epoch", "revoked_at_epoch", "updated_at_epoch",
        ),
        "runtime_record_id",
    ),
    "qr_onboarding_runtime_operations": TableSpec(
        ("operation_key_sha256", "runtime_record_id", "request_sha256", "receipt_json", "created_at_epoch"),
        "operation_key_sha256",
    ),
    "safe_auto_repair_recommendations": TableSpec(
        (
            "recommendation_id", "household_id", "resource_id", "resource_generation", "evidence_sha256",
            "policy_id", "policy_sha256", "eligible_for_auto_repair", "recommendation_json", "recorded_at_epoch",
        ),
        "recommendation_id",
    ),
}

DELETE_ORDER = (
    "qr_onboarding_runtime_operations",
    "qr_onboarding_runtime",
    "home_service_instance_transitions",
    "home_service_instances",
    "action_job_metadata",
    "jobs",
    "desired_state",
    "safe_auto_repair_recommendations",
    "cluster_meta",
)

INSERT_ORDER = (
    "cluster_meta",
    "desired_state",
    "jobs",
    "action_job_metadata",
    "home_service_instances",
    "home_service_instance_transitions",
    "qr_onboarding_runtime",
    "qr_onboarding_runtime_operations",
    "safe_auto_repair_recommendations",
)


def _cluster_id(connection: sqlite3.Connection) -> str:
    row = connection.execute("SELECT value_json FROM cluster_meta WHERE key='cluster_id'").fetchone()
    if row is None:
        raise ValueError("cluster_id_missing")
    value = json.loads(row[0])
    if not isinstance(value, str) or not value:
        raise ValueError("cluster_id_invalid")
    return value


def _tables_snapshot(connection: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for table, spec in AUTHORITATIVE_TABLES.items():
        fields = ",".join(f'"{column}"' for column in spec.columns)
        if table == "cluster_meta":
            rows = connection.execute(
                f"SELECT {fields} FROM cluster_meta WHERE key <> ? ORDER BY key",
                ("cluster_id",),
            ).fetchall()
        else:
            rows = connection.execute(
                f'SELECT {fields} FROM "{table}" ORDER BY {spec.order_by}'
            ).fetchall()
        result[table] = {
            "columns": list(spec.columns),
            "rows": [list(row) for row in rows],
        }
    return result


def digest_tables(tables: dict[str, dict[str, Any]]) -> str:
    return sha256_bytes(canonical_json(tables).encode("utf-8"))


def snapshot_authoritative(connection: sqlite3.Connection) -> dict[str, Any]:
    """Return one consistent, deterministic snapshot of writer-owned state."""
    own_transaction = not connection.in_transaction
    if own_transaction:
        connection.execute("BEGIN")
    try:
        cluster_id = _cluster_id(connection)
        tables = _tables_snapshot(connection)
        return {
            "schema": SNAPSHOT_SCHEMA,
            "cluster_id": cluster_id,
            "tables": tables,
            "authoritative_sha256": digest_tables(tables),
        }
    finally:
        if own_transaction:
            connection.rollback()


def validate_snapshot(snapshot: dict[str, Any], *, expected_cluster_id: str) -> None:
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "schema", "cluster_id", "tables", "authoritative_sha256"
    }:
        raise ValueError("authoritative_snapshot_shape_rejected")
    if snapshot["schema"] != SNAPSHOT_SCHEMA:
        raise ValueError("authoritative_snapshot_schema_rejected")
    if snapshot["cluster_id"] != expected_cluster_id:
        raise ValueError("authoritative_snapshot_cluster_rejected")
    tables = snapshot["tables"]
    if not isinstance(tables, dict) or set(tables) != set(AUTHORITATIVE_TABLES):
        raise ValueError("authoritative_snapshot_table_set_rejected")
    for table, spec in AUTHORITATIVE_TABLES.items():
        value = tables[table]
        if not isinstance(value, dict) or set(value) != {"columns", "rows"}:
            raise ValueError(f"authoritative_snapshot_table_shape_rejected:{table}")
        if value["columns"] != list(spec.columns):
            raise ValueError(f"authoritative_snapshot_columns_rejected:{table}")
        rows = value["rows"]
        if not isinstance(rows, list):
            raise ValueError(f"authoritative_snapshot_rows_rejected:{table}")
        for row in rows:
            if not isinstance(row, list) or len(row) != len(spec.columns):
                raise ValueError(f"authoritative_snapshot_row_shape_rejected:{table}")
        if table == "cluster_meta" and any(row[0] == "cluster_id" for row in rows):
            raise ValueError("authoritative_snapshot_cluster_id_must_be_local")
    digest = snapshot["authoritative_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or digest != digest_tables(tables):
        raise ValueError("authoritative_snapshot_digest_rejected")


def apply_authoritative_snapshot(connection: sqlite3.Connection, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Atomically replace writer-owned state while preserving node-local state."""
    if connection.in_transaction:
        raise RuntimeError("authoritative_apply_requires_transaction_boundary")
    local_cluster_id = _cluster_id(connection)
    validate_snapshot(snapshot, expected_cluster_id=local_cluster_id)
    incoming_digest = str(snapshot["authoritative_sha256"])

    connection.execute("BEGIN IMMEDIATE")
    try:
        before = _tables_snapshot(connection)
        before_digest = digest_tables(before)

        for table in DELETE_ORDER:
            if table == "cluster_meta":
                connection.execute("DELETE FROM cluster_meta WHERE key <> ?", ("cluster_id",))
            else:
                connection.execute(f'DELETE FROM "{table}"')

        for table in INSERT_ORDER:
            item = snapshot["tables"][table]
            rows = item["rows"]
            if not rows:
                continue
            columns = item["columns"]
            fields = ",".join(f'"{column}"' for column in columns)
            markers = ",".join("?" for _ in columns)
            connection.executemany(
                f'INSERT INTO "{table}" ({fields}) VALUES ({markers})',
                rows,
            )

        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            raise RuntimeError("authoritative_apply_foreign_key_check_failed")

        after = _tables_snapshot(connection)
        after_digest = digest_tables(after)
        if after_digest != incoming_digest:
            raise RuntimeError("authoritative_apply_digest_mismatch")
        if _cluster_id(connection) != local_cluster_id:
            raise RuntimeError("authoritative_apply_cluster_id_changed")
        connection.commit()
    except Exception:
        connection.rollback()
        raise

    return {
        "schema": "home-center.authoritative-apply-result.v1",
        "changed": before_digest != incoming_digest,
        "authoritative_sha256": incoming_digest,
    }
