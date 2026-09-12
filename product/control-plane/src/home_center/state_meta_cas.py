"""Atomic compare-and-swap helpers for persisted cluster metadata.

StateStore exposes keyed metadata reads/writes but not optimistic compare-and-swap.
The 0.58 managed-state commit boundary needs exact-state replacement, including an
atomic state+Job+Audit commit so a crash cannot report false success or leave a
successful state mutation without durable operational evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Any

from .store import StateStore
from .util import canonical_json, utc_now


def _inputs(store: StateStore, key: str) -> None:
    if not isinstance(store, StateStore):
        raise TypeError("invalid_state_store")
    if not isinstance(key, str) or not key:
        raise ValueError("invalid_meta_key")


def compare_and_swap_meta(
    store: StateStore,
    *,
    key: str,
    expected: Any,
    replacement: Any,
) -> bool:
    """Atomically replace one metadata value only when it still equals expected."""

    _inputs(store, key)
    expected_payload = canonical_json(expected)
    replacement_payload = canonical_json(replacement)
    with store._lock:
        store._connection.execute("BEGIN IMMEDIATE")
        try:
            row = store._connection.execute(
                "SELECT value_json FROM cluster_meta WHERE key=?",
                (key,),
            ).fetchone()
            if row is None or row[0] != expected_payload:
                store._connection.rollback()
                return False
            cursor = store._connection.execute(
                """UPDATE cluster_meta
                SET value_json=?, updated_at=?
                WHERE key=? AND value_json=?""",
                (replacement_payload, utc_now(), key, expected_payload),
            )
            if cursor.rowcount != 1:
                store._connection.rollback()
                return False
            store._connection.commit()
            return True
        except Exception:
            store._connection.rollback()
            raise


def compare_and_swap_meta_succeed_job_and_audit(
    store: StateStore,
    *,
    key: str,
    expected: Any,
    replacement: Any,
    job_id: str,
    expected_job_state: str,
    result: dict[str, Any],
    evidence: dict[str, Any],
    steps: list[dict[str, Any]],
    audit_actor: str,
    audit_action: str,
    audit_target: str,
    audit_outcome: str,
    audit_correlation_id: str,
    audit_details: dict[str, Any],
    audit_event_id: str | None = None,
) -> str | None:
    """Atomically replace metadata, succeed one action Job, and append Audit.

    ``None`` means the metadata or Job precondition changed and nothing was
    written. Any returned event id proves all three records committed together.
    A caller may pre-allocate ``audit_event_id`` so the terminal Job receipt can
    reference the exact Audit entry in the same transaction.
    """

    _inputs(store, key)
    if not isinstance(job_id, str) or not job_id:
        raise ValueError("invalid_job_id")
    if expected_job_state != "verifying":
        raise ValueError("invalid_expected_job_state")
    if not isinstance(result, dict) or not isinstance(evidence, dict):
        raise TypeError("invalid_job_terminal_payload")
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        raise TypeError("invalid_job_steps")
    for value, code in (
        (audit_actor, "invalid_audit_actor"),
        (audit_action, "invalid_audit_action"),
        (audit_target, "invalid_audit_target"),
        (audit_outcome, "invalid_audit_outcome"),
        (audit_correlation_id, "invalid_audit_correlation_id"),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(code)
    if not isinstance(audit_details, dict):
        raise TypeError("invalid_audit_details")
    if audit_event_id is not None and (
        not isinstance(audit_event_id, str)
        or not audit_event_id
        or len(audit_event_id) > 128
    ):
        raise ValueError("invalid_audit_event_id")

    expected_payload = canonical_json(expected)
    replacement_payload = canonical_json(replacement)
    result_payload = canonical_json(result)
    evidence_payload = canonical_json(evidence)
    steps_payload = canonical_json(steps)
    details_json = canonical_json(audit_details)
    now = utc_now()
    event_id = audit_event_id or str(uuid.uuid4())

    with store._lock:
        store._connection.execute("BEGIN IMMEDIATE")
        try:
            meta_row = store._connection.execute(
                "SELECT value_json FROM cluster_meta WHERE key=?",
                (key,),
            ).fetchone()
            job_row = store._connection.execute(
                "SELECT state FROM jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
            metadata_row = store._connection.execute(
                "SELECT job_id FROM action_job_metadata WHERE job_id=?",
                (job_id,),
            ).fetchone()
            if (
                meta_row is None
                or meta_row[0] != expected_payload
                or job_row is None
                or job_row[0] != expected_job_state
                or metadata_row is None
            ):
                store._connection.rollback()
                return None

            previous = store._connection.execute(
                "SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous[0] if previous else "0" * 64
            material = canonical_json(
                {
                    "event_id": event_id,
                    "occurred_at": now,
                    "actor": audit_actor,
                    "action": audit_action,
                    "target": audit_target,
                    "outcome": audit_outcome,
                    "correlation_id": audit_correlation_id,
                    "details": json.loads(details_json),
                    "previous_hash": previous_hash,
                }
            ).encode("utf-8")
            entry_hash = hmac.new(store.audit_key, material, hashlib.sha256).hexdigest()

            meta_update = store._connection.execute(
                """UPDATE cluster_meta
                SET value_json=?, updated_at=?
                WHERE key=? AND value_json=?""",
                (replacement_payload, now, key, expected_payload),
            )
            job_update = store._connection.execute(
                """UPDATE jobs
                SET state='succeeded', result_json=?, evidence_json=?, updated_at=?
                WHERE job_id=? AND state=?""",
                (result_payload, evidence_payload, now, job_id, expected_job_state),
            )
            steps_update = store._connection.execute(
                "UPDATE action_job_metadata SET steps_json=? WHERE job_id=?",
                (steps_payload, job_id),
            )
            audit_insert = store._connection.execute(
                """INSERT INTO audit(
                    event_id,occurred_at,actor,action,target,outcome,correlation_id,
                    details_json,previous_hash,entry_hash
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    event_id,
                    now,
                    audit_actor,
                    audit_action,
                    audit_target,
                    audit_outcome,
                    audit_correlation_id,
                    details_json,
                    previous_hash,
                    entry_hash,
                ),
            )
            if (
                meta_update.rowcount != 1
                or job_update.rowcount != 1
                or steps_update.rowcount != 1
                or audit_insert.rowcount != 1
            ):
                store._connection.rollback()
                return None

            store._connection.commit()
            return event_id
        except Exception:
            store._connection.rollback()
            raise
