"""Atomic compare-and-swap helpers for persisted cluster metadata.

StateStore exposes keyed metadata reads/writes but not optimistic compare-and-swap.
The 0.58 managed-state commit boundary needs exact-state replacement, including an
atomic state+Job success commit so a crash cannot report false success or leave a
successful state mutation behind a failed durable Job.
"""
from __future__ import annotations

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
    with store._lock:  # Internal package helper: share the store's SQLite critical section.
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


def compare_and_swap_meta_and_succeed_job(
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
) -> bool:
    """Atomically replace metadata and transition one action Job to succeeded.

    This is intentionally narrow: callers must put the Job in the verifying state
    and persist all preflight intent before invoking it. The transaction refuses
    to mutate either side if the metadata value or Job state changed meanwhile.
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

    expected_payload = canonical_json(expected)
    replacement_payload = canonical_json(replacement)
    result_payload = canonical_json(result)
    evidence_payload = canonical_json(evidence)
    steps_payload = canonical_json(steps)
    now = utc_now()

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
                return False

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
            if (
                meta_update.rowcount != 1
                or job_update.rowcount != 1
                or steps_update.rowcount != 1
            ):
                store._connection.rollback()
                return False

            store._connection.commit()
            return True
        except Exception:
            store._connection.rollback()
            raise
