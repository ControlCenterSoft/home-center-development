"""Atomic compare-and-swap helper for persisted cluster metadata.

StateStore exposes keyed metadata reads/writes but not optimistic compare-and-swap.
The 0.58 managed-state commit boundary needs an atomic exact-state replacement, so
this internal helper performs one SQLite transaction under the store lock.
"""
from __future__ import annotations

from typing import Any

from .store import StateStore
from .util import canonical_json, utc_now


def compare_and_swap_meta(
    store: StateStore,
    *,
    key: str,
    expected: Any,
    replacement: Any,
) -> bool:
    """Atomically replace one metadata value only when it still equals expected."""

    if not isinstance(store, StateStore):
        raise TypeError("invalid_state_store")
    if not isinstance(key, str) or not key:
        raise ValueError("invalid_meta_key")

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
