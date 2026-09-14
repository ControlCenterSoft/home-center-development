"""Durable HA membership and manual-failover journal stored in cluster metadata."""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from .manual_failover import MANUAL_MODE, TRANSITION_SCHEMA
from .util import canonical_json, utc_now

MEMBERSHIP_KEY = "ha.cluster-membership.v1"
TRANSITION_KEY = "ha.manual-failover.current.v1"
MEMBERSHIP_SCHEMA = "home-center.cluster-membership.v1"
TRANSITION_PHASES = frozenset({
    "planned",
    "source_quiesced",
    "final_sync_verified",
    "source_fenced",
    "target_promoted",
    "target_verified",
    "completed",
    "failed",
})
TERMINAL_PHASES = frozenset({"completed", "failed"})


class HAStateConflict(RuntimeError):
    """Durable HA state changed since the caller's precondition was observed."""


def _local_cluster_id(connection: sqlite3.Connection) -> str:
    row = connection.execute("SELECT value_json FROM cluster_meta WHERE key='cluster_id'").fetchone()
    if row is None:
        raise HAStateConflict("cluster_id_missing")
    value = json.loads(row[0])
    if not isinstance(value, str) or not value:
        raise HAStateConflict("cluster_id_invalid")
    return value


def _read_meta(connection: sqlite3.Connection, key: str) -> dict[str, Any] | None:
    row = connection.execute("SELECT value_json FROM cluster_meta WHERE key=?", (key,)).fetchone()
    if row is None:
        return None
    value = json.loads(row[0])
    if not isinstance(value, dict):
        raise HAStateConflict(f"ha_meta_not_object:{key}")
    return value


def _write_meta(connection: sqlite3.Connection, key: str, value: dict[str, Any]) -> None:
    connection.execute(
        """INSERT INTO cluster_meta(key,value_json,updated_at) VALUES(?,?,?)
        ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at""",
        (key, canonical_json(value), utc_now()),
    )


def validate_membership(membership: dict[str, Any], *, expected_cluster_id: str) -> None:
    if not isinstance(membership, dict) or membership.get("schema") != MEMBERSHIP_SCHEMA:
        raise HAStateConflict("membership_schema_rejected")
    if membership.get("cluster_id") != expected_cluster_id:
        raise HAStateConflict("membership_cluster_rejected")
    generation = membership.get("generation")
    writer = membership.get("writer")
    members = membership.get("members")
    quorum = membership.get("quorum")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise HAStateConflict("membership_generation_rejected")
    if not isinstance(writer, str) or not writer:
        raise HAStateConflict("membership_writer_rejected")
    if not isinstance(members, list) or len(members) != 2:
        raise HAStateConflict("membership_requires_two_members")
    member_ids: set[str] = set()
    for member in members:
        if not isinstance(member, dict) or not isinstance(member.get("node_id"), str):
            raise HAStateConflict("membership_member_rejected")
        member_ids.add(member["node_id"])
    if len(member_ids) != 2 or writer not in member_ids:
        raise HAStateConflict("membership_identity_rejected")
    if not isinstance(quorum, dict):
        raise HAStateConflict("membership_quorum_rejected")
    if quorum.get("mode") != MANUAL_MODE or quorum.get("automatic_failover") is not False:
        raise HAStateConflict("membership_manual_mode_required")


def validate_transition(transition: dict[str, Any], *, expected_cluster_id: str) -> None:
    if not isinstance(transition, dict) or transition.get("schema") != TRANSITION_SCHEMA:
        raise HAStateConflict("transition_schema_rejected")
    if transition.get("cluster_id") != expected_cluster_id:
        raise HAStateConflict("transition_cluster_rejected")
    if not isinstance(transition.get("transition_id"), str) or not transition["transition_id"]:
        raise HAStateConflict("transition_identity_rejected")
    if transition.get("phase") not in TRANSITION_PHASES:
        raise HAStateConflict("transition_phase_rejected")
    source = transition.get("source_writer")
    target = transition.get("target_writer")
    if not isinstance(source, str) or not isinstance(target, str) or not source or not target or source == target:
        raise HAStateConflict("transition_writer_identity_rejected")
    source_generation = transition.get("from_generation")
    target_generation = transition.get("to_generation")
    if (
        isinstance(source_generation, bool)
        or not isinstance(source_generation, int)
        or source_generation < 1
        or isinstance(target_generation, bool)
        or not isinstance(target_generation, int)
        or target_generation != source_generation + 1
    ):
        raise HAStateConflict("transition_generation_rejected")


def load_membership(connection: sqlite3.Connection) -> dict[str, Any] | None:
    value = _read_meta(connection, MEMBERSHIP_KEY)
    if value is not None:
        validate_membership(value, expected_cluster_id=_local_cluster_id(connection))
    return value


def initialize_membership(connection: sqlite3.Connection, membership: dict[str, Any]) -> bool:
    """Persist the initial writer epoch exactly once."""
    if connection.in_transaction:
        raise HAStateConflict("membership_initialize_requires_transaction_boundary")
    cluster_id = _local_cluster_id(connection)
    validate_membership(membership, expected_cluster_id=cluster_id)
    if membership["generation"] != 1:
        raise HAStateConflict("initial_membership_generation_must_be_one")
    connection.execute("BEGIN IMMEDIATE")
    try:
        current = _read_meta(connection, MEMBERSHIP_KEY)
        if current is not None:
            if current == membership:
                connection.rollback()
                return False
            raise HAStateConflict("membership_already_initialized")
        _write_meta(connection, MEMBERSHIP_KEY, membership)
        connection.commit()
        return True
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise


def load_transition(connection: sqlite3.Connection) -> dict[str, Any] | None:
    value = _read_meta(connection, TRANSITION_KEY)
    if value is not None:
        validate_transition(value, expected_cluster_id=_local_cluster_id(connection))
    return value


def persist_transition(
    connection: sqlite3.Connection,
    transition: dict[str, Any],
    *,
    expected_phase: str | None,
) -> bool:
    """CAS-update the current transition journal; exact replay is idempotent."""
    if connection.in_transaction:
        raise HAStateConflict("transition_persist_requires_transaction_boundary")
    cluster_id = _local_cluster_id(connection)
    validate_transition(transition, expected_cluster_id=cluster_id)
    connection.execute("BEGIN IMMEDIATE")
    try:
        current = _read_meta(connection, TRANSITION_KEY)
        if current == transition:
            connection.rollback()
            return False
        if current is None:
            if expected_phase is not None:
                raise HAStateConflict("transition_missing")
            if transition.get("phase") != "planned":
                raise HAStateConflict("new_transition_must_start_planned")
        else:
            validate_transition(current, expected_cluster_id=cluster_id)
            current_terminal = current.get("phase") in TERMINAL_PHASES
            same_transition = current.get("transition_id") == transition.get("transition_id")
            if current_terminal:
                if same_transition:
                    raise HAStateConflict("terminal_transition_immutable")
                if expected_phase is not None:
                    raise HAStateConflict("transition_phase_changed")
                if transition.get("phase") != "planned":
                    raise HAStateConflict("new_transition_must_start_planned")
            else:
                if expected_phase is None:
                    raise HAStateConflict("transition_already_active")
                if current.get("phase") != expected_phase:
                    raise HAStateConflict("transition_phase_changed")
                if not same_transition:
                    raise HAStateConflict("different_transition_active")
                if current.get("from_generation") != transition.get("from_generation"):
                    raise HAStateConflict("transition_generation_changed")
        _write_meta(connection, TRANSITION_KEY, transition)
        connection.commit()
        return True
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise


def commit_promotion(
    connection: sqlite3.Connection,
    *,
    before_membership: dict[str, Any],
    after_membership: dict[str, Any],
    before_transition: dict[str, Any],
    after_transition: dict[str, Any],
) -> None:
    """Atomically advance writer generation and transition phase."""
    if connection.in_transaction:
        raise HAStateConflict("promotion_commit_requires_transaction_boundary")
    cluster_id = _local_cluster_id(connection)
    validate_membership(before_membership, expected_cluster_id=cluster_id)
    validate_membership(after_membership, expected_cluster_id=cluster_id)
    validate_transition(before_transition, expected_cluster_id=cluster_id)
    validate_transition(after_transition, expected_cluster_id=cluster_id)
    if before_transition.get("phase") != "source_fenced" or after_transition.get("phase") != "target_promoted":
        raise HAStateConflict("promotion_transition_phase_rejected")
    if before_transition.get("transition_id") != after_transition.get("transition_id"):
        raise HAStateConflict("promotion_transition_identity_changed")
    if after_membership.get("generation") != before_membership.get("generation") + 1:
        raise HAStateConflict("promotion_membership_generation_rejected")
    if before_membership.get("writer") != before_transition.get("source_writer"):
        raise HAStateConflict("promotion_source_writer_rejected")
    if after_membership.get("writer") != after_transition.get("target_writer"):
        raise HAStateConflict("promotion_target_writer_rejected")
    if after_membership.get("generation") != after_transition.get("to_generation"):
        raise HAStateConflict("promotion_epoch_rejected")

    connection.execute("BEGIN IMMEDIATE")
    try:
        current_membership = _read_meta(connection, MEMBERSHIP_KEY)
        current_transition = _read_meta(connection, TRANSITION_KEY)
        if current_membership != before_membership:
            raise HAStateConflict("membership_changed_before_promotion")
        if current_transition != before_transition:
            raise HAStateConflict("transition_changed_before_promotion")
        _write_meta(connection, MEMBERSHIP_KEY, after_membership)
        _write_meta(connection, TRANSITION_KEY, after_transition)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
