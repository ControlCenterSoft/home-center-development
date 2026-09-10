"""Durable, replay-safe role authority for bounded Home Center HA transitions."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import dataclass
from enum import StrEnum

from .ha_rolling_authority import (
    HARoleAssignment,
    HARoleAssignmentSnapshot,
    HARoleCoordinationError,
    build_role_assignment_snapshot,
)
from .ha_rolling_safety import NodeRole

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")


class HARoleJournalError(ValueError):
    """Stable fail-closed error for persisted HA role-authority evidence."""


class HARoleTransitionKind(StrEnum):
    ELECTION = "election"
    FAILOVER = "failover"
    RECOVERY = "recovery"
    ROLLBACK = "rollback"


@dataclass(frozen=True, slots=True)
class HARoleAuthorityState:
    snapshot: HARoleAssignmentSnapshot
    journal_seq: int
    resource_version: int
    transition_id: str
    transition_kind: str
    production_mutation_enabled: bool = False
    schema: str = "home-center.ha-role-authority-state.v1"


@dataclass(frozen=True, slots=True)
class HARoleJournalEntry:
    cluster_id: str
    journal_seq: int
    role_epoch: int
    resource_version: int
    transition_id: str
    transition_kind: str
    previous_assignment_id: str | None
    assignment_id: str


class HARoleJournalAuthority:
    """SQLite-backed HARoleAuthority with append-only journal and exact CAS."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise HARoleJournalError("invalid_role_journal_connection")
        self._db = connection
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS hc_ha_role_state (
              cluster_id TEXT PRIMARY KEY,
              role_epoch INTEGER NOT NULL,
              resource_version INTEGER NOT NULL,
              assignment_id TEXT NOT NULL,
              assignments_json TEXT NOT NULL,
              journal_seq INTEGER NOT NULL,
              transition_id TEXT NOT NULL,
              transition_kind TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hc_ha_role_journal (
              cluster_id TEXT NOT NULL,
              journal_seq INTEGER NOT NULL,
              role_epoch INTEGER NOT NULL,
              resource_version INTEGER NOT NULL,
              transition_id TEXT NOT NULL,
              transition_kind TEXT NOT NULL,
              previous_assignment_id TEXT,
              assignment_id TEXT NOT NULL,
              assignments_json TEXT NOT NULL,
              PRIMARY KEY (cluster_id, journal_seq),
              UNIQUE (cluster_id, transition_id)
            );
            """
        )
        self._db.commit()

    @staticmethod
    def _json(assignments: tuple[HARoleAssignment, ...]) -> str:
        return json.dumps(
            [item.to_dict() for item in assignments],
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _decode(raw: str) -> tuple[HARoleAssignment, ...]:
        try:
            payload = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise HARoleJournalError("role_state_corrupt") from exc
        if not isinstance(payload, list):
            raise HARoleJournalError("role_state_corrupt")
        result: list[HARoleAssignment] = []
        for item in payload:
            if not isinstance(item, dict) or set(item) != {"node_id", "role"}:
                raise HARoleJournalError("role_state_corrupt")
            try:
                result.append(HARoleAssignment(item["node_id"], NodeRole(item["role"])))
            except (TypeError, ValueError, HARoleCoordinationError) as exc:
                raise HARoleJournalError("role_state_corrupt") from exc
        return tuple(result)

    @staticmethod
    def _transition_id(
        cluster_id: str,
        kind: str,
        previous_assignment_id: str | None,
        assignment_id: str,
        role_epoch: int,
        resource_version: int,
        journal_seq: int,
    ) -> str:
        material = {
            "schema": "home-center.ha-role-transition.v1",
            "cluster_id": cluster_id,
            "kind": kind,
            "previous_assignment_id": previous_assignment_id,
            "assignment_id": assignment_id,
            "role_epoch": role_epoch,
            "resource_version": resource_version,
            "journal_seq": journal_seq,
        }
        digest = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return f"ha-role-transition-{digest}"

    def _journal_row(self, cluster_id: str, journal_seq: int) -> sqlite3.Row:
        row = self._db.execute(
            "SELECT * FROM hc_ha_role_journal WHERE cluster_id=? AND journal_seq=?",
            (cluster_id, journal_seq),
        ).fetchone()
        if row is None:
            raise HARoleJournalError("role_journal_entry_missing")
        return row

    def _state(self, row: sqlite3.Row) -> HARoleAuthorityState:
        journal = self._journal_row(row["cluster_id"], row["journal_seq"])
        for key in (
            "role_epoch",
            "resource_version",
            "assignment_id",
            "assignments_json",
            "transition_id",
            "transition_kind",
        ):
            if row[key] != journal[key]:
                raise HARoleJournalError("role_state_journal_mismatch")
        snapshot = build_role_assignment_snapshot(
            cluster_id=row["cluster_id"],
            role_epoch=row["role_epoch"],
            assignments=self._decode(row["assignments_json"]),
        )
        if snapshot.assignment_id != row["assignment_id"]:
            raise HARoleJournalError("role_state_identity_invalid")
        expected = self._transition_id(
            row["cluster_id"],
            row["transition_kind"],
            journal["previous_assignment_id"],
            row["assignment_id"],
            row["role_epoch"],
            row["resource_version"],
            row["journal_seq"],
        )
        if expected != row["transition_id"]:
            raise HARoleJournalError("role_transition_identity_invalid")
        return HARoleAuthorityState(
            snapshot,
            row["journal_seq"],
            row["resource_version"],
            row["transition_id"],
            row["transition_kind"],
        )

    def bootstrap(
        self,
        *,
        cluster_id: str,
        assignments: tuple[HARoleAssignment, ...],
    ) -> HARoleAuthorityState:
        """Initialize authoritative roles; exact bootstrap replay is idempotent."""

        if IDENTIFIER.fullmatch(cluster_id) is None:
            raise HARoleJournalError("invalid_role_cluster_id")
        snapshot = build_role_assignment_snapshot(
            cluster_id=cluster_id,
            role_epoch=0,
            assignments=assignments,
        )
        encoded = self._json(snapshot.assignments)
        transition_id = self._transition_id(
            cluster_id, "bootstrap", None, snapshot.assignment_id, 0, 1, 1
        )
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM hc_ha_role_state WHERE cluster_id=?", (cluster_id,)
                ).fetchone()
                if row is not None:
                    state = self._state(row)
                    if state.transition_id == transition_id:
                        self._db.commit()
                        return state
                    raise HARoleJournalError("role_state_already_initialized")
                self._db.execute(
                    """INSERT INTO hc_ha_role_journal VALUES
                       (?,1,0,1,?,'bootstrap',NULL,?,?)""",
                    (cluster_id, transition_id, snapshot.assignment_id, encoded),
                )
                self._db.execute(
                    """INSERT INTO hc_ha_role_state VALUES
                       (?,0,1,?,?,1,?,'bootstrap')""",
                    (cluster_id, snapshot.assignment_id, encoded, transition_id),
                )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
            return self._current(cluster_id, tuple(x.node_id for x in snapshot.assignments))

    def transition(
        self,
        *,
        cluster_id: str,
        assignments: tuple[HARoleAssignment, ...],
        transition_kind: HARoleTransitionKind,
        expected_assignment_id: str,
        expected_role_epoch: int,
        expected_resource_version: int,
        expected_journal_seq: int,
    ) -> HARoleAuthorityState:
        """Append one typed role transition and CAS-update current evidence atomically."""

        if IDENTIFIER.fullmatch(cluster_id) is None:
            raise HARoleJournalError("invalid_role_cluster_id")
        if not isinstance(transition_kind, HARoleTransitionKind):
            raise HARoleJournalError("invalid_role_transition_kind")
        expected = (expected_role_epoch, expected_resource_version, expected_journal_seq)
        if any(isinstance(x, bool) or not isinstance(x, int) or x < 0 for x in expected):
            raise HARoleJournalError("invalid_role_transition_revision")
        next_snapshot = build_role_assignment_snapshot(
            cluster_id=cluster_id,
            role_epoch=expected_role_epoch + 1,
            assignments=assignments,
        )
        next_resource = expected_resource_version + 1
        next_seq = expected_journal_seq + 1
        transition_id = self._transition_id(
            cluster_id,
            transition_kind.value,
            expected_assignment_id,
            next_snapshot.assignment_id,
            next_snapshot.role_epoch,
            next_resource,
            next_seq,
        )
        encoded = self._json(next_snapshot.assignments)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._db.execute(
                    "SELECT 1 FROM hc_ha_role_journal WHERE cluster_id=? AND transition_id=?",
                    (cluster_id, transition_id),
                ).fetchone()
                row = self._db.execute(
                    "SELECT * FROM hc_ha_role_state WHERE cluster_id=?", (cluster_id,)
                ).fetchone()
                if row is None:
                    raise HARoleJournalError("role_state_not_initialized")
                current = self._state(row)
                if replay is not None:
                    if current.transition_id != transition_id:
                        raise HARoleJournalError("role_transition_superseded")
                    self._db.commit()
                    return current
                checks = (
                    (
                        current.snapshot.assignment_id,
                        expected_assignment_id,
                        "role_assignment_stale",
                    ),
                    (current.snapshot.role_epoch, expected_role_epoch, "role_epoch_stale"),
                    (
                        current.resource_version,
                        expected_resource_version,
                        "role_resource_version_stale",
                    ),
                    (current.journal_seq, expected_journal_seq, "role_journal_stale"),
                )
                for actual, wanted, code in checks:
                    if actual != wanted:
                        raise HARoleJournalError(code)
                current_members = tuple(x.node_id for x in current.snapshot.assignments)
                next_members = tuple(x.node_id for x in next_snapshot.assignments)
                if current_members != next_members:
                    raise HARoleJournalError("role_membership_change_rejected")
                if tuple(x.to_dict() for x in current.snapshot.assignments) == tuple(
                    x.to_dict() for x in next_snapshot.assignments
                ):
                    raise HARoleJournalError("role_transition_noop")
                self._db.execute(
                    """INSERT INTO hc_ha_role_journal VALUES
                       (?,?,?,?,?,?,?,?,?)""",
                    (
                        cluster_id,
                        next_seq,
                        next_snapshot.role_epoch,
                        next_resource,
                        transition_id,
                        transition_kind.value,
                        expected_assignment_id,
                        next_snapshot.assignment_id,
                        encoded,
                    ),
                )
                updated = self._db.execute(
                    """UPDATE hc_ha_role_state SET role_epoch=?, resource_version=?,
                       assignment_id=?, assignments_json=?, journal_seq=?, transition_id=?,
                       transition_kind=? WHERE cluster_id=? AND resource_version=?""",
                    (
                        next_snapshot.role_epoch,
                        next_resource,
                        next_snapshot.assignment_id,
                        encoded,
                        next_seq,
                        transition_id,
                        transition_kind.value,
                        cluster_id,
                        expected_resource_version,
                    ),
                )
                if updated.rowcount != 1:
                    raise HARoleJournalError("role_cas_lost")
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
            return self._current(cluster_id, next_members)

    def _current(self, cluster_id: str, node_ids: tuple[str, ...]) -> HARoleAuthorityState:
        row = self._db.execute(
            "SELECT * FROM hc_ha_role_state WHERE cluster_id=?", (cluster_id,)
        ).fetchone()
        if row is None:
            raise HARoleJournalError("role_state_not_initialized")
        state = self._state(row)
        if tuple(x.node_id for x in state.snapshot.assignments) != tuple(sorted(node_ids)):
            raise HARoleJournalError("role_membership_mismatch")
        return state

    def state_for(self, *, cluster_id: str, node_ids: tuple[str, ...]) -> HARoleAuthorityState:
        if IDENTIFIER.fullmatch(cluster_id) is None:
            raise HARoleJournalError("invalid_role_cluster_id")
        if not 1 <= len(node_ids) <= 64 or len(node_ids) != len(set(node_ids)):
            raise HARoleJournalError("invalid_role_membership")
        with self._lock:
            return self._current(cluster_id, node_ids)

    def snapshot_for(
        self,
        *,
        cluster_id: str,
        node_ids: tuple[str, ...],
    ) -> HARoleAssignmentSnapshot:
        """Satisfy HARoleAuthority using persisted evidence, never peer-reported roles."""

        return self.state_for(cluster_id=cluster_id, node_ids=node_ids).snapshot

    def journal_entries(
        self, *, cluster_id: str, limit: int = 32
    ) -> tuple[HARoleJournalEntry, ...]:
        if IDENTIFIER.fullmatch(cluster_id) is None:
            raise HARoleJournalError("invalid_role_cluster_id")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 128:
            raise HARoleJournalError("invalid_role_journal_limit")
        with self._lock:
            rows = self._db.execute(
                """SELECT * FROM hc_ha_role_journal WHERE cluster_id=?
                   ORDER BY journal_seq DESC LIMIT ?""",
                (cluster_id, limit),
            ).fetchall()
            result: list[HARoleJournalEntry] = []
            for row in reversed(rows):
                snapshot = build_role_assignment_snapshot(
                    cluster_id=row["cluster_id"],
                    role_epoch=row["role_epoch"],
                    assignments=self._decode(row["assignments_json"]),
                )
                expected = self._transition_id(
                    row["cluster_id"],
                    row["transition_kind"],
                    row["previous_assignment_id"],
                    row["assignment_id"],
                    row["role_epoch"],
                    row["resource_version"],
                    row["journal_seq"],
                )
                if snapshot.assignment_id != row["assignment_id"]:
                    raise HARoleJournalError("role_journal_identity_invalid")
                if expected != row["transition_id"]:
                    raise HARoleJournalError("role_transition_identity_invalid")
                result.append(
                    HARoleJournalEntry(
                        row["cluster_id"],
                        row["journal_seq"],
                        row["role_epoch"],
                        row["resource_version"],
                        row["transition_id"],
                        row["transition_kind"],
                        row["previous_assignment_id"],
                        row["assignment_id"],
                    )
                )
            return tuple(result)
