"""SQLite state store with migrations and a keyed append-only audit chain."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from .util import canonical_json, utc_now


MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cluster_meta (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            address TEXT NOT NULL,
            status TEXT NOT NULL,
            capabilities_json TEXT NOT NULL,
            last_seen TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS desired_state (
            resource_key TEXT PRIMARY KEY,
            generation INTEGER NOT NULL,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            job_type TEXT NOT NULL,
            state TEXT NOT NULL,
            initiator TEXT NOT NULL,
            reason TEXT NOT NULL,
            preflight_json TEXT NOT NULL,
            result_json TEXT,
            evidence_json TEXT,
            recovery_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            occurred_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            outcome TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            details_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL UNIQUE
        );
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS action_job_metadata (
            job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
            actor TEXT NOT NULL,
            action_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            steps_json TEXT NOT NULL,
            UNIQUE(actor, action_id, idempotency_key)
        );
        """,
    ),
    (
        3,
        """
        CREATE TABLE IF NOT EXISTS home_service_instances (
            instance_id TEXT PRIMARY KEY,
            service_id TEXT NOT NULL,
            target_node_id TEXT NOT NULL,
            state TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation >= 1),
            resource_version TEXT NOT NULL,
            configuration_revision_id TEXT,
            external_publication_enabled INTEGER NOT NULL CHECK(external_publication_enabled IN (0,1)),
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS home_service_instance_transitions (
            instance_id TEXT NOT NULL REFERENCES home_service_instances(instance_id) ON DELETE CASCADE,
            idempotency_key TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(instance_id, idempotency_key)
        );
        """,
    ),
)


class IdempotencyConflict(ValueError):
    """The same idempotency key was reused with different request material."""


class StatePreconditionFailed(RuntimeError):
    """A home-service instance changed after the caller observed it."""


class StateStore:
    def __init__(self, path: Path, audit_key: bytes, cluster_id: str) -> None:
        self.path = path
        self.audit_key = audit_key
        self.cluster_id = cluster_id
        self._lock = threading.RLock()
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o750)
        self._connection = sqlite3.connect(path, check_same_thread=False, timeout=5)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._migrate()
        os.chmod(path, 0o640)
        self.set_meta("cluster_id", cluster_id)
        self.verify_audit_chain()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _migrate(self) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            current = {
                int(row[0]) for row in self._connection.execute("SELECT version FROM schema_migrations")
            }
            for version, sql in MIGRATIONS:
                if version in current:
                    continue
                self._connection.executescript(sql)
                self._connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", (version, utc_now())
                )

    def set_meta(self, key: str, value: Any) -> None:
        payload = canonical_json(value)
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO cluster_meta(key, value_json, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at""",
                (key, payload, utc_now()),
            )

    def get_meta(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._connection.execute("SELECT value_json FROM cluster_meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def upsert_node(self, capability: dict[str, Any], status: str) -> None:
        node = capability["node"]
        now = utc_now()
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO nodes(node_id,name,role,address,status,capabilities_json,last_seen,updated_at)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(node_id) DO UPDATE SET
                  name=excluded.name, role=excluded.role, address=excluded.address,
                  status=excluded.status, capabilities_json=excluded.capabilities_json,
                  last_seen=excluded.last_seen, updated_at=excluded.updated_at""",
                (
                    node["id"],
                    node["name"],
                    node["role"],
                    node["address"],
                    status,
                    canonical_json(capability),
                    capability.get("observed_at", now),
                    now,
                ),
            )

    def mark_node(self, node_id: str, status: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE nodes SET status=?, updated_at=? WHERE node_id=?", (status, utc_now(), node_id)
            )

    def nodes(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT node_id,name,role,address,status,capabilities_json,last_seen,updated_at FROM nodes ORDER BY name"
            ).fetchall()
        return [
            {
                "node_id": row["node_id"],
                "name": row["name"],
                "role": row["role"],
                "address": row["address"],
                "status": row["status"],
                "capabilities": json.loads(row["capabilities_json"]),
                "last_seen": row["last_seen"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    @staticmethod
    def _decode_home_service_instance(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "schema": "home-center.home-service-instance.v1",
            "instance_id": row["instance_id"],
            "service_id": row["service_id"],
            "target_node_id": row["target_node_id"],
            "state": row["state"],
            "generation": row["generation"],
            "resource_version": row["resource_version"],
            "configuration_revision_id": row["configuration_revision_id"],
            "external_publication_enabled": bool(row["external_publication_enabled"]),
            "updated_at": row["updated_at"],
        }

    def create_home_service_instance(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO home_service_instances(
                instance_id,service_id,target_node_id,state,generation,resource_version,
                configuration_revision_id,external_publication_enabled,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    record["instance_id"], record["service_id"], record["target_node_id"],
                    record["state"], record["generation"], record["resource_version"],
                    record.get("configuration_revision_id"),
                    1 if record.get("external_publication_enabled") else 0,
                    record["updated_at"],
                ),
            )
        value = self.home_service_instance(record["instance_id"])
        if value is None:
            raise RuntimeError("home-service instance persistence failed")
        return value

    def home_service_instance(self, instance_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM home_service_instances WHERE instance_id=?", (instance_id,)
            ).fetchone()
        return self._decode_home_service_instance(row) if row else None

    def transition_home_service_instance(
        self,
        *,
        instance_id: str,
        expected_generation: int,
        expected_resource_version: str,
        idempotency_key: str,
        request_hash: str,
        target_state: str,
        generation: int,
        resource_version: str,
        configuration_revision_id: str | None,
        external_publication_enabled: bool,
        updated_at: str,
    ) -> tuple[dict[str, Any], bool]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._connection.execute(
                    """SELECT request_hash,result_json FROM home_service_instance_transitions
                    WHERE instance_id=? AND idempotency_key=?""",
                    (instance_id, idempotency_key),
                ).fetchone()
                if replay:
                    if replay["request_hash"] != request_hash:
                        raise IdempotencyConflict(idempotency_key)
                    self._connection.commit()
                    return json.loads(replay["result_json"]), False
                row = self._connection.execute(
                    "SELECT * FROM home_service_instances WHERE instance_id=?", (instance_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(instance_id)
                if row["generation"] != expected_generation or row["resource_version"] != expected_resource_version:
                    raise StatePreconditionFailed(instance_id)
                self._connection.execute(
                    """UPDATE home_service_instances SET state=?,generation=?,resource_version=?,
                    configuration_revision_id=?,external_publication_enabled=?,updated_at=?
                    WHERE instance_id=?""",
                    (
                        target_state, generation, resource_version, configuration_revision_id,
                        1 if external_publication_enabled else 0, updated_at, instance_id,
                    ),
                )
                result_row = self._connection.execute(
                    "SELECT * FROM home_service_instances WHERE instance_id=?", (instance_id,)
                ).fetchone()
                if result_row is None:
                    raise RuntimeError("home-service instance transition failed")
                result = self._decode_home_service_instance(result_row)
                self._connection.execute(
                    """INSERT INTO home_service_instance_transitions(
                    instance_id,idempotency_key,request_hash,result_json,created_at
                    ) VALUES(?,?,?,?,?)""",
                    (instance_id, idempotency_key, request_hash, canonical_json(result), updated_at),
                )
                self._connection.commit()
                return result, True
            except Exception:
                self._connection.rollback()
                raise

    def audit(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        outcome: str,
        correlation_id: str,
        details: dict[str, Any] | None = None,
    ) -> str:
        event_id = str(uuid.uuid4())
        occurred_at = utc_now()
        details_json = canonical_json(details or {})
        with self._lock, self._connection:
            row = self._connection.execute("SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            previous_hash = row[0] if row else "0" * 64
            material = canonical_json(
                {
                    "event_id": event_id,
                    "occurred_at": occurred_at,
                    "actor": actor,
                    "action": action,
                    "target": target,
                    "outcome": outcome,
                    "correlation_id": correlation_id,
                    "details": json.loads(details_json),
                    "previous_hash": previous_hash,
                }
            ).encode("utf-8")
            entry_hash = hmac.new(self.audit_key, material, hashlib.sha256).hexdigest()
            self._connection.execute(
                """INSERT INTO audit(event_id,occurred_at,actor,action,target,outcome,correlation_id,
                details_json,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    event_id,
                    occurred_at,
                    actor,
                    action,
                    target,
                    outcome,
                    correlation_id,
                    details_json,
                    previous_hash,
                    entry_hash,
                ),
            )
        return event_id

    def verify_audit_chain(self) -> str:
        previous_hash = "0" * 64
        with self._lock:
            rows = self._connection.execute("SELECT * FROM audit ORDER BY seq").fetchall()
        for row in rows:
            if row["previous_hash"] != previous_hash:
                raise RuntimeError(f"audit chain discontinuity at seq {row['seq']}")
            material = canonical_json(
                {
                    "event_id": row["event_id"],
                    "occurred_at": row["occurred_at"],
                    "actor": row["actor"],
                    "action": row["action"],
                    "target": row["target"],
                    "outcome": row["outcome"],
                    "correlation_id": row["correlation_id"],
                    "details": json.loads(row["details_json"]),
                    "previous_hash": row["previous_hash"],
                }
            ).encode("utf-8")
            expected = hmac.new(self.audit_key, material, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, row["entry_hash"]):
                raise RuntimeError(f"audit chain signature mismatch at seq {row['seq']}")
            previous_hash = row["entry_hash"]
        return previous_hash

    def audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        with self._lock:
            rows = self._connection.execute(
                """SELECT seq,event_id,occurred_at,actor,action,target,outcome,correlation_id,
                details_json,previous_hash,entry_hash FROM audit ORDER BY seq DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [
            {
                **{key: row[key] for key in row.keys() if key != "details_json"},
                "details": json.loads(row["details_json"]),
            }
            for row in rows
        ]

    @staticmethod
    def _decode_job(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "schema": "home-center.job.v1",
            "job_id": row["job_id"],
            "job_type": row["job_type"],
            "state": row["state"],
            "initiator": row["initiator"],
            "reason": row["reason"],
            "idempotency_key": row["idempotency_key"] or f"legacy:{row['job_id']}",
            "preflight": json.loads(row["preflight_json"]),
            "steps": json.loads(row["steps_json"]) if row["steps_json"] else [],
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
            "evidence": json.loads(row["evidence_json"]) if row["evidence_json"] else None,
            "recovery": json.loads(row["recovery_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def jobs(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        with self._lock:
            rows = self._connection.execute(
                """SELECT j.*,m.idempotency_key,m.request_hash,m.steps_json
                FROM jobs AS j LEFT JOIN action_job_metadata AS m ON m.job_id=j.job_id
                ORDER BY j.created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._decode_job(row) for row in rows]

    def job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """SELECT j.*,m.idempotency_key,m.request_hash,m.steps_json
                FROM jobs AS j LEFT JOIN action_job_metadata AS m ON m.job_id=j.job_id
                WHERE j.job_id=?""",
                (job_id,),
            ).fetchone()
        return self._decode_job(row) if row else None

    def create_action_job(
        self,
        *,
        action_id: str,
        actor: str,
        reason: str,
        idempotency_key: str,
        request_hash: str,
        preflight: dict[str, Any],
        steps: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], bool]:
        now = utc_now()
        job_id = str(uuid.uuid4())
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """SELECT j.*,m.idempotency_key,m.request_hash,m.steps_json
                    FROM action_job_metadata AS m JOIN jobs AS j ON j.job_id=m.job_id
                    WHERE m.actor=? AND m.action_id=? AND m.idempotency_key=?""",
                    (actor, action_id, idempotency_key),
                ).fetchone()
                if row:
                    if row["request_hash"] != request_hash:
                        raise IdempotencyConflict(idempotency_key)
                    self._connection.commit()
                    return self._decode_job(row), False
                self._connection.execute(
                    """INSERT INTO jobs(
                    job_id,job_type,state,initiator,reason,preflight_json,result_json,evidence_json,
                    recovery_json,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        job_id,
                        action_id,
                        "preflight",
                        actor,
                        reason,
                        canonical_json(preflight),
                        None,
                        None,
                        canonical_json({"strategy": "none-read-only", "checkpoint": None}),
                        now,
                        now,
                    ),
                )
                self._connection.execute(
                    """INSERT INTO action_job_metadata(
                    job_id,actor,action_id,idempotency_key,request_hash,steps_json
                    ) VALUES(?,?,?,?,?,?)""",
                    (job_id, actor, action_id, idempotency_key, request_hash, canonical_json(steps)),
                )
                row = self._connection.execute(
                    """SELECT j.*,m.idempotency_key,m.request_hash,m.steps_json
                    FROM jobs AS j JOIN action_job_metadata AS m ON m.job_id=j.job_id
                    WHERE j.job_id=?""",
                    (job_id,),
                ).fetchone()
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        if row is None:
            raise RuntimeError("action job persistence failed")
        return self._decode_job(row), True

    def transition_action_job(
        self,
        job_id: str,
        *,
        expected_state: str,
        new_state: str,
        result: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
        steps: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        allowed = {
            "preflight": {"running", "failed"},
            "running": {"verifying", "failed"},
            "verifying": {"succeeded", "failed"},
        }
        if new_state not in allowed.get(expected_state, set()):
            raise ValueError(f"invalid job transition {expected_state}->{new_state}")
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT j.*,m.idempotency_key,m.request_hash,m.steps_json
                FROM jobs AS j JOIN action_job_metadata AS m ON m.job_id=j.job_id
                WHERE j.job_id=?""",
                (job_id,),
            ).fetchone()
            if row is None:
                raise KeyError(job_id)
            if row["state"] != expected_state:
                raise RuntimeError("job state changed concurrently")
            self._connection.execute(
                """UPDATE jobs SET state=?, result_json=COALESCE(?,result_json),
                evidence_json=COALESCE(?,evidence_json), updated_at=?
                WHERE job_id=? AND state=?""",
                (
                    new_state,
                    canonical_json(result) if result is not None else None,
                    canonical_json(evidence) if evidence is not None else None,
                    utc_now(),
                    job_id,
                    expected_state,
                ),
            )
            if steps is not None:
                self._connection.execute(
                    "UPDATE action_job_metadata SET steps_json=? WHERE job_id=?",
                    (canonical_json(steps), job_id),
                )
            row = self._connection.execute(
                """SELECT j.*,m.idempotency_key,m.request_hash,m.steps_json
                FROM jobs AS j JOIN action_job_metadata AS m ON m.job_id=j.job_id
                WHERE j.job_id=?""",
                (job_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError("action job transition failed")
        return self._decode_job(row)

    def desired_state(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT resource_key,generation,value_json,updated_at FROM desired_state ORDER BY resource_key"
            ).fetchall()
        return [
            {
                "resource_key": row["resource_key"],
                "generation": row["generation"],
                "value": json.loads(row["value_json"]),
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def backup_to(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            target = sqlite3.connect(destination)
            try:
                self._connection.backup(target)
                target.execute("PRAGMA wal_checkpoint(FULL)")
                target.commit()
            finally:
                target.close()

    def integrity_check(self) -> bool:
        with self._lock:
            result = self._connection.execute("PRAGMA integrity_check").fetchone()[0]
        return result == "ok"
