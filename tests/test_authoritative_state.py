from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from home_center.authoritative_state import (
    AUTHORITATIVE_TABLES,
    apply_authoritative_snapshot,
    snapshot_authoritative,
    validate_snapshot,
)
from home_center.store import StateStore


class AuthoritativeStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.source = StateStore(root / "source.db", b"s" * 32, "cluster-test")
        self.target = StateStore(root / "target.db", b"t" * 32, "cluster-test")
        self._seed_local_state()
        self._seed_authoritative_state()

    def tearDown(self) -> None:
        self.source.close()
        self.target.close()
        self.temp.cleanup()

    @staticmethod
    def _node(node_id: str, name: str, role: str, address: str) -> dict:
        return {
            "schema": "home-center.node-capability.v1",
            "observed_at": "2026-09-14T12:00:00Z",
            "node": {"id": node_id, "name": name, "role": role, "address": address},
        }

    def _seed_local_state(self) -> None:
        self.source.upsert_node(self._node("source-node", "source", "leader", "source.example"), "ready")
        self.target.upsert_node(self._node("target-node", "target", "standby", "target.example"), "ready")
        self.source.audit(
            actor="system:test", action="source.local", target="source-node", outcome="ok",
            correlation_id="source-audit", details={"local": "source"},
        )
        self.target.audit(
            actor="system:test", action="target.local", target="target-node", outcome="ok",
            correlation_id="target-audit", details={"local": "target"},
        )

    def _seed_authoritative_state(self) -> None:
        self.source.set_meta("product.state", {"generation": 7, "owner": "writer"})
        self.target.set_meta("target.stale", {"generation": 1})
        now = "2026-09-14T12:00:00Z"
        with self.source._lock, self.source._connection:
            connection = self.source._connection
            connection.execute(
                "INSERT INTO desired_state(resource_key,generation,value_json,updated_at) VALUES(?,?,?,?)",
                ("resource:test", 3, '{"enabled":true}', now),
            )
            connection.execute(
                """INSERT INTO jobs(job_id,job_type,state,initiator,reason,preflight_json,result_json,
                evidence_json,recovery_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "job-test", "action.test", "succeeded", "local-admin:admin", "ha-test", "{}",
                    '{"ok":true}', '{"verified":true}', '{"strategy":"none-read-only","checkpoint":null}',
                    now, now,
                ),
            )
            connection.execute(
                """INSERT INTO action_job_metadata(job_id,actor,action_id,idempotency_key,request_hash,steps_json)
                VALUES(?,?,?,?,?,?)""",
                ("job-test", "local-admin:admin", "action.test", "idem-test", "a" * 64, "[]"),
            )
            connection.execute(
                """INSERT INTO home_service_instances(instance_id,service_id,target_node_id,state,generation,
                resource_version,configuration_revision_id,external_publication_enabled,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                ("service-test", "minecraft-server", "source-node", "installed", 2, "rv-test", None, 0, now),
            )
            connection.execute(
                """INSERT INTO home_service_instance_transitions(instance_id,idempotency_key,request_hash,
                result_json,created_at) VALUES(?,?,?,?,?)""",
                ("service-test", "transition-test", "b" * 64, '{"state":"installed"}', now),
            )
            connection.execute(
                """INSERT INTO qr_onboarding_runtime(runtime_record_id,invitation_id,household_id,
                household_snapshot_id,household_resource_version,household_generation,target_member_id,
                invitation_json,invitation_evidence_sha256,token_sha256,state,version,created_at_epoch,
                expires_at_epoch,consumed_at_epoch,revoked_at_epoch,updated_at_epoch)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "qr-runtime-test", "invitation-test", "home", "snapshot-test", "household-rv-test", 4,
                    "member-test", '{"kind":"guest"}', "c" * 64, "d" * 64, "consumed", 2,
                    1000, 1800, 1200, None, 1200,
                ),
            )
            connection.execute(
                """INSERT INTO qr_onboarding_runtime_operations(operation_key_sha256,runtime_record_id,
                request_sha256,receipt_json,created_at_epoch) VALUES(?,?,?,?,?)""",
                ("e" * 64, "qr-runtime-test", "f" * 64, '{"outcome":"consumed"}', 1200),
            )
            connection.execute(
                """INSERT INTO safe_auto_repair_recommendations(recommendation_id,household_id,resource_id,
                resource_generation,evidence_sha256,policy_id,policy_sha256,eligible_for_auto_repair,
                recommendation_json,recorded_at_epoch) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    "repair-test", "home", "resource:test", 3, "1" * 64, "policy-test", "2" * 64, 1,
                    '{"action":"repair"}', 1300,
                ),
            )

    @staticmethod
    def _rows(store: StateStore, table: str) -> list[tuple]:
        with store._lock:
            return [tuple(row) for row in store._connection.execute(f'SELECT * FROM "{table}" ORDER BY 1').fetchall()]

    def test_snapshot_covers_every_writer_owned_table(self) -> None:
        snapshot = snapshot_authoritative(self.source._connection)
        self.assertEqual(set(AUTHORITATIVE_TABLES), set(snapshot["tables"]))
        for table in AUTHORITATIVE_TABLES:
            self.assertTrue(snapshot["tables"][table]["rows"], table)
        self.assertFalse(
            any(row[0] == "cluster_id" for row in snapshot["tables"]["cluster_meta"]["rows"])
        )

    def test_apply_reaches_exact_parity_and_preserves_local_state(self) -> None:
        target_nodes = self._rows(self.target, "nodes")
        target_audit = self._rows(self.target, "audit")
        target_migrations = self._rows(self.target, "schema_migrations")
        with self.target._lock:
            target_cluster_meta = self.target._connection.execute(
                "SELECT value_json,updated_at FROM cluster_meta WHERE key='cluster_id'"
            ).fetchone()
            self.assertIsNotNone(target_cluster_meta)
            target_cluster_meta = tuple(target_cluster_meta)

        snapshot = snapshot_authoritative(self.source._connection)
        result = apply_authoritative_snapshot(self.target._connection, snapshot)

        self.assertTrue(result["changed"])
        self.assertEqual(snapshot["authoritative_sha256"], result["authoritative_sha256"])
        self.assertEqual(snapshot, snapshot_authoritative(self.target._connection))
        self.assertEqual(target_nodes, self._rows(self.target, "nodes"))
        self.assertEqual(target_audit, self._rows(self.target, "audit"))
        self.assertEqual(target_migrations, self._rows(self.target, "schema_migrations"))
        with self.target._lock:
            after_cluster_meta = self.target._connection.execute(
                "SELECT value_json,updated_at FROM cluster_meta WHERE key='cluster_id'"
            ).fetchone()
            self.assertEqual(target_cluster_meta, tuple(after_cluster_meta))

        replay = apply_authoritative_snapshot(self.target._connection, snapshot)
        self.assertFalse(replay["changed"])

    def test_source_deletion_is_mirrored_without_touching_local_tables(self) -> None:
        apply_authoritative_snapshot(self.target._connection, snapshot_authoritative(self.source._connection))
        target_nodes = self._rows(self.target, "nodes")
        target_audit = self._rows(self.target, "audit")

        with self.source._lock, self.source._connection:
            self.source._connection.execute("DELETE FROM cluster_meta WHERE key='product.state'")
            self.source._connection.execute("DELETE FROM desired_state WHERE resource_key='resource:test'")
            self.source._connection.execute("DELETE FROM qr_onboarding_runtime_operations WHERE runtime_record_id='qr-runtime-test'")
            self.source._connection.execute("DELETE FROM qr_onboarding_runtime WHERE runtime_record_id='qr-runtime-test'")
            self.source._connection.execute("DELETE FROM safe_auto_repair_recommendations WHERE recommendation_id='repair-test'")

        snapshot = snapshot_authoritative(self.source._connection)
        apply_authoritative_snapshot(self.target._connection, snapshot)
        self.assertEqual(snapshot, snapshot_authoritative(self.target._connection))
        self.assertFalse(self.target.get_meta("product.state"))
        self.assertEqual([], self.target.desired_state())
        self.assertEqual([], self._rows(self.target, "qr_onboarding_runtime"))
        self.assertEqual([], self._rows(self.target, "safe_auto_repair_recommendations"))
        self.assertEqual(target_nodes, self._rows(self.target, "nodes"))
        self.assertEqual(target_audit, self._rows(self.target, "audit"))

    def test_validation_fails_closed_on_shape_digest_and_cluster_drift(self) -> None:
        snapshot = snapshot_authoritative(self.source._connection)

        wrong_table = copy.deepcopy(snapshot)
        wrong_table["tables"]["unexpected"] = {"columns": [], "rows": []}
        with self.assertRaisesRegex(ValueError, "table_set"):
            validate_snapshot(wrong_table, expected_cluster_id="cluster-test")

        wrong_digest = copy.deepcopy(snapshot)
        wrong_digest["tables"]["cluster_meta"]["rows"][0][1] = '{"tampered":true}'
        with self.assertRaisesRegex(ValueError, "digest"):
            validate_snapshot(wrong_digest, expected_cluster_id="cluster-test")

        wrong_cluster = copy.deepcopy(snapshot)
        wrong_cluster["cluster_id"] = "other-cluster"
        with self.assertRaisesRegex(ValueError, "cluster"):
            validate_snapshot(wrong_cluster, expected_cluster_id="cluster-test")

        leaked_cluster_id = copy.deepcopy(snapshot)
        leaked_cluster_id["tables"]["cluster_meta"]["rows"].append(
            ["cluster_id", '"cluster-test"', "2026-09-14T12:00:00Z"]
        )
        leaked_cluster_id["authoritative_sha256"] = snapshot["authoritative_sha256"]
        with self.assertRaises(ValueError):
            validate_snapshot(leaked_cluster_id, expected_cluster_id="cluster-test")


if __name__ == "__main__":
    unittest.main()
