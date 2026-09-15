from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from home_center.ha_state import initialize_membership, load_membership
from home_center.ha_status import status
from home_center.store import StateStore


def membership(*, generation: int = 1, writer: str = "node-a") -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-test",
        "generation": generation,
        "writer": writer,
        "members": [
            {"node_id": "node-a", "state": "ready", "roles": ["control-plane"]},
            {"node_id": "node-b", "state": "ready", "roles": ["control-plane"]},
        ],
        "quorum": {
            "mode": "single-writer-manual-failover",
            "automatic_failover": False,
            "witness_id": None,
        },
        "observed_at": "2026-09-14T20:00:00Z",
    }


def runtime(store: StateStore, *, node_id: str, role: str, sync: dict | None = None):
    value = SimpleNamespace(
        store=store,
        config=SimpleNamespace(
            cluster_id="cluster-test",
            node_id=node_id,
            role=role,
        ),
    )
    if sync is not None:
        value.ha_state_reconciler = SimpleNamespace(status=lambda: dict(sync))
    return value


class HAStatusQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.db", b"a" * 32, "cluster-test")

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_sync_failure_degrades_cluster_status_without_mutating_membership(self) -> None:
        current = membership(writer="node-a")
        initialize_membership(self.store._connection, current)
        before = load_membership(self.store._connection)
        observed = status(
            runtime(
                self.store,
                node_id="node-b",
                role="standby",
                sync={
                    "schema": "home-center.ha-sync-status.v1",
                    "state": "degraded",
                    "reason": "peer_release_drift",
                    "direction": None,
                    "writer_node_id": "node-a",
                    "generation": 1,
                    "authoritative_sha256": None,
                    "source_instance_id": None,
                    "source_sequence": None,
                    "last_success_at": None,
                    "changed": False,
                },
            )
        )

        self.assertEqual("degraded", observed["state"])
        self.assertEqual("peer_release_drift", observed["reason"])
        self.assertEqual("standby", observed["effective_role"])
        self.assertEqual("node-a", observed["writer_node_id"])
        self.assertEqual(1, observed["generation"])
        self.assertFalse(observed["automatic_failover"])
        self.assertEqual(before, load_membership(self.store._connection))

    def test_writer_side_sync_drift_degrades_cluster_without_demoting_writer(self) -> None:
        current = membership(writer="node-a")
        initialize_membership(self.store._connection, current)
        before = load_membership(self.store._connection)

        for reason in ("writer_peer_state_drift", "peer_stale_writer", "peer_epoch_behind"):
            with self.subTest(reason=reason):
                observed = status(
                    runtime(
                        self.store,
                        node_id="node-a",
                        role="leader",
                        sync={
                            "schema": "home-center.ha-sync-status.v1",
                            "state": "writer",
                            "reason": reason,
                            "direction": None,
                            "writer_node_id": "node-a",
                            "generation": 1,
                            "authoritative_sha256": "b" * 64,
                            "source_instance_id": None,
                            "source_sequence": None,
                            "last_success_at": None,
                            "changed": False,
                        },
                    )
                )

                self.assertEqual("degraded", observed["state"])
                self.assertEqual(reason, observed["reason"])
                self.assertEqual("leader", observed["effective_role"])
                self.assertEqual("node-a", observed["writer_node_id"])
                self.assertEqual(1, observed["generation"])
                self.assertFalse(observed["automatic_failover"])
                self.assertEqual(before, load_membership(self.store._connection))

    def test_sync_status_exception_degrades_cluster_without_losing_writer_epoch(self) -> None:
        current = membership(generation=3, writer="node-a")
        initialize_membership(self.store._connection, current)
        before = load_membership(self.store._connection)
        current_runtime = runtime(self.store, node_id="node-a", role="leader")

        def unavailable() -> dict:
            raise RuntimeError("synthetic reconciler status failure")

        current_runtime.ha_state_reconciler = SimpleNamespace(status=unavailable)
        observed = status(current_runtime)

        self.assertEqual("degraded", observed["state"])
        self.assertEqual("ha_sync_status_unavailable", observed["reason"])
        self.assertEqual("leader", observed["effective_role"])
        self.assertEqual("node-a", observed["writer_node_id"])
        self.assertEqual(3, observed["generation"])
        self.assertEqual("ha_sync_status_unavailable", observed["sync"]["reason"])
        self.assertEqual("RuntimeError", observed["detail"])
        self.assertFalse(observed["automatic_failover"])
        self.assertEqual(before, load_membership(self.store._connection))

    def test_malformed_sync_status_degrades_cluster_without_losing_writer_epoch(self) -> None:
        current = membership(generation=4, writer="node-a")
        initialize_membership(self.store._connection, current)
        before = load_membership(self.store._connection)
        current_runtime = runtime(self.store, node_id="node-a", role="leader")
        current_runtime.ha_state_reconciler = SimpleNamespace(status=lambda: ["invalid"])

        observed = status(current_runtime)

        self.assertEqual("degraded", observed["state"])
        self.assertEqual("ha_sync_status_invalid", observed["reason"])
        self.assertEqual("leader", observed["effective_role"])
        self.assertEqual("node-a", observed["writer_node_id"])
        self.assertEqual(4, observed["generation"])
        self.assertEqual("ha_sync_status_invalid", observed["sync"]["reason"])
        self.assertEqual("list", observed["detail"])
        self.assertFalse(observed["automatic_failover"])
        self.assertEqual(before, load_membership(self.store._connection))

    def test_sync_epoch_mismatch_degrades_cluster_without_losing_durable_writer_epoch(self) -> None:
        current = membership(generation=5, writer="node-a")
        initialize_membership(self.store._connection, current)
        before = load_membership(self.store._connection)
        base_sync = {
            "schema": "home-center.ha-sync-status.v1",
            "state": "writer",
            "reason": "writer_peer_in_sync",
            "direction": None,
            "writer_node_id": "node-a",
            "generation": 5,
            "authoritative_sha256": "b" * 64,
            "source_instance_id": None,
            "source_sequence": None,
            "last_success_at": None,
            "changed": False,
        }

        cases = (
            {**base_sync, "writer_node_id": "node-b"},
            {**base_sync, "generation": 6},
            {**base_sync, "generation": True},
        )
        for sync in cases:
            with self.subTest(sync_writer=sync["writer_node_id"], sync_generation=sync["generation"]):
                observed = status(runtime(self.store, node_id="node-a", role="leader", sync=sync))

                self.assertEqual("degraded", observed["state"])
                self.assertEqual("ha_sync_epoch_mismatch", observed["reason"])
                self.assertEqual("leader", observed["effective_role"])
                self.assertEqual("node-a", observed["writer_node_id"])
                self.assertEqual(5, observed["generation"])
                self.assertEqual("ha_sync_epoch_mismatch", observed["sync"]["reason"])
                self.assertEqual("node-a", observed["sync"]["writer_node_id"])
                self.assertEqual(5, observed["sync"]["generation"])
                self.assertEqual("reconciler_epoch_mismatch", observed["detail"])
                self.assertFalse(observed["automatic_failover"])
                self.assertEqual(before, load_membership(self.store._connection))

    def test_durable_writer_epoch_overrides_static_standby_role_truthfully(self) -> None:
        initialize_membership(self.store._connection, membership(generation=2, writer="node-b"))
        observed = status(runtime(self.store, node_id="node-b", role="standby"))

        self.assertEqual("writer", observed["state"])
        self.assertEqual("leader", observed["effective_role"])
        self.assertEqual("node-b", observed["writer_node_id"])
        self.assertEqual(2, observed["generation"])
        self.assertEqual("local_node_is_writer", observed["reason"])
        self.assertFalse(observed["automatic_failover"])

    def test_invalid_durable_ha_state_fails_closed_in_observability_projection(self) -> None:
        self.store.set_meta("ha.cluster-membership.v1", {"schema": "unexpected"})
        observed = status(runtime(self.store, node_id="node-a", role="leader"))

        self.assertEqual("degraded", observed["state"])
        self.assertEqual("ha_state_invalid", observed["reason"])
        self.assertEqual("unknown", observed["effective_role"])
        self.assertIsNone(observed["writer_node_id"])
        self.assertIsNone(observed["generation"])
        self.assertFalse(observed["automatic_failover"])
        self.assertIsNone(observed["membership"])
        self.assertIsNone(observed["transition"])
        self.assertEqual("HAStateConflict", observed["detail"])


if __name__ == "__main__":
    unittest.main()
