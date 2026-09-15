from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from home_center.ha_state import initialize_membership, load_membership
from home_center.ha_status import status
from home_center.store import StateStore


def membership() -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-test",
        "generation": 5,
        "writer": "node-a",
        "members": [
            {"node_id": "node-a", "state": "ready", "roles": ["control-plane"]},
            {"node_id": "node-b", "state": "ready", "roles": ["control-plane"]},
        ],
        "quorum": {
            "mode": "single-writer-manual-failover",
            "automatic_failover": False,
            "witness_id": None,
        },
        "observed_at": "2026-09-15T09:00:00Z",
    }


def runtime(store: StateStore, sync: dict):
    return SimpleNamespace(
        store=store,
        config=SimpleNamespace(
            cluster_id="cluster-test",
            node_id="node-a",
            role="leader",
        ),
        ha_state_reconciler=SimpleNamespace(status=lambda: dict(sync)),
    )


def valid_sync() -> dict:
    return {
        "schema": "home-center.ha-sync-status.v1",
        "state": "writer",
        "reason": "writer_peer_in_sync",
        "direction": None,
        "writer_node_id": "node-a",
        "generation": 5,
        "authoritative_sha256": "b" * 64,
        "source_instance_id": "5a30170d-1d15-4f52-b0fe-d178c2de9225",
        "source_sequence": 7,
        "last_success_at": "2026-09-15T09:00:00Z",
        "changed": False,
    }


class HAStatusSyncEvidenceValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.db", b"a" * 32, "cluster-test")
        initialize_membership(self.store._connection, membership())
        self.before = load_membership(self.store._connection)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_valid_sync_evidence_is_preserved(self) -> None:
        observed = status(runtime(self.store, valid_sync()))

        self.assertEqual("writer", observed["state"])
        self.assertEqual("local_node_is_writer", observed["reason"])
        self.assertEqual(valid_sync(), observed["sync"])
        self.assertFalse(observed["automatic_failover"])
        self.assertEqual(self.before, load_membership(self.store._connection))

    def test_malformed_healthy_sync_evidence_fails_closed(self) -> None:
        cases = {
            "unexpected_field": {**valid_sync(), "unexpected": "value"},
            "unknown_state": {**valid_sync(), "state": "healthy"},
            "bad_digest": {**valid_sync(), "authoritative_sha256": "not-a-digest"},
            "bad_instance": {**valid_sync(), "source_instance_id": "not-a-uuid"},
            "boolean_sequence": {**valid_sync(), "source_sequence": True},
            "integer_changed": {**valid_sync(), "changed": 1},
            "bad_timestamp": {**valid_sync(), "last_success_at": 123},
            "bad_direction": {**valid_sync(), "direction": ["node-a", "node-b"]},
        }

        for name, candidate in cases.items():
            with self.subTest(name=name):
                observed = status(runtime(self.store, candidate))

                self.assertEqual("degraded", observed["state"])
                self.assertEqual("ha_sync_status_invalid", observed["reason"])
                self.assertEqual("ha_sync_status_invalid", observed["sync"]["reason"])
                self.assertEqual("node-a", observed["writer_node_id"])
                self.assertEqual(5, observed["generation"])
                self.assertFalse(observed["automatic_failover"])
                self.assertEqual(self.before, load_membership(self.store._connection))


if __name__ == "__main__":
    unittest.main()
