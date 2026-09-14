from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from home_center.ha_peer import (
    HAPeerExportClock,
    HAPeerProtocolError,
    build_authoritative_export,
    build_ha_status,
)
from home_center.ha_state import initialize_membership
from home_center.store import StateStore


REVISION = "a" * 40


def release_identity() -> dict:
    return {
        "schema": "home-center.release-identity.v1",
        "version": "0.64.0",
        "revision": REVISION,
        "build": REVISION[:12],
        "source": "immutable-artifact",
    }


def membership(writer: str) -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-test",
        "generation": 1,
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
        "observed_at": "2026-09-14T12:00:00Z",
    }


class HAPeerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = StateStore(root / "state.db", b"a" * 32, "cluster-test")
        self.runtime = SimpleNamespace(
            config=SimpleNamespace(
                cluster_id="cluster-test",
                node_id="node-a",
                role="leader",
            ),
            store=self.store,
            ha_export_clock=HAPeerExportClock("11111111-1111-4111-8111-111111111111"),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    @patch("home_center.ha_peer.current_release_identity", side_effect=release_identity)
    def test_status_is_non_mutating_and_reports_durable_writer_epoch(self, _release) -> None:
        initialize_membership(self.store._connection, membership("node-a"))
        before = self.runtime.ha_export_clock.current()

        value = build_ha_status(self.runtime)

        after = self.runtime.ha_export_clock.current()
        self.assertEqual(before, after)
        self.assertEqual("home-center.ha-peer-status.v1", value["schema"])
        self.assertEqual("node-a", value["membership"]["writer"])
        self.assertEqual(1, value["membership"]["generation"])
        self.assertTrue(value["writer_admission"]["allowed"])
        self.assertEqual(0, value["source_sequence"])
        self.assertEqual(64, len(value["authoritative_sha256"]))

    @patch("home_center.ha_peer.current_release_identity", side_effect=release_identity)
    def test_writer_export_is_monotonic_and_self_consistent(self, _release) -> None:
        initialize_membership(self.store._connection, membership("node-a"))
        self.store.set_meta("writer.created.state", {"generation": 1})

        first = build_authoritative_export(self.runtime)
        second = build_authoritative_export(self.runtime)

        self.assertEqual(1, first["source_sequence"])
        self.assertEqual(2, second["source_sequence"])
        self.assertEqual(first["source_instance_id"], second["source_instance_id"])
        self.assertEqual(first["authoritative_sha256"], first["snapshot"]["authoritative_sha256"])
        self.assertEqual("node-a", first["membership"]["writer"])

    @patch("home_center.ha_peer.current_release_identity", side_effect=release_identity)
    def test_non_writer_cannot_export_authoritative_state(self, _release) -> None:
        initialize_membership(self.store._connection, membership("node-b"))

        with self.assertRaisesRegex(HAPeerProtocolError, "durable_writer"):
            build_authoritative_export(self.runtime)

    def test_source_tree_release_is_not_qualified_for_ha_export(self) -> None:
        with patch(
            "home_center.ha_peer.current_release_identity",
            return_value={
                "schema": "home-center.release-identity.v1",
                "version": "0.64.0",
                "revision": None,
                "build": "source",
                "source": "source-tree",
            },
        ):
            with self.assertRaisesRegex(HAPeerProtocolError, "immutable"):
                build_ha_status(self.runtime)


if __name__ == "__main__":
    unittest.main()
