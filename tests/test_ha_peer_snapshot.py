from __future__ import annotations

import unittest
from types import SimpleNamespace

from home_center.config import Peer
from home_center.ha_peer_snapshot import (
    HAPeerSnapshotError,
    PeerHealthState,
    build_peer_state_snapshot,
)
from home_center.reconcile import Reconciler


def row(
    node_id: str,
    *,
    role: str = "control-plane",
    status: str = "ready",
    observed_at: str = "2026-09-10T00:00:00Z",
    service_state: str = "active",
) -> dict[str, object]:
    return {
        "node_id": node_id,
        "name": node_id,
        "role": role,
        "address": "192.0.2.10" if node_id == "node-a" else "192.0.2.11",
        "status": status,
        "capabilities": {
            "schema": "home-center.node-capability.v1",
            "observed_at": observed_at,
            "node": {"id": node_id, "role": role},
            "services": {"home-center.service": service_state},
        },
        "last_seen": observed_at,
        "updated_at": observed_at,
    }


class HAPeerSnapshotTests(unittest.TestCase):
    def test_missing_configured_peer_is_unknown(self) -> None:
        snapshot = build_peer_state_snapshot(
            cluster_id="home-cluster",
            configured_node_ids=("node-a", "node-b"),
            node_rows=(row("node-a"),),
            audit_events=(),
        )
        self.assertEqual(("node-a", "node-b"), tuple(item.node_id for item in snapshot.members))
        self.assertEqual(PeerHealthState.UNKNOWN, snapshot.members[1].state)
        self.assertEqual(0, snapshot.journal_seq)

    def test_peer_transition_audit_seq_is_bound(self) -> None:
        snapshot = build_peer_state_snapshot(
            cluster_id="home-cluster",
            configured_node_ids=("node-a", "node-b"),
            node_rows=(row("node-a"), row("node-b", status="unreachable")),
            audit_events=(
                {"seq": 7, "action": "runtime.start"},
                {"seq": 11, "action": "peer.health.transition"},
                {"seq": 9, "action": "peer.health.transition"},
            ),
        )
        self.assertEqual(11, snapshot.journal_seq)

    def test_snapshot_is_deterministic_across_input_order(self) -> None:
        events = (
            {"seq": 3, "action": "peer.health.transition"},
            {"seq": 4, "action": "runtime.start"},
        )
        first = build_peer_state_snapshot(
            cluster_id="home-cluster",
            configured_node_ids=("node-a", "node-b"),
            node_rows=(row("node-a"), row("node-b")),
            audit_events=events,
        )
        second = build_peer_state_snapshot(
            cluster_id="home-cluster",
            configured_node_ids=("node-b", "node-a"),
            node_rows=(row("node-b"), row("node-a")),
            audit_events=tuple(reversed(events)),
        )
        self.assertEqual(first.snapshot_id, second.snapshot_id)

    def test_volatile_observation_timestamp_does_not_change_snapshot(self) -> None:
        first = build_peer_state_snapshot(
            cluster_id="home-cluster",
            configured_node_ids=("node-a",),
            node_rows=(row("node-a", observed_at="2026-09-10T00:00:00Z"),),
            audit_events=(),
        )
        second = build_peer_state_snapshot(
            cluster_id="home-cluster",
            configured_node_ids=("node-a",),
            node_rows=(row("node-a", observed_at="2026-09-10T00:01:00Z"),),
            audit_events=(),
        )
        self.assertEqual(first.snapshot_id, second.snapshot_id)

    def test_meaningful_state_change_changes_snapshot(self) -> None:
        first = build_peer_state_snapshot(
            cluster_id="home-cluster",
            configured_node_ids=("node-a",),
            node_rows=(row("node-a"),),
            audit_events=(),
        )
        second = build_peer_state_snapshot(
            cluster_id="home-cluster",
            configured_node_ids=("node-a",),
            node_rows=(row("node-a", service_state="failed"),),
            audit_events=(),
        )
        self.assertNotEqual(first.snapshot_id, second.snapshot_id)

    def test_stale_snapshot_and_journal_fail_closed(self) -> None:
        snapshot = build_peer_state_snapshot(
            cluster_id="home-cluster",
            configured_node_ids=("node-a",),
            node_rows=(row("node-a"),),
            audit_events=({"seq": 5, "action": "peer.health.transition"},),
        )
        with self.assertRaisesRegex(HAPeerSnapshotError, "ha_snapshot_stale"):
            snapshot.require_exact(expected_snapshot_id="ha-state-wrong", expected_journal_seq=5)
        with self.assertRaisesRegex(HAPeerSnapshotError, "ha_transition_journal_stale"):
            snapshot.require_exact(
                expected_snapshot_id=snapshot.snapshot_id,
                expected_journal_seq=4,
            )

    def test_unexpected_stored_node_fails_closed(self) -> None:
        with self.assertRaisesRegex(HAPeerSnapshotError, "unexpected_observed_node"):
            build_peer_state_snapshot(
                cluster_id="home-cluster",
                configured_node_ids=("node-a",),
                node_rows=(row("node-a"), row("node-b")),
                audit_events=(),
            )

    def test_invalid_state_fails_closed(self) -> None:
        with self.assertRaisesRegex(HAPeerSnapshotError, "invalid_observed_state"):
            build_peer_state_snapshot(
                cluster_id="home-cluster",
                configured_node_ids=("node-a",),
                node_rows=(row("node-a", status="draining"),),
                audit_events=(),
            )

    def test_invalid_transition_seq_fails_closed(self) -> None:
        with self.assertRaisesRegex(HAPeerSnapshotError, "invalid_peer_transition_seq"):
            build_peer_state_snapshot(
                cluster_id="home-cluster",
                configured_node_ids=("node-a",),
                node_rows=(row("node-a"),),
                audit_events=({"seq": 0, "action": "peer.health.transition"},),
            )

    def test_reconciler_snapshot_uses_configured_members_and_store_journal(self) -> None:
        class Store:
            def nodes(self):
                return [row("node-a")]

            def audit_events(self, limit=100):
                self.limit = limit
                return [{"seq": 12, "action": "peer.health.transition"}]

        reconciler = Reconciler.__new__(Reconciler)
        reconciler.config = SimpleNamespace(
            cluster_id="home-cluster",
            node_id="node-a",
            peers=(Peer("node-b", "node-b", "192.0.2.11", "https://192.0.2.11:9443", "node-b"),),
        )
        reconciler.store = Store()
        snapshot = reconciler.ha_state_snapshot()
        self.assertEqual(12, snapshot.journal_seq)
        self.assertEqual(("node-a", "node-b"), tuple(item.node_id for item in snapshot.members))
        self.assertEqual(PeerHealthState.UNKNOWN, snapshot.members[1].state)
        self.assertEqual(500, reconciler.store.limit)


if __name__ == "__main__":
    unittest.main()
