from __future__ import annotations

import unittest

from home_center.cluster_health import ClusterMember, aggregate_cluster_health
from home_center.node_health import HealthSignal, HealthState, aggregate_node_health


def _node_health(state: HealthState):
    return aggregate_node_health([HealthSignal("service", state)])


class ClusterHealthTests(unittest.TestCase):
    def test_empty_membership_is_unknown(self) -> None:
        health = aggregate_cluster_health([])
        self.assertEqual(HealthState.UNKNOWN, health.state)
        self.assertFalse(health.ready)
        self.assertEqual(("no-members",), health.reasons)

    def test_matching_healthy_members_are_healthy(self) -> None:
        health = aggregate_cluster_health(
            [
                ClusterMember("node-b", _node_health(HealthState.HEALTHY), "0.64.0", "abc123"),
                ClusterMember("node-a", _node_health(HealthState.HEALTHY), "0.64.0", "abc123"),
            ]
        )
        self.assertEqual(HealthState.HEALTHY, health.state)
        self.assertTrue(health.ready)
        self.assertTrue(health.release_consistent)
        self.assertEqual(["node-a", "node-b"], [member.node_id for member in health.members])

    def test_version_drift_degrades_cluster_not_nodes(self) -> None:
        first = ClusterMember("node-a", _node_health(HealthState.HEALTHY), "0.64.0", "abc123")
        second = ClusterMember("node-b", _node_health(HealthState.HEALTHY), "0.63.0", "abc123")

        health = aggregate_cluster_health([first, second])

        self.assertEqual(HealthState.DEGRADED, health.state)
        self.assertTrue(health.ready)
        self.assertFalse(health.release_consistent)
        self.assertIn("release-version-mismatch", health.reasons)
        self.assertEqual(HealthState.HEALTHY, first.health.state)
        self.assertEqual(HealthState.HEALTHY, second.health.state)

    def test_revision_drift_degrades_cluster(self) -> None:
        health = aggregate_cluster_health(
            [
                ClusterMember("node-a", _node_health(HealthState.HEALTHY), "0.64.0", "abc123"),
                ClusterMember("node-b", _node_health(HealthState.HEALTHY), "0.64.0", "def456"),
            ]
        )
        self.assertEqual(HealthState.DEGRADED, health.state)
        self.assertIn("release-revision-mismatch", health.reasons)

    def test_loss_of_one_member_degrades_still_ready_cluster(self) -> None:
        health = aggregate_cluster_health(
            [
                ClusterMember("node-a", _node_health(HealthState.HEALTHY), "0.64.0", "abc123"),
                ClusterMember("node-b", _node_health(HealthState.UNHEALTHY), "0.64.0", "abc123"),
            ]
        )
        self.assertEqual(HealthState.DEGRADED, health.state)
        self.assertTrue(health.ready)
        self.assertIn("member-unhealthy:node-b", health.reasons)

    def test_no_ready_member_is_unhealthy_when_failure_is_known(self) -> None:
        health = aggregate_cluster_health(
            [
                ClusterMember("node-a", _node_health(HealthState.UNHEALTHY), "0.64.0", "abc123"),
                ClusterMember("node-b", _node_health(HealthState.UNHEALTHY), "0.64.0", "abc123"),
            ]
        )
        self.assertEqual(HealthState.UNHEALTHY, health.state)
        self.assertFalse(health.ready)

    def test_single_node_does_not_require_peer_release_identity(self) -> None:
        health = aggregate_cluster_health(
            [ClusterMember("node-a", _node_health(HealthState.HEALTHY))]
        )
        self.assertEqual(HealthState.HEALTHY, health.state)
        self.assertTrue(health.release_consistent)

    def test_missing_identity_degrades_multi_node_cluster(self) -> None:
        health = aggregate_cluster_health(
            [
                ClusterMember("node-a", _node_health(HealthState.HEALTHY), "0.64.0", "abc123"),
                ClusterMember("node-b", _node_health(HealthState.HEALTHY), None, None),
            ]
        )
        self.assertEqual(HealthState.DEGRADED, health.state)
        self.assertIn("release-version-unknown:node-b", health.reasons)
        self.assertIn("release-revision-unknown:node-b", health.reasons)

    def test_duplicate_member_ids_are_rejected(self) -> None:
        member = ClusterMember("node-a", _node_health(HealthState.HEALTHY))
        with self.assertRaises(ValueError):
            aggregate_cluster_health([member, member])


if __name__ == "__main__":
    unittest.main()
