from __future__ import annotations

import unittest

from home_center.node_maintenance import plan_node_maintenance


class NodeMaintenanceTests(unittest.TestCase):
    def test_allows_drain_when_peer_exists_and_services_are_movable(self) -> None:
        decision = plan_node_maintenance(
            "node-a",
            healthy_peers=1,
            required_services=("dns", "files"),
            movable_services=("files", "dns"),
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.blockers, ())

    def test_reports_deterministic_blockers(self) -> None:
        decision = plan_node_maintenance(
            "node-a",
            healthy_peers=0,
            required_services=("files", "dns"),
            movable_services=("dns",),
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.blockers,
            ("no-healthy-peer", "service-not-movable:files"),
        )


if __name__ == "__main__":
    unittest.main()
