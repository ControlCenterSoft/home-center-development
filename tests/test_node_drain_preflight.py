from __future__ import annotations

import unittest

from home_center.node_drain_preflight import DrainState, evaluate_drain


class DrainPreflightTests(unittest.TestCase):
    def test_allows_safe_drain(self) -> None:
        decision = evaluate_drain(
            DrainState(
                node_id="node-a",
                healthy_voters=3,
                required_voters=2,
                hosts_critical_service=True,
                critical_service_movable=True,
                failover_target_ready=True,
            )
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.blockers, ())

    def test_blocks_quorum_loss(self) -> None:
        decision = evaluate_drain(DrainState(node_id="node-a", healthy_voters=2, required_voters=2))
        self.assertFalse(decision.allowed)
        self.assertIn("quorum", decision.blockers)

    def test_blocks_stranded_critical_service(self) -> None:
        decision = evaluate_drain(
            DrainState(
                node_id="node-a",
                healthy_voters=3,
                required_voters=2,
                hosts_critical_service=True,
                critical_service_movable=False,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("critical-service-immovable", decision.blockers)

    def test_blocks_unready_failover_target(self) -> None:
        decision = evaluate_drain(
            DrainState(
                node_id="node-a",
                healthy_voters=3,
                required_voters=2,
                hosts_critical_service=True,
                critical_service_movable=True,
                failover_target_ready=False,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("failover-target-not-ready", decision.blockers)


if __name__ == "__main__":
    unittest.main()
