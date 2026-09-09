from __future__ import annotations

import unittest

from home_center.ha_rolling_safety import (
    HASafetyError,
    NodeObservation,
    NodeRole,
    NodeState,
    RollingSafetyRequest,
    evaluate_rolling_safety,
    observations,
)


def node(
    node_id: str,
    role: NodeRole,
    state: NodeState = NodeState.READY,
    revision: str = "0.22.3",
) -> NodeObservation:
    return NodeObservation(node_id=node_id, role=role, state=state, revision=revision)


class HARollingSafetyTests(unittest.TestCase):
    def test_two_node_standby_can_enter_maintenance(self) -> None:
        request = RollingSafetyRequest(
            cluster_id="home-cluster",
            target_node_id="node-b",
            observations=observations(node("node-a", NodeRole.WRITER), node("node-b", NodeRole.STANDBY)),
            minimum_ready_nodes=1,
            expected_transition_seq=7,
            observed_transition_seq=7,
        )
        decision = evaluate_rolling_safety(request)
        self.assertTrue(decision.safe)
        self.assertEqual(1, decision.ready_after_target_stops)
        self.assertEqual("node-a", decision.writer_node_id)
        self.assertFalse(decision.production_mutation_enabled)
        self.assertTrue(decision.rollback_required_on_failure)

    def test_writer_must_be_handed_off_before_rolling_second_node(self) -> None:
        request = RollingSafetyRequest(
            cluster_id="home-cluster",
            target_node_id="node-a",
            observations=observations(node("node-a", NodeRole.WRITER), node("node-b", NodeRole.STANDBY)),
            minimum_ready_nodes=1,
            expected_transition_seq=8,
            observed_transition_seq=8,
        )
        decision = evaluate_rolling_safety(request)
        self.assertFalse(decision.safe)
        self.assertIn("writer_handoff_required", decision.blockers)

    def test_second_node_is_safe_after_explicit_writer_handoff(self) -> None:
        request = RollingSafetyRequest(
            cluster_id="home-cluster",
            target_node_id="node-a",
            observations=observations(
                node("node-a", NodeRole.STANDBY),
                node("node-b", NodeRole.WRITER, revision="0.23.0"),
            ),
            minimum_ready_nodes=1,
            expected_transition_seq=9,
            observed_transition_seq=9,
            required_predecessor_node_id="node-b",
            required_predecessor_revision="0.23.0",
        )
        self.assertTrue(evaluate_rolling_safety(request).safe)

    def test_predecessor_must_be_ready_and_at_required_revision(self) -> None:
        request = RollingSafetyRequest(
            cluster_id="home-cluster",
            target_node_id="node-a",
            observations=observations(
                node("node-a", NodeRole.STANDBY),
                node("node-b", NodeRole.WRITER, NodeState.DEGRADED, revision="0.22.3"),
            ),
            minimum_ready_nodes=1,
            expected_transition_seq=10,
            observed_transition_seq=10,
            required_predecessor_node_id="node-b",
            required_predecessor_revision="0.23.0",
        )
        decision = evaluate_rolling_safety(request)
        self.assertFalse(decision.safe)
        self.assertIn("predecessor_not_ready", decision.blockers)
        self.assertIn("predecessor_revision_mismatch", decision.blockers)
        self.assertIn("writer_not_unique", decision.blockers)
        self.assertIn("minimum_ready_nodes_not_met", decision.blockers)

    def test_split_brain_fails_closed(self) -> None:
        request = RollingSafetyRequest(
            cluster_id="home-cluster",
            target_node_id="node-c",
            observations=observations(
                node("node-a", NodeRole.WRITER),
                node("node-b", NodeRole.WRITER),
                node("node-c", NodeRole.STANDBY),
            ),
            minimum_ready_nodes=2,
            expected_transition_seq=11,
            observed_transition_seq=11,
        )
        decision = evaluate_rolling_safety(request)
        self.assertFalse(decision.safe)
        self.assertIn("split_brain_detected", decision.blockers)
        self.assertIn("writer_not_unique", decision.blockers)

    def test_stale_transition_journal_fails_closed(self) -> None:
        request = RollingSafetyRequest(
            cluster_id="home-cluster",
            target_node_id="node-b",
            observations=observations(node("node-a", NodeRole.WRITER), node("node-b", NodeRole.STANDBY)),
            minimum_ready_nodes=1,
            expected_transition_seq=12,
            observed_transition_seq=11,
        )
        decision = evaluate_rolling_safety(request)
        self.assertFalse(decision.safe)
        self.assertIn("transition_journal_stale", decision.blockers)

    def test_single_node_requires_explicit_downtime_acknowledgement(self) -> None:
        base = dict(
            cluster_id="home-cluster",
            target_node_id="node-a",
            observations=observations(node("node-a", NodeRole.WRITER)),
            minimum_ready_nodes=0,
            expected_transition_seq=1,
            observed_transition_seq=1,
        )
        self.assertFalse(evaluate_rolling_safety(RollingSafetyRequest(**base)).safe)
        acknowledged = RollingSafetyRequest(**base, single_node_downtime_acknowledged=True)
        self.assertTrue(evaluate_rolling_safety(acknowledged).safe)
        self.assertEqual(0, evaluate_rolling_safety(acknowledged).ready_after_target_stops)

    def test_ha_requires_positive_minimum_ready_nodes(self) -> None:
        with self.assertRaisesRegex(HASafetyError, "ha_minimum_ready_must_be_positive"):
            RollingSafetyRequest(
                cluster_id="home-cluster",
                target_node_id="node-b",
                observations=observations(node("node-a", NodeRole.WRITER), node("node-b", NodeRole.STANDBY)),
                minimum_ready_nodes=0,
                expected_transition_seq=1,
                observed_transition_seq=1,
            )

    def test_plan_id_is_deterministic_across_observation_order(self) -> None:
        first = RollingSafetyRequest(
            cluster_id="home-cluster",
            target_node_id="node-b",
            observations=observations(node("node-a", NodeRole.WRITER), node("node-b", NodeRole.STANDBY)),
            minimum_ready_nodes=1,
            expected_transition_seq=3,
            observed_transition_seq=3,
        )
        second = RollingSafetyRequest(
            cluster_id="home-cluster",
            target_node_id="node-b",
            observations=observations(node("node-b", NodeRole.STANDBY), node("node-a", NodeRole.WRITER)),
            minimum_ready_nodes=1,
            expected_transition_seq=3,
            observed_transition_seq=3,
        )
        self.assertEqual(evaluate_rolling_safety(first).plan_id, evaluate_rolling_safety(second).plan_id)


if __name__ == "__main__":
    unittest.main()
