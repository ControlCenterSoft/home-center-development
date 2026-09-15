from __future__ import annotations

import unittest

from home_center.manual_failover import ManualFailoverRejected
from home_center.manual_failover_resume import decide_manual_failover_resume


REVISION = "a" * 40
DIGEST = "b" * 64


def membership(*, writer: str = "node-a", generation: int = 7, second: str = "node-b") -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-test",
        "generation": generation,
        "writer": writer,
        "members": [
            {"node_id": "node-a", "state": "ready", "roles": ["control-plane"]},
            {"node_id": second, "state": "ready", "roles": ["control-plane"]},
        ],
        "quorum": {
            "mode": "single-writer-manual-failover",
            "automatic_failover": False,
            "witness_id": None,
        },
        "observed_at": "2026-09-15T00:00:00Z",
    }


def transition(phase: str) -> dict:
    final_sequence = None if phase in {"planned", "source_quiesced", "failed"} else 11
    return {
        "schema": "home-center.manual-failover-transition.v1",
        "transition_id": "transition-test",
        "cluster_id": "cluster-test",
        "source_writer": "node-a",
        "target_writer": "node-b",
        "from_generation": 7,
        "to_generation": 8,
        "phase": phase,
        "version": "0.64.0",
        "revision": REVISION,
        "authoritative_sha256": DIGEST,
        "final_source_sequence": final_sequence,
        "started_at": "2026-09-15T00:00:00+00:00",
        "updated_at": "2026-09-15T00:01:00+00:00",
        "failure_reason": "operator_abort" if phase == "failed" else None,
    }


class ManualFailoverResumeTests(unittest.TestCase):
    def test_every_nonterminal_phase_maps_to_one_restart_safe_action(self) -> None:
        cases = (
            ("planned", "quiesce_source", "node-a", 7),
            ("source_quiesced", "verify_final_sync", "node-a", 7),
            ("final_sync_verified", "fence_source", "node-a", 7),
            ("source_fenced", "commit_promotion", "node-a", 7),
            ("target_promoted", "verify_target", "node-b", 8),
            ("target_verified", "complete_transition", "node-b", 8),
        )
        for phase, action, writer, generation in cases:
            with self.subTest(phase=phase):
                decision = decide_manual_failover_resume(
                    transition(phase),
                    membership(writer=writer, generation=generation),
                )
                self.assertEqual(action, decision.action)
                self.assertEqual(writer, decision.expected_writer)
                self.assertEqual(generation, decision.expected_generation)
                self.assertFalse(decision.terminal)

    def test_completed_transition_is_terminal_only_on_promoted_writer_epoch(self) -> None:
        decision = decide_manual_failover_resume(
            transition("completed"),
            membership(writer="node-b", generation=8),
        )
        self.assertEqual("terminal_completed", decision.action)
        self.assertTrue(decision.terminal)

        with self.assertRaisesRegex(ManualFailoverRejected, "resume_membership_phase_mismatch"):
            decide_manual_failover_resume(
                transition("completed"),
                membership(writer="node-a", generation=7),
            )

    def test_restart_rejects_membership_that_disagrees_with_transition_phase(self) -> None:
        with self.assertRaisesRegex(ManualFailoverRejected, "resume_membership_phase_mismatch"):
            decide_manual_failover_resume(
                transition("source_fenced"),
                membership(writer="node-b", generation=8),
            )

        with self.assertRaisesRegex(ManualFailoverRejected, "resume_membership_phase_mismatch"):
            decide_manual_failover_resume(
                transition("target_promoted"),
                membership(writer="node-a", generation=7),
            )

        with self.assertRaisesRegex(ManualFailoverRejected, "resume_membership_phase_mismatch"):
            decide_manual_failover_resume(
                transition("target_promoted"),
                membership(writer="node-b", generation=9),
            )

    def test_restart_rejects_transition_member_identity_drift(self) -> None:
        with self.assertRaisesRegex(ManualFailoverRejected, "resume_membership_identity_mismatch"):
            decide_manual_failover_resume(
                transition("planned"),
                membership(second="node-c"),
            )

    def test_failed_transition_is_terminal_only_on_known_transition_epochs(self) -> None:
        before_promotion = decide_manual_failover_resume(
            transition("failed"),
            membership(writer="node-a", generation=7),
        )
        after_promotion = decide_manual_failover_resume(
            transition("failed"),
            membership(writer="node-b", generation=8),
        )
        self.assertEqual("terminal_failed", before_promotion.action)
        self.assertEqual("terminal_failed", after_promotion.action)
        self.assertTrue(before_promotion.terminal)
        self.assertTrue(after_promotion.terminal)

        drift_cases = (
            ("node-a", 8),
            ("node-b", 7),
            ("node-a", 9),
            ("node-b", 9),
        )
        for writer, generation in drift_cases:
            with self.subTest(writer=writer, generation=generation):
                with self.assertRaisesRegex(
                    ManualFailoverRejected,
                    "resume_failed_membership_epoch_mismatch",
                ):
                    decide_manual_failover_resume(
                        transition("failed"),
                        membership(writer=writer, generation=generation),
                    )


if __name__ == "__main__":
    unittest.main()
