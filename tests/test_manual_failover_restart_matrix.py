from __future__ import annotations

import unittest

from home_center.manual_failover import (
    ManualFailoverRejected,
    NodeEvidence,
    begin_manual_failover,
    complete_manual_failover,
    promote_membership,
    record_final_sync_verified,
    record_source_fenced,
    record_source_quiesced,
    record_target_verified,
)
from home_center.manual_failover_recovery import restore_manual_failover_transition
from home_center.manual_failover_resume import decide_manual_failover_resume

REVISION = "a" * 40
INITIAL_DIGEST = "b" * 64
FINAL_DIGEST = "c" * 64


def membership(*, writer: str = "node-a", generation: int = 7) -> dict:
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
        "observed_at": "2026-09-15T00:00:00Z",
    }


def evidence(
    node_id: str,
    *,
    service_active: bool,
    fenced: bool,
    digest: str,
    sequence: int,
) -> NodeEvidence:
    return NodeEvidence(
        node_id=node_id,
        version="0.64.0",
        revision=REVISION,
        ready=True,
        service_active=service_active,
        fenced=fenced,
        authoritative_sha256=digest,
        source_sequence=sequence,
    )


class ManualFailoverRestartMatrixTests(unittest.TestCase):
    def assert_restart_action(
        self,
        transition,
        current_membership: dict,
        *,
        action: str,
        writer: str,
        generation: int,
        terminal: bool = False,
    ):
        restored = restore_manual_failover_transition(transition.as_dict())
        decision = decide_manual_failover_resume(
            restored.as_dict(),
            current_membership,
        )
        self.assertEqual(transition.transition_id, restored.transition_id)
        self.assertEqual(transition.phase, restored.phase)
        self.assertEqual(transition.final_source_sequence, restored.final_source_sequence)
        self.assertEqual(action, decision.action)
        self.assertEqual(writer, decision.expected_writer)
        self.assertEqual(generation, decision.expected_generation)
        self.assertEqual(terminal, decision.terminal)
        return restored

    def test_restart_after_every_phase_preserves_single_safe_continuation(self) -> None:
        current_membership = membership()
        source = evidence(
            "node-a",
            service_active=True,
            fenced=False,
            digest=INITIAL_DIGEST,
            sequence=10,
        )
        target = evidence(
            "node-b",
            service_active=True,
            fenced=True,
            digest=INITIAL_DIGEST,
            sequence=10,
        )

        transition = begin_manual_failover(
            current_membership,
            target_node_id="node-b",
            source=source,
            target=target,
            transition_id="restart-matrix",
        )
        transition = self.assert_restart_action(
            transition,
            current_membership,
            action="quiesce_source",
            writer="node-a",
            generation=7,
        )

        quiesced_source = evidence(
            "node-a",
            service_active=False,
            fenced=False,
            digest=FINAL_DIGEST,
            sequence=11,
        )
        transition = record_source_quiesced(transition, quiesced_source)
        transition = self.assert_restart_action(
            transition,
            current_membership,
            action="verify_final_sync",
            writer="node-a",
            generation=7,
        )

        synced_target = evidence(
            "node-b",
            service_active=True,
            fenced=True,
            digest=FINAL_DIGEST,
            sequence=11,
        )
        transition = record_final_sync_verified(
            transition,
            source=quiesced_source,
            target=synced_target,
        )
        transition = self.assert_restart_action(
            transition,
            current_membership,
            action="fence_source",
            writer="node-a",
            generation=7,
        )

        fenced_source = evidence(
            "node-a",
            service_active=False,
            fenced=True,
            digest=FINAL_DIGEST,
            sequence=11,
        )
        transition = record_source_fenced(transition, fenced_source)
        transition = self.assert_restart_action(
            transition,
            current_membership,
            action="commit_promotion",
            writer="node-a",
            generation=7,
        )

        transition, current_membership = promote_membership(
            transition,
            current_membership,
        )
        transition = self.assert_restart_action(
            transition,
            current_membership,
            action="verify_target",
            writer="node-b",
            generation=8,
        )

        serving_target = evidence(
            "node-b",
            service_active=True,
            fenced=False,
            digest=FINAL_DIGEST,
            sequence=11,
        )
        transition = record_target_verified(
            transition,
            source=fenced_source,
            target=serving_target,
            write_readback_verified=True,
            source_write_rejected=True,
        )
        transition = self.assert_restart_action(
            transition,
            current_membership,
            action="complete_transition",
            writer="node-b",
            generation=8,
        )

        transition = complete_manual_failover(transition)
        self.assert_restart_action(
            transition,
            current_membership,
            action="terminal_completed",
            writer="node-b",
            generation=8,
            terminal=True,
        )

    def test_restart_matrix_rejects_writer_epoch_from_the_other_side_of_promotion(self) -> None:
        current_membership = membership()
        source = evidence(
            "node-a",
            service_active=True,
            fenced=False,
            digest=INITIAL_DIGEST,
            sequence=10,
        )
        target = evidence(
            "node-b",
            service_active=True,
            fenced=True,
            digest=INITIAL_DIGEST,
            sequence=10,
        )
        transition = begin_manual_failover(
            current_membership,
            target_node_id="node-b",
            source=source,
            target=target,
            transition_id="restart-epoch-matrix",
        )

        pre_promotion = [
            transition,
            record_source_quiesced(
                transition,
                evidence(
                    "node-a",
                    service_active=False,
                    fenced=False,
                    digest=FINAL_DIGEST,
                    sequence=11,
                ),
            ),
        ]
        pre_promotion.append(
            record_final_sync_verified(
                pre_promotion[-1],
                source=evidence(
                    "node-a",
                    service_active=False,
                    fenced=False,
                    digest=FINAL_DIGEST,
                    sequence=11,
                ),
                target=evidence(
                    "node-b",
                    service_active=True,
                    fenced=True,
                    digest=FINAL_DIGEST,
                    sequence=11,
                ),
            )
        )
        pre_promotion.append(
            record_source_fenced(
                pre_promotion[-1],
                evidence(
                    "node-a",
                    service_active=False,
                    fenced=True,
                    digest=FINAL_DIGEST,
                    sequence=11,
                ),
            )
        )

        for phase_transition in pre_promotion:
            with self.subTest(phase=phase_transition.phase):
                with self.assertRaisesRegex(
                    ManualFailoverRejected,
                    "resume_membership_phase_mismatch",
                ):
                    decide_manual_failover_resume(
                        phase_transition.as_dict(),
                        membership(writer="node-b", generation=8),
                    )

        promoted_transition, promoted_membership = promote_membership(
            pre_promotion[-1],
            current_membership,
        )
        verified_transition = record_target_verified(
            promoted_transition,
            source=evidence(
                "node-a",
                service_active=False,
                fenced=True,
                digest=FINAL_DIGEST,
                sequence=11,
            ),
            target=evidence(
                "node-b",
                service_active=True,
                fenced=False,
                digest=FINAL_DIGEST,
                sequence=11,
            ),
            write_readback_verified=True,
            source_write_rejected=True,
        )
        completed_transition = complete_manual_failover(verified_transition)

        self.assertEqual("node-b", promoted_membership["writer"])
        self.assertEqual(8, promoted_membership["generation"])

        for phase_transition in (
            promoted_transition,
            verified_transition,
            completed_transition,
        ):
            with self.subTest(phase=phase_transition.phase):
                with self.assertRaisesRegex(
                    ManualFailoverRejected,
                    "resume_membership_phase_mismatch",
                ):
                    decide_manual_failover_resume(
                        phase_transition.as_dict(),
                        membership(writer="node-a", generation=7),
                    )


if __name__ == "__main__":
    unittest.main()
