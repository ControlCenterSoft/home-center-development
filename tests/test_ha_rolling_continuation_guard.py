from __future__ import annotations

import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import home_center.ha_rolling_continuation_guard as guard
from home_center.ha_rolling_continuation_guard import (
    HARollingContinuationGuardError,
    HARollingContinuationJournal,
)


def checkpoint(checkpoint_id: str = "retry-checkpoint-a"):
    return SimpleNamespace(
        cluster_id="home-cluster",
        checkpoint_id=checkpoint_id,
        retry_plan_id="retry-plan-c",
        retry_node_id="node-c",
        completed_revision="state-node-c-v2",
        rolling_checkpoint=SimpleNamespace(checkpoint_id="rolling-checkpoint-c"),
    )


def decision(
    *,
    plan_id: str = "next-plan-d",
    target_node_id: str = "node-d",
    peer_snapshot_id: str = "peer-11",
    peer_journal_seq: int = 11,
    safe: bool = True,
    blockers: tuple[str, ...] = (),
):
    return SimpleNamespace(
        cluster_id="home-cluster",
        plan_id=plan_id,
        target_node_id=target_node_id,
        peer_snapshot_id=peer_snapshot_id,
        peer_journal_seq=peer_journal_seq,
        role_assignment_id="role-assignment-1",
        role_epoch=0,
        role_resource_version=1,
        role_journal_seq=1,
        role_transition_id="role-transition-1",
        minimum_ready_nodes=2,
        required_predecessor_node_id="node-c",
        required_predecessor_revision="state-node-c-v2",
        ready_before=4,
        ready_after_target_stops=3,
        writer_node_id="node-a",
        safe=safe,
        blockers=blockers,
        production_mutation_enabled=False,
    )


class RollingContinuationJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.journal = HARollingContinuationJournal(self.db)
        self.checkpoint = checkpoint()
        self.decision = decision()

    def tearDown(self) -> None:
        self.db.close()

    def inputs(self) -> dict[str, object]:
        token = object()
        return {
            "checkpoint": self.checkpoint,
            "reentry": token,
            "retry_decision": token,
            "gate": token,
            "receipt": token,
            "handoff": token,
            "failed_decision": token,
            "pre_step_peer_snapshot": token,
            "failure_peer_snapshot": token,
            "recovery_completion_peer_snapshot": token,
            "retry_completion_peer_snapshot": token,
            "role_authority": token,
            "target_node_id": self.decision.target_node_id,
            "predecessor_checkpoint": token,
        }

    def consume(self, *, evaluated=None):
        evaluated = evaluated or self.decision
        with (
            patch.object(
                guard,
                "revalidate_rolling_recovery_retry_checkpoint",
                return_value=self.checkpoint,
            ),
            patch.object(
                guard,
                "evaluate_next_rolling_step_after_recovery_retry",
                return_value=evaluated,
            ),
        ):
            return self.journal.consume_after_recovery_retry(**self.inputs())

    def test_exact_replay_is_idempotent_and_single_row(self) -> None:
        first = self.consume()
        second = self.consume()
        self.assertEqual(first, second)
        count = self.db.execute(
            "SELECT COUNT(*) FROM hc_ha_rolling_retry_continuation"
        ).fetchone()[0]
        self.assertEqual(1, count)
        self.assertTrue(first.checkpoint_consumed)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.production_mutation_enabled)

    def test_same_checkpoint_cannot_seed_competing_next_plan(self) -> None:
        self.consume()
        competing = decision(plan_id="next-plan-e", target_node_id="node-e")
        inputs = self.inputs()
        inputs["target_node_id"] = "node-e"
        with (
            patch.object(
                guard,
                "revalidate_rolling_recovery_retry_checkpoint",
                return_value=self.checkpoint,
            ),
            patch.object(
                guard,
                "evaluate_next_rolling_step_after_recovery_retry",
                return_value=competing,
            ),
            self.assertRaisesRegex(
                HARollingContinuationGuardError,
                "rolling_retry_checkpoint_already_consumed",
            ),
        ):
            self.journal.consume_after_recovery_retry(**inputs)

    def test_unsafe_next_step_is_never_consumed(self) -> None:
        blocked = decision(
            safe=False,
            blockers=("writer_handoff_required",),
        )
        with self.assertRaisesRegex(
            HARollingContinuationGuardError,
            "rolling_continuation_next_step_not_safe",
        ):
            self.consume(evaluated=blocked)
        count = self.db.execute(
            "SELECT COUNT(*) FROM hc_ha_rolling_retry_continuation"
        ).fetchone()[0]
        self.assertEqual(0, count)

    def test_single_node_has_no_continuation_consumption(self) -> None:
        with (
            patch.object(
                guard,
                "revalidate_rolling_recovery_retry_checkpoint",
                return_value=self.checkpoint,
            ),
            patch.object(
                guard,
                "evaluate_next_rolling_step_after_recovery_retry",
                side_effect=ValueError("single_node_has_no_next_rolling_step"),
            ),
            self.assertRaisesRegex(
                ValueError,
                "single_node_has_no_next_rolling_step",
            ),
        ):
            self.journal.consume_after_recovery_retry(**self.inputs())
        count = self.db.execute(
            "SELECT COUNT(*) FROM hc_ha_rolling_retry_continuation"
        ).fetchone()[0]
        self.assertEqual(0, count)

    def test_role_failover_drift_fails_closed_before_consumption(self) -> None:
        with (
            patch.object(
                guard,
                "revalidate_rolling_recovery_retry_checkpoint",
                side_effect=ValueError("rolling_retry_checkpoint_role_revision_stale"),
            ),
            patch.object(
                guard,
                "evaluate_next_rolling_step_after_recovery_retry",
                return_value=self.decision,
            ),
            self.assertRaisesRegex(
                ValueError,
                "rolling_retry_checkpoint_role_revision_stale",
            ),
        ):
            self.journal.consume_after_recovery_retry(**self.inputs())
        count = self.db.execute(
            "SELECT COUNT(*) FROM hc_ha_rolling_retry_continuation"
        ).fetchone()[0]
        self.assertEqual(0, count)

    def test_reopen_preserves_exact_consumption_and_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "continuation.sqlite"
            first_db = sqlite3.connect(database)
            first_journal = HARollingContinuationJournal(first_db)
            with (
                patch.object(
                    guard,
                    "revalidate_rolling_recovery_retry_checkpoint",
                    return_value=self.checkpoint,
                ),
                patch.object(
                    guard,
                    "evaluate_next_rolling_step_after_recovery_retry",
                    return_value=self.decision,
                ),
            ):
                first = first_journal.consume_after_recovery_retry(**self.inputs())
            first_db.close()

            second_db = sqlite3.connect(database)
            second_journal = HARollingContinuationJournal(second_db)
            with (
                patch.object(
                    guard,
                    "revalidate_rolling_recovery_retry_checkpoint",
                    return_value=self.checkpoint,
                ),
                patch.object(
                    guard,
                    "evaluate_next_rolling_step_after_recovery_retry",
                    return_value=self.decision,
                ),
            ):
                second = second_journal.consume_after_recovery_retry(**self.inputs())
            self.assertEqual(first, second)
            second_db.close()

    def test_peer_or_plan_drift_invalidates_saved_consumption(self) -> None:
        saved = self.consume()
        drifted = decision(
            plan_id="next-plan-d-drifted",
            peer_snapshot_id="peer-12",
            peer_journal_seq=12,
        )
        inputs = self.inputs()
        inputs.pop("target_node_id")
        with (
            patch.object(
                guard,
                "revalidate_rolling_recovery_retry_checkpoint",
                return_value=self.checkpoint,
            ),
            patch.object(
                guard,
                "evaluate_next_rolling_step_after_recovery_retry",
                return_value=drifted,
            ),
            self.assertRaisesRegex(
                HARollingContinuationGuardError,
                "rolling_continuation_evidence_stale",
            ),
        ):
            self.journal.revalidate_consumption(
                consumption=saved,
                **inputs,
            )

    def test_corrupt_journal_fails_closed(self) -> None:
        saved = self.consume()
        self.db.execute(
            """
            UPDATE hc_ha_rolling_retry_continuation
            SET material_json='{}'
            WHERE retry_checkpoint_id=?
            """,
            (saved.retry_checkpoint_id,),
        )
        self.db.commit()
        inputs = self.inputs()
        inputs.pop("target_node_id")
        with (
            patch.object(
                guard,
                "revalidate_rolling_recovery_retry_checkpoint",
                return_value=self.checkpoint,
            ),
            patch.object(
                guard,
                "evaluate_next_rolling_step_after_recovery_retry",
                return_value=self.decision,
            ),
            self.assertRaisesRegex(
                HARollingContinuationGuardError,
                "rolling_continuation_journal_corrupt",
            ),
        ):
            self.journal.revalidate_consumption(
                consumption=saved,
                **inputs,
            )

    def test_tampered_consumption_authority_is_rejected(self) -> None:
        saved = self.consume()
        tampered = replace(saved, failover_authorized=True)
        inputs = self.inputs()
        inputs.pop("target_node_id")
        with self.assertRaisesRegex(
            HARollingContinuationGuardError,
            "rolling_continuation_authority_invalid",
        ):
            self.journal.revalidate_consumption(
                consumption=tampered,
                **inputs,
            )


if __name__ == "__main__":
    unittest.main()
