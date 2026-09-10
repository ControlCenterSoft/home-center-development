from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from dataclasses import replace

from home_center.ha_peer_snapshot import (
    HAPeerStateSnapshot,
    ObservedPeerState,
    PeerHealthState,
)
from home_center.ha_role_journal import HARoleJournalAuthority, HARoleTransitionKind
from home_center.ha_rolling_authority import HARoleAssignment
from home_center.ha_rolling_checkpoint import (
    HARollingCheckpointError,
    evaluate_next_rolling_step,
    seal_rolling_step_checkpoint,
)
from home_center.ha_rolling_recovery import seal_rolling_recovery_handoff
from home_center.ha_rolling_recovery_completion import (
    seal_rolling_recovery_completion,
    seal_rolling_recovery_ready_gate,
)
from home_center.ha_rolling_recovery_reentry import evaluate_rolling_recovery_reentry
from home_center.ha_rolling_recovery_retry_checkpoint import (
    HARollingRecoveryRetryCheckpointError,
    evaluate_next_rolling_step_after_recovery_retry,
    revalidate_rolling_recovery_retry_checkpoint,
    seal_rolling_recovery_retry_checkpoint,
)
from home_center.ha_rolling_revision import evaluate_revision_bound_rolling_safety
from home_center.ha_rolling_safety import NodeRole


def roles(
    writer: str = "node-a",
    nodes: tuple[str, ...] = ("node-a", "node-b", "node-c"),
) -> tuple[HARoleAssignment, ...]:
    return tuple(
        HARoleAssignment(
            node_id,
            NodeRole.WRITER if node_id == writer else NodeRole.STANDBY,
        )
        for node_id in nodes
    )


def peer_snapshot(
    states: dict[str, PeerHealthState],
    *,
    revisions: dict[str, str] | None = None,
    journal_seq: int,
) -> HAPeerStateSnapshot:
    revisions = revisions or {}
    members = tuple(
        ObservedPeerState(
            node_id,
            "untrusted",
            states[node_id],
            revisions.get(node_id, f"state-{node_id}"),
        )
        for node_id in sorted(states)
    )
    canonical = {
        "schema": "home-center.ha-peer-state-snapshot.v1",
        "cluster_id": "home-cluster",
        "journal_seq": journal_seq,
        "members": [member.to_dict() for member in members],
    }
    snapshot_id = "ha-state-" + hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return HAPeerStateSnapshot("home-cluster", journal_seq, members, snapshot_id)


class RollingRecoveryRetryCheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.store = HARoleJournalAuthority(self.db)
        self.initial = self.store.bootstrap(
            cluster_id="home-cluster",
            assignments=roles(),
        )
        ready = {
            "node-a": PeerHealthState.READY,
            "node-b": PeerHealthState.READY,
            "node-c": PeerHealthState.READY,
        }
        self.before_first = peer_snapshot(ready, journal_seq=7)
        first = self.evaluate(
            snapshot=self.before_first,
            target_node_id="node-b",
        )
        self.pre = peer_snapshot(
            ready,
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=8,
        )
        self.predecessor = seal_rolling_step_checkpoint(
            decision=first,
            pre_step_peer_snapshot=self.before_first,
            completion_peer_snapshot=self.pre,
            role_authority=self.store,
            expected_completion_peer_snapshot_id=self.pre.snapshot_id,
            expected_completion_peer_journal_seq=self.pre.journal_seq,
            expected_completed_revision="state-node-b-v2",
        )
        self.failed_decision = evaluate_next_rolling_step(
            checkpoint=self.predecessor,
            peer_snapshot=self.pre,
            role_authority=self.store,
            target_node_id="node-c",
        )
        self.failure = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.DEGRADED,
            },
            revisions={
                "node-b": "state-node-b-v2",
                "node-c": "state-node-c-failed",
            },
            journal_seq=9,
        )
        self.handoff = seal_rolling_recovery_handoff(
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=self.failure,
            role_authority=self.store,
            expected_failure_peer_snapshot_id=self.failure.snapshot_id,
            expected_failure_peer_journal_seq=self.failure.journal_seq,
            predecessor_checkpoint=self.predecessor,
        )
        self.recovery_completion = peer_snapshot(
            ready,
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=10,
        )
        self.receipt = seal_rolling_recovery_completion(
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=self.failure,
            completion_peer_snapshot=self.recovery_completion,
            role_authority=self.store,
            expected_completion_peer_snapshot_id=self.recovery_completion.snapshot_id,
            expected_completion_peer_journal_seq=self.recovery_completion.journal_seq,
            predecessor_checkpoint=self.predecessor,
        )
        self.gate = seal_rolling_recovery_ready_gate(
            receipt=self.receipt,
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=self.failure,
            completion_peer_snapshot=self.recovery_completion,
            role_authority=self.store,
            predecessor_checkpoint=self.predecessor,
        )
        self.reentry = evaluate_rolling_recovery_reentry(
            gate=self.gate,
            receipt=self.receipt,
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=self.failure,
            completion_peer_snapshot=self.recovery_completion,
            role_authority=self.store,
            target_node_id="node-c",
            predecessor_checkpoint=self.predecessor,
        )
        self.retry_decision = self.evaluate_retry()
        self.retry_completion = peer_snapshot(
            ready,
            revisions={
                "node-b": "state-node-b-v2",
                "node-c": "state-node-c-v2",
            },
            journal_seq=11,
        )

    def tearDown(self) -> None:
        self.db.close()

    def evaluate(
        self,
        *,
        snapshot: HAPeerStateSnapshot,
        target_node_id: str,
    ):
        state = self.store.state_for(
            cluster_id=snapshot.cluster_id,
            node_ids=tuple(member.node_id for member in snapshot.members),
        )
        return evaluate_revision_bound_rolling_safety(
            peer_snapshot=snapshot,
            role_authority=self.store,
            target_node_id=target_node_id,
            minimum_ready_nodes=2,
            expected_peer_snapshot_id=snapshot.snapshot_id,
            expected_peer_journal_seq=snapshot.journal_seq,
            expected_role_assignment_id=state.snapshot.assignment_id,
            expected_role_epoch=state.snapshot.role_epoch,
            expected_role_resource_version=state.resource_version,
            expected_role_journal_seq=state.journal_seq,
            expected_role_transition_id=state.transition_id,
        )

    def evaluate_retry(self):
        state = self.store.state_for(
            cluster_id=self.recovery_completion.cluster_id,
            node_ids=tuple(
                member.node_id
                for member in self.recovery_completion.members
            ),
        )
        return evaluate_revision_bound_rolling_safety(
            peer_snapshot=self.recovery_completion,
            role_authority=self.store,
            target_node_id="node-c",
            minimum_ready_nodes=self.reentry.minimum_ready_nodes,
            expected_peer_snapshot_id=self.reentry.peer_snapshot_id,
            expected_peer_journal_seq=self.reentry.peer_journal_seq,
            expected_role_assignment_id=self.reentry.role_assignment_id,
            expected_role_epoch=self.reentry.role_epoch,
            expected_role_resource_version=self.reentry.role_resource_version,
            expected_role_journal_seq=self.reentry.role_journal_seq,
            expected_role_transition_id=self.reentry.role_transition_id,
            required_predecessor_node_id=(
                self.reentry.required_predecessor_node_id
            ),
            required_predecessor_revision=(
                self.reentry.required_predecessor_revision
            ),
            single_node_downtime_acknowledged=(
                self.reentry.single_node_downtime_acknowledged
            ),
        )

    def seal(self):
        return seal_rolling_recovery_retry_checkpoint(
            reentry=self.reentry,
            retry_decision=self.retry_decision,
            gate=self.gate,
            receipt=self.receipt,
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=self.failure,
            recovery_completion_peer_snapshot=self.recovery_completion,
            retry_completion_peer_snapshot=self.retry_completion,
            role_authority=self.store,
            expected_retry_completion_peer_snapshot_id=(
                self.retry_completion.snapshot_id
            ),
            expected_retry_completion_peer_journal_seq=(
                self.retry_completion.journal_seq
            ),
            expected_completed_revision="state-node-c-v2",
            predecessor_checkpoint=self.predecessor,
        )

    def revalidate(self, checkpoint):
        return revalidate_rolling_recovery_retry_checkpoint(
            checkpoint=checkpoint,
            reentry=self.reentry,
            retry_decision=self.retry_decision,
            gate=self.gate,
            receipt=self.receipt,
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=self.failure,
            recovery_completion_peer_snapshot=self.recovery_completion,
            retry_completion_peer_snapshot=self.retry_completion,
            role_authority=self.store,
            predecessor_checkpoint=self.predecessor,
        )

    def test_seal_is_deterministic_and_consumes_recovery_lineage(self) -> None:
        first = self.seal()
        second = self.seal()
        self.assertEqual(first, second)
        self.assertEqual(self.reentry.decision_id, first.reentry_decision_id)
        self.assertEqual(self.failed_decision.plan_id, first.failed_plan_id)
        self.assertEqual(self.retry_decision.plan_id, first.retry_plan_id)
        self.assertNotEqual(first.failed_plan_id, first.retry_plan_id)
        self.assertTrue(first.retry_completed)
        self.assertTrue(first.failed_plan_retired)
        self.assertTrue(first.recovery_lineage_consumed)
        self.assertTrue(first.continuation_reassessment_required)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.production_mutation_enabled)

    def test_retry_checkpoint_binds_new_revision_and_exact_retry_plan(self) -> None:
        checkpoint = self.seal()
        rolling = checkpoint.rolling_checkpoint
        self.assertEqual("node-c", checkpoint.retry_node_id)
        self.assertEqual("state-node-c-v2", checkpoint.completed_revision)
        self.assertEqual(self.retry_decision.plan_id, rolling.completed_plan_id)
        self.assertEqual(self.retry_completion.snapshot_id, rolling.completion_peer_snapshot_id)
        self.assertEqual(self.retry_completion.journal_seq, rolling.completion_peer_journal_seq)

    def test_next_step_uses_recovered_retry_as_predecessor(self) -> None:
        checkpoint = self.seal()
        decision = evaluate_next_rolling_step_after_recovery_retry(
            checkpoint=checkpoint,
            reentry=self.reentry,
            retry_decision=self.retry_decision,
            gate=self.gate,
            receipt=self.receipt,
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=self.failure,
            recovery_completion_peer_snapshot=self.recovery_completion,
            retry_completion_peer_snapshot=self.retry_completion,
            role_authority=self.store,
            target_node_id="node-a",
            predecessor_checkpoint=self.predecessor,
        )
        self.assertEqual("node-c", decision.required_predecessor_node_id)
        self.assertEqual("state-node-c-v2", decision.required_predecessor_revision)
        self.assertIn("writer_handoff_required", decision.blockers)
        self.assertFalse(decision.safe)
        self.assertFalse(decision.production_mutation_enabled)

    def test_tampered_checkpoint_authority_is_rejected(self) -> None:
        checkpoint = self.seal()
        tampered = replace(checkpoint, execution_authorized=True)
        with self.assertRaisesRegex(
            HARollingRecoveryRetryCheckpointError,
            "rolling_retry_checkpoint_authority_invalid",
        ):
            self.revalidate(tampered)

    def test_retry_candidate_drift_is_rejected(self) -> None:
        drifted = replace(
            self.retry_decision,
            required_predecessor_revision="state-node-b-other",
        )
        with self.assertRaises(ValueError):
            seal_rolling_recovery_retry_checkpoint(
                reentry=self.reentry,
                retry_decision=drifted,
                gate=self.gate,
                receipt=self.receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.pre,
                failure_peer_snapshot=self.failure,
                recovery_completion_peer_snapshot=self.recovery_completion,
                retry_completion_peer_snapshot=self.retry_completion,
                role_authority=self.store,
                expected_retry_completion_peer_snapshot_id=(
                    self.retry_completion.snapshot_id
                ),
                expected_retry_completion_peer_journal_seq=(
                    self.retry_completion.journal_seq
                ),
                expected_completed_revision="state-node-c-v2",
                predecessor_checkpoint=self.predecessor,
            )

    def test_wrong_retry_completion_revision_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            HARollingCheckpointError,
            "completed_revision_mismatch",
        ):
            seal_rolling_recovery_retry_checkpoint(
                reentry=self.reentry,
                retry_decision=self.retry_decision,
                gate=self.gate,
                receipt=self.receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.pre,
                failure_peer_snapshot=self.failure,
                recovery_completion_peer_snapshot=self.recovery_completion,
                retry_completion_peer_snapshot=self.retry_completion,
                role_authority=self.store,
                expected_retry_completion_peer_snapshot_id=(
                    self.retry_completion.snapshot_id
                ),
                expected_retry_completion_peer_journal_seq=(
                    self.retry_completion.journal_seq
                ),
                expected_completed_revision="state-node-c-v3",
                predecessor_checkpoint=self.predecessor,
            )

    def test_role_failover_after_reentry_invalidates_retry_checkpoint(self) -> None:
        checkpoint = self.seal()
        self.store.transition(
            cluster_id="home-cluster",
            assignments=roles("node-b"),
            transition_kind=HARoleTransitionKind.FAILOVER,
            expected_assignment_id=self.initial.snapshot.assignment_id,
            expected_role_epoch=self.initial.snapshot.role_epoch,
            expected_resource_version=self.initial.resource_version,
            expected_journal_seq=self.initial.journal_seq,
        )
        with self.assertRaises(ValueError):
            self.revalidate(checkpoint)

    def test_retry_completion_snapshot_drift_invalidates_checkpoint(self) -> None:
        checkpoint = self.seal()
        drifted = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.READY,
            },
            revisions={
                "node-b": "state-node-b-v2",
                "node-c": "state-node-c-v2",
            },
            journal_seq=12,
        )
        with self.assertRaises(ValueError):
            revalidate_rolling_recovery_retry_checkpoint(
                checkpoint=checkpoint,
                reentry=self.reentry,
                retry_decision=self.retry_decision,
                gate=self.gate,
                receipt=self.receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.pre,
                failure_peer_snapshot=self.failure,
                recovery_completion_peer_snapshot=self.recovery_completion,
                retry_completion_peer_snapshot=drifted,
                role_authority=self.store,
                predecessor_checkpoint=self.predecessor,
            )


if __name__ == "__main__":
    unittest.main()
