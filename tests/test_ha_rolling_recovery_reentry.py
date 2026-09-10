from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from dataclasses import replace

from home_center.ha_peer_snapshot import HAPeerStateSnapshot, ObservedPeerState, PeerHealthState
from home_center.ha_role_journal import HARoleJournalAuthority, HARoleTransitionKind
from home_center.ha_rolling_authority import HARoleAssignment
from home_center.ha_rolling_checkpoint import (
    evaluate_next_rolling_step,
    seal_rolling_step_checkpoint,
)
from home_center.ha_rolling_recovery import seal_rolling_recovery_handoff
from home_center.ha_rolling_recovery_completion import (
    seal_rolling_recovery_completion,
    seal_rolling_recovery_ready_gate,
)
from home_center.ha_rolling_recovery_reentry import (
    HARollingRecoveryReentryError,
    evaluate_rolling_recovery_reentry,
    revalidate_rolling_recovery_reentry,
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


class RollingRecoveryReentryTests(unittest.TestCase):
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
        first = self.evaluate(snapshot=self.before_first, target_node_id="node-b")
        self.pre = peer_snapshot(
            ready,
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=8,
        )
        self.checkpoint = seal_rolling_step_checkpoint(
            decision=first,
            pre_step_peer_snapshot=self.before_first,
            completion_peer_snapshot=self.pre,
            role_authority=self.store,
            expected_completion_peer_snapshot_id=self.pre.snapshot_id,
            expected_completion_peer_journal_seq=self.pre.journal_seq,
            expected_completed_revision="state-node-b-v2",
        )
        self.failed_decision = evaluate_next_rolling_step(
            checkpoint=self.checkpoint,
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
            predecessor_checkpoint=self.checkpoint,
        )
        self.completion = peer_snapshot(
            ready,
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=10,
        )
        self.receipt = seal_rolling_recovery_completion(
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=self.failure,
            completion_peer_snapshot=self.completion,
            role_authority=self.store,
            expected_completion_peer_snapshot_id=self.completion.snapshot_id,
            expected_completion_peer_journal_seq=self.completion.journal_seq,
            predecessor_checkpoint=self.checkpoint,
        )
        self.gate = seal_rolling_recovery_ready_gate(
            receipt=self.receipt,
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=self.failure,
            completion_peer_snapshot=self.completion,
            role_authority=self.store,
            predecessor_checkpoint=self.checkpoint,
        )

    def tearDown(self) -> None:
        self.db.close()

    def evaluate(self, *, snapshot: HAPeerStateSnapshot, target_node_id: str):
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

    def reentry(self):
        return evaluate_rolling_recovery_reentry(
            gate=self.gate,
            receipt=self.receipt,
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=self.failure,
            completion_peer_snapshot=self.completion,
            role_authority=self.store,
            target_node_id="node-c",
            predecessor_checkpoint=self.checkpoint,
        )

    def test_reentry_is_deterministic_retry_only_and_non_authorizing(self) -> None:
        first = self.reentry()
        second = self.reentry()
        self.assertEqual(first, second)
        self.assertTrue(first.safe)
        self.assertFalse(first.blockers)
        self.assertNotEqual(self.failed_decision.plan_id, first.candidate_plan_id)
        self.assertEqual("node-c", first.target_node_id)
        self.assertTrue(first.retry_same_failed_node)
        self.assertTrue(first.reassessment_completed)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.production_mutation_enabled)

    def test_reentry_preserves_predecessor_and_minimum_ready_contract(self) -> None:
        decision = self.reentry()
        self.assertEqual(self.checkpoint.completed_node_id, decision.required_predecessor_node_id)
        self.assertEqual(
            self.checkpoint.completed_revision,
            decision.required_predecessor_revision,
        )
        self.assertEqual(self.failed_decision.minimum_ready_nodes, decision.minimum_ready_nodes)
        self.assertEqual(self.handoff.recovery_mode, decision.recovery_mode)

    def test_reentry_cannot_skip_the_recovered_failed_node(self) -> None:
        with self.assertRaisesRegex(
            HARollingRecoveryReentryError,
            "rolling_reentry_target_must_retry_failed_node",
        ):
            evaluate_rolling_recovery_reentry(
                gate=self.gate,
                receipt=self.receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.pre,
                failure_peer_snapshot=self.failure,
                completion_peer_snapshot=self.completion,
                role_authority=self.store,
                target_node_id="node-a",
                predecessor_checkpoint=self.checkpoint,
            )

    def test_role_transition_after_gate_invalidates_reentry(self) -> None:
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
            self.reentry()

    def test_completion_snapshot_drift_invalidates_saved_reentry(self) -> None:
        decision = self.reentry()
        drifted = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.READY,
            },
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=11,
        )
        with self.assertRaises(ValueError):
            revalidate_rolling_recovery_reentry(
                decision=decision,
                gate=self.gate,
                receipt=self.receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.pre,
                failure_peer_snapshot=self.failure,
                completion_peer_snapshot=drifted,
                role_authority=self.store,
                predecessor_checkpoint=self.checkpoint,
            )

    def test_tampered_reentry_decision_is_rejected(self) -> None:
        decision = self.reentry()
        tampered = replace(decision, execution_authorized=True)
        with self.assertRaisesRegex(
            HARollingRecoveryReentryError,
            "rolling_reentry_authority_invalid",
        ):
            revalidate_rolling_recovery_reentry(
                decision=tampered,
                gate=self.gate,
                receipt=self.receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.pre,
                failure_peer_snapshot=self.failure,
                completion_peer_snapshot=self.completion,
                role_authority=self.store,
                predecessor_checkpoint=self.checkpoint,
            )

    def test_single_node_reentry_preserves_downtime_acknowledgement(self) -> None:
        db = sqlite3.connect(":memory:")
        try:
            store = HARoleJournalAuthority(db)
            state = store.bootstrap(
                cluster_id="home-cluster",
                assignments=roles(nodes=("node-a",)),
            )
            before = peer_snapshot({"node-a": PeerHealthState.READY}, journal_seq=1)
            failed_decision = evaluate_revision_bound_rolling_safety(
                peer_snapshot=before,
                role_authority=store,
                target_node_id="node-a",
                minimum_ready_nodes=0,
                expected_peer_snapshot_id=before.snapshot_id,
                expected_peer_journal_seq=before.journal_seq,
                expected_role_assignment_id=state.snapshot.assignment_id,
                expected_role_epoch=state.snapshot.role_epoch,
                expected_role_resource_version=state.resource_version,
                expected_role_journal_seq=state.journal_seq,
                expected_role_transition_id=state.transition_id,
                single_node_downtime_acknowledged=True,
            )
            failure = peer_snapshot(
                {"node-a": PeerHealthState.UNREACHABLE},
                revisions={"node-a": "state-node-a-failed"},
                journal_seq=2,
            )
            handoff = seal_rolling_recovery_handoff(
                failed_decision=failed_decision,
                pre_step_peer_snapshot=before,
                failure_peer_snapshot=failure,
                role_authority=store,
                expected_failure_peer_snapshot_id=failure.snapshot_id,
                expected_failure_peer_journal_seq=failure.journal_seq,
            )
            completion = peer_snapshot({"node-a": PeerHealthState.READY}, journal_seq=3)
            receipt = seal_rolling_recovery_completion(
                handoff=handoff,
                failed_decision=failed_decision,
                pre_step_peer_snapshot=before,
                failure_peer_snapshot=failure,
                completion_peer_snapshot=completion,
                role_authority=store,
                expected_completion_peer_snapshot_id=completion.snapshot_id,
                expected_completion_peer_journal_seq=completion.journal_seq,
            )
            gate = seal_rolling_recovery_ready_gate(
                receipt=receipt,
                handoff=handoff,
                failed_decision=failed_decision,
                pre_step_peer_snapshot=before,
                failure_peer_snapshot=failure,
                completion_peer_snapshot=completion,
                role_authority=store,
            )
            decision = evaluate_rolling_recovery_reentry(
                gate=gate,
                receipt=receipt,
                handoff=handoff,
                failed_decision=failed_decision,
                pre_step_peer_snapshot=before,
                failure_peer_snapshot=failure,
                completion_peer_snapshot=completion,
                role_authority=store,
                target_node_id="node-a",
            )
            self.assertTrue(decision.safe)
            self.assertTrue(decision.single_node_downtime_acknowledged)
            self.assertEqual("single-node-rollback", decision.recovery_mode)
            self.assertFalse(decision.execution_authorized)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
