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
    HARollingRecoveryCompletionError,
    revalidate_rolling_recovery_completion,
    revalidate_rolling_recovery_ready_gate,
    seal_rolling_recovery_completion,
    seal_rolling_recovery_ready_gate,
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


class RollingRecoveryCompletionTests(unittest.TestCase):
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
        self.pre = peer_snapshot(ready, journal_seq=7)
        first = self.evaluate(snapshot=self.pre, target_node_id="node-b")
        self.after_first = peer_snapshot(
            ready,
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=8,
        )
        self.checkpoint = seal_rolling_step_checkpoint(
            decision=first,
            pre_step_peer_snapshot=self.pre,
            completion_peer_snapshot=self.after_first,
            role_authority=self.store,
            expected_completion_peer_snapshot_id=self.after_first.snapshot_id,
            expected_completion_peer_journal_seq=self.after_first.journal_seq,
            expected_completed_revision="state-node-b-v2",
        )
        self.failed_decision = evaluate_next_rolling_step(
            checkpoint=self.checkpoint,
            peer_snapshot=self.after_first,
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
            pre_step_peer_snapshot=self.after_first,
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

    def seal(self, completion: HAPeerStateSnapshot | None = None):
        completion = completion or self.completion
        return seal_rolling_recovery_completion(
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.after_first,
            failure_peer_snapshot=self.failure,
            completion_peer_snapshot=completion,
            role_authority=self.store,
            expected_completion_peer_snapshot_id=completion.snapshot_id,
            expected_completion_peer_journal_seq=completion.journal_seq,
            predecessor_checkpoint=self.checkpoint,
        )

    def test_receipt_and_ready_gate_are_deterministic_and_non_authorizing(self) -> None:
        first = self.seal()
        second = self.seal()
        self.assertEqual(first, second)
        self.assertEqual("state-node-c", first.rollback_target_revision)
        self.assertEqual(("node-a", "node-b", "node-c"), first.ready_node_ids)
        self.assertTrue(first.rollback_completed)
        self.assertTrue(first.ready_for_reassessment)
        self.assertFalse(first.next_step_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.production_mutation_enabled)

        gate = seal_rolling_recovery_ready_gate(
            receipt=first,
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.after_first,
            failure_peer_snapshot=self.failure,
            completion_peer_snapshot=self.completion,
            role_authority=self.store,
            predecessor_checkpoint=self.checkpoint,
        )
        self.assertTrue(gate.reassessment_authorized)
        self.assertFalse(gate.next_step_authorized)
        self.assertFalse(gate.execution_authorized)
        self.assertFalse(gate.failover_authorized)
        self.assertFalse(gate.production_mutation_enabled)

    def test_recovery_target_must_be_ready_at_exact_rollback_revision(self) -> None:
        not_ready = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.DEGRADED,
            },
            revisions={
                "node-b": "state-node-b-v2",
                "node-c": "state-node-c",
            },
            journal_seq=10,
        )
        with self.assertRaisesRegex(
            HARollingRecoveryCompletionError,
            "rolling_recovery_completion_target_not_ready",
        ):
            self.seal(not_ready)

        wrong_revision = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.READY,
            },
            revisions={
                "node-b": "state-node-b-v2",
                "node-c": "state-node-c-other",
            },
            journal_seq=10,
        )
        with self.assertRaisesRegex(
            HARollingRecoveryCompletionError,
            "rolling_recovery_completion_revision_mismatch",
        ):
            self.seal(wrong_revision)

    def test_completion_requires_journal_advance_and_stable_membership(self) -> None:
        stale_journal = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.READY,
            },
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=9,
        )
        with self.assertRaisesRegex(
            HARollingRecoveryCompletionError,
            "rolling_recovery_completion_journal_not_advanced",
        ):
            self.seal(stale_journal)

        membership_change = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-c": PeerHealthState.READY,
            },
            journal_seq=10,
        )
        with self.assertRaises(ValueError):
            self.seal(membership_change)

    def test_non_target_peer_drift_is_rejected(self) -> None:
        drift = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.READY,
            },
            revisions={
                "node-b": "state-node-b-drifted",
                "node-c": "state-node-c",
            },
            journal_seq=10,
        )
        with self.assertRaisesRegex(
            HARollingRecoveryCompletionError,
            "rolling_recovery_completion_non_target_drift",
        ):
            self.seal(drift)

    def test_role_failover_invalidates_completion_evidence(self) -> None:
        receipt = self.seal()
        gate = seal_rolling_recovery_ready_gate(
            receipt=receipt,
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.after_first,
            failure_peer_snapshot=self.failure,
            completion_peer_snapshot=self.completion,
            role_authority=self.store,
            predecessor_checkpoint=self.checkpoint,
        )
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
            revalidate_rolling_recovery_completion(
                receipt=receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.after_first,
                failure_peer_snapshot=self.failure,
                completion_peer_snapshot=self.completion,
                role_authority=self.store,
                predecessor_checkpoint=self.checkpoint,
            )
        with self.assertRaises(ValueError):
            revalidate_rolling_recovery_ready_gate(
                gate=gate,
                receipt=receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.after_first,
                failure_peer_snapshot=self.failure,
                completion_peer_snapshot=self.completion,
                role_authority=self.store,
                predecessor_checkpoint=self.checkpoint,
            )

    def test_tampered_receipt_and_gate_are_rejected(self) -> None:
        receipt = self.seal()
        tampered_receipt = replace(receipt, recovered_node_id="node-b")
        with self.assertRaisesRegex(
            HARollingRecoveryCompletionError,
            "rolling_recovery_completion_identity_invalid",
        ):
            revalidate_rolling_recovery_completion(
                receipt=tampered_receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.after_first,
                failure_peer_snapshot=self.failure,
                completion_peer_snapshot=self.completion,
                role_authority=self.store,
                predecessor_checkpoint=self.checkpoint,
            )

        gate = seal_rolling_recovery_ready_gate(
            receipt=receipt,
            handoff=self.handoff,
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.after_first,
            failure_peer_snapshot=self.failure,
            completion_peer_snapshot=self.completion,
            role_authority=self.store,
            predecessor_checkpoint=self.checkpoint,
        )
        tampered_gate = replace(gate, recovered_node_id="node-b")
        with self.assertRaisesRegex(
            HARollingRecoveryCompletionError,
            "rolling_recovery_ready_gate_identity_invalid",
        ):
            revalidate_rolling_recovery_ready_gate(
                gate=tampered_gate,
                receipt=receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.after_first,
                failure_peer_snapshot=self.failure,
                completion_peer_snapshot=self.completion,
                role_authority=self.store,
                predecessor_checkpoint=self.checkpoint,
            )

    def test_completion_snapshot_drift_invalidates_saved_receipt(self) -> None:
        receipt = self.seal()
        changed = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.READY,
            },
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=11,
        )
        with self.assertRaisesRegex(
            HARollingRecoveryCompletionError,
            "rolling_recovery_completion_snapshot_stale",
        ):
            revalidate_rolling_recovery_completion(
                receipt=receipt,
                handoff=self.handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.after_first,
                failure_peer_snapshot=self.failure,
                completion_peer_snapshot=changed,
                role_authority=self.store,
                predecessor_checkpoint=self.checkpoint,
            )

    def test_single_node_completion_only_reopens_reassessment(self) -> None:
        db = sqlite3.connect(":memory:")
        try:
            store = HARoleJournalAuthority(db)
            state = store.bootstrap(
                cluster_id="home-cluster",
                assignments=roles(nodes=("node-a",)),
            )
            before = peer_snapshot({"node-a": PeerHealthState.READY}, journal_seq=1)
            decision = evaluate_revision_bound_rolling_safety(
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
                failed_decision=decision,
                pre_step_peer_snapshot=before,
                failure_peer_snapshot=failure,
                role_authority=store,
                expected_failure_peer_snapshot_id=failure.snapshot_id,
                expected_failure_peer_journal_seq=failure.journal_seq,
            )
            completion = peer_snapshot(
                {"node-a": PeerHealthState.READY},
                journal_seq=3,
            )
            receipt = seal_rolling_recovery_completion(
                handoff=handoff,
                failed_decision=decision,
                pre_step_peer_snapshot=before,
                failure_peer_snapshot=failure,
                completion_peer_snapshot=completion,
                role_authority=store,
                expected_completion_peer_snapshot_id=completion.snapshot_id,
                expected_completion_peer_journal_seq=completion.journal_seq,
            )
            self.assertEqual(("node-a",), receipt.ready_node_ids)
            self.assertTrue(receipt.ready_for_reassessment)
            self.assertFalse(receipt.next_step_authorized)
            self.assertFalse(receipt.failover_authorized)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
