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
from home_center.ha_rolling_recovery import (
    HARollingRecoveryError,
    revalidate_rolling_recovery_handoff,
    seal_rolling_recovery_handoff,
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


class RollingRecoveryHandoffTests(unittest.TestCase):
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
        self.completed = peer_snapshot(
            ready,
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=8,
        )
        self.checkpoint = seal_rolling_step_checkpoint(
            decision=first,
            pre_step_peer_snapshot=self.pre,
            completion_peer_snapshot=self.completed,
            role_authority=self.store,
            expected_completion_peer_snapshot_id=self.completed.snapshot_id,
            expected_completion_peer_journal_seq=self.completed.journal_seq,
            expected_completed_revision="state-node-b-v2",
        )
        self.failed_decision = evaluate_next_rolling_step(
            checkpoint=self.checkpoint,
            peer_snapshot=self.completed,
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

    def tearDown(self) -> None:
        self.db.close()

    def evaluate(
        self,
        *,
        snapshot: HAPeerStateSnapshot,
        target_node_id: str,
        minimum_ready_nodes: int = 2,
        single_node_downtime_acknowledged: bool = False,
    ):
        state = self.store.state_for(
            cluster_id=snapshot.cluster_id,
            node_ids=tuple(member.node_id for member in snapshot.members),
        )
        return evaluate_revision_bound_rolling_safety(
            peer_snapshot=snapshot,
            role_authority=self.store,
            target_node_id=target_node_id,
            minimum_ready_nodes=minimum_ready_nodes,
            expected_peer_snapshot_id=snapshot.snapshot_id,
            expected_peer_journal_seq=snapshot.journal_seq,
            expected_role_assignment_id=state.snapshot.assignment_id,
            expected_role_epoch=state.snapshot.role_epoch,
            expected_role_resource_version=state.resource_version,
            expected_role_journal_seq=state.journal_seq,
            expected_role_transition_id=state.transition_id,
            single_node_downtime_acknowledged=single_node_downtime_acknowledged,
        )

    def seal(self, *, failure=None, checkpoint=True):
        failure = failure or self.failure
        predecessor = self.checkpoint if checkpoint else None
        return seal_rolling_recovery_handoff(
            failed_decision=self.failed_decision,
            pre_step_peer_snapshot=self.completed,
            failure_peer_snapshot=failure,
            role_authority=self.store,
            expected_failure_peer_snapshot_id=failure.snapshot_id,
            expected_failure_peer_journal_seq=failure.journal_seq,
            predecessor_checkpoint=predecessor,
        )

    def test_handoff_is_deterministic_and_non_authorizing(self) -> None:
        first = self.seal()
        second = self.seal()
        self.assertEqual(first, second)
        self.assertEqual("state-node-c", first.rollback_target_revision)
        self.assertEqual("state-node-c-failed", first.failed_observed_revision)
        self.assertEqual(("node-a", "node-b"), first.ready_node_ids)
        self.assertEqual("ha-target-rollback", first.recovery_mode)
        self.assertTrue(first.rollback_required)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.production_mutation_enabled)

    def test_first_step_failure_does_not_require_predecessor_checkpoint(self) -> None:
        decision = self.evaluate(snapshot=self.pre, target_node_id="node-b")
        failure = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.UNREACHABLE,
                "node-c": PeerHealthState.READY,
            },
            revisions={"node-b": "state-node-b-failed"},
            journal_seq=8,
        )
        handoff = seal_rolling_recovery_handoff(
            failed_decision=decision,
            pre_step_peer_snapshot=self.pre,
            failure_peer_snapshot=failure,
            role_authority=self.store,
            expected_failure_peer_snapshot_id=failure.snapshot_id,
            expected_failure_peer_journal_seq=failure.journal_seq,
        )
        self.assertIsNone(handoff.predecessor_checkpoint_id)
        self.assertEqual("state-node-b", handoff.rollback_target_revision)

    def test_predecessor_bound_plan_requires_exact_checkpoint(self) -> None:
        with self.assertRaisesRegex(
            HARollingRecoveryError,
            "rolling_recovery_predecessor_checkpoint_required",
        ):
            self.seal(checkpoint=False)

    def test_ready_target_does_not_prove_failure(self) -> None:
        not_failed = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.READY,
            },
            revisions={"node-b": "state-node-b-v2", "node-c": "state-node-c-v2"},
            journal_seq=9,
        )
        with self.assertRaisesRegex(
            HARollingRecoveryError,
            "rolling_recovery_failure_not_proven",
        ):
            self.seal(failure=not_failed)

    def test_unknown_target_does_not_prove_bounded_failure(self) -> None:
        unknown = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.UNKNOWN,
            },
            revisions={"node-b": "state-node-b-v2", "node-c": "state-node-c-unknown"},
            journal_seq=9,
        )
        with self.assertRaisesRegex(
            HARollingRecoveryError,
            "rolling_recovery_failure_not_proven",
        ):
            self.seal(failure=unknown)

    def test_non_target_peer_drift_is_fail_closed(self) -> None:
        drift = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.DEGRADED,
            },
            revisions={
                "node-b": "state-node-b-drifted",
                "node-c": "state-node-c-failed",
            },
            journal_seq=9,
        )
        with self.assertRaisesRegex(
            HARollingRecoveryError,
            "rolling_recovery_non_target_peer_drift",
        ):
            self.seal(failure=drift)

    def test_failure_requires_peer_journal_advance(self) -> None:
        stale = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.DEGRADED,
            },
            revisions={
                "node-b": "state-node-b-v2",
                "node-c": "state-node-c-failed",
            },
            journal_seq=8,
        )
        with self.assertRaisesRegex(
            HARollingRecoveryError,
            "rolling_recovery_peer_journal_not_advanced",
        ):
            self.seal(failure=stale)

    def test_role_failover_invalidates_recovery_evidence(self) -> None:
        handoff = self.seal()
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
            revalidate_rolling_recovery_handoff(
                handoff=handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.completed,
                failure_peer_snapshot=self.failure,
                role_authority=self.store,
                predecessor_checkpoint=self.checkpoint,
            )

    def test_tampered_handoff_identity_is_rejected(self) -> None:
        handoff = self.seal()
        tampered = replace(handoff, failed_observed_revision="state-node-c-tampered")
        with self.assertRaisesRegex(
            HARollingRecoveryError,
            "rolling_recovery_identity_invalid",
        ):
            revalidate_rolling_recovery_handoff(
                handoff=tampered,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.completed,
                failure_peer_snapshot=self.failure,
                role_authority=self.store,
                predecessor_checkpoint=self.checkpoint,
            )

    def test_failure_snapshot_drift_invalidates_saved_handoff(self) -> None:
        handoff = self.seal()
        changed = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.UNREACHABLE,
            },
            revisions={
                "node-b": "state-node-b-v2",
                "node-c": "state-node-c-failed-again",
            },
            journal_seq=10,
        )
        with self.assertRaisesRegex(
            HARollingRecoveryError,
            "rolling_recovery_failure_snapshot_stale",
        ):
            revalidate_rolling_recovery_handoff(
                handoff=handoff,
                failed_decision=self.failed_decision,
                pre_step_peer_snapshot=self.completed,
                failure_peer_snapshot=changed,
                role_authority=self.store,
                predecessor_checkpoint=self.checkpoint,
            )

    def test_single_node_failure_gets_non_failover_recovery_handoff(self) -> None:
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
            self.assertEqual("single-node-rollback", handoff.recovery_mode)
            self.assertEqual((), handoff.ready_node_ids)
            self.assertFalse(handoff.failover_authorized)
            self.assertFalse(handoff.execution_authorized)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
