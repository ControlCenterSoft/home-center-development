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
    HARollingCheckpointError,
    evaluate_next_rolling_step,
    revalidate_rolling_step_checkpoint,
    seal_rolling_step_checkpoint,
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
    journal_seq: int = 7,
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


class RollingStepCheckpointTests(unittest.TestCase):
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
        self.completed = peer_snapshot(
            ready,
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=8,
        )
        self.decision = self.evaluate(target_node_id="node-b")

    def tearDown(self) -> None:
        self.db.close()

    def evaluate(self, *, target_node_id: str, snapshot=None):
        snapshot = snapshot or self.pre
        state = self.store.state_for(
            cluster_id="home-cluster",
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

    def seal(self, *, snapshot=None, revision: str = "state-node-b-v2"):
        snapshot = snapshot or self.completed
        return seal_rolling_step_checkpoint(
            decision=self.decision,
            pre_step_peer_snapshot=self.pre,
            completion_peer_snapshot=snapshot,
            role_authority=self.store,
            expected_completion_peer_snapshot_id=snapshot.snapshot_id,
            expected_completion_peer_journal_seq=snapshot.journal_seq,
            expected_completed_revision=revision,
        )

    def test_checkpoint_is_deterministic_and_non_authorizing(self) -> None:
        first = self.seal()
        second = self.seal()
        self.assertEqual(first, second)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.production_mutation_enabled)
        self.assertEqual(("node-a", "node-b", "node-c"), first.ready_node_ids)

    def test_next_step_is_bound_to_completed_predecessor_revision(self) -> None:
        checkpoint = self.seal()
        next_step = evaluate_next_rolling_step(
            checkpoint=checkpoint,
            peer_snapshot=self.completed,
            role_authority=self.store,
            target_node_id="node-c",
        )
        self.assertTrue(next_step.safe)
        self.assertEqual("node-b", next_step.required_predecessor_node_id)
        self.assertEqual("state-node-b-v2", next_step.required_predecessor_revision)

    def test_peer_degradation_invalidates_saved_checkpoint(self) -> None:
        checkpoint = self.seal()
        degraded = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.DEGRADED,
                "node-c": PeerHealthState.READY,
            },
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=9,
        )
        with self.assertRaisesRegex(
            HARollingCheckpointError,
            "checkpoint_peer_snapshot_stale",
        ):
            revalidate_rolling_step_checkpoint(
                checkpoint=checkpoint,
                completion_peer_snapshot=degraded,
                role_authority=self.store,
            )

    def test_peer_journal_advance_invalidates_saved_checkpoint(self) -> None:
        checkpoint = self.seal()
        advanced = peer_snapshot(
            {node_id: PeerHealthState.READY for node_id in checkpoint.member_node_ids},
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=9,
        )
        with self.assertRaisesRegex(
            HARollingCheckpointError,
            "checkpoint_peer_snapshot_stale",
        ):
            revalidate_rolling_step_checkpoint(
                checkpoint=checkpoint,
                completion_peer_snapshot=advanced,
                role_authority=self.store,
            )

    def test_failover_invalidates_saved_checkpoint(self) -> None:
        checkpoint = self.seal()
        self.store.transition(
            cluster_id="home-cluster",
            assignments=roles("node-c"),
            transition_kind=HARoleTransitionKind.FAILOVER,
            expected_assignment_id=self.initial.snapshot.assignment_id,
            expected_role_epoch=self.initial.snapshot.role_epoch,
            expected_resource_version=self.initial.resource_version,
            expected_journal_seq=self.initial.journal_seq,
        )
        with self.assertRaisesRegex(
            HARollingCheckpointError,
            "rolling_checkpoint_role_revision_stale",
        ):
            revalidate_rolling_step_checkpoint(
                checkpoint=checkpoint,
                completion_peer_snapshot=self.completed,
                role_authority=self.store,
            )

    def test_completion_requires_minimum_ready_plus_next_target_capacity(self) -> None:
        degraded = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.DEGRADED,
            },
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=8,
        )
        with self.assertRaisesRegex(
            HARollingCheckpointError,
            "next_step_ready_floor_not_met",
        ):
            self.seal(snapshot=degraded)

    def test_writer_must_be_ready_at_checkpoint(self) -> None:
        degraded = peer_snapshot(
            {
                "node-a": PeerHealthState.DEGRADED,
                "node-b": PeerHealthState.READY,
                "node-c": PeerHealthState.READY,
            },
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=8,
        )
        with self.assertRaisesRegex(
            HARollingCheckpointError,
            "writer_not_ready_at_checkpoint",
        ):
            self.seal(snapshot=degraded)

    def test_completed_revision_must_match_exact_observation(self) -> None:
        with self.assertRaisesRegex(
            HARollingCheckpointError,
            "completed_revision_mismatch",
        ):
            self.seal(revision="state-node-b-v3")

    def test_membership_change_is_fail_closed_before_role_read(self) -> None:
        changed = peer_snapshot(
            {
                "node-a": PeerHealthState.READY,
                "node-b": PeerHealthState.READY,
            },
            revisions={"node-b": "state-node-b-v2"},
            journal_seq=8,
        )
        with self.assertRaisesRegex(
            HARollingCheckpointError,
            "rolling_membership_changed",
        ):
            self.seal(snapshot=changed)

    def test_tampered_checkpoint_identity_is_rejected(self) -> None:
        checkpoint = self.seal()
        tampered = replace(checkpoint, completed_revision="state-node-b-tampered")
        with self.assertRaisesRegex(
            HARollingCheckpointError,
            "rolling_checkpoint_identity_invalid",
        ):
            revalidate_rolling_step_checkpoint(
                checkpoint=tampered,
                completion_peer_snapshot=self.completed,
                role_authority=self.store,
            )

    def test_unsafe_original_plan_cannot_be_checkpointed(self) -> None:
        unsafe = self.evaluate(target_node_id="node-a")
        self.assertFalse(unsafe.safe)
        with self.assertRaisesRegex(
            HARollingCheckpointError,
            "completed_plan_was_not_safe",
        ):
            seal_rolling_step_checkpoint(
                decision=unsafe,
                pre_step_peer_snapshot=self.pre,
                completion_peer_snapshot=self.completed,
                role_authority=self.store,
                expected_completion_peer_snapshot_id=self.completed.snapshot_id,
                expected_completion_peer_journal_seq=self.completed.journal_seq,
                expected_completed_revision="state-node-a",
            )

    def test_single_node_checkpoint_has_no_next_step(self) -> None:
        single_db = sqlite3.connect(":memory:")
        try:
            store = HARoleJournalAuthority(single_db)
            state = store.bootstrap(
                cluster_id="home-cluster",
                assignments=roles(nodes=("node-a",)),
            )
            before = peer_snapshot({"node-a": PeerHealthState.READY}, journal_seq=1)
            completed = peer_snapshot(
                {"node-a": PeerHealthState.READY},
                revisions={"node-a": "state-node-a-v2"},
                journal_seq=2,
            )
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
            checkpoint = seal_rolling_step_checkpoint(
                decision=decision,
                pre_step_peer_snapshot=before,
                completion_peer_snapshot=completed,
                role_authority=store,
                expected_completion_peer_snapshot_id=completed.snapshot_id,
                expected_completion_peer_journal_seq=completed.journal_seq,
                expected_completed_revision="state-node-a-v2",
            )
            with self.assertRaisesRegex(
                HARollingCheckpointError,
                "single_node_has_no_next_rolling_step",
            ):
                evaluate_next_rolling_step(
                    checkpoint=checkpoint,
                    peer_snapshot=completed,
                    role_authority=store,
                    target_node_id="node-a",
                )
        finally:
            single_db.close()


if __name__ == "__main__":
    unittest.main()
