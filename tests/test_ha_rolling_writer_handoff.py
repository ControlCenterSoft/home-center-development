from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from dataclasses import replace

from home_center.ha_peer_snapshot import (
    HAPeerSnapshotError,
    HAPeerStateSnapshot,
    ObservedPeerState,
    PeerHealthState,
)
from home_center.ha_role_journal import (
    HARoleJournalAuthority,
    HARoleJournalError,
    HARoleTransitionKind,
)
from home_center.ha_rolling_authority import HARoleAssignment
from home_center.ha_rolling_revision import evaluate_revision_bound_rolling_safety
from home_center.ha_rolling_safety import NodeRole
from home_center.ha_rolling_writer_handoff import (
    HARollingWriterHandoffError,
    commit_rolling_writer_handoff,
    evaluate_rolling_after_writer_handoff,
    plan_rolling_writer_handoff,
    revalidate_rolling_writer_handoff_receipt,
)


NODES = ("node-a", "node-b", "node-c")


def roles(
    writer: str = "node-a",
    node_ids: tuple[str, ...] = NODES,
) -> tuple[HARoleAssignment, ...]:
    return tuple(
        HARoleAssignment(
            node_id,
            NodeRole.WRITER if node_id == writer else NodeRole.STANDBY,
        )
        for node_id in node_ids
    )


def peer_snapshot(
    *,
    states: dict[str, PeerHealthState] | None = None,
    journal_seq: int = 7,
    node_ids: tuple[str, ...] = NODES,
) -> HAPeerStateSnapshot:
    states = states or {}
    members = tuple(
        ObservedPeerState(
            node_id,
            "untrusted",
            states.get(node_id, PeerHealthState.READY),
            f"state-{node_id}-{states.get(node_id, PeerHealthState.READY).value}",
        )
        for node_id in sorted(node_ids)
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


class RollingWriterHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.store = HARoleJournalAuthority(self.db)
        self.initial = self.store.bootstrap(
            cluster_id="home-cluster",
            assignments=roles(),
        )
        self.peers = peer_snapshot()
        self.decision = self.evaluate(self.initial, self.peers)

    def tearDown(self) -> None:
        self.db.close()

    def evaluate(
        self,
        state,
        snapshot: HAPeerStateSnapshot,
        *,
        target_node_id: str = "node-a",
        minimum_ready_nodes: int = 2,
        single_node_downtime_acknowledged: bool = False,
        authority=None,
    ):
        authority = authority or self.store
        return evaluate_revision_bound_rolling_safety(
            peer_snapshot=snapshot,
            role_authority=authority,
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

    def test_plan_is_deterministic_and_selects_ready_standby(self) -> None:
        first = plan_rolling_writer_handoff(
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        second = plan_rolling_writer_handoff(
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        self.assertEqual(first, second)
        self.assertEqual("node-b", first.successor_writer_node_id)
        self.assertEqual(("writer_handoff_required",), self.decision.blockers)
        self.assertTrue(first.cas_bound)
        self.assertTrue(first.single_use_by_cas)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.host_mutation_authorized)
        self.assertFalse(first.production_mutation_enabled)

    def test_commit_is_typed_atomic_and_unblocks_same_target(self) -> None:
        intent = plan_rolling_writer_handoff(
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        receipt = commit_rolling_writer_handoff(
            intent=intent,
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        state = self.store.state_for(
            cluster_id="home-cluster",
            node_ids=NODES,
        )
        writers = tuple(
            item.node_id for item in state.snapshot.assignments if item.role is NodeRole.WRITER
        )
        self.assertEqual(("node-b",), writers)
        self.assertEqual(HARoleTransitionKind.ELECTION.value, state.transition_kind)
        self.assertEqual(self.initial.resource_version + 1, state.resource_version)
        self.assertFalse(receipt.failover_authorized)
        self.assertFalse(receipt.host_mutation_authorized)

        next_decision = evaluate_rolling_after_writer_handoff(
            receipt=receipt,
            intent=intent,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        self.assertTrue(next_decision.safe)
        self.assertEqual((), next_decision.blockers)
        self.assertEqual("node-a", next_decision.target_node_id)
        self.assertEqual("node-b", next_decision.writer_node_id)
        self.assertFalse(next_decision.production_mutation_enabled)

    def test_exact_commit_retry_is_idempotent_after_ambiguous_result(self) -> None:
        intent = plan_rolling_writer_handoff(
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        first = commit_rolling_writer_handoff(
            intent=intent,
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        second = commit_rolling_writer_handoff(
            intent=intent,
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        self.assertEqual(first, second)
        self.assertEqual(
            2,
            len(self.store.journal_entries(cluster_id="home-cluster")),
        )

    def test_ready_successor_selection_is_deterministic_under_partial_degradation(self) -> None:
        peers = peer_snapshot(states={"node-b": PeerHealthState.DEGRADED})
        decision = self.evaluate(
            self.initial,
            peers,
            minimum_ready_nodes=1,
        )
        self.assertEqual(("writer_handoff_required",), decision.blockers)
        intent = plan_rolling_writer_handoff(
            decision=decision,
            peer_snapshot=peers,
            role_authority=self.store,
        )
        self.assertEqual("node-c", intent.successor_writer_node_id)

    def test_handoff_requires_majority_quorum_even_with_lower_ready_floor(self) -> None:
        node_ids = ("node-a", "node-b", "node-c", "node-d", "node-e")
        db = sqlite3.connect(":memory:")
        try:
            store = HARoleJournalAuthority(db)
            state = store.bootstrap(
                cluster_id="home-cluster",
                assignments=roles("node-a", node_ids),
            )
            peers = peer_snapshot(
                node_ids=node_ids,
                states={
                    "node-c": PeerHealthState.DEGRADED,
                    "node-d": PeerHealthState.DEGRADED,
                    "node-e": PeerHealthState.DEGRADED,
                },
            )
            decision = self.evaluate(
                state,
                peers,
                minimum_ready_nodes=1,
                authority=store,
            )
            self.assertEqual(("writer_handoff_required",), decision.blockers)
            with self.assertRaisesRegex(
                HARollingWriterHandoffError,
                "rolling_writer_handoff_quorum_not_met",
            ):
                plan_rolling_writer_handoff(
                    decision=decision,
                    peer_snapshot=peers,
                    role_authority=store,
                )
            self.assertEqual(
                1,
                len(store.journal_entries(cluster_id="home-cluster")),
            )
        finally:
            db.close()

    def test_peer_drift_fails_closed_before_role_transition(self) -> None:
        intent = plan_rolling_writer_handoff(
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        drifted = peer_snapshot(journal_seq=self.peers.journal_seq + 1)
        with self.assertRaisesRegex(HAPeerSnapshotError, "ha_snapshot_stale"):
            commit_rolling_writer_handoff(
                intent=intent,
                decision=self.decision,
                peer_snapshot=drifted,
                role_authority=self.store,
            )
        self.assertEqual(
            1,
            len(self.store.journal_entries(cluster_id="home-cluster")),
        )

    def test_unrelated_role_drift_fails_closed(self) -> None:
        intent = plan_rolling_writer_handoff(
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
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
            HARoleJournalError,
            "role_(transition_superseded|assignment_stale|epoch_stale|resource_version_stale)",
        ):
            commit_rolling_writer_handoff(
                intent=intent,
                decision=self.decision,
                peer_snapshot=self.peers,
                role_authority=self.store,
            )

    def test_superseded_handoff_replay_is_rejected(self) -> None:
        intent = plan_rolling_writer_handoff(
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        receipt = commit_rolling_writer_handoff(
            intent=intent,
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        current = self.store.state_for(
            cluster_id="home-cluster",
            node_ids=NODES,
        )
        self.store.transition(
            cluster_id="home-cluster",
            assignments=roles("node-a"),
            transition_kind=HARoleTransitionKind.RECOVERY,
            expected_assignment_id=current.snapshot.assignment_id,
            expected_role_epoch=current.snapshot.role_epoch,
            expected_resource_version=current.resource_version,
            expected_journal_seq=current.journal_seq,
        )
        with self.assertRaisesRegex(HARoleJournalError, "role_transition_superseded"):
            commit_rolling_writer_handoff(
                intent=intent,
                decision=self.decision,
                peer_snapshot=self.peers,
                role_authority=self.store,
            )
        with self.assertRaisesRegex(
            HARollingWriterHandoffError,
            "post_revision_invalid|receipt_stale",
        ):
            revalidate_rolling_writer_handoff_receipt(
                receipt=receipt,
                intent=intent,
                peer_snapshot=self.peers,
                role_authority=self.store,
            )

    def test_tampered_authority_is_rejected(self) -> None:
        intent = plan_rolling_writer_handoff(
            decision=self.decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        tampered = replace(intent, failover_authorized=True)
        with self.assertRaisesRegex(
            HARollingWriterHandoffError,
            "intent_authority_invalid",
        ):
            commit_rolling_writer_handoff(
                intent=tampered,
                decision=self.decision,
                peer_snapshot=self.peers,
                role_authority=self.store,
            )

    def test_single_node_keeps_downtime_path_without_handoff(self) -> None:
        db = sqlite3.connect(":memory:")
        try:
            store = HARoleJournalAuthority(db)
            state = store.bootstrap(
                cluster_id="home-cluster",
                assignments=(HARoleAssignment("node-a", NodeRole.WRITER),),
            )
            peers = peer_snapshot(node_ids=("node-a",), journal_seq=1)
            decision = self.evaluate(
                state,
                peers,
                target_node_id="node-a",
                minimum_ready_nodes=0,
                single_node_downtime_acknowledged=True,
                authority=store,
            )
            self.assertTrue(decision.safe)
            with self.assertRaisesRegex(
                HARollingWriterHandoffError,
                "rolling_writer_handoff_not_required",
            ):
                plan_rolling_writer_handoff(
                    decision=decision,
                    peer_snapshot=peers,
                    role_authority=store,
                )
            self.assertEqual(
                1,
                len(store.journal_entries(cluster_id="home-cluster")),
            )
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
