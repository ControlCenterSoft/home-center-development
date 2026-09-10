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
from home_center.ha_rolling_revision import evaluate_revision_bound_rolling_safety
from home_center.ha_rolling_safety import NodeRole
from home_center.ha_rolling_writer_handoff import (
    commit_rolling_writer_handoff,
    plan_rolling_writer_handoff,
)
from home_center.ha_rolling_writer_handoff_recovery import (
    HARollingWriterHandoffRecoveryError,
    WriterHandoffRecoveryDisposition,
    assess_rolling_writer_handoff_recovery,
    revalidate_rolling_writer_handoff_recovery_assessment,
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


class RollingWriterHandoffRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.store = HARoleJournalAuthority(self.db)
        self.initial = self.store.bootstrap(
            cluster_id="home-cluster",
            assignments=roles(),
        )
        self.peers = peer_snapshot()
        decision = self.evaluate(self.initial, self.peers)
        self.intent = plan_rolling_writer_handoff(
            decision=decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        self.receipt = commit_rolling_writer_handoff(
            intent=self.intent,
            decision=decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )

    def tearDown(self) -> None:
        self.db.close()

    def evaluate(
        self,
        state,
        snapshot: HAPeerStateSnapshot,
        *,
        target_node_id: str = "node-a",
        minimum_ready_nodes: int = 2,
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
        )

    def assess(self, snapshot: HAPeerStateSnapshot):
        return assess_rolling_writer_handoff_recovery(
            intent=self.intent,
            receipt=self.receipt,
            peer_snapshot=snapshot,
            role_authority=self.store,
        )

    def test_healthy_handoff_is_deterministic_and_non_mutating(self) -> None:
        first = self.assess(self.peers)
        for _ in range(100):
            self.assertEqual(first, self.assess(self.peers))
        self.assertEqual(WriterHandoffRecoveryDisposition.HEALTHY, first.disposition)
        self.assertEqual("handoff_healthy", first.reason)
        self.assertFalse(first.fencing_required)
        self.assertFalse(first.reconciliation_required)
        self.assertFalse(first.role_transition_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.host_mutation_authorized)
        self.assertFalse(first.production_mutation_enabled)
        self.assertEqual(2, len(self.store.journal_entries(cluster_id="home-cluster")))

    def test_successor_health_loss_requires_fencing_before_any_recovery(self) -> None:
        degraded = peer_snapshot(states={"node-b": PeerHealthState.DEGRADED})
        assessment = self.assess(degraded)
        self.assertEqual(WriterHandoffRecoveryDisposition.RECONCILE, assessment.disposition)
        self.assertEqual("successor_not_ready_fencing_required", assessment.reason)
        self.assertTrue(assessment.fencing_required)
        self.assertTrue(assessment.reconciliation_required)
        self.assertEqual(("node-a", "node-c"), assessment.ready_node_ids)
        self.assertEqual(2, len(self.store.journal_entries(cluster_id="home-cluster")))

    def test_previous_writer_not_ready_blocks_rollback_candidate(self) -> None:
        degraded = peer_snapshot(
            states={
                "node-a": PeerHealthState.DEGRADED,
                "node-b": PeerHealthState.UNREACHABLE,
            }
        )
        assessment = self.assess(degraded)
        self.assertEqual(WriterHandoffRecoveryDisposition.RECONCILE, assessment.disposition)
        self.assertEqual("previous_writer_not_ready", assessment.reason)
        self.assertTrue(assessment.fencing_required)
        self.assertEqual(2, len(self.store.journal_entries(cluster_id="home-cluster")))

    def test_successor_loss_without_majority_is_reconciliation_only(self) -> None:
        degraded = peer_snapshot(
            states={
                "node-b": PeerHealthState.UNREACHABLE,
                "node-c": PeerHealthState.DEGRADED,
            }
        )
        assessment = self.assess(degraded)
        self.assertEqual(WriterHandoffRecoveryDisposition.RECONCILE, assessment.disposition)
        self.assertEqual("majority_quorum_not_met", assessment.reason)
        self.assertEqual(1, assessment.ready_count)
        self.assertEqual(2, assessment.required_quorum_nodes)
        self.assertTrue(assessment.fencing_required)
        self.assertFalse(assessment.role_transition_authorized)

    def test_ready_successor_holds_when_cluster_loses_majority(self) -> None:
        node_ids = ("node-a", "node-b", "node-c", "node-d", "node-e")
        db = sqlite3.connect(":memory:")
        try:
            store = HARoleJournalAuthority(db)
            initial = store.bootstrap(
                cluster_id="home-cluster",
                assignments=roles("node-a", node_ids),
            )
            peers = peer_snapshot(node_ids=node_ids)
            decision = self.evaluate(
                initial,
                peers,
                minimum_ready_nodes=1,
                authority=store,
            )
            intent = plan_rolling_writer_handoff(
                decision=decision,
                peer_snapshot=peers,
                role_authority=store,
            )
            receipt = commit_rolling_writer_handoff(
                intent=intent,
                decision=decision,
                peer_snapshot=peers,
                role_authority=store,
            )
            degraded = peer_snapshot(
                node_ids=node_ids,
                states={
                    "node-a": PeerHealthState.DEGRADED,
                    "node-c": PeerHealthState.DEGRADED,
                    "node-d": PeerHealthState.DEGRADED,
                },
            )
            assessment = assess_rolling_writer_handoff_recovery(
                intent=intent,
                receipt=receipt,
                peer_snapshot=degraded,
                role_authority=store,
            )
            self.assertEqual(WriterHandoffRecoveryDisposition.HOLD, assessment.disposition)
            self.assertEqual("majority_quorum_not_met", assessment.reason)
            self.assertFalse(assessment.fencing_required)
            self.assertTrue(assessment.reconciliation_required)
            self.assertEqual(2, len(store.journal_entries(cluster_id="home-cluster")))
        finally:
            db.close()

    def test_role_journal_drift_invalidates_old_handoff_recovery(self) -> None:
        current = self.store.state_for(cluster_id="home-cluster", node_ids=NODES)
        self.store.transition(
            cluster_id="home-cluster",
            assignments=roles("node-c"),
            transition_kind=HARoleTransitionKind.FAILOVER,
            expected_assignment_id=current.snapshot.assignment_id,
            expected_role_epoch=current.snapshot.role_epoch,
            expected_resource_version=current.resource_version,
            expected_journal_seq=current.journal_seq,
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRecoveryError,
            "rolling_writer_handoff_recovery_role_stale",
        ):
            self.assess(self.peers)

    def test_tampered_source_receipt_authority_fails_closed(self) -> None:
        tampered = replace(self.receipt, failover_authorized=True)
        with self.assertRaisesRegex(
            HARollingWriterHandoffRecoveryError,
            "source_receipt_authority_invalid",
        ):
            assess_rolling_writer_handoff_recovery(
                intent=self.intent,
                receipt=tampered,
                peer_snapshot=self.peers,
                role_authority=self.store,
            )

    def test_tampered_peer_snapshot_identity_fails_closed(self) -> None:
        tampered = replace(self.peers, snapshot_id="ha-state-" + "0" * 64)
        with self.assertRaisesRegex(
            HARollingWriterHandoffRecoveryError,
            "peer_identity_invalid",
        ):
            self.assess(tampered)

    def test_saved_assessment_is_rejected_after_peer_drift(self) -> None:
        degraded = peer_snapshot(states={"node-b": PeerHealthState.DEGRADED})
        assessment = self.assess(degraded)
        changed = peer_snapshot(
            states={
                "node-b": PeerHealthState.DEGRADED,
                "node-c": PeerHealthState.DEGRADED,
            },
            journal_seq=degraded.journal_seq + 1,
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRecoveryError,
            "assessment_stale",
        ):
            revalidate_rolling_writer_handoff_recovery_assessment(
                assessment=assessment,
                intent=self.intent,
                receipt=self.receipt,
                peer_snapshot=changed,
                role_authority=self.store,
            )


if __name__ == "__main__":
    unittest.main()
