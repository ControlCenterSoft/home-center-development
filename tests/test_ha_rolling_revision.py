from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from dataclasses import replace

from home_center.ha_peer_snapshot import HAPeerStateSnapshot, ObservedPeerState, PeerHealthState
from home_center.ha_role_journal import HARoleJournalAuthority, HARoleTransitionKind
from home_center.ha_rolling_authority import HARoleAssignment
from home_center.ha_rolling_revision import (
    HARollingRevisionError,
    evaluate_revision_bound_rolling_safety,
    revalidate_revision_bound_rolling_safety,
)
from home_center.ha_rolling_safety import NodeRole


def roles(writer: str = "node-a") -> tuple[HARoleAssignment, ...]:
    standby = "node-b" if writer == "node-a" else "node-a"
    return (
        HARoleAssignment(writer, NodeRole.WRITER),
        HARoleAssignment(standby, NodeRole.STANDBY),
    )


def peer_snapshot(*node_ids: str, journal_seq: int = 7) -> HAPeerStateSnapshot:
    members = tuple(
        ObservedPeerState(node_id, "untrusted", PeerHealthState.READY, f"state-{node_id}")
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


class MutatingAuthority:
    def __init__(self, store: HARoleJournalAuthority, initial) -> None:
        self.store = store
        self.initial = initial
        self.mutated = False

    def state_for(self, *, cluster_id: str, node_ids: tuple[str, ...]):
        return self.store.state_for(cluster_id=cluster_id, node_ids=node_ids)

    def snapshot_for(self, *, cluster_id: str, node_ids: tuple[str, ...]):
        snapshot = self.store.snapshot_for(cluster_id=cluster_id, node_ids=node_ids)
        if not self.mutated:
            self.store.transition(
                cluster_id=cluster_id,
                assignments=roles("node-b"),
                transition_kind=HARoleTransitionKind.FAILOVER,
                expected_assignment_id=self.initial.snapshot.assignment_id,
                expected_role_epoch=self.initial.snapshot.role_epoch,
                expected_resource_version=self.initial.resource_version,
                expected_journal_seq=self.initial.journal_seq,
            )
            self.mutated = True
        return snapshot


class MutationFlagAuthority:
    def __init__(self, store: HARoleJournalAuthority) -> None:
        self.store = store

    def state_for(self, *, cluster_id: str, node_ids: tuple[str, ...]):
        state = self.store.state_for(cluster_id=cluster_id, node_ids=node_ids)
        return replace(state, production_mutation_enabled=True)

    def snapshot_for(self, *, cluster_id: str, node_ids: tuple[str, ...]):
        return self.store.snapshot_for(cluster_id=cluster_id, node_ids=node_ids)


class RevisionBoundRollingSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.store = HARoleJournalAuthority(self.db)
        self.initial = self.store.bootstrap(cluster_id="home-cluster", assignments=roles())
        self.peers = peer_snapshot("node-a", "node-b")

    def tearDown(self) -> None:
        self.db.close()

    def evaluate(self, *, authority=None, state=None, snapshot=None, **kwargs):
        authority = authority or self.store
        state = state or self.initial
        snapshot = snapshot or self.peers
        return evaluate_revision_bound_rolling_safety(
            peer_snapshot=snapshot,
            role_authority=authority,
            target_node_id=kwargs.pop("target_node_id", "node-b"),
            minimum_ready_nodes=kwargs.pop("minimum_ready_nodes", 1),
            expected_peer_snapshot_id=kwargs.pop(
                "expected_peer_snapshot_id", snapshot.snapshot_id
            ),
            expected_peer_journal_seq=kwargs.pop(
                "expected_peer_journal_seq", snapshot.journal_seq
            ),
            expected_role_assignment_id=kwargs.pop(
                "expected_role_assignment_id", state.snapshot.assignment_id
            ),
            expected_role_epoch=kwargs.pop("expected_role_epoch", state.snapshot.role_epoch),
            expected_role_resource_version=kwargs.pop(
                "expected_role_resource_version", state.resource_version
            ),
            expected_role_journal_seq=kwargs.pop(
                "expected_role_journal_seq", state.journal_seq
            ),
            expected_role_transition_id=kwargs.pop(
                "expected_role_transition_id", state.transition_id
            ),
            **kwargs,
        )

    def failover(self):
        return self.store.transition(
            cluster_id="home-cluster",
            assignments=roles("node-b"),
            transition_kind=HARoleTransitionKind.FAILOVER,
            expected_assignment_id=self.initial.snapshot.assignment_id,
            expected_role_epoch=self.initial.snapshot.role_epoch,
            expected_resource_version=self.initial.resource_version,
            expected_journal_seq=self.initial.journal_seq,
        )

    def test_binds_exact_durable_role_revision_without_mutation(self) -> None:
        decision = self.evaluate()
        self.assertTrue(decision.safe)
        self.assertEqual(self.initial.resource_version, decision.role_resource_version)
        self.assertEqual(self.initial.journal_seq, decision.role_journal_seq)
        self.assertEqual(self.initial.transition_id, decision.role_transition_id)
        self.assertFalse(decision.production_mutation_enabled)
        self.assertEqual(1, len(self.store.journal_entries(cluster_id="home-cluster")))

    def test_identity_is_deterministic_for_same_evidence(self) -> None:
        first = self.evaluate()
        second = self.evaluate()
        self.assertEqual(first.plan_id, second.plan_id)
        self.assertEqual(first, second)

    def test_exact_revalidation_succeeds_without_journal_write(self) -> None:
        decision = self.evaluate()
        fresh = revalidate_revision_bound_rolling_safety(
            decision=decision,
            peer_snapshot=self.peers,
            role_authority=self.store,
        )
        self.assertEqual(decision, fresh)
        self.assertEqual(1, len(self.store.journal_entries(cluster_id="home-cluster")))

    def test_resource_version_drift_is_fail_closed(self) -> None:
        self.failover()
        with self.assertRaisesRegex(HARollingRevisionError, "ha_role_resource_version_stale"):
            self.evaluate()

    def test_role_journal_drift_is_fail_closed(self) -> None:
        self.failover()
        failed_over = self.store.state_for(
            cluster_id="home-cluster", node_ids=("node-a", "node-b")
        )
        with self.assertRaisesRegex(HARollingRevisionError, "ha_role_journal_stale"):
            self.evaluate(
                state=failed_over,
                expected_role_journal_seq=self.initial.journal_seq,
            )

    def test_transition_id_drift_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(HARollingRevisionError, "ha_role_transition_stale"):
            self.evaluate(expected_role_transition_id="ha-role-transition-stale")

    def test_saved_decision_is_stale_after_failover(self) -> None:
        decision = self.evaluate()
        self.failover()
        with self.assertRaisesRegex(HARollingRevisionError, "ha_role_resource_version_stale"):
            revalidate_revision_bound_rolling_safety(
                decision=decision,
                peer_snapshot=self.peers,
                role_authority=self.store,
            )

    def test_transition_during_evaluation_is_rejected(self) -> None:
        authority = MutatingAuthority(self.store, self.initial)
        with self.assertRaisesRegex(
            HARollingRevisionError, "ha_role_revision_changed_during_evaluation"
        ):
            self.evaluate(authority=authority)

    def test_tampered_saved_decision_identity_is_rejected(self) -> None:
        decision = self.evaluate()
        tampered = replace(decision, role_transition_id="ha-role-transition-tampered")
        with self.assertRaisesRegex(
            HARollingRevisionError, "rolling_revision_decision_identity_invalid"
        ):
            revalidate_revision_bound_rolling_safety(
                decision=tampered,
                peer_snapshot=self.peers,
                role_authority=self.store,
            )

    def test_mutation_capable_authority_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            HARollingRevisionError, "role_authority_mutation_enabled"
        ):
            self.evaluate(authority=MutationFlagAuthority(self.store))

    def test_single_node_mode_preserves_explicit_downtime_ack(self) -> None:
        single_db = sqlite3.connect(":memory:")
        try:
            store = HARoleJournalAuthority(single_db)
            state = store.bootstrap(
                cluster_id="home-cluster",
                assignments=(HARoleAssignment("node-a", NodeRole.WRITER),),
            )
            snapshot = peer_snapshot("node-a", journal_seq=1)
            decision = evaluate_revision_bound_rolling_safety(
                peer_snapshot=snapshot,
                role_authority=store,
                target_node_id="node-a",
                minimum_ready_nodes=0,
                expected_peer_snapshot_id=snapshot.snapshot_id,
                expected_peer_journal_seq=snapshot.journal_seq,
                expected_role_assignment_id=state.snapshot.assignment_id,
                expected_role_epoch=state.snapshot.role_epoch,
                expected_role_resource_version=state.resource_version,
                expected_role_journal_seq=state.journal_seq,
                expected_role_transition_id=state.transition_id,
                single_node_downtime_acknowledged=True,
            )
            self.assertTrue(decision.safe)
            self.assertTrue(decision.single_node_downtime_acknowledged)
            self.assertFalse(decision.production_mutation_enabled)
        finally:
            single_db.close()


if __name__ == "__main__":
    unittest.main()
