from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from home_center.ha_role_journal import (
    HARoleJournalAuthority,
    HARoleJournalError,
    HARoleTransitionKind,
)
from home_center.ha_rolling_authority import HARoleAssignment, HARoleCoordinationError
from home_center.ha_rolling_safety import NodeRole


def roles(writer: str = "node-a") -> tuple[HARoleAssignment, ...]:
    standby = "node-b" if writer == "node-a" else "node-a"
    return (
        HARoleAssignment(writer, NodeRole.WRITER),
        HARoleAssignment(standby, NodeRole.STANDBY),
    )


class HARoleJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.store = HARoleJournalAuthority(self.db)

    def bootstrap(self):
        return self.store.bootstrap(cluster_id="home-cluster", assignments=roles())

    def failover(self, state):
        return self.store.transition(
            cluster_id="home-cluster",
            assignments=roles("node-b"),
            transition_kind=HARoleTransitionKind.FAILOVER,
            expected_assignment_id=state.snapshot.assignment_id,
            expected_role_epoch=state.snapshot.role_epoch,
            expected_resource_version=state.resource_version,
            expected_journal_seq=state.journal_seq,
        )

    def test_bootstrap_is_deterministic_and_exact_replay_is_idempotent(self) -> None:
        first = self.bootstrap()
        second = self.bootstrap()
        self.assertEqual(first, second)
        self.assertEqual(0, first.snapshot.role_epoch)
        self.assertEqual(1, first.resource_version)
        self.assertEqual(1, first.journal_seq)
        self.assertEqual(1, len(self.store.journal_entries(cluster_id="home-cluster")))

    def test_snapshot_for_implements_exact_membership_authority(self) -> None:
        state = self.bootstrap()
        snapshot = self.store.snapshot_for(
            cluster_id="home-cluster", node_ids=("node-b", "node-a")
        )
        self.assertEqual(state.snapshot, snapshot)
        self.assertEqual(NodeRole.WRITER, snapshot.assignments[0].role)
        with self.assertRaisesRegex(HARoleJournalError, "role_membership_mismatch"):
            self.store.snapshot_for(cluster_id="home-cluster", node_ids=("node-a",))

    def test_failover_is_atomic_and_monotonic(self) -> None:
        initial = self.bootstrap()
        changed = self.failover(initial)
        self.assertEqual(1, changed.snapshot.role_epoch)
        self.assertEqual(2, changed.resource_version)
        self.assertEqual(2, changed.journal_seq)
        self.assertEqual(NodeRole.STANDBY, changed.snapshot.assignments[0].role)
        self.assertEqual(NodeRole.WRITER, changed.snapshot.assignments[1].role)
        journal = self.store.journal_entries(cluster_id="home-cluster")
        self.assertEqual(["bootstrap", "failover"], [entry.transition_kind for entry in journal])
        self.assertEqual(initial.snapshot.assignment_id, journal[-1].previous_assignment_id)

    def test_bootstrap_identity_is_order_independent(self) -> None:
        first = self.bootstrap()
        other_db = sqlite3.connect(":memory:")
        other = HARoleJournalAuthority(other_db)
        reversed_state = other.bootstrap(
            cluster_id="home-cluster", assignments=tuple(reversed(roles()))
        )
        self.assertEqual(first.snapshot.assignment_id, reversed_state.snapshot.assignment_id)
        self.assertEqual(first.transition_id, reversed_state.transition_id)
        other_db.close()

    def test_file_backed_state_reopens_with_verified_journal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "ha.sqlite3"
            connection = sqlite3.connect(path)
            store = HARoleJournalAuthority(connection)
            initial = store.bootstrap(cluster_id="home-cluster", assignments=roles())
            changed = store.transition(
                cluster_id="home-cluster",
                assignments=roles("node-b"),
                transition_kind=HARoleTransitionKind.FAILOVER,
                expected_assignment_id=initial.snapshot.assignment_id,
                expected_role_epoch=initial.snapshot.role_epoch,
                expected_resource_version=initial.resource_version,
                expected_journal_seq=initial.journal_seq,
            )
            connection.close()

            reopened_connection = sqlite3.connect(path)
            reopened = HARoleJournalAuthority(reopened_connection)
            observed = reopened.state_for(
                cluster_id="home-cluster", node_ids=("node-a", "node-b")
            )
            self.assertEqual(changed, observed)
            self.assertEqual(2, len(reopened.journal_entries(cluster_id="home-cluster")))
            reopened_connection.close()

    def test_exact_transition_replay_is_idempotent_until_superseded(self) -> None:
        initial = self.bootstrap()
        first = self.failover(initial)
        replay = self.failover(initial)
        self.assertEqual(first, replay)
        self.assertEqual(2, len(self.store.journal_entries(cluster_id="home-cluster")))

    def test_stale_resource_version_is_fail_closed(self) -> None:
        initial = self.bootstrap()
        with self.assertRaisesRegex(HARoleJournalError, "role_resource_version_stale"):
            self.store.transition(
                cluster_id="home-cluster",
                assignments=roles("node-b"),
                transition_kind=HARoleTransitionKind.FAILOVER,
                expected_assignment_id=initial.snapshot.assignment_id,
                expected_role_epoch=initial.snapshot.role_epoch,
                expected_resource_version=99,
                expected_journal_seq=initial.journal_seq,
            )
        self.assertEqual(
            initial,
            self.store.state_for(
                cluster_id="home-cluster", node_ids=("node-a", "node-b")
            ),
        )

    def test_stale_journal_sequence_is_fail_closed(self) -> None:
        initial = self.bootstrap()
        with self.assertRaisesRegex(HARoleJournalError, "role_journal_stale"):
            self.store.transition(
                cluster_id="home-cluster",
                assignments=roles("node-b"),
                transition_kind=HARoleTransitionKind.FAILOVER,
                expected_assignment_id=initial.snapshot.assignment_id,
                expected_role_epoch=initial.snapshot.role_epoch,
                expected_resource_version=initial.resource_version,
                expected_journal_seq=99,
            )
        self.assertEqual(1, len(self.store.journal_entries(cluster_id="home-cluster")))

    def test_stale_assignment_is_fail_closed(self) -> None:
        initial = self.bootstrap()
        with self.assertRaisesRegex(HARoleJournalError, "role_assignment_stale"):
            self.store.transition(
                cluster_id="home-cluster",
                assignments=roles("node-b"),
                transition_kind=HARoleTransitionKind.FAILOVER,
                expected_assignment_id="ha-role-stale",
                expected_role_epoch=initial.snapshot.role_epoch,
                expected_resource_version=initial.resource_version,
                expected_journal_seq=initial.journal_seq,
            )

    def test_noop_role_transition_is_rejected(self) -> None:
        initial = self.bootstrap()
        with self.assertRaisesRegex(HARoleJournalError, "role_transition_noop"):
            self.store.transition(
                cluster_id="home-cluster",
                assignments=roles(),
                transition_kind=HARoleTransitionKind.ELECTION,
                expected_assignment_id=initial.snapshot.assignment_id,
                expected_role_epoch=initial.snapshot.role_epoch,
                expected_resource_version=initial.resource_version,
                expected_journal_seq=initial.journal_seq,
            )

    def test_split_brain_assignment_never_reaches_journal(self) -> None:
        initial = self.bootstrap()
        with self.assertRaisesRegex(HARoleCoordinationError, "writer_assignment_not_unique"):
            self.store.transition(
                cluster_id="home-cluster",
                assignments=(
                    HARoleAssignment("node-a", NodeRole.WRITER),
                    HARoleAssignment("node-b", NodeRole.WRITER),
                ),
                transition_kind=HARoleTransitionKind.FAILOVER,
                expected_assignment_id=initial.snapshot.assignment_id,
                expected_role_epoch=initial.snapshot.role_epoch,
                expected_resource_version=initial.resource_version,
                expected_journal_seq=initial.journal_seq,
            )
        self.assertEqual(1, len(self.store.journal_entries(cluster_id="home-cluster")))

    def test_single_node_bootstrap_is_supported(self) -> None:
        state = self.store.bootstrap(
            cluster_id="single-home",
            assignments=(HARoleAssignment("node-a", NodeRole.WRITER),),
        )
        self.assertEqual(("node-a",), tuple(x.node_id for x in state.snapshot.assignments))
        self.assertEqual(1, state.resource_version)

    def test_superseded_replay_is_rejected(self) -> None:
        initial = self.bootstrap()
        failed_over = self.failover(initial)
        recovered = self.store.transition(
            cluster_id="home-cluster",
            assignments=roles("node-a"),
            transition_kind=HARoleTransitionKind.RECOVERY,
            expected_assignment_id=failed_over.snapshot.assignment_id,
            expected_role_epoch=failed_over.snapshot.role_epoch,
            expected_resource_version=failed_over.resource_version,
            expected_journal_seq=failed_over.journal_seq,
        )
        self.assertEqual(2, recovered.snapshot.role_epoch)
        with self.assertRaisesRegex(HARoleJournalError, "role_transition_superseded"):
            self.failover(initial)

    def test_membership_change_is_rejected(self) -> None:
        initial = self.bootstrap()
        with self.assertRaisesRegex(HARoleJournalError, "role_membership_change_rejected"):
            self.store.transition(
                cluster_id="home-cluster",
                assignments=(
                    HARoleAssignment("node-a", NodeRole.STANDBY),
                    HARoleAssignment("node-b", NodeRole.WRITER),
                    HARoleAssignment("node-c", NodeRole.STANDBY),
                ),
                transition_kind=HARoleTransitionKind.FAILOVER,
                expected_assignment_id=initial.snapshot.assignment_id,
                expected_role_epoch=initial.snapshot.role_epoch,
                expected_resource_version=initial.resource_version,
                expected_journal_seq=initial.journal_seq,
            )
        self.assertEqual(1, len(self.store.journal_entries(cluster_id="home-cluster")))

    def test_tampered_current_journal_fails_closed(self) -> None:
        initial = self.bootstrap()
        self.db.execute(
            "UPDATE hc_ha_role_journal SET transition_kind = 'recovery' WHERE cluster_id = ?",
            ("home-cluster",),
        )
        self.db.commit()
        with self.assertRaisesRegex(HARoleJournalError, "role_state_journal_mismatch"):
            self.store.state_for(cluster_id="home-cluster", node_ids=("node-a", "node-b"))
        self.assertFalse(initial.production_mutation_enabled)

    def test_transition_kind_is_typed(self) -> None:
        initial = self.bootstrap()
        with self.assertRaisesRegex(HARoleJournalError, "invalid_role_transition_kind"):
            self.store.transition(
                cluster_id="home-cluster",
                assignments=roles("node-b"),
                transition_kind="shell",  # type: ignore[arg-type]
                expected_assignment_id=initial.snapshot.assignment_id,
                expected_role_epoch=initial.snapshot.role_epoch,
                expected_resource_version=initial.resource_version,
                expected_journal_seq=initial.journal_seq,
            )


if __name__ == "__main__":
    unittest.main()
