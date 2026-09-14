from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from home_center.authoritative_state import apply_authoritative_snapshot, snapshot_authoritative
from home_center.ha_state import (
    HAStateConflict,
    commit_promotion,
    initialize_membership,
    load_membership,
    load_transition,
    persist_transition,
)
from home_center.manual_failover import (
    NodeEvidence,
    begin_manual_failover,
    promote_membership,
    record_final_sync_verified,
    record_source_fenced,
    record_source_quiesced,
)
from home_center.store import StateStore


REVISION = "a" * 40
DIGEST = "b" * 64
FINAL_DIGEST = "c" * 64


def membership(*, generation: int = 1, writer: str = "node-a") -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-test",
        "generation": generation,
        "writer": writer,
        "members": [
            {"node_id": "node-a", "state": "ready", "roles": ["control-plane"]},
            {"node_id": "node-b", "state": "ready", "roles": ["control-plane"]},
        ],
        "quorum": {
            "mode": "single-writer-manual-failover",
            "automatic_failover": False,
            "witness_id": None,
        },
        "observed_at": "2026-09-14T12:00:00Z",
    }


def evidence(
    node_id: str,
    *,
    active: bool = True,
    fenced: bool = False,
    digest: str = DIGEST,
    sequence: int = 10,
) -> NodeEvidence:
    return NodeEvidence(
        node_id=node_id,
        version="0.64.0",
        revision=REVISION,
        ready=True,
        service_active=active,
        fenced=fenced,
        authoritative_sha256=digest,
        source_sequence=sequence,
    )


class HAStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.node_a = StateStore(root / "node-a.db", b"a" * 32, "cluster-test")
        self.node_b = StateStore(root / "node-b.db", b"b" * 32, "cluster-test")

    def tearDown(self) -> None:
        self.node_a.close()
        self.node_b.close()
        self.temp.cleanup()

    def _source_fenced_transition(self) -> tuple[dict, object]:
        current = membership()
        transition = begin_manual_failover(
            current,
            target_node_id="node-b",
            source=evidence("node-a"),
            target=evidence("node-b", fenced=True),
            transition_id="transition-test",
        )
        transition = record_source_quiesced(transition, evidence("node-a", active=False))
        transition = record_final_sync_verified(
            transition,
            source=evidence("node-a", active=False, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        transition = record_source_fenced(
            transition,
            evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        return current, transition

    def test_membership_initialization_is_idempotent_but_conflicting_reinitialization_fails(self) -> None:
        initial = membership()
        self.assertTrue(initialize_membership(self.node_a._connection, initial))
        self.assertFalse(initialize_membership(self.node_a._connection, initial))
        self.assertEqual(initial, load_membership(self.node_a._connection))

        with self.assertRaisesRegex(HAStateConflict, "already_initialized"):
            initialize_membership(self.node_a._connection, membership(writer="node-b"))

    def test_transition_journal_is_compare_and_set_guarded(self) -> None:
        initialize_membership(self.node_a._connection, membership())
        transition = begin_manual_failover(
            membership(),
            target_node_id="node-b",
            source=evidence("node-a"),
            target=evidence("node-b", fenced=True),
            transition_id="transition-test",
        )
        self.assertTrue(persist_transition(self.node_a._connection, transition.as_dict(), expected_phase=None))
        self.assertFalse(persist_transition(self.node_a._connection, transition.as_dict(), expected_phase=None))

        quiesced = record_source_quiesced(transition, evidence("node-a", active=False))
        self.assertTrue(
            persist_transition(self.node_a._connection, quiesced.as_dict(), expected_phase="planned")
        )
        self.assertEqual("source_quiesced", load_transition(self.node_a._connection)["phase"])

        with self.assertRaisesRegex(HAStateConflict, "phase_changed"):
            persist_transition(self.node_a._connection, transition.as_dict(), expected_phase="planned")

    def test_writer_generation_and_transition_phase_commit_atomically(self) -> None:
        current, transition = self._source_fenced_transition()
        initialize_membership(self.node_a._connection, current)
        planned = begin_manual_failover(
            current,
            target_node_id="node-b",
            source=evidence("node-a"),
            target=evidence("node-b", fenced=True),
            transition_id="transition-test",
        )
        persist_transition(self.node_a._connection, planned.as_dict(), expected_phase=None)
        quiesced = record_source_quiesced(planned, evidence("node-a", active=False))
        persist_transition(self.node_a._connection, quiesced.as_dict(), expected_phase="planned")
        synced = record_final_sync_verified(
            quiesced,
            source=evidence("node-a", active=False, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        persist_transition(self.node_a._connection, synced.as_dict(), expected_phase="source_quiesced")
        persist_transition(self.node_a._connection, transition.as_dict(), expected_phase="final_sync_verified")

        promoted_transition, promoted_membership = promote_membership(transition, current)
        commit_promotion(
            self.node_a._connection,
            before_membership=current,
            after_membership=promoted_membership,
            before_transition=transition.as_dict(),
            after_transition=promoted_transition.as_dict(),
        )

        self.assertEqual(2, load_membership(self.node_a._connection)["generation"])
        self.assertEqual("node-b", load_membership(self.node_a._connection)["writer"])
        self.assertEqual("target_promoted", load_transition(self.node_a._connection)["phase"])

        with self.assertRaisesRegex(HAStateConflict, "membership_changed_before_promotion"):
            commit_promotion(
                self.node_a._connection,
                before_membership=current,
                after_membership=promoted_membership,
                before_transition=transition.as_dict(),
                after_transition=promoted_transition.as_dict(),
            )

    def test_promoted_membership_and_journal_can_reverse_mirror_to_returning_node(self) -> None:
        current, transition = self._source_fenced_transition()
        initialize_membership(self.node_b._connection, current)
        persist_transition(self.node_b._connection, transition.as_dict(), expected_phase=None)
        promoted_transition, promoted_membership = promote_membership(transition, current)
        commit_promotion(
            self.node_b._connection,
            before_membership=current,
            after_membership=promoted_membership,
            before_transition=transition.as_dict(),
            after_transition=promoted_transition.as_dict(),
        )
        self.node_b.set_meta("writer.created.state", {"writer": "node-b", "generation": 2})

        reverse_snapshot = snapshot_authoritative(self.node_b._connection)
        result = apply_authoritative_snapshot(self.node_a._connection, reverse_snapshot)

        self.assertTrue(result["changed"])
        self.assertEqual(reverse_snapshot, snapshot_authoritative(self.node_a._connection))
        self.assertEqual("node-b", load_membership(self.node_a._connection)["writer"])
        self.assertEqual(2, load_membership(self.node_a._connection)["generation"])
        self.assertEqual("target_promoted", load_transition(self.node_a._connection)["phase"])
        self.assertEqual(
            {"writer": "node-b", "generation": 2},
            self.node_a.get_meta("writer.created.state"),
        )


if __name__ == "__main__":
    unittest.main()
