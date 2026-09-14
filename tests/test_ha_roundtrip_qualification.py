from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from home_center.authoritative_state import apply_authoritative_snapshot, snapshot_authoritative
from home_center.ha_admission import writer_admission
from home_center.ha_state import (
    commit_promotion,
    initialize_membership,
    load_membership,
    load_transition,
    persist_transition,
)
from home_center.manual_failover import (
    NodeEvidence,
    begin_manual_failover,
    complete_manual_failover,
    promote_membership,
    record_final_sync_verified,
    record_source_fenced,
    record_source_quiesced,
    record_target_verified,
)
from home_center.store import StateStore


REVISION = "a" * 40


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
    digest: str,
    *,
    active: bool = True,
    fenced: bool = False,
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


def digest(store: StateStore) -> str:
    return snapshot_authoritative(store._connection)["authoritative_sha256"]


def mirror(source: StateStore, target: StateStore) -> None:
    apply_authoritative_snapshot(target._connection, snapshot_authoritative(source._connection))


class HARoundTripQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.node_a = StateStore(root / "node-a.db", b"a" * 32, "cluster-test")
        self.node_b = StateStore(root / "node-b.db", b"b" * 32, "cluster-test")
        initial = membership()
        initialize_membership(self.node_a._connection, initial)
        initialize_membership(self.node_b._connection, initial)
        self.node_a.set_meta("application.state", {"writer": "node-a", "revision": 1})
        mirror(self.node_a, self.node_b)

    def tearDown(self) -> None:
        self.node_a.close()
        self.node_b.close()
        self.temp.cleanup()

    def _handoff(
        self,
        *,
        source: StateStore,
        target: StateStore,
        source_id: str,
        target_id: str,
        transition_id: str,
        source_sequence: int,
    ) -> None:
        current = load_membership(source._connection)
        self.assertIsNotNone(current)
        self.assertEqual(source_id, current["writer"])
        self.assertEqual(current, load_membership(target._connection))
        initial_digest = digest(source)
        self.assertEqual(initial_digest, digest(target))

        transition = begin_manual_failover(
            current,
            target_node_id=target_id,
            source=evidence(source_id, initial_digest, sequence=source_sequence),
            target=evidence(target_id, initial_digest, fenced=True, sequence=source_sequence),
            transition_id=transition_id,
        )
        persist_transition(source._connection, transition.as_dict(), expected_phase=None)
        mirror(source, target)

        transition = record_source_quiesced(
            transition,
            evidence(source_id, digest(source), active=False, sequence=source_sequence),
        )
        persist_transition(source._connection, transition.as_dict(), expected_phase="planned")
        mirror(source, target)

        final_digest = digest(source)
        transition = record_final_sync_verified(
            transition,
            source=evidence(
                source_id,
                final_digest,
                active=False,
                sequence=source_sequence + 1,
            ),
            target=evidence(
                target_id,
                final_digest,
                fenced=True,
                sequence=source_sequence + 1,
            ),
        )
        persist_transition(
            source._connection,
            transition.as_dict(),
            expected_phase="source_quiesced",
        )
        mirror(source, target)

        # The source is now externally stopped/fenced. The target advances the
        # durable journal using observed fence evidence; no source write follows.
        transition = record_source_fenced(
            transition,
            evidence(
                source_id,
                final_digest,
                active=False,
                fenced=True,
                sequence=source_sequence + 1,
            ),
        )
        persist_transition(
            target._connection,
            transition.as_dict(),
            expected_phase="final_sync_verified",
        )
        promoted_transition, promoted_membership = promote_membership(transition, current)
        commit_promotion(
            target._connection,
            before_membership=current,
            after_membership=promoted_membership,
            before_transition=transition.as_dict(),
            after_transition=promoted_transition.as_dict(),
        )

        target_digest = digest(target)
        promoted_transition = record_target_verified(
            promoted_transition,
            source=evidence(
                source_id,
                final_digest,
                active=False,
                fenced=True,
                sequence=source_sequence + 1,
            ),
            target=evidence(
                target_id,
                target_digest,
                active=True,
                fenced=False,
                sequence=source_sequence + 1,
            ),
            write_readback_verified=True,
            source_write_rejected=True,
        )
        persist_transition(
            target._connection,
            promoted_transition.as_dict(),
            expected_phase="target_promoted",
        )
        completed = complete_manual_failover(promoted_transition)
        persist_transition(
            target._connection,
            completed.as_dict(),
            expected_phase="target_verified",
        )

        applied = load_membership(target._connection)
        self.assertEqual(current["generation"] + 1, applied["generation"])
        self.assertEqual(target_id, applied["writer"])
        self.assertEqual("completed", load_transition(target._connection)["phase"])

    def test_a_to_b_write_reverse_sync_and_b_to_a_failback(self) -> None:
        self._handoff(
            source=self.node_a,
            target=self.node_b,
            source_id="node-a",
            target_id="node-b",
            transition_id="failover-a-to-b",
            source_sequence=20,
        )

        # A is still stale but externally fenced; B is the only admitted writer.
        self.assertTrue(
            writer_admission(
                self.node_b._connection,
                local_node_id="node-b",
                bootstrap_role="standby",
            ).allowed
        )
        self.node_b.set_meta(
            "application.state",
            {"writer": "node-b", "revision": 2, "committed_after_promotion": True},
        )

        # Returning A receives B's authoritative generation and write before it
        # can participate again. Its old bootstrap role no longer grants writes.
        mirror(self.node_b, self.node_a)
        self.assertEqual(snapshot_authoritative(self.node_b._connection), snapshot_authoritative(self.node_a._connection))
        self.assertEqual("node-b", load_membership(self.node_a._connection)["writer"])
        self.assertFalse(
            writer_admission(
                self.node_a._connection,
                local_node_id="node-a",
                bootstrap_role="leader",
            ).allowed
        )
        self.assertEqual(
            {"writer": "node-b", "revision": 2, "committed_after_promotion": True},
            self.node_a.get_meta("application.state"),
        )

        self._handoff(
            source=self.node_b,
            target=self.node_a,
            source_id="node-b",
            target_id="node-a",
            transition_id="failback-b-to-a",
            source_sequence=40,
        )
        self.node_a.set_meta(
            "application.state",
            {"writer": "node-a", "revision": 3, "committed_after_failback": True},
        )
        mirror(self.node_a, self.node_b)

        final_a = load_membership(self.node_a._connection)
        final_b = load_membership(self.node_b._connection)
        self.assertEqual(final_a, final_b)
        self.assertEqual(3, final_a["generation"])
        self.assertEqual("node-a", final_a["writer"])
        self.assertEqual(snapshot_authoritative(self.node_a._connection), snapshot_authoritative(self.node_b._connection))
        self.assertEqual(
            {"writer": "node-a", "revision": 3, "committed_after_failback": True},
            self.node_b.get_meta("application.state"),
        )
        self.assertTrue(
            writer_admission(
                self.node_a._connection,
                local_node_id="node-a",
                bootstrap_role="leader",
            ).allowed
        )
        self.assertFalse(
            writer_admission(
                self.node_b._connection,
                local_node_id="node-b",
                bootstrap_role="standby",
            ).allowed
        )


if __name__ == "__main__":
    unittest.main()
