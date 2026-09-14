from __future__ import annotations

import copy
import tempfile
import unittest
import uuid
from pathlib import Path

from home_center.authoritative_state import snapshot_authoritative
from home_center.config import Config, Peer
from home_center.ha_reconcile import HAReconcileRejected, HAStateReconciler
from home_center.ha_state import initialize_membership, load_membership, persist_transition
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
SOURCE_INSTANCE = str(uuid.uuid4())


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
    digest: str = "b" * 64,
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


def config(node_id: str, peer: Peer) -> Config:
    root = Path("/tmp/home-center-ha-test")
    return Config(
        cluster_id="cluster-test",
        node_id=node_id,
        node_name=node_id,
        role="leader" if node_id == "node-a" else "standby",
        management_address="192.0.2.10" if node_id == "node-a" else "192.0.2.11",
        web_port=8443,
        peer_port=9443,
        state_db=root / f"{node_id}.db",
        backup_dir=root / "backups",
        web_root=root / "web",
        local_admin_credentials_file=root / "local-admin.json",
        session_key_file=root / "session.key",
        audit_key_file=root / "audit.key",
        tls_certificate=root / "node.crt",
        tls_private_key=root / "node.key",
        cluster_ca=root / "ca.crt",
        web_ca=root / "web-ca.crt",
        deployment_profile=root / "deployment-profile.json",
        peers=(peer,),
        reconcile_interval_seconds=15,
        peer_timeout_seconds=3,
    )


def release_identity() -> dict:
    return {
        "schema": "home-center.release-identity.v1",
        "version": "0.64.0",
        "revision": REVISION,
        "build": REVISION[:12],
        "source": "immutable-artifact",
    }


def status_for(store: StateStore, node_id: str, *, transition: dict | None = None, sequence: int = 0) -> dict:
    snapshot = snapshot_authoritative(store._connection)
    current = load_membership(store._connection)
    assert current is not None
    return {
        "schema": "home-center.ha-peer-status.v1",
        "cluster_id": "cluster-test",
        "node_id": node_id,
        "version": "0.64.0",
        "revision": REVISION,
        "writer_admission": {
            "allowed": current["writer"] == node_id,
            "reason": "local_node_is_writer" if current["writer"] == node_id else "local_node_is_not_writer",
            "writer_node_id": current["writer"],
            "generation": current["generation"],
        },
        "membership": current,
        "transition": transition,
        "authoritative_sha256": snapshot["authoritative_sha256"],
        "source_instance_id": SOURCE_INSTANCE,
        "source_sequence": sequence,
        "observed_at": "2026-09-14T12:00:00Z",
    }


def export_for(store: StateStore, node_id: str, *, transition: dict | None = None, sequence: int = 1) -> dict:
    snapshot = snapshot_authoritative(store._connection)
    current = load_membership(store._connection)
    assert current is not None
    return {
        "schema": "home-center.ha-peer-authoritative-state.v1",
        "cluster_id": "cluster-test",
        "node_id": node_id,
        "version": "0.64.0",
        "revision": REVISION,
        "membership": current,
        "transition": transition,
        "authoritative_sha256": snapshot["authoritative_sha256"],
        "source_instance_id": SOURCE_INSTANCE,
        "source_sequence": sequence,
        "generated_at": "2026-09-14T12:00:01Z",
        "snapshot": snapshot,
    }


class FakeClient:
    def __init__(self, status: dict, export: dict) -> None:
        self.status = status
        self.export = export
        self.status_calls = 0
        self.snapshot_calls = 0

    def fetch_status(self, _peer: Peer) -> dict:
        self.status_calls += 1
        return copy.deepcopy(self.status)

    def fetch_snapshot(self, _peer: Peer) -> dict:
        self.snapshot_calls += 1
        return copy.deepcopy(self.export)


class HAReconcileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.node_a = StateStore(root / "node-a.db", b"a" * 32, "cluster-test")
        self.node_b = StateStore(root / "node-b.db", b"b" * 32, "cluster-test")
        self.peer_a = Peer("node-a", "node-a", "192.0.2.10", "https://192.0.2.10:9443", "node-a-cert")
        self.peer_b = Peer("node-b", "node-b", "192.0.2.11", "https://192.0.2.11:9443", "node-b-cert")

    def tearDown(self) -> None:
        self.node_a.close()
        self.node_b.close()
        self.temp.cleanup()

    def test_standby_pulls_current_writer_state(self) -> None:
        initial = membership()
        initialize_membership(self.node_a._connection, initial)
        initialize_membership(self.node_b._connection, initial)
        self.node_a.set_meta("writer.created.state", {"value": "from-a"})
        client = FakeClient(status_for(self.node_a, "node-a"), export_for(self.node_a, "node-a"))
        reconciler = HAStateReconciler(
            config("node-b", self.peer_a),
            self.node_b,
            client=client,
            release_identity_provider=release_identity,
        )

        reconciler.reconcile_once()

        self.assertEqual({"value": "from-a"}, self.node_b.get_meta("writer.created.state"))
        self.assertEqual("node-a", load_membership(self.node_b._connection)["writer"])
        self.assertEqual(1, client.snapshot_calls)
        self.assertEqual("node-a->node-b", reconciler.status()["direction"])
        self.assertEqual(1, reconciler.status()["source_sequence"])

    def _promote_node_b(self) -> dict:
        initial = membership()
        initialize_membership(self.node_b._connection, initial)
        transition = begin_manual_failover(
            initial,
            target_node_id="node-b",
            source=evidence("node-a"),
            target=evidence("node-b", fenced=True),
            transition_id="transition-rejoin",
        )
        persist_transition(self.node_b._connection, transition.as_dict(), expected_phase=None)
        transition = record_source_quiesced(transition, evidence("node-a", active=False))
        persist_transition(self.node_b._connection, transition.as_dict(), expected_phase="planned")
        transition = record_final_sync_verified(
            transition,
            source=evidence("node-a", active=False, digest="c" * 64, sequence=11),
            target=evidence("node-b", fenced=True, digest="c" * 64, sequence=11),
        )
        persist_transition(self.node_b._connection, transition.as_dict(), expected_phase="source_quiesced")
        transition = record_source_fenced(
            transition,
            evidence("node-a", active=False, fenced=True, digest="c" * 64, sequence=11),
        )
        persist_transition(self.node_b._connection, transition.as_dict(), expected_phase="final_sync_verified")
        promoted_transition, promoted_membership = promote_membership(transition, initial)
        from home_center.ha_state import commit_promotion

        commit_promotion(
            self.node_b._connection,
            before_membership=initial,
            after_membership=promoted_membership,
            before_transition=transition.as_dict(),
            after_transition=promoted_transition.as_dict(),
        )
        return promoted_transition.as_dict()

    def test_returning_old_writer_accepts_only_proven_generation_plus_one_takeover(self) -> None:
        initialize_membership(self.node_a._connection, membership())
        promoted_transition = self._promote_node_b()
        self.node_b.set_meta("writer.created.state", {"value": "from-b", "generation": 2})
        client = FakeClient(
            status_for(self.node_b, "node-b", transition=promoted_transition),
            export_for(self.node_b, "node-b", transition=promoted_transition),
        )
        reconciler = HAStateReconciler(
            config("node-a", self.peer_b),
            self.node_a,
            client=client,
            release_identity_provider=release_identity,
        )

        reconciler.reconcile_once()

        applied = load_membership(self.node_a._connection)
        self.assertEqual(2, applied["generation"])
        self.assertEqual("node-b", applied["writer"])
        self.assertEqual(
            {"value": "from-b", "generation": 2},
            self.node_a.get_meta("writer.created.state"),
        )
        self.assertEqual("node-b->node-a", reconciler.status()["direction"])

    def test_same_generation_conflicting_writer_is_rejected_without_apply(self) -> None:
        initialize_membership(self.node_a._connection, membership(writer="node-a"))
        initialize_membership(self.node_b._connection, membership(writer="node-b"))
        before = snapshot_authoritative(self.node_a._connection)
        client = FakeClient(status_for(self.node_b, "node-b"), export_for(self.node_b, "node-b"))
        reconciler = HAStateReconciler(
            config("node-a", self.peer_b),
            self.node_a,
            client=client,
            release_identity_provider=release_identity,
        )

        with self.assertRaisesRegex(HAReconcileRejected, "same_generation_writer_conflict"):
            reconciler.reconcile_once()

        self.assertEqual(before, snapshot_authoritative(self.node_a._connection))
        self.assertEqual(0, client.snapshot_calls)
        self.assertEqual("degraded", reconciler.status()["state"])

    def test_unproven_generation_jump_is_rejected(self) -> None:
        initialize_membership(self.node_a._connection, membership(generation=1, writer="node-a"))
        initialize_membership(self.node_b._connection, membership(generation=1, writer="node-b"))
        peer_status = status_for(self.node_b, "node-b")
        peer_status["membership"]["generation"] = 3
        peer_status["writer_admission"]["generation"] = 3
        peer_export = export_for(self.node_b, "node-b")
        client = FakeClient(peer_status, peer_export)
        reconciler = HAStateReconciler(
            config("node-a", self.peer_b),
            self.node_a,
            client=client,
            release_identity_provider=release_identity,
        )

        with self.assertRaisesRegex(HAReconcileRejected, "generation_gap"):
            reconciler.reconcile_once()
        self.assertEqual(0, client.snapshot_calls)

    def test_same_source_instance_requires_monotonic_export_sequence(self) -> None:
        initial = membership()
        initialize_membership(self.node_a._connection, initial)
        initialize_membership(self.node_b._connection, initial)
        export = export_for(self.node_a, "node-a", sequence=1)
        client = FakeClient(status_for(self.node_a, "node-a", sequence=1), export)
        reconciler = HAStateReconciler(
            config("node-b", self.peer_a),
            self.node_b,
            client=client,
            release_identity_provider=release_identity,
        )
        reconciler.reconcile_once()

        with self.assertRaisesRegex(HAReconcileRejected, "sequence_not_monotonic"):
            reconciler.reconcile_once()


if __name__ == "__main__":
    unittest.main()
