from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from dataclasses import dataclass, replace

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
from home_center.ha_rolling_writer_handoff_fencing import (
    HARollingWriterHandoffFencingError,
    build_writer_handoff_fencing_evidence,
)
from home_center.ha_rolling_writer_handoff_recovery import (
    assess_rolling_writer_handoff_recovery,
)
from home_center.ha_rolling_writer_handoff_rollback_admission import (
    HARollingWriterHandoffRollbackAdmissionError,
    build_writer_handoff_rollback_admission,
    revalidate_writer_handoff_rollback_admission,
)

NODES = ("node-a", "node-b", "node-c")


def stable_id(prefix: str, material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(
            material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return f"{prefix}-{digest}"


def roles(writer: str = "node-a") -> tuple[HARoleAssignment, ...]:
    return tuple(
        HARoleAssignment(
            node_id,
            NodeRole.WRITER if node_id == writer else NodeRole.STANDBY,
        )
        for node_id in NODES
    )


def peer_snapshot(
    *,
    states: dict[str, PeerHealthState] | None = None,
    journal_seq: int = 8,
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
    snapshot_id = stable_id("ha-state", canonical)
    return HAPeerStateSnapshot("home-cluster", journal_seq, members, snapshot_id)


@dataclass(frozen=True, slots=True)
class LeaseState:
    cluster_id: str
    node_id: str
    lease_id: str
    lease_epoch: int
    resource_version: int
    holder_node_id: str | None
    revoked: bool
    revoked_for_role_transition_id: str
    state_id: str
    production_mutation_enabled: bool = False


def lease_state(
    role_transition_id: str,
    *,
    resource_version: int = 12,
    revoked: bool = True,
    holder_node_id: str | None = None,
) -> LeaseState:
    provisional = LeaseState(
        cluster_id="home-cluster",
        node_id="node-b",
        lease_id="writer-lease-node-b",
        lease_epoch=9,
        resource_version=resource_version,
        holder_node_id=holder_node_id,
        revoked=revoked,
        revoked_for_role_transition_id=role_transition_id,
        state_id="pending",
    )
    material = {
        "schema": "home-center.ha-writer-lease-state.v1",
        "cluster_id": provisional.cluster_id,
        "node_id": provisional.node_id,
        "lease_id": provisional.lease_id,
        "lease_epoch": provisional.lease_epoch,
        "resource_version": provisional.resource_version,
        "holder_node_id": provisional.holder_node_id,
        "revoked": provisional.revoked,
        "revoked_for_role_transition_id": provisional.revoked_for_role_transition_id,
    }
    return replace(provisional, state_id=stable_id("ha-writer-lease", material))


class LeaseAuthority:
    def __init__(self, state: LeaseState):
        self.state = state

    def state_for(self, *, cluster_id: str, node_id: str) -> LeaseState:
        return self.state


class PeerAuthority:
    def __init__(self, *snapshots: HAPeerStateSnapshot):
        self.snapshots = snapshots
        self.calls = 0

    def snapshot_for(
        self,
        *,
        cluster_id: str,
        node_ids: tuple[str, ...],
    ) -> HAPeerStateSnapshot:
        index = min(self.calls, len(self.snapshots) - 1)
        self.calls += 1
        return self.snapshots[index]


class RollingWriterHandoffRollbackAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.store = HARoleJournalAuthority(self.db)
        initial = self.store.bootstrap(
            cluster_id="home-cluster",
            assignments=roles(),
        )
        healthy = peer_snapshot(journal_seq=7)
        decision = evaluate_revision_bound_rolling_safety(
            peer_snapshot=healthy,
            role_authority=self.store,
            target_node_id="node-a",
            minimum_ready_nodes=2,
            expected_peer_snapshot_id=healthy.snapshot_id,
            expected_peer_journal_seq=healthy.journal_seq,
            expected_role_assignment_id=initial.snapshot.assignment_id,
            expected_role_epoch=initial.snapshot.role_epoch,
            expected_role_resource_version=initial.resource_version,
            expected_role_journal_seq=initial.journal_seq,
            expected_role_transition_id=initial.transition_id,
        )
        intent = plan_rolling_writer_handoff(
            decision=decision,
            peer_snapshot=healthy,
            role_authority=self.store,
        )
        receipt = commit_rolling_writer_handoff(
            intent=intent,
            decision=decision,
            peer_snapshot=healthy,
            role_authority=self.store,
        )
        self.degraded = peer_snapshot(
            states={"node-b": PeerHealthState.DEGRADED},
            journal_seq=8,
        )
        self.assessment = assess_rolling_writer_handoff_recovery(
            intent=intent,
            receipt=receipt,
            peer_snapshot=self.degraded,
            role_authority=self.store,
        )
        self.lease = lease_state(self.assessment.role_transition_id)
        self.fencing = build_writer_handoff_fencing_evidence(
            assessment=self.assessment,
            lease_authority=LeaseAuthority(self.lease),
        )

    def tearDown(self) -> None:
        self.db.close()

    def build(self, *, peer_authority=None, lease_authority=None):
        return build_writer_handoff_rollback_admission(
            evidence=self.fencing,
            assessment=self.assessment,
            peer_authority=peer_authority or PeerAuthority(self.degraded),
            role_authority=self.store,
            lease_authority=lease_authority or LeaseAuthority(self.lease),
        )

    def test_admission_is_deterministic_cas_bound_and_non_executing(self) -> None:
        first = self.build()
        for _ in range(100):
            self.assertEqual(first, self.build())
        self.assertEqual("node-a", first.rollback_writer_node_id)
        self.assertEqual("node-b", first.fenced_successor_node_id)
        self.assertTrue(first.cas_bound)
        self.assertTrue(first.single_use_by_cas)
        self.assertTrue(first.rollback_transition_admitted)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.host_mutation_authorized)
        self.assertFalse(first.production_mutation_enabled)
        self.assertEqual(first.expected_role_epoch + 1, first.target_role_epoch)
        self.assertNotEqual(first.expected_role_assignment_id, first.target_role_assignment_id)

    def test_fresh_safe_peer_revision_can_be_admitted(self) -> None:
        fresh = peer_snapshot(
            states={"node-b": PeerHealthState.UNREACHABLE},
            journal_seq=9,
        )
        admission = self.build(peer_authority=PeerAuthority(fresh))
        self.assertEqual(fresh.snapshot_id, admission.peer_snapshot_id)
        self.assertEqual(9, admission.peer_journal_seq)
        self.assertEqual(("node-a", "node-c"), admission.ready_node_ids)

    def test_lost_quorum_blocks_admission(self) -> None:
        unsafe = peer_snapshot(
            states={
                "node-b": PeerHealthState.UNREACHABLE,
                "node-c": PeerHealthState.DEGRADED,
            },
            journal_seq=9,
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackAdmissionError,
            "safety_boundary_not_met",
        ):
            self.build(peer_authority=PeerAuthority(unsafe))

    def test_successor_becoming_ready_blocks_admission(self) -> None:
        successor_ready = peer_snapshot(journal_seq=9)
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackAdmissionError,
            "safety_boundary_not_met",
        ):
            self.build(peer_authority=PeerAuthority(successor_ready))

    def test_previous_writer_degradation_blocks_admission(self) -> None:
        previous_degraded = peer_snapshot(
            states={
                "node-a": PeerHealthState.DEGRADED,
                "node-b": PeerHealthState.UNREACHABLE,
            },
            journal_seq=9,
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackAdmissionError,
            "safety_boundary_not_met",
        ):
            self.build(peer_authority=PeerAuthority(previous_degraded))

    def test_peer_movement_while_sealing_blocks_admission(self) -> None:
        moved = peer_snapshot(
            states={"node-b": PeerHealthState.UNREACHABLE},
            journal_seq=9,
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackAdmissionError,
            "peer_state_moved",
        ):
            self.build(peer_authority=PeerAuthority(self.degraded, moved))

    def test_role_revision_drift_blocks_admission(self) -> None:
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
            HARollingWriterHandoffRollbackAdmissionError,
            "role_revision_stale",
        ):
            self.build()

    def test_lease_revision_drift_blocks_admission(self) -> None:
        changed = lease_state(
            self.assessment.role_transition_id,
            resource_version=self.lease.resource_version + 1,
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffFencingError,
            "evidence_stale",
        ):
            self.build(lease_authority=LeaseAuthority(changed))

    def test_saved_admission_is_rejected_after_peer_drift(self) -> None:
        admission = self.build()
        changed = peer_snapshot(
            states={"node-b": PeerHealthState.UNREACHABLE},
            journal_seq=9,
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackAdmissionError,
            "admission_stale",
        ):
            revalidate_writer_handoff_rollback_admission(
                admission=admission,
                evidence=self.fencing,
                assessment=self.assessment,
                peer_authority=PeerAuthority(changed),
                role_authority=self.store,
                lease_authority=LeaseAuthority(self.lease),
            )

    def test_tampered_admission_cannot_enable_execution(self) -> None:
        admission = self.build()
        tampered = replace(admission, execution_authorized=True)
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackAdmissionError,
            "admission_authority_invalid",
        ):
            revalidate_writer_handoff_rollback_admission(
                admission=tampered,
                evidence=self.fencing,
                assessment=self.assessment,
                peer_authority=PeerAuthority(self.degraded),
                role_authority=self.store,
                lease_authority=LeaseAuthority(self.lease),
            )


if __name__ == "__main__":
    unittest.main()
