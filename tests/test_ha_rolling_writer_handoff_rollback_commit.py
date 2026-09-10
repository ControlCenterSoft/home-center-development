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
    build_writer_handoff_fencing_evidence,
)
from home_center.ha_rolling_writer_handoff_recovery import (
    assess_rolling_writer_handoff_recovery,
)
from home_center.ha_rolling_writer_handoff_rollback_admission import (
    build_writer_handoff_rollback_admission,
)
from home_center.ha_rolling_writer_handoff_rollback_commit import (
    HARollingWriterHandoffRollbackCommitError,
    commit_writer_handoff_rollback,
    revalidate_writer_handoff_rollback_commit_receipt,
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
) -> HAPeerStateSnapshot:
    states = states or {}
    members = tuple(
        ObservedPeerState(
            node_id,
            "untrusted",
            states.get(node_id, PeerHealthState.READY),
            f"state-{node_id}-{states.get(node_id, PeerHealthState.READY).value}",
        )
        for node_id in NODES
    )
    canonical = {
        "schema": "home-center.ha-peer-state-snapshot.v1",
        "cluster_id": "home-cluster",
        "journal_seq": journal_seq,
        "members": [member.to_dict() for member in members],
    }
    return HAPeerStateSnapshot(
        "home-cluster",
        journal_seq,
        members,
        stable_id("ha-state", canonical),
    )


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


def lease_state(role_transition_id: str, *, resource_version: int = 12) -> LeaseState:
    provisional = LeaseState(
        cluster_id="home-cluster",
        node_id="node-b",
        lease_id="writer-lease-node-b",
        lease_epoch=9,
        resource_version=resource_version,
        holder_node_id=None,
        revoked=True,
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


class RacingRoleAuthority:
    def __init__(self, store: HARoleJournalAuthority):
        self.store = store
        self.raced = False

    def state_for(self, *, cluster_id: str, node_ids: tuple[str, ...]):
        return self.store.state_for(cluster_id=cluster_id, node_ids=node_ids)

    def transition(self, **kwargs):
        if not self.raced:
            self.raced = True
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
        return self.store.transition(**kwargs)


class RollingWriterHandoffRollbackCommitTests(unittest.TestCase):
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
        handoff = commit_rolling_writer_handoff(
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
            receipt=handoff,
            peer_snapshot=self.degraded,
            role_authority=self.store,
        )
        self.lease = lease_state(self.assessment.role_transition_id)
        self.lease_authority = LeaseAuthority(self.lease)
        self.fencing = build_writer_handoff_fencing_evidence(
            assessment=self.assessment,
            lease_authority=self.lease_authority,
        )
        self.admission = build_writer_handoff_rollback_admission(
            evidence=self.fencing,
            assessment=self.assessment,
            peer_authority=PeerAuthority(self.degraded),
            role_authority=self.store,
            lease_authority=self.lease_authority,
        )

    def tearDown(self) -> None:
        self.db.close()

    def commit(self, *, peer_authority=None, role_authority=None, lease_authority=None):
        return commit_writer_handoff_rollback(
            admission=self.admission,
            evidence=self.fencing,
            assessment=self.assessment,
            peer_authority=peer_authority or PeerAuthority(self.degraded),
            role_authority=role_authority or self.store,
            lease_authority=lease_authority or self.lease_authority,
        )

    def test_commit_is_typed_single_use_and_non_serving(self) -> None:
        receipt = self.commit()
        self.assertEqual("rollback", receipt.transition_kind)
        self.assertTrue(receipt.role_commit_applied)
        self.assertTrue(receipt.single_use_by_cas)
        self.assertFalse(receipt.retry_authorized)
        self.assertFalse(receipt.execution_authorized)
        self.assertFalse(receipt.failover_authorized)
        self.assertFalse(receipt.writer_service_authorized)
        self.assertFalse(receipt.host_mutation_authorized)
        self.assertFalse(receipt.production_mutation_enabled)
        current = self.store.state_for(cluster_id="home-cluster", node_ids=NODES)
        writers = tuple(
            item.node_id
            for item in current.snapshot.assignments
            if item.role is NodeRole.WRITER
        )
        self.assertEqual(("node-a",), writers)
        self.assertEqual(receipt.committed_role_transition_id, current.transition_id)
        self.assertEqual(
            receipt,
            revalidate_writer_handoff_rollback_commit_receipt(
                receipt=receipt,
                role_authority=self.store,
            ),
        )

    def test_peer_drift_immediately_before_cas_blocks_commit(self) -> None:
        moved = peer_snapshot(
            states={"node-b": PeerHealthState.UNREACHABLE},
            journal_seq=9,
        )
        authority = PeerAuthority(self.degraded, self.degraded, moved)
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackCommitError,
            "peer_state_stale",
        ):
            self.commit(peer_authority=authority)
        current = self.store.state_for(cluster_id="home-cluster", node_ids=NODES)
        writers = tuple(
            item.node_id
            for item in current.snapshot.assignments
            if item.role is NodeRole.WRITER
        )
        self.assertEqual(("node-b",), writers)

    def test_cas_race_requires_reconciliation_without_retry(self) -> None:
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackCommitError,
            "reconciliation_required",
        ):
            self.commit(role_authority=RacingRoleAuthority(self.store))
        current = self.store.state_for(cluster_id="home-cluster", node_ids=NODES)
        writers = tuple(
            item.node_id
            for item in current.snapshot.assignments
            if item.role is NodeRole.WRITER
        )
        self.assertEqual(("node-c",), writers)
        self.assertEqual("failover", current.transition_kind)

    def test_same_admission_cannot_be_replayed_after_commit(self) -> None:
        self.commit()
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackCommitError,
            "reconciliation_required",
        ):
            self.commit()
        self.assertEqual(
            3,
            len(self.store.journal_entries(cluster_id="home-cluster")),
        )

    def test_lease_drift_before_commit_requires_reconciliation(self) -> None:
        changed = LeaseAuthority(
            lease_state(
                self.assessment.role_transition_id,
                resource_version=self.lease.resource_version + 1,
            )
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackCommitError,
            "reconciliation_required",
        ):
            self.commit(lease_authority=changed)
        current = self.store.state_for(cluster_id="home-cluster", node_ids=NODES)
        self.assertEqual(
            self.admission.expected_role_assignment_id,
            current.snapshot.assignment_id,
        )

    def test_receipt_tampering_cannot_grant_execution(self) -> None:
        receipt = self.commit()
        tampered = replace(receipt, execution_authorized=True)
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackCommitError,
            "receipt_authority_invalid",
        ):
            revalidate_writer_handoff_rollback_commit_receipt(
                receipt=tampered,
                role_authority=self.store,
            )


if __name__ == "__main__":
    unittest.main()
