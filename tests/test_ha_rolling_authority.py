from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from home_center.ha_peer_snapshot import (
    HAPeerStateSnapshot,
    ObservedPeerState,
    PeerHealthState,
)
from home_center.ha_rolling_authority import (
    HARoleAssignment,
    HARoleCoordinationError,
    build_role_assignment_snapshot,
    evaluate_authoritative_rolling_safety,
)
from home_center.ha_rolling_safety import NodeRole


def peer_snapshot(*members: ObservedPeerState, journal_seq: int = 7) -> HAPeerStateSnapshot:
    ordered = tuple(sorted(members, key=lambda item: item.node_id))
    canonical = {
        "schema": "home-center.ha-peer-state-snapshot.v1",
        "cluster_id": "home-cluster",
        "journal_seq": journal_seq,
        "members": [member.to_dict() for member in ordered],
    }
    snapshot_id = "ha-state-" + hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    return HAPeerStateSnapshot("home-cluster", journal_seq, ordered, snapshot_id)


def peer(
    node_id: str,
    state: PeerHealthState = PeerHealthState.READY,
    role: str = "untrusted",
) -> ObservedPeerState:
    return ObservedPeerState(node_id, role, state, f"state-{node_id}")


class Authority:
    def __init__(self, epoch: int = 4) -> None:
        self.snapshot = build_role_assignment_snapshot(
            cluster_id="home-cluster",
            role_epoch=epoch,
            assignments=(
                HARoleAssignment("node-b", NodeRole.STANDBY),
                HARoleAssignment("node-a", NodeRole.WRITER),
            ),
        )
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def snapshot_for(self, *, cluster_id: str, node_ids: tuple[str, ...]):
        self.calls.append((cluster_id, node_ids))
        return self.snapshot


class CoordinatedRollingSafetyTests(unittest.TestCase):
    def evaluate(self, snapshot: HAPeerStateSnapshot, authority: Authority, **kwargs):
        return evaluate_authoritative_rolling_safety(
            peer_snapshot=snapshot,
            role_authority=authority,
            target_node_id=kwargs.pop("target_node_id", "node-b"),
            minimum_ready_nodes=kwargs.pop("minimum_ready_nodes", 1),
            expected_peer_snapshot_id=kwargs.pop("expected_peer_snapshot_id", snapshot.snapshot_id),
            expected_peer_journal_seq=kwargs.pop("expected_peer_journal_seq", snapshot.journal_seq),
            expected_role_assignment_id=kwargs.pop(
                "expected_role_assignment_id", authority.snapshot.assignment_id
            ),
            expected_role_epoch=kwargs.pop("expected_role_epoch", authority.snapshot.role_epoch),
            **kwargs,
        )

    def test_peer_reported_roles_are_ignored(self) -> None:
        snapshot = peer_snapshot(peer("node-a", role="standby"), peer("node-b", role="writer"))
        authority = Authority()
        decision = self.evaluate(snapshot, authority)
        self.assertTrue(decision.safe)
        self.assertEqual("node-a", decision.writer_node_id)
        self.assertFalse(decision.production_mutation_enabled)
        self.assertEqual([("home-cluster", ("node-a", "node-b"))], authority.calls)

    def test_role_epoch_drift_invalidates_decision(self) -> None:
        snapshot = peer_snapshot(peer("node-a"), peer("node-b"))
        authority = Authority(epoch=5)
        with self.assertRaisesRegex(HARoleCoordinationError, "ha_role_epoch_stale"):
            self.evaluate(snapshot, authority, expected_role_epoch=4)

    def test_role_assignment_identity_drift_invalidates_decision(self) -> None:
        snapshot = peer_snapshot(peer("node-a"), peer("node-b"))
        authority = Authority()
        with self.assertRaisesRegex(HARoleCoordinationError, "ha_role_assignment_stale"):
            self.evaluate(snapshot, authority, expected_role_assignment_id="ha-role-stale")

    def test_peer_snapshot_drift_invalidates_decision(self) -> None:
        snapshot = peer_snapshot(peer("node-a"), peer("node-b"))
        authority = Authority()
        with self.assertRaisesRegex(Exception, "ha_snapshot_stale"):
            self.evaluate(snapshot, authority, expected_peer_snapshot_id="ha-state-stale")

    def test_peer_journal_drift_invalidates_decision(self) -> None:
        snapshot = peer_snapshot(peer("node-a"), peer("node-b"), journal_seq=9)
        authority = Authority()
        with self.assertRaisesRegex(Exception, "ha_transition_journal_stale"):
            self.evaluate(snapshot, authority, expected_peer_journal_seq=8)

    def test_unknown_peer_is_fail_closed(self) -> None:
        snapshot = peer_snapshot(peer("node-a"), peer("node-b", PeerHealthState.UNKNOWN))
        authority = Authority()
        decision = self.evaluate(snapshot, authority)
        self.assertFalse(decision.safe)
        self.assertIn("peer_state_unknown", decision.blockers)

    def test_role_membership_mismatch_is_rejected(self) -> None:
        snapshot = peer_snapshot(peer("node-a"), peer("node-b"))
        authority = Authority()
        authority.snapshot = build_role_assignment_snapshot(
            cluster_id="home-cluster",
            role_epoch=4,
            assignments=(
                HARoleAssignment("node-a", NodeRole.WRITER),
                HARoleAssignment("node-c", NodeRole.STANDBY),
            ),
        )
        with self.assertRaisesRegex(HARoleCoordinationError, "role_membership_mismatch"):
            self.evaluate(snapshot, authority)

    def test_multiple_writers_are_rejected_at_role_authority_boundary(self) -> None:
        with self.assertRaisesRegex(HARoleCoordinationError, "writer_assignment_not_unique"):
            build_role_assignment_snapshot(
                cluster_id="home-cluster",
                role_epoch=4,
                assignments=(
                    HARoleAssignment("node-a", NodeRole.WRITER),
                    HARoleAssignment("node-b", NodeRole.WRITER),
                ),
            )

    def test_tampered_peer_snapshot_identity_is_rejected(self) -> None:
        snapshot = peer_snapshot(peer("node-a"), peer("node-b"))
        authority = Authority()
        tampered = replace(snapshot, snapshot_id="ha-state-tampered")
        with self.assertRaisesRegex(HARoleCoordinationError, "peer_snapshot_identity_invalid"):
            self.evaluate(
                tampered,
                authority,
                expected_peer_snapshot_id="ha-state-tampered",
            )

    def test_plan_identity_is_deterministic(self) -> None:
        snapshot = peer_snapshot(peer("node-b"), peer("node-a"))
        first = Authority()
        second = Authority()
        self.assertEqual(self.evaluate(snapshot, first).plan_id, self.evaluate(snapshot, second).plan_id)

    def test_single_node_still_requires_explicit_downtime_ack(self) -> None:
        role = build_role_assignment_snapshot(
            cluster_id="home-cluster",
            role_epoch=1,
            assignments=(HARoleAssignment("node-a", NodeRole.WRITER),),
        )

        class SingleAuthority:
            def snapshot_for(self, *, cluster_id, node_ids):
                return role

        snapshot = peer_snapshot(peer("node-a"), journal_seq=1)
        denied = evaluate_authoritative_rolling_safety(
            peer_snapshot=snapshot,
            role_authority=SingleAuthority(),
            target_node_id="node-a",
            minimum_ready_nodes=0,
            expected_peer_snapshot_id=snapshot.snapshot_id,
            expected_peer_journal_seq=1,
            expected_role_assignment_id=role.assignment_id,
            expected_role_epoch=1,
        )
        self.assertFalse(denied.safe)
        allowed = evaluate_authoritative_rolling_safety(
            peer_snapshot=snapshot,
            role_authority=SingleAuthority(),
            target_node_id="node-a",
            minimum_ready_nodes=0,
            expected_peer_snapshot_id=snapshot.snapshot_id,
            expected_peer_journal_seq=1,
            expected_role_assignment_id=role.assignment_id,
            expected_role_epoch=1,
            single_node_downtime_acknowledged=True,
        )
        self.assertTrue(allowed.safe)


if __name__ == "__main__":
    unittest.main()
