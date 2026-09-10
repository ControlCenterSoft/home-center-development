from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import dataclass, replace

from home_center.ha_rolling_writer_handoff_fencing import (
    HARollingWriterHandoffFencingError,
    build_writer_handoff_fencing_evidence,
    revalidate_writer_handoff_fencing_evidence,
)
from home_center.ha_rolling_writer_handoff_recovery import (
    RollingWriterHandoffRecoveryAssessment,
    WriterHandoffRecoveryDisposition,
)


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


def recovery_assessment(
    *,
    previous_health: str = "ready",
    successor_health: str = "degraded",
    ready_node_ids: tuple[str, ...] = ("node-a", "node-c"),
    reason: str = "successor_not_ready_fencing_required",
) -> RollingWriterHandoffRecoveryAssessment:
    provisional = RollingWriterHandoffRecoveryAssessment(
        cluster_id="home-cluster",
        assessment_id="pending",
        handoff_receipt_id="ha-roll-writer-handoff-receipt-" + "1" * 64,
        handoff_intent_id="ha-roll-writer-handoff-" + "2" * 64,
        blocked_plan_id="ha-roll-rev-" + "3" * 64,
        previous_writer_node_id="node-a",
        successor_writer_node_id="node-b",
        member_node_ids=("node-a", "node-b", "node-c"),
        peer_snapshot_id="ha-state-" + "4" * 64,
        peer_journal_seq=8,
        role_assignment_id="ha-role-" + "5" * 64,
        role_epoch=2,
        role_resource_version=2,
        role_journal_seq=2,
        role_transition_id="transition-2",
        minimum_ready_nodes=2,
        required_quorum_nodes=2,
        ready_node_ids=ready_node_ids,
        ready_count=len(ready_node_ids),
        previous_writer_health=previous_health,
        successor_writer_health=successor_health,
        disposition=WriterHandoffRecoveryDisposition.RECONCILE,
        reason=reason,
        fencing_required=True,
        reconciliation_required=True,
    )
    material = provisional.to_dict()
    material.pop("assessment_id")
    return replace(
        provisional,
        assessment_id=stable_id("ha-roll-writer-handoff-recovery", material),
    )


@dataclass(frozen=True, slots=True)
class LeaseState:
    cluster_id: str = "home-cluster"
    node_id: str = "node-b"
    lease_id: str = "writer-lease-node-b"
    lease_epoch: int = 9
    resource_version: int = 12
    holder_node_id: str | None = None
    revoked: bool = True
    state_id: str = ""
    production_mutation_enabled: bool = False


def lease_state(**changes) -> LeaseState:
    provisional = LeaseState(**changes)
    material = {
        "schema": "home-center.ha-writer-lease-state.v1",
        "cluster_id": provisional.cluster_id,
        "node_id": provisional.node_id,
        "lease_id": provisional.lease_id,
        "lease_epoch": provisional.lease_epoch,
        "resource_version": provisional.resource_version,
        "holder_node_id": provisional.holder_node_id,
        "revoked": provisional.revoked,
    }
    return replace(provisional, state_id=stable_id("ha-writer-lease", material))


class LeaseAuthority:
    def __init__(self, *states: LeaseState):
        self.states = states
        self.calls = 0

    def state_for(self, *, cluster_id: str, node_id: str) -> LeaseState:
        index = min(self.calls, len(self.states) - 1)
        self.calls += 1
        return self.states[index]


class WriterHandoffFencingEvidenceTests(unittest.TestCase):
    def test_confirmed_fence_is_deterministic_and_non_authorizing(self) -> None:
        assessment = recovery_assessment()
        state = lease_state()
        first = build_writer_handoff_fencing_evidence(
            assessment=assessment,
            lease_authority=LeaseAuthority(state),
        )
        for _ in range(100):
            current = build_writer_handoff_fencing_evidence(
                assessment=assessment,
                lease_authority=LeaseAuthority(state),
            )
            self.assertEqual(first, current)
        self.assertTrue(first.lease_revoked)
        self.assertTrue(first.fence_confirmed)
        self.assertEqual("node-a", first.rollback_candidate_node_id)
        self.assertFalse(first.rollback_admission_authorized)
        self.assertFalse(first.role_transition_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.host_mutation_authorized)
        self.assertFalse(first.production_mutation_enabled)

    def test_unrevoked_lease_is_rejected(self) -> None:
        state = lease_state(revoked=False, holder_node_id="node-b")
        with self.assertRaisesRegex(
            HARollingWriterHandoffFencingError,
            "lease_not_revoked",
        ):
            build_writer_handoff_fencing_evidence(
                assessment=recovery_assessment(),
                lease_authority=LeaseAuthority(state),
            )

    def test_revoked_lease_with_holder_is_rejected(self) -> None:
        state = lease_state(holder_node_id="node-b")
        with self.assertRaisesRegex(
            HARollingWriterHandoffFencingError,
            "lease_holder_present",
        ):
            build_writer_handoff_fencing_evidence(
                assessment=recovery_assessment(),
                lease_authority=LeaseAuthority(state),
            )

    def test_tampered_lease_identity_is_rejected(self) -> None:
        state = replace(lease_state(), state_id="ha-writer-lease-" + "0" * 64)
        with self.assertRaisesRegex(
            HARollingWriterHandoffFencingError,
            "lease_state_identity_invalid",
        ):
            build_writer_handoff_fencing_evidence(
                assessment=recovery_assessment(),
                lease_authority=LeaseAuthority(state),
            )

    def test_lease_revision_movement_while_sealing_is_rejected(self) -> None:
        before = lease_state(resource_version=12)
        after = lease_state(resource_version=13)
        with self.assertRaisesRegex(
            HARollingWriterHandoffFencingError,
            "lease_state_stale",
        ):
            build_writer_handoff_fencing_evidence(
                assessment=recovery_assessment(),
                lease_authority=LeaseAuthority(before, after),
            )

    def test_lost_quorum_recovery_is_not_eligible_for_fencing_evidence(self) -> None:
        assessment = recovery_assessment(
            ready_node_ids=("node-a",),
            reason="majority_quorum_not_met",
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffFencingError,
            "recovery_not_eligible",
        ):
            build_writer_handoff_fencing_evidence(
                assessment=assessment,
                lease_authority=LeaseAuthority(lease_state()),
            )

    def test_previous_writer_not_ready_is_not_eligible(self) -> None:
        assessment = recovery_assessment(
            previous_health="degraded",
            ready_node_ids=("node-c",),
            reason="previous_writer_not_ready",
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffFencingError,
            "recovery_not_eligible",
        ):
            build_writer_handoff_fencing_evidence(
                assessment=assessment,
                lease_authority=LeaseAuthority(lease_state()),
            )

    def test_tampered_recovery_identity_is_rejected(self) -> None:
        assessment = replace(
            recovery_assessment(),
            assessment_id="ha-roll-writer-handoff-recovery-" + "0" * 64,
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffFencingError,
            "recovery_identity_invalid",
        ):
            build_writer_handoff_fencing_evidence(
                assessment=assessment,
                lease_authority=LeaseAuthority(lease_state()),
            )

    def test_revalidation_rejects_changed_lease_revision(self) -> None:
        assessment = recovery_assessment()
        state = lease_state(resource_version=12)
        evidence = build_writer_handoff_fencing_evidence(
            assessment=assessment,
            lease_authority=LeaseAuthority(state),
        )
        changed = lease_state(resource_version=13)
        with self.assertRaisesRegex(
            HARollingWriterHandoffFencingError,
            "evidence_stale",
        ):
            revalidate_writer_handoff_fencing_evidence(
                evidence=evidence,
                assessment=assessment,
                lease_authority=LeaseAuthority(changed),
            )

    def test_tampered_evidence_cannot_authorize_rollback(self) -> None:
        assessment = recovery_assessment()
        state = lease_state()
        evidence = build_writer_handoff_fencing_evidence(
            assessment=assessment,
            lease_authority=LeaseAuthority(state),
        )
        tampered = replace(evidence, rollback_admission_authorized=True)
        with self.assertRaisesRegex(
            HARollingWriterHandoffFencingError,
            "evidence_authority_invalid",
        ):
            revalidate_writer_handoff_fencing_evidence(
                evidence=tampered,
                assessment=assessment,
                lease_authority=LeaseAuthority(state),
            )


if __name__ == "__main__":
    unittest.main()
