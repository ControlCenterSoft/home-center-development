from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from home_center.ha_role_journal import HARoleAuthorityState
from home_center.ha_rolling_authority import (
    HARoleAssignment,
    HARoleAssignmentSnapshot,
    build_role_assignment_snapshot,
)
from home_center.ha_rolling_safety import NodeRole
from home_center.ha_rolling_writer_handoff_rollback_admission import (
    RollingWriterHandoffRollbackAdmission,
)
from home_center.ha_rolling_writer_handoff_rollback_reconciliation import (
    RollbackCommitOutcome,
    reconcile_writer_handoff_rollback,
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


def roles(writer: str) -> tuple[HARoleAssignment, ...]:
    return tuple(
        HARoleAssignment(
            node_id,
            NodeRole.WRITER if node_id == writer else NodeRole.STANDBY,
        )
        for node_id in NODES
    )


def valid_admission() -> RollingWriterHandoffRollbackAdmission:
    previous = build_role_assignment_snapshot(
        cluster_id="home-cluster",
        role_epoch=1,
        assignments=roles("node-b"),
    )
    target = build_role_assignment_snapshot(
        cluster_id="home-cluster",
        role_epoch=2,
        assignments=roles("node-a"),
    )
    provisional = RollingWriterHandoffRollbackAdmission(
        cluster_id="home-cluster",
        admission_id="pending",
        fencing_evidence_id="fence-evidence-01",
        recovery_assessment_id="recovery-assessment-01",
        handoff_receipt_id="handoff-receipt-01",
        handoff_intent_id="handoff-intent-01",
        blocked_plan_id="blocked-plan-01",
        rollback_writer_node_id="node-a",
        fenced_successor_node_id="node-b",
        member_node_ids=NODES,
        peer_snapshot_id="ha-state-degraded-01",
        peer_journal_seq=8,
        ready_node_ids=("node-a", "node-c"),
        ready_count=2,
        minimum_ready_nodes=2,
        required_quorum_nodes=2,
        expected_role_assignment_id=previous.assignment_id,
        expected_role_epoch=1,
        expected_role_resource_version=2,
        expected_role_journal_seq=2,
        expected_role_transition_id="ha-role-transition-handoff-01",
        target_role_assignment_id=target.assignment_id,
        target_role_epoch=2,
        lease_id="writer-lease-node-b",
        lease_epoch=9,
        lease_resource_version=12,
        lease_state_id="ha-writer-lease-revoked-01",
        lease_revoked_for_role_transition_id="ha-role-transition-handoff-01",
    )
    material = provisional.to_dict()
    material.pop("admission_id")
    return replace(
        provisional,
        admission_id=stable_id(
            "ha-roll-writer-handoff-rollback-admission",
            material,
        ),
    )


class MalformedAuthority:
    def __init__(self) -> None:
        self.snapshot = HARoleAssignmentSnapshot(
            cluster_id="home-cluster",
            role_epoch=2,
            assignments=(
                HARoleAssignment("node-a", NodeRole.WRITER),
                HARoleAssignment("node-b", NodeRole.WRITER),
                HARoleAssignment("node-c", NodeRole.STANDBY),
            ),
            assignment_id="ha-role-invalid-split-brain",
        )

    def state_for(self, *, cluster_id: str, node_ids: tuple[str, ...]):
        return HARoleAuthorityState(
            snapshot=self.snapshot,
            journal_seq=3,
            resource_version=3,
            transition_id="ha-role-transition-invalid-split-brain",
            transition_kind="failover",
        )

    def journal_entries(self, *, cluster_id: str, limit: int = 32):
        raise AssertionError("malformed state must fail closed before journal use")


class MalformedRoleEvidenceTests(unittest.TestCase):
    def test_split_brain_role_evidence_becomes_ambiguous_without_retry(self) -> None:
        receipt = reconcile_writer_handoff_rollback(
            admission=valid_admission(),
            role_authority=MalformedAuthority(),
        )
        self.assertIs(receipt.outcome, RollbackCommitOutcome.AMBIGUOUS)
        self.assertEqual("role_authority_unavailable", receipt.reason)
        self.assertTrue(receipt.operator_reconciliation_required)
        self.assertFalse(receipt.fresh_admission_authorized)
        self.assertFalse(receipt.automatic_retry_authorized)
        self.assertFalse(receipt.execution_authorized)
        self.assertFalse(receipt.failover_authorized)
        self.assertFalse(receipt.writer_service_authorized)
        self.assertFalse(receipt.production_mutation_enabled)


if __name__ == "__main__":
    unittest.main()
