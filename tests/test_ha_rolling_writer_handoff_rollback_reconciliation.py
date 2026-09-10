from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from home_center.ha_role_journal import (
    HARoleAuthorityState,
    HARoleJournalEntry,
    HARoleJournalError,
)
from home_center.ha_rolling_authority import (
    HARoleAssignment,
    build_role_assignment_snapshot,
)
from home_center.ha_rolling_safety import NodeRole
from home_center.ha_rolling_writer_handoff_rollback_admission import (
    RollingWriterHandoffRollbackAdmission,
)
from home_center.ha_rolling_writer_handoff_rollback_reconciliation import (
    HARollingWriterHandoffRollbackReconciliationError,
    RollbackCommitOutcome,
    reconcile_writer_handoff_rollback,
    revalidate_writer_handoff_rollback_reconciliation_receipt,
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


def assignments(writer: str) -> tuple[HARoleAssignment, ...]:
    return tuple(
        HARoleAssignment(
            node_id,
            NodeRole.WRITER if node_id == writer else NodeRole.STANDBY,
        )
        for node_id in NODES
    )


def transition_id(
    *,
    previous_assignment_id: str,
    assignment_id: str,
    role_epoch: int,
    resource_version: int,
    journal_seq: int,
    kind: str,
) -> str:
    return stable_id(
        "ha-role-transition",
        {
            "schema": "home-center.ha-role-transition.v1",
            "cluster_id": "home-cluster",
            "kind": kind,
            "previous_assignment_id": previous_assignment_id,
            "assignment_id": assignment_id,
            "role_epoch": role_epoch,
            "resource_version": resource_version,
            "journal_seq": journal_seq,
        },
    )


def admission() -> RollingWriterHandoffRollbackAdmission:
    previous = build_role_assignment_snapshot(
        cluster_id="home-cluster",
        role_epoch=1,
        assignments=assignments("node-b"),
    )
    target = build_role_assignment_snapshot(
        cluster_id="home-cluster",
        role_epoch=2,
        assignments=assignments("node-a"),
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


def state(
    *,
    writer: str,
    role_epoch: int,
    resource_version: int,
    journal_seq: int,
    transition_kind: str,
    transition: str,
) -> HARoleAuthorityState:
    snapshot = build_role_assignment_snapshot(
        cluster_id="home-cluster",
        role_epoch=role_epoch,
        assignments=assignments(writer),
    )
    return HARoleAuthorityState(
        snapshot=snapshot,
        journal_seq=journal_seq,
        resource_version=resource_version,
        transition_id=transition,
        transition_kind=transition_kind,
    )


def entry(
    current: HARoleAuthorityState,
    *,
    previous_assignment_id: str | None,
) -> HARoleJournalEntry:
    return HARoleJournalEntry(
        cluster_id="home-cluster",
        journal_seq=current.journal_seq,
        role_epoch=current.snapshot.role_epoch,
        resource_version=current.resource_version,
        transition_id=current.transition_id,
        transition_kind=current.transition_kind,
        previous_assignment_id=previous_assignment_id,
        assignment_id=current.snapshot.assignment_id,
    )


class RoleAuthority:
    def __init__(
        self,
        current: HARoleAuthorityState,
        entries: tuple[HARoleJournalEntry, ...],
    ) -> None:
        self.current = current
        self.entries = entries

    def state_for(
        self,
        *,
        cluster_id: str,
        node_ids: tuple[str, ...],
    ) -> HARoleAuthorityState:
        return self.current

    def journal_entries(
        self,
        *,
        cluster_id: str,
        limit: int = 32,
    ) -> tuple[HARoleJournalEntry, ...]:
        return self.entries[-limit:]


class UnavailableAuthority:
    def state_for(self, *, cluster_id: str, node_ids: tuple[str, ...]):
        raise HARoleJournalError("role_state_unavailable")

    def journal_entries(self, *, cluster_id: str, limit: int = 32):
        raise AssertionError("journal must not be read after state failure")


class RollbackCommitReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.admission = admission()
        self.rollback_transition = transition_id(
            previous_assignment_id=self.admission.expected_role_assignment_id,
            assignment_id=self.admission.target_role_assignment_id,
            role_epoch=self.admission.target_role_epoch,
            resource_version=self.admission.expected_role_resource_version + 1,
            journal_seq=self.admission.expected_role_journal_seq + 1,
            kind="rollback",
        )

    def test_exact_current_rollback_is_committed_and_non_serving(self) -> None:
        current = state(
            writer="node-a",
            role_epoch=2,
            resource_version=3,
            journal_seq=3,
            transition_kind="rollback",
            transition=self.rollback_transition,
        )
        receipt = reconcile_writer_handoff_rollback(
            admission=self.admission,
            role_authority=RoleAuthority(
                current,
                (
                    entry(
                        current,
                        previous_assignment_id=self.admission.expected_role_assignment_id,
                    ),
                ),
            ),
        )
        self.assertIs(receipt.outcome, RollbackCommitOutcome.COMMITTED)
        self.assertTrue(receipt.rollback_completed)
        self.assertTrue(receipt.rollback_transition_observed)
        self.assertFalse(receipt.fresh_admission_required)
        self.assertFalse(receipt.operator_reconciliation_required)
        self.assertFalse(receipt.fresh_admission_authorized)
        self.assertFalse(receipt.automatic_retry_authorized)
        self.assertFalse(receipt.execution_authorized)
        self.assertFalse(receipt.writer_service_authorized)

    def test_exact_precommit_state_is_definitely_not_applied(self) -> None:
        current = state(
            writer="node-b",
            role_epoch=1,
            resource_version=2,
            journal_seq=2,
            transition_kind="failover",
            transition=self.admission.expected_role_transition_id,
        )
        receipt = reconcile_writer_handoff_rollback(
            admission=self.admission,
            role_authority=RoleAuthority(
                current,
                (entry(current, previous_assignment_id="prior-assignment-01"),),
            ),
        )
        self.assertIs(
            receipt.outcome,
            RollbackCommitOutcome.DEFINITELY_NOT_APPLIED,
        )
        self.assertFalse(receipt.rollback_completed)
        self.assertTrue(receipt.fresh_admission_required)
        self.assertFalse(receipt.fresh_admission_authorized)
        self.assertFalse(receipt.automatic_retry_authorized)

    def test_competing_transition_supersedes_admission_without_retry(self) -> None:
        competing = state(
            writer="node-c",
            role_epoch=2,
            resource_version=3,
            journal_seq=3,
            transition_kind="failover",
            transition="ha-role-transition-competing-01",
        )
        receipt = reconcile_writer_handoff_rollback(
            admission=self.admission,
            role_authority=RoleAuthority(
                competing,
                (
                    entry(
                        competing,
                        previous_assignment_id=self.admission.expected_role_assignment_id,
                    ),
                ),
            ),
        )
        self.assertIs(receipt.outcome, RollbackCommitOutcome.SUPERSEDED)
        self.assertEqual(
            "competing_transition_superseded_admission",
            receipt.reason,
        )
        self.assertTrue(receipt.operator_reconciliation_required)
        self.assertFalse(receipt.automatic_retry_authorized)
        self.assertFalse(receipt.failover_authorized)

    def test_committed_then_later_failover_is_superseded(self) -> None:
        rolled_back = state(
            writer="node-a",
            role_epoch=2,
            resource_version=3,
            journal_seq=3,
            transition_kind="rollback",
            transition=self.rollback_transition,
        )
        later = state(
            writer="node-c",
            role_epoch=3,
            resource_version=4,
            journal_seq=4,
            transition_kind="failover",
            transition="ha-role-transition-later-01",
        )
        receipt = reconcile_writer_handoff_rollback(
            admission=self.admission,
            role_authority=RoleAuthority(
                later,
                (
                    entry(
                        rolled_back,
                        previous_assignment_id=self.admission.expected_role_assignment_id,
                    ),
                    entry(
                        later,
                        previous_assignment_id=rolled_back.snapshot.assignment_id,
                    ),
                ),
            ),
        )
        self.assertIs(receipt.outcome, RollbackCommitOutcome.SUPERSEDED)
        self.assertEqual("rollback_transition_superseded", receipt.reason)
        self.assertTrue(receipt.rollback_transition_observed)
        self.assertTrue(receipt.operator_reconciliation_required)

    def test_missing_current_journal_evidence_is_ambiguous(self) -> None:
        current = state(
            writer="node-a",
            role_epoch=2,
            resource_version=3,
            journal_seq=3,
            transition_kind="rollback",
            transition=self.rollback_transition,
        )
        receipt = reconcile_writer_handoff_rollback(
            admission=self.admission,
            role_authority=RoleAuthority(current, ()),
        )
        self.assertIs(receipt.outcome, RollbackCommitOutcome.AMBIGUOUS)
        self.assertEqual("current_role_journal_evidence_missing", receipt.reason)
        self.assertTrue(receipt.operator_reconciliation_required)
        self.assertFalse(receipt.automatic_retry_authorized)

    def test_role_authority_failure_is_ambiguous(self) -> None:
        receipt = reconcile_writer_handoff_rollback(
            admission=self.admission,
            role_authority=UnavailableAuthority(),
        )
        self.assertIs(receipt.outcome, RollbackCommitOutcome.AMBIGUOUS)
        self.assertEqual("role_authority_unavailable", receipt.reason)
        self.assertIsNone(receipt.observed_role_journal_seq)
        self.assertTrue(receipt.operator_reconciliation_required)

    def test_receipt_identity_is_deterministic(self) -> None:
        current = state(
            writer="node-b",
            role_epoch=1,
            resource_version=2,
            journal_seq=2,
            transition_kind="failover",
            transition=self.admission.expected_role_transition_id,
        )
        authority = RoleAuthority(
            current,
            (entry(current, previous_assignment_id="prior-assignment-01"),),
        )
        ids = {
            reconcile_writer_handoff_rollback(
                admission=self.admission,
                role_authority=authority,
            ).receipt_id
            for _ in range(100)
        }
        self.assertEqual(1, len(ids))

    def test_tampering_cannot_create_retry_or_execution_authority(self) -> None:
        current = state(
            writer="node-b",
            role_epoch=1,
            resource_version=2,
            journal_seq=2,
            transition_kind="failover",
            transition=self.admission.expected_role_transition_id,
        )
        receipt = reconcile_writer_handoff_rollback(
            admission=self.admission,
            role_authority=RoleAuthority(
                current,
                (entry(current, previous_assignment_id="prior-assignment-01"),),
            ),
        )
        for tampered in (
            replace(receipt, fresh_admission_authorized=True),
            replace(receipt, automatic_retry_authorized=True),
            replace(receipt, execution_authorized=True),
            replace(receipt, failover_authorized=True),
            replace(receipt, writer_service_authorized=True),
            replace(receipt, production_mutation_enabled=True),
        ):
            with self.assertRaisesRegex(
                HARollingWriterHandoffRollbackReconciliationError,
                "receipt_authority_invalid",
            ):
                revalidate_writer_handoff_rollback_reconciliation_receipt(
                    receipt=tampered,
                )

    def test_admission_tampering_is_rejected_before_authority_read(self) -> None:
        tampered = replace(self.admission, execution_authorized=True)
        current = state(
            writer="node-b",
            role_epoch=1,
            resource_version=2,
            journal_seq=2,
            transition_kind="failover",
            transition=self.admission.expected_role_transition_id,
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackReconciliationError,
            "admission_authority_invalid",
        ):
            reconcile_writer_handoff_rollback(
                admission=tampered,
                role_authority=RoleAuthority(
                    current,
                    (entry(current, previous_assignment_id="prior-assignment-01"),),
                ),
            )


if __name__ == "__main__":
    unittest.main()
