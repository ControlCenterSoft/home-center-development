from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from home_center.ha_rolling_writer_handoff_rollback_admission import (
    RollingWriterHandoffRollbackAdmission,
)
from home_center.ha_rolling_writer_handoff_rollback_readmission import (
    RollingWriterHandoffRollbackReadmission,
)
from home_center.ha_rolling_writer_handoff_rollback_readmission_reconciliation import (
    HARollingWriterHandoffRollbackReadmissionReconciliationError,
    reconcile_writer_handoff_rollback_readmission,
    revalidate_writer_handoff_rollback_readmission_reconciliation_receipt,
)
from home_center.ha_rolling_writer_handoff_rollback_reconciliation import (
    RollbackCommitOutcome,
    RollingWriterHandoffRollbackReconciliationReceipt,
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


def admission(*, peer_snapshot_id: str = "ha-state-fresh-02", peer_journal_seq: int = 9):
    provisional = RollingWriterHandoffRollbackAdmission(
        cluster_id="home-cluster",
        admission_id="pending",
        fencing_evidence_id="ha-fence-01",
        recovery_assessment_id="ha-recovery-01",
        handoff_receipt_id="ha-handoff-receipt-01",
        handoff_intent_id="ha-handoff-intent-01",
        blocked_plan_id="ha-plan-01",
        rollback_writer_node_id="node-a",
        fenced_successor_node_id="node-b",
        member_node_ids=("node-a", "node-b", "node-c"),
        peer_snapshot_id=peer_snapshot_id,
        peer_journal_seq=peer_journal_seq,
        ready_node_ids=("node-a", "node-c"),
        ready_count=2,
        minimum_ready_nodes=2,
        required_quorum_nodes=2,
        expected_role_assignment_id="ha-role-assignment-before",
        expected_role_epoch=3,
        expected_role_resource_version=4,
        expected_role_journal_seq=5,
        expected_role_transition_id="ha-role-transition-failover",
        target_role_assignment_id="ha-role-assignment-rollback",
        target_role_epoch=4,
        lease_id="ha-writer-lease-node-b",
        lease_epoch=7,
        lease_resource_version=9,
        lease_state_id="ha-writer-lease-state-01",
        lease_revoked_for_role_transition_id="ha-role-transition-failover",
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


def readmission(candidate: RollingWriterHandoffRollbackAdmission):
    provisional = RollingWriterHandoffRollbackReadmission(
        cluster_id=candidate.cluster_id,
        readmission_id="pending",
        reconciliation_receipt_id="ha-rollback-reconciliation-source-01",
        prior_admission_id="ha-rollback-admission-prior-01",
        candidate_admission_id=candidate.admission_id,
        fencing_evidence_id=candidate.fencing_evidence_id,
        recovery_assessment_id=candidate.recovery_assessment_id,
        rollback_writer_node_id=candidate.rollback_writer_node_id,
        fenced_successor_node_id=candidate.fenced_successor_node_id,
        member_node_ids=candidate.member_node_ids,
        peer_snapshot_id=candidate.peer_snapshot_id,
        peer_journal_seq=candidate.peer_journal_seq,
        ready_node_ids=candidate.ready_node_ids,
        ready_count=candidate.ready_count,
        minimum_ready_nodes=candidate.minimum_ready_nodes,
        required_quorum_nodes=candidate.required_quorum_nodes,
        expected_role_assignment_id=candidate.expected_role_assignment_id,
        expected_role_epoch=candidate.expected_role_epoch,
        expected_role_resource_version=candidate.expected_role_resource_version,
        expected_role_journal_seq=candidate.expected_role_journal_seq,
        expected_role_transition_id=candidate.expected_role_transition_id,
        target_role_assignment_id=candidate.target_role_assignment_id,
        target_role_epoch=candidate.target_role_epoch,
        lease_id=candidate.lease_id,
        lease_epoch=candidate.lease_epoch,
        lease_resource_version=candidate.lease_resource_version,
        lease_state_id=candidate.lease_state_id,
        lease_revoked_for_role_transition_id=candidate.lease_revoked_for_role_transition_id,
    )
    material = provisional.to_dict()
    material.pop("readmission_id")
    return replace(
        provisional,
        readmission_id=stable_id(
            "ha-roll-writer-handoff-rollback-readmission",
            material,
        ),
    )


def expected_transition_id(candidate: RollingWriterHandoffRollbackAdmission) -> str:
    return stable_id(
        "ha-role-transition",
        {
            "schema": "home-center.ha-role-transition.v1",
            "cluster_id": candidate.cluster_id,
            "kind": "rollback",
            "previous_assignment_id": candidate.expected_role_assignment_id,
            "assignment_id": candidate.target_role_assignment_id,
            "role_epoch": candidate.target_role_epoch,
            "resource_version": candidate.expected_role_resource_version + 1,
            "journal_seq": candidate.expected_role_journal_seq + 1,
        },
    )


def observation(
    candidate: RollingWriterHandoffRollbackAdmission,
    outcome: RollbackCommitOutcome,
):
    transition_id = expected_transition_id(candidate)
    if outcome is RollbackCommitOutcome.COMMITTED:
        observed = {
            "observed_role_assignment_id": candidate.target_role_assignment_id,
            "observed_role_epoch": candidate.target_role_epoch,
            "observed_role_resource_version": candidate.expected_role_resource_version + 1,
            "observed_role_journal_seq": candidate.expected_role_journal_seq + 1,
            "observed_role_transition_id": transition_id,
            "observed_role_transition_kind": "rollback",
            "observed_writer_node_ids": (candidate.rollback_writer_node_id,),
            "rollback_transition_observed": True,
            "reason": "exact_rollback_transition_current",
            "rollback_completed": True,
            "fresh_admission_required": False,
            "operator_reconciliation_required": False,
        }
    elif outcome is RollbackCommitOutcome.DEFINITELY_NOT_APPLIED:
        observed = {
            "observed_role_assignment_id": candidate.expected_role_assignment_id,
            "observed_role_epoch": candidate.expected_role_epoch,
            "observed_role_resource_version": candidate.expected_role_resource_version,
            "observed_role_journal_seq": candidate.expected_role_journal_seq,
            "observed_role_transition_id": candidate.expected_role_transition_id,
            "observed_role_transition_kind": "failover",
            "observed_writer_node_ids": (candidate.fenced_successor_node_id,),
            "rollback_transition_observed": False,
            "reason": "exact_precommit_revision_current",
            "rollback_completed": False,
            "fresh_admission_required": True,
            "operator_reconciliation_required": False,
        }
    elif outcome is RollbackCommitOutcome.SUPERSEDED:
        observed = {
            "observed_role_assignment_id": "ha-role-assignment-newer",
            "observed_role_epoch": candidate.expected_role_epoch + 2,
            "observed_role_resource_version": candidate.expected_role_resource_version + 2,
            "observed_role_journal_seq": candidate.expected_role_journal_seq + 2,
            "observed_role_transition_id": "ha-role-transition-newer",
            "observed_role_transition_kind": "recovery",
            "observed_writer_node_ids": ("node-c",),
            "rollback_transition_observed": True,
            "reason": "rollback_transition_superseded",
            "rollback_completed": False,
            "fresh_admission_required": False,
            "operator_reconciliation_required": True,
        }
    else:
        observed = {
            "observed_role_assignment_id": None,
            "observed_role_epoch": None,
            "observed_role_resource_version": None,
            "observed_role_journal_seq": None,
            "observed_role_transition_id": None,
            "observed_role_transition_kind": None,
            "observed_writer_node_ids": (),
            "rollback_transition_observed": False,
            "reason": "role_authority_unavailable",
            "rollback_completed": False,
            "fresh_admission_required": False,
            "operator_reconciliation_required": True,
        }
    provisional = RollingWriterHandoffRollbackReconciliationReceipt(
        cluster_id=candidate.cluster_id,
        receipt_id="pending",
        admission_id=candidate.admission_id,
        member_node_ids=candidate.member_node_ids,
        rollback_writer_node_id=candidate.rollback_writer_node_id,
        fenced_successor_node_id=candidate.fenced_successor_node_id,
        expected_role_assignment_id=candidate.expected_role_assignment_id,
        expected_role_epoch=candidate.expected_role_epoch,
        expected_role_resource_version=candidate.expected_role_resource_version,
        expected_role_journal_seq=candidate.expected_role_journal_seq,
        expected_role_transition_id=candidate.expected_role_transition_id,
        target_role_assignment_id=candidate.target_role_assignment_id,
        target_role_epoch=candidate.target_role_epoch,
        expected_rollback_transition_id=transition_id,
        outcome=outcome,
        **observed,
    )
    material = provisional.to_dict()
    material.pop("receipt_id")
    return replace(
        provisional,
        receipt_id=stable_id(
            "ha-roll-writer-handoff-rollback-reconciliation",
            material,
        ),
    )


class TerminalReadmissionReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = admission()
        self.readmission = readmission(self.candidate)

    def reconcile(self, outcome: RollbackCommitOutcome):
        observed = observation(self.candidate, outcome)
        with (
            patch(
                "home_center."
                "ha_rolling_writer_handoff_rollback_readmission_reconciliation."
                "reconcile_writer_handoff_rollback",
                return_value=observed,
            ),
            patch(
                "home_center."
                "ha_rolling_writer_handoff_rollback_readmission_reconciliation."
                "revalidate_writer_handoff_rollback_commit_receipt",
            ),
            patch(
                "home_center."
                "ha_rolling_writer_handoff_rollback_readmission_reconciliation."
                "revalidate_writer_handoff_rollback_readmission_consumption_receipt",
            ),
        ):
            return reconcile_writer_handoff_rollback_readmission(
                readmission=self.readmission,
                candidate_admission=self.candidate,
                role_authority=object(),
            )

    def test_committed_recovers_terminal_consumption_deterministically(self):
        first = self.reconcile(RollbackCommitOutcome.COMMITTED)
        for _ in range(100):
            self.assertEqual(first, self.reconcile(RollbackCommitOutcome.COMMITTED))

        receipt = first.receipt
        self.assertTrue(receipt.terminal_consumption_recovered)
        self.assertFalse(receipt.operator_recovery_closure_required)
        self.assertIsNotNone(first.recovered_commit_receipt)
        self.assertIsNotNone(first.recovered_consumption_receipt)
        self.assertEqual(
            receipt.recovered_commit_receipt_id,
            first.recovered_commit_receipt.receipt_id,
        )
        self.assertEqual(
            receipt.recovered_consumption_id,
            first.recovered_consumption_receipt.consumption_id,
        )
        self.assertFalse(receipt.further_readmission_authorized)
        self.assertFalse(receipt.fresh_admission_authorized)
        self.assertFalse(receipt.automatic_retry_authorized)
        self.assertFalse(receipt.failover_authorized)
        self.assertFalse(receipt.production_mutation_enabled)

    def test_definitely_not_applied_is_terminal_closure_not_generation_two(self):
        result = self.reconcile(RollbackCommitOutcome.DEFINITELY_NOT_APPLIED)
        receipt = result.receipt
        self.assertFalse(receipt.terminal_consumption_recovered)
        self.assertTrue(receipt.operator_recovery_closure_required)
        self.assertIsNone(receipt.recovered_commit_receipt_id)
        self.assertIsNone(receipt.recovered_consumption_id)
        self.assertEqual(1, receipt.recovery_generation)
        self.assertEqual(1, receipt.maximum_recovery_generation)
        self.assertFalse(receipt.further_readmission_authorized)
        self.assertFalse(receipt.fresh_admission_authorized)
        self.assertFalse(receipt.automatic_retry_authorized)

    def test_superseded_and_ambiguous_require_operator_closure(self):
        for outcome in (
            RollbackCommitOutcome.SUPERSEDED,
            RollbackCommitOutcome.AMBIGUOUS,
        ):
            with self.subTest(outcome=outcome):
                result = self.reconcile(outcome)
                self.assertTrue(result.receipt.operator_recovery_closure_required)
                self.assertFalse(result.receipt.terminal_consumption_recovered)
                self.assertIsNone(result.recovered_commit_receipt)
                self.assertIsNone(result.recovered_consumption_receipt)
                self.assertFalse(result.receipt.failover_authorized)
                self.assertFalse(result.receipt.execution_authorized)

    def test_candidate_lineage_mismatch_is_rejected_before_state_read(self):
        moved = replace(
            self.candidate,
            peer_journal_seq=self.candidate.peer_journal_seq + 1,
        )
        with patch(
            "home_center."
            "ha_rolling_writer_handoff_rollback_readmission_reconciliation."
            "reconcile_writer_handoff_rollback"
        ) as reconcile:
            with self.assertRaisesRegex(
                HARollingWriterHandoffRollbackReadmissionReconciliationError,
                "candidate_lineage_invalid",
            ):
                reconcile_writer_handoff_rollback_readmission(
                    readmission=self.readmission,
                    candidate_admission=moved,
                    role_authority=object(),
                )
        reconcile.assert_not_called()

    def test_generation_or_retry_authority_tampering_is_rejected(self):
        for tampered in (
            replace(self.readmission, recovery_generation=2),
            replace(self.readmission, automatic_retry_authorized=True),
        ):
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(
                    HARollingWriterHandoffRollbackReadmissionReconciliationError,
                    "readmission_invalid",
                ):
                    reconcile_writer_handoff_rollback_readmission(
                        readmission=tampered,
                        candidate_admission=self.candidate,
                        role_authority=object(),
                    )

    def test_committed_writer_or_transition_drift_fails_closed(self):
        for changed in (
            replace(
                observation(self.candidate, RollbackCommitOutcome.COMMITTED),
                observed_writer_node_ids=("node-c",),
            ),
            replace(
                observation(self.candidate, RollbackCommitOutcome.COMMITTED),
                observed_role_transition_kind="recovery",
            ),
        ):
            with (
                patch(
                    "home_center."
                    "ha_rolling_writer_handoff_rollback_readmission_reconciliation."
                    "reconcile_writer_handoff_rollback",
                    return_value=changed,
                ),
                patch(
                    "home_center."
                    "ha_rolling_writer_handoff_rollback_readmission_reconciliation."
                    "revalidate_writer_handoff_rollback_reconciliation_receipt",
                ),
            ):
                with self.assertRaisesRegex(
                    HARollingWriterHandoffRollbackReadmissionReconciliationError,
                    "committed_evidence_invalid",
                ):
                    reconcile_writer_handoff_rollback_readmission(
                        readmission=self.readmission,
                        candidate_admission=self.candidate,
                        role_authority=object(),
                    )

    def test_committed_state_moving_after_observation_fails_closed(self):
        observed = observation(self.candidate, RollbackCommitOutcome.COMMITTED)
        with (
            patch(
                "home_center."
                "ha_rolling_writer_handoff_rollback_readmission_reconciliation."
                "reconcile_writer_handoff_rollback",
                return_value=observed,
            ),
            patch(
                "home_center."
                "ha_rolling_writer_handoff_rollback_readmission_reconciliation."
                "revalidate_writer_handoff_rollback_commit_receipt",
                side_effect=ValueError("state moved"),
            ),
        ):
            with self.assertRaisesRegex(
                HARollingWriterHandoffRollbackReadmissionReconciliationError,
                "commit_revalidation_failed",
            ):
                reconcile_writer_handoff_rollback_readmission(
                    readmission=self.readmission,
                    candidate_admission=self.candidate,
                    role_authority=object(),
                )

    def test_terminal_receipt_rejects_failover_or_retry_capability_tampering(self):
        receipt = self.reconcile(RollbackCommitOutcome.AMBIGUOUS).receipt
        for tampered in (
            replace(receipt, failover_authorized=True),
            replace(receipt, automatic_retry_authorized=True),
            replace(receipt, maximum_recovery_generation=2),
        ):
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(
                    HARollingWriterHandoffRollbackReadmissionReconciliationError,
                    "authority_invalid",
                ):
                    revalidate_writer_handoff_rollback_readmission_reconciliation_receipt(
                        receipt=tampered
                    )


if __name__ == "__main__":
    unittest.main()
