from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from home_center.ha_rolling_writer_handoff_rollback_admission import (
    HARollingWriterHandoffRollbackAdmissionError,
    RollingWriterHandoffRollbackAdmission,
)
from home_center.ha_rolling_writer_handoff_rollback_readmission import (
    HARollingWriterHandoffRollbackReadmissionError,
    build_writer_handoff_rollback_readmission,
    revalidate_writer_handoff_rollback_readmission,
)
from home_center.ha_rolling_writer_handoff_rollback_reconciliation import (
    RollbackCommitOutcome,
    RollingWriterHandoffRollbackReconciliationReceipt,
)


def stable_id(prefix: str, material: dict[str, object]) -> str:
    return f"{prefix}-{hashlib.sha256(json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()).hexdigest()}"


def admission(*, peer_snapshot_id: str = "ha-state-01", peer_journal_seq: int = 8):
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
        admission_id=stable_id("ha-roll-writer-handoff-rollback-admission", material),
    )


def reconciliation(
    prior: RollingWriterHandoffRollbackAdmission,
    *,
    outcome: RollbackCommitOutcome = RollbackCommitOutcome.DEFINITELY_NOT_APPLIED,
):
    eligible = outcome is RollbackCommitOutcome.DEFINITELY_NOT_APPLIED
    provisional = RollingWriterHandoffRollbackReconciliationReceipt(
        cluster_id=prior.cluster_id,
        receipt_id="pending",
        admission_id=prior.admission_id,
        member_node_ids=prior.member_node_ids,
        rollback_writer_node_id=prior.rollback_writer_node_id,
        fenced_successor_node_id=prior.fenced_successor_node_id,
        expected_role_assignment_id=prior.expected_role_assignment_id,
        expected_role_epoch=prior.expected_role_epoch,
        expected_role_resource_version=prior.expected_role_resource_version,
        expected_role_journal_seq=prior.expected_role_journal_seq,
        expected_role_transition_id=prior.expected_role_transition_id,
        target_role_assignment_id=prior.target_role_assignment_id,
        target_role_epoch=prior.target_role_epoch,
        expected_rollback_transition_id="ha-role-transition-rollback",
        observed_role_assignment_id=prior.expected_role_assignment_id,
        observed_role_epoch=prior.expected_role_epoch,
        observed_role_resource_version=prior.expected_role_resource_version,
        observed_role_journal_seq=prior.expected_role_journal_seq,
        observed_role_transition_id=prior.expected_role_transition_id,
        observed_role_transition_kind="failover",
        observed_writer_node_ids=(prior.fenced_successor_node_id,),
        rollback_transition_observed=False,
        outcome=outcome,
        reason="exact_precommit_revision_current" if eligible else "other-outcome",
        rollback_completed=outcome is RollbackCommitOutcome.COMMITTED,
        fresh_admission_required=eligible,
        operator_reconciliation_required=outcome
        in {RollbackCommitOutcome.SUPERSEDED, RollbackCommitOutcome.AMBIGUOUS},
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


class RollbackReadmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.prior = admission()
        self.receipt = reconciliation(self.prior)
        self.candidate = admission(
            peer_snapshot_id="ha-state-fresh-02",
            peer_journal_seq=9,
        )
        self.candidate = replace(self.candidate, admission_id="pending")
        material = self.candidate.to_dict()
        material.pop("admission_id")
        self.candidate = replace(
            self.candidate,
            admission_id=stable_id(
                "ha-roll-writer-handoff-rollback-admission",
                material,
            ),
        )

    def build(self):
        with (
            patch(
                "home_center.ha_rolling_writer_handoff_rollback_readmission."
                "build_writer_handoff_rollback_admission",
                return_value=self.candidate,
            ),
            patch(
                "home_center.ha_rolling_writer_handoff_rollback_readmission."
                "revalidate_writer_handoff_rollback_admission",
                return_value=self.candidate,
            ) as revalidate,
        ):
            result = build_writer_handoff_rollback_readmission(
                prior_admission=self.prior,
                reconciliation=self.receipt,
                evidence=object(),
                assessment=object(),
                peer_authority=object(),
                role_authority=object(),
                lease_authority=object(),
            )
        revalidate.assert_called_once()
        return result

    def test_deterministic_single_generation_and_no_execution_authority(self) -> None:
        first = self.build()
        for _ in range(100):
            self.assertEqual(first, self.build())
        self.assertEqual(1, first.recovery_generation)
        self.assertEqual(1, first.maximum_recovery_generation)
        self.assertTrue(first.fresh_cas_admission)
        self.assertTrue(first.single_use_by_cas)
        self.assertTrue(first.rollback_transition_admitted)
        self.assertFalse(first.automatic_retry_authorized)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.writer_service_authorized)
        self.assertFalse(first.host_mutation_authorized)
        self.assertFalse(first.production_mutation_enabled)

    def test_only_definitely_not_applied_receipt_is_eligible(self) -> None:
        for outcome in (
            RollbackCommitOutcome.COMMITTED,
            RollbackCommitOutcome.SUPERSEDED,
            RollbackCommitOutcome.AMBIGUOUS,
        ):
            with self.subTest(outcome=outcome):
                with self.assertRaisesRegex(
                    HARollingWriterHandoffRollbackReadmissionError,
                    "reconciliation_not_eligible",
                ):
                    build_writer_handoff_rollback_readmission(
                        prior_admission=self.prior,
                        reconciliation=reconciliation(self.prior, outcome=outcome),
                        evidence=object(),
                        assessment=object(),
                        peer_authority=object(),
                        role_authority=object(),
                        lease_authority=object(),
                    )

    def test_candidate_must_preserve_role_fence_and_lease_lineage(self) -> None:
        bad = replace(self.candidate, expected_role_epoch=99)
        with patch(
            "home_center.ha_rolling_writer_handoff_rollback_readmission."
            "build_writer_handoff_rollback_admission",
            return_value=bad,
        ):
            with self.assertRaisesRegex(
                HARollingWriterHandoffRollbackReadmissionError,
                "current_lineage_moved",
            ):
                build_writer_handoff_rollback_readmission(
                    prior_admission=self.prior,
                    reconciliation=self.receipt,
                    evidence=object(),
                    assessment=object(),
                    peer_authority=object(),
                    role_authority=object(),
                    lease_authority=object(),
                )

    def test_fresh_safety_or_failover_failure_propagates_fail_closed(self) -> None:
        for error in (
            HARollingWriterHandoffRollbackAdmissionError(
                "rolling_writer_handoff_rollback_safety_boundary_not_met"
            ),
            HARollingWriterHandoffRollbackAdmissionError(
                "rolling_writer_handoff_rollback_role_revision_stale"
            ),
        ):
            with self.subTest(error=str(error)):
                with patch(
                    "home_center.ha_rolling_writer_handoff_rollback_readmission."
                    "build_writer_handoff_rollback_admission",
                    side_effect=error,
                ):
                    with self.assertRaises(type(error)):
                        build_writer_handoff_rollback_readmission(
                            prior_admission=self.prior,
                            reconciliation=self.receipt,
                            evidence=object(),
                            assessment=object(),
                            peer_authority=object(),
                            role_authority=object(),
                            lease_authority=object(),
                        )

    def test_tampered_prior_identity_is_rejected_before_fresh_admission(self) -> None:
        with patch(
            "home_center.ha_rolling_writer_handoff_rollback_readmission."
            "build_writer_handoff_rollback_admission"
        ) as builder:
            with self.assertRaises(ValueError):
                build_writer_handoff_rollback_readmission(
                    prior_admission=replace(self.prior, admission_id="tampered"),
                    reconciliation=self.receipt,
                    evidence=object(),
                    assessment=object(),
                    peer_authority=object(),
                    role_authority=object(),
                    lease_authority=object(),
                )
            builder.assert_not_called()

    def test_saved_readmission_rejects_authority_and_generation_tampering(self) -> None:
        result = self.build()
        for tampered in (
            replace(result, automatic_retry_authorized=True),
            replace(result, execution_authorized=True),
            replace(result, failover_authorized=True),
            replace(result, writer_service_authorized=True),
            replace(result, host_mutation_authorized=True),
            replace(result, production_mutation_enabled=True),
            replace(result, recovery_generation=2),
            replace(result, maximum_recovery_generation=2),
        ):
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(
                    HARollingWriterHandoffRollbackReadmissionError,
                    "authority_invalid",
                ):
                    revalidate_writer_handoff_rollback_readmission(
                        readmission=tampered,
                        prior_admission=self.prior,
                        reconciliation=self.receipt,
                        evidence=object(),
                        assessment=object(),
                        peer_authority=object(),
                        role_authority=object(),
                        lease_authority=object(),
                    )


if __name__ == "__main__":
    unittest.main()
