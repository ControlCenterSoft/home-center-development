from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from home_center.ha_rolling_writer_handoff_rollback_admission import (
    RollingWriterHandoffRollbackAdmission,
)
from home_center.ha_rolling_writer_handoff_rollback_commit import (
    HARollingWriterHandoffRollbackCommitError,
    RollingWriterHandoffRollbackCommitReceipt,
)
from home_center.ha_rolling_writer_handoff_rollback_readmission import (
    RollingWriterHandoffRollbackReadmission,
)
from home_center.ha_rolling_writer_handoff_rollback_readmission_consumption import (
    HARollingWriterHandoffRollbackReadmissionConsumptionError,
    consume_writer_handoff_rollback_readmission,
    revalidate_writer_handoff_rollback_readmission_consumption_receipt,
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


def admission(*, peer_snapshot_id: str, peer_journal_seq: int):
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


def readmission(
    *,
    prior: RollingWriterHandoffRollbackAdmission,
    candidate: RollingWriterHandoffRollbackAdmission,
):
    provisional = RollingWriterHandoffRollbackReadmission(
        cluster_id=candidate.cluster_id,
        readmission_id="pending",
        reconciliation_receipt_id="ha-rollback-reconciliation-01",
        prior_admission_id=prior.admission_id,
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


def commit_receipt(candidate: RollingWriterHandoffRollbackAdmission):
    provisional = RollingWriterHandoffRollbackCommitReceipt(
        cluster_id=candidate.cluster_id,
        receipt_id="pending",
        admission_id=candidate.admission_id,
        fencing_evidence_id=candidate.fencing_evidence_id,
        recovery_assessment_id=candidate.recovery_assessment_id,
        handoff_receipt_id=candidate.handoff_receipt_id,
        handoff_intent_id=candidate.handoff_intent_id,
        blocked_plan_id=candidate.blocked_plan_id,
        rollback_writer_node_id=candidate.rollback_writer_node_id,
        fenced_successor_node_id=candidate.fenced_successor_node_id,
        member_node_ids=candidate.member_node_ids,
        precommit_peer_snapshot_id=candidate.peer_snapshot_id,
        precommit_peer_journal_seq=candidate.peer_journal_seq,
        precommit_ready_node_ids=candidate.ready_node_ids,
        minimum_ready_nodes=candidate.minimum_ready_nodes,
        required_quorum_nodes=candidate.required_quorum_nodes,
        previous_role_assignment_id=candidate.expected_role_assignment_id,
        previous_role_epoch=candidate.expected_role_epoch,
        previous_role_resource_version=candidate.expected_role_resource_version,
        previous_role_journal_seq=candidate.expected_role_journal_seq,
        previous_role_transition_id=candidate.expected_role_transition_id,
        committed_role_assignment_id=candidate.target_role_assignment_id,
        committed_role_epoch=candidate.target_role_epoch,
        committed_role_resource_version=candidate.expected_role_resource_version + 1,
        committed_role_journal_seq=candidate.expected_role_journal_seq + 1,
        committed_role_transition_id="ha-role-transition-rollback-final",
        lease_id=candidate.lease_id,
        lease_epoch=candidate.lease_epoch,
        lease_resource_version=candidate.lease_resource_version,
        lease_state_id=candidate.lease_state_id,
    )
    material = provisional.to_dict()
    material.pop("receipt_id")
    return replace(
        provisional,
        receipt_id=stable_id("ha-roll-writer-handoff-rollback-commit", material),
    )


class RollbackReadmissionConsumptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.prior = admission(peer_snapshot_id="ha-state-prior-01", peer_journal_seq=8)
        self.candidate = admission(
            peer_snapshot_id="ha-state-fresh-02",
            peer_journal_seq=9,
        )
        self.readmission = readmission(prior=self.prior, candidate=self.candidate)
        self.commit = commit_receipt(self.candidate)

    def build(self):
        with (
            patch(
                "home_center.ha_rolling_writer_handoff_rollback_readmission_consumption."
                "revalidate_writer_handoff_rollback_readmission",
                return_value=self.readmission,
            ) as readmission_revalidate,
            patch(
                "home_center.ha_rolling_writer_handoff_rollback_readmission_consumption."
                "commit_writer_handoff_rollback",
                return_value=self.commit,
            ) as commit,
        ):
            result = consume_writer_handoff_rollback_readmission(
                readmission=self.readmission,
                prior_admission=self.prior,
                reconciliation=object(),
                candidate_admission=self.candidate,
                evidence=object(),
                assessment=object(),
                peer_authority=object(),
                role_authority=object(),
                lease_authority=object(),
            )
        readmission_revalidate.assert_called_once()
        commit.assert_called_once()
        return result

    def test_deterministic_terminal_consumption_has_no_retry_or_failover_authority(self):
        first = self.build()
        for _ in range(100):
            self.assertEqual(first, self.build())
        self.assertEqual(1, first.recovery_generation)
        self.assertEqual(1, first.maximum_recovery_generation)
        self.assertTrue(first.readmission_consumed)
        self.assertTrue(first.role_commit_applied)
        self.assertTrue(first.single_use_by_cas)
        self.assertFalse(first.fresh_admission_required)
        self.assertFalse(first.further_readmission_authorized)
        self.assertFalse(first.automatic_retry_authorized)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.failover_authorized)
        self.assertFalse(first.writer_service_authorized)
        self.assertFalse(first.host_mutation_authorized)
        self.assertFalse(first.production_mutation_enabled)

    def test_candidate_admission_must_match_fresh_readmission_exactly(self):
        bad = replace(self.candidate, peer_journal_seq=10)
        with (
            patch(
                "home_center.ha_rolling_writer_handoff_rollback_readmission_consumption."
                "revalidate_writer_handoff_rollback_readmission",
                return_value=self.readmission,
            ),
            patch(
                "home_center.ha_rolling_writer_handoff_rollback_readmission_consumption."
                "commit_writer_handoff_rollback",
            ) as commit,
        ):
            with self.assertRaisesRegex(
                HARollingWriterHandoffRollbackReadmissionConsumptionError,
                "candidate_lineage_invalid",
            ):
                consume_writer_handoff_rollback_readmission(
                    readmission=self.readmission,
                    prior_admission=self.prior,
                    reconciliation=object(),
                    candidate_admission=bad,
                    evidence=object(),
                    assessment=object(),
                    peer_authority=object(),
                    role_authority=object(),
                    lease_authority=object(),
                )
        commit.assert_not_called()

    def test_commit_receipt_must_bind_exact_candidate_and_role_revision(self):
        bad = replace(
            self.commit,
            committed_role_assignment_id="ha-role-assignment-other",
        )
        with (
            patch(
                "home_center.ha_rolling_writer_handoff_rollback_readmission_consumption."
                "revalidate_writer_handoff_rollback_readmission",
                return_value=self.readmission,
            ),
            patch(
                "home_center.ha_rolling_writer_handoff_rollback_readmission_consumption."
                "commit_writer_handoff_rollback",
                return_value=bad,
            ),
        ):
            with self.assertRaisesRegex(
                HARollingWriterHandoffRollbackReadmissionConsumptionError,
                "commit_lineage_invalid",
            ):
                consume_writer_handoff_rollback_readmission(
                    readmission=self.readmission,
                    prior_admission=self.prior,
                    reconciliation=object(),
                    candidate_admission=self.candidate,
                    evidence=object(),
                    assessment=object(),
                    peer_authority=object(),
                    role_authority=object(),
                    lease_authority=object(),
                )

    def test_ambiguous_final_cas_stays_on_reconciliation_path(self):
        failure = HARollingWriterHandoffRollbackCommitError(
            "rolling_writer_handoff_rollback_commit_reconciliation_required"
        )
        with (
            patch(
                "home_center.ha_rolling_writer_handoff_rollback_readmission_consumption."
                "revalidate_writer_handoff_rollback_readmission",
                return_value=self.readmission,
            ),
            patch(
                "home_center.ha_rolling_writer_handoff_rollback_readmission_consumption."
                "commit_writer_handoff_rollback",
                side_effect=failure,
            ),
        ):
            with self.assertRaisesRegex(
                HARollingWriterHandoffRollbackCommitError,
                "reconciliation_required",
            ):
                consume_writer_handoff_rollback_readmission(
                    readmission=self.readmission,
                    prior_admission=self.prior,
                    reconciliation=object(),
                    candidate_admission=self.candidate,
                    evidence=object(),
                    assessment=object(),
                    peer_authority=object(),
                    role_authority=object(),
                    lease_authority=object(),
                )

    def test_tampered_terminal_authority_or_generation_is_rejected(self):
        result = self.build()
        for tampered in (
            replace(result, further_readmission_authorized=True),
            replace(result, automatic_retry_authorized=True),
            replace(result, execution_authorized=True),
            replace(result, failover_authorized=True),
            replace(result, writer_service_authorized=True),
            replace(result, host_mutation_authorized=True),
            replace(result, production_mutation_enabled=True),
            replace(result, fresh_admission_required=True),
            replace(result, recovery_generation=2),
            replace(result, maximum_recovery_generation=2),
        ):
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(
                    HARollingWriterHandoffRollbackReadmissionConsumptionError,
                    "authority_invalid",
                ):
                    revalidate_writer_handoff_rollback_readmission_consumption_receipt(
                        receipt=tampered,
                        commit_receipt=self.commit,
                        role_authority=object(),
                    )

    def test_quorum_and_minimum_ready_evidence_cannot_be_relaxed(self):
        result = self.build()
        tampered = replace(result, precommit_ready_node_ids=("node-a",))
        material = tampered.to_dict()
        material.pop("consumption_id")
        tampered = replace(
            tampered,
            consumption_id=stable_id(
                "ha-roll-writer-handoff-rollback-readmission-consumption",
                material,
            ),
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackReadmissionConsumptionError,
            "safety_evidence_invalid",
        ):
            revalidate_writer_handoff_rollback_readmission_consumption_receipt(
                receipt=tampered,
                commit_receipt=self.commit,
                role_authority=object(),
            )

    def test_durable_revalidation_requires_exact_commit_receipt(self):
        result = self.build()
        with patch(
            "home_center.ha_rolling_writer_handoff_rollback_readmission_consumption."
            "revalidate_writer_handoff_rollback_commit_receipt",
            return_value=self.commit,
        ) as commit_revalidate:
            self.assertEqual(
                result,
                revalidate_writer_handoff_rollback_readmission_consumption_receipt(
                    receipt=result,
                    commit_receipt=self.commit,
                    role_authority=object(),
                ),
            )
        commit_revalidate.assert_called_once()

        wrong = replace(self.commit, admission_id=self.prior.admission_id)
        with patch(
            "home_center.ha_rolling_writer_handoff_rollback_readmission_consumption."
            "revalidate_writer_handoff_rollback_commit_receipt",
            return_value=wrong,
        ):
            with self.assertRaisesRegex(
                HARollingWriterHandoffRollbackReadmissionConsumptionError,
                "receipt_stale",
            ):
                revalidate_writer_handoff_rollback_readmission_consumption_receipt(
                    receipt=result,
                    commit_receipt=wrong,
                    role_authority=object(),
                )


if __name__ == "__main__":
    unittest.main()
