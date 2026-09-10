from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from home_center.ha_rolling_writer_handoff_rollback_readmission_reconciliation import (
    RollingWriterHandoffRollbackReadmissionReconciliationReceipt,
)
from home_center.ha_rolling_writer_handoff_rollback_reconciliation import (
    RollbackCommitOutcome,
)
from home_center.ha_rolling_writer_handoff_rollback_terminal_closure import (
    HARollingWriterHandoffRollbackTerminalClosureError,
    close_terminal_rollback_readmission_reconciliation,
    revalidate_writer_handoff_rollback_terminal_closure_receipt,
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


def source_receipt(
    *,
    outcome: RollbackCommitOutcome = RollbackCommitOutcome.DEFINITELY_NOT_APPLIED,
):
    committed = outcome is RollbackCommitOutcome.COMMITTED
    provisional = RollingWriterHandoffRollbackReadmissionReconciliationReceipt(
        cluster_id="home-cluster",
        receipt_id="pending",
        readmission_id="ha-readmission-01",
        source_reconciliation_receipt_id="ha-source-reconciliation-01",
        prior_admission_id="ha-prior-admission-01",
        candidate_admission_id="ha-candidate-admission-01",
        observed_reconciliation_receipt_id="ha-observed-reconciliation-01",
        recovered_commit_receipt_id="ha-commit-01" if committed else None,
        recovered_consumption_id="ha-consumption-01" if committed else None,
        rollback_writer_node_id="node-a",
        fenced_successor_node_id="node-b",
        member_node_ids=("node-a", "node-b", "node-c"),
        expected_role_assignment_id="ha-role-before",
        expected_role_epoch=4,
        expected_role_resource_version=7,
        expected_role_journal_seq=9,
        expected_role_transition_id="ha-role-transition-before",
        target_role_assignment_id="ha-role-target",
        target_role_epoch=5,
        observed_role_assignment_id=("ha-role-target" if committed else "ha-role-before"),
        observed_role_epoch=5 if committed else 4,
        observed_role_resource_version=8 if committed else 7,
        observed_role_journal_seq=10 if committed else 9,
        observed_role_transition_id=("ha-rollback-transition-01" if committed else None),
        observed_writer_node_ids=("node-a",),
        outcome=outcome,
        reason=("exact_rollback_transition_current" if committed else "cas_not_applied"),
        terminal_consumption_recovered=committed,
        operator_recovery_closure_required=not committed,
    )
    material = provisional.to_dict()
    material.pop("receipt_id")
    return replace(
        provisional,
        receipt_id=stable_id(
            "ha-roll-writer-handoff-rollback-readmission-reconciliation",
            material,
        ),
    )


class TerminalRollbackClosureTests(unittest.TestCase):
    def test_closes_non_committed_terminal_lineage_without_authority(self):
        result = close_terminal_rollback_readmission_reconciliation(
            receipt=source_receipt(),
            operator_decision_id="operator-closure-01",
        )
        self.assertTrue(result.operator_recovery_closed)
        self.assertTrue(result.single_use_by_source_receipt)
        self.assertTrue(result.requires_new_recovery_lineage)
        self.assertTrue(result.new_peer_snapshot_required)
        self.assertTrue(result.new_fencing_evidence_required)
        self.assertTrue(result.new_recovery_assessment_required)
        self.assertFalse(result.previous_readmission_reusable)
        self.assertFalse(result.previous_admission_reusable)
        self.assertFalse(result.current_lineage_recovery_authorized)
        self.assertFalse(result.fresh_admission_authorized)
        self.assertFalse(result.further_readmission_authorized)
        self.assertFalse(result.automatic_retry_authorized)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.failover_authorized)
        self.assertFalse(result.writer_service_authorized)
        self.assertFalse(result.host_mutation_authorized)
        self.assertFalse(result.production_mutation_enabled)

    def test_closure_is_deterministic(self):
        source = source_receipt(outcome=RollbackCommitOutcome.AMBIGUOUS)
        first = close_terminal_rollback_readmission_reconciliation(
            receipt=source,
            operator_decision_id="operator-closure-02",
        )
        for _ in range(100):
            self.assertEqual(
                first,
                close_terminal_rollback_readmission_reconciliation(
                    receipt=source,
                    operator_decision_id="operator-closure-02",
                ),
            )

    def test_source_receipt_has_single_durable_replay_key(self):
        source = source_receipt(outcome=RollbackCommitOutcome.SUPERSEDED)
        first = close_terminal_rollback_readmission_reconciliation(
            receipt=source,
            operator_decision_id="operator-closure-a",
        )
        second = close_terminal_rollback_readmission_reconciliation(
            receipt=source,
            operator_decision_id="operator-closure-b",
        )
        self.assertEqual(first.closure_replay_key, second.closure_replay_key)
        self.assertNotEqual(first.closure_id, second.closure_id)

    def test_committed_terminal_lineage_is_not_closable(self):
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackTerminalClosureError,
            "rollback_terminal_closure_source_not_closable",
        ):
            close_terminal_rollback_readmission_reconciliation(
                receipt=source_receipt(outcome=RollbackCommitOutcome.COMMITTED),
                operator_decision_id="operator-closure-03",
            )

    def test_rejects_tampered_source_authority(self):
        source = replace(source_receipt(), automatic_retry_authorized=True)
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackTerminalClosureError,
            "rollback_terminal_closure_source_invalid",
        ):
            close_terminal_rollback_readmission_reconciliation(
                receipt=source,
                operator_decision_id="operator-closure-04",
            )

    def test_rejects_tampered_source_identity(self):
        source = replace(source_receipt(), receipt_id="tampered")
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackTerminalClosureError,
            "rollback_terminal_closure_source_invalid",
        ):
            close_terminal_rollback_readmission_reconciliation(
                receipt=source,
                operator_decision_id="operator-closure-05",
            )

    def test_revalidation_rejects_retry_authority(self):
        result = close_terminal_rollback_readmission_reconciliation(
            receipt=source_receipt(),
            operator_decision_id="operator-closure-06",
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackTerminalClosureError,
            "rollback_terminal_closure_authority_invalid",
        ):
            revalidate_writer_handoff_rollback_terminal_closure_receipt(
                receipt=replace(result, automatic_retry_authorized=True)
            )

    def test_revalidation_rejects_replay_key_tampering(self):
        result = close_terminal_rollback_readmission_reconciliation(
            receipt=source_receipt(),
            operator_decision_id="operator-closure-07",
        )
        with self.assertRaisesRegex(
            HARollingWriterHandoffRollbackTerminalClosureError,
            "rollback_terminal_closure_replay_key_invalid",
        ):
            revalidate_writer_handoff_rollback_terminal_closure_receipt(
                receipt=replace(result, closure_replay_key="tampered")
            )

    def test_operator_decision_id_is_bounded_token(self):
        for value in ("", " leading", "contains space", "x" * 129, "/bin/sh"):
            with self.subTest(value=value), self.assertRaisesRegex(
                HARollingWriterHandoffRollbackTerminalClosureError,
                "rollback_terminal_closure_operator_decision_id_invalid",
            ):
                close_terminal_rollback_readmission_reconciliation(
                    receipt=source_receipt(),
                    operator_decision_id=value,
                )


if __name__ == "__main__":
    unittest.main()
