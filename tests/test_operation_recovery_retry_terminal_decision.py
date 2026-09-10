from __future__ import annotations

import hashlib
import unittest

from home_center.operation_recovery_retry_terminal_decision import (
    OperationRecoveryRetryTerminalDecisionError,
    decide_operation_recovery_retry_terminal_boundary,
)
from home_center.operation_recovery_retry_terminal_lineage_revalidation import (
    OperationRecoveryRetryTerminalLineageRevalidation,
)
from home_center.util import canonical_json


def sha256(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def make_revalidation(
    *,
    status: str = "current",
    reason: str | None = None,
) -> OperationRecoveryRetryTerminalLineageRevalidation:
    if reason is None:
        reasons = {
            "current": "exact_terminal_lineage_current",
            "superseded": "durable_job_revision_advanced_after_seal",
            "ambiguous": "sealed_terminal_digest_mismatch",
        }
        reason = reasons[status]
    current = status == "current"
    values = {
        "seal_id": "oprecoveryseal-" + "1" * 24,
        "seal_sha256": "2" * 64,
        "job_id": "opjob-" + "3" * 24,
        "receipt_id": "oprecoveryverify-" + "4" * 24,
        "plan_id": "opplan-" + "5" * 24,
        "target_node_id": "home-node-a",
        "sealed_job_state": "rolled_back",
        "sealed_job_state_version": 8,
        "observed_job_state": "rolled_back",
        "observed_job_state_version": 9 if status == "superseded" else 8,
        "observed_job_completion_sha256": "6" * 64,
        "observed_terminal_evidence_sha256": "7" * 64,
        "observed_completion_journal_sha256": "8" * 64,
        "observed_audit_event_sha256": "9" * 64,
        "status": status,
        "reason": reason,
        "exact_seal_current": current,
        "fresh_decision_required": not current,
        "immutable_evidence_only": True,
        "contains_command_material": False,
        "accepts_caller_argv": False,
        "accepts_shell": False,
        "grants_execution_authority": False,
        "retry_authorized": False,
        "rollback_authorized": False,
        "production_mutation_enabled": False,
    }
    digest = sha256(values)
    return OperationRecoveryRetryTerminalLineageRevalidation(
        revalidation_id=f"oprecoveryrevalidate-{digest[:24]}",
        seal_id=values["seal_id"],
        seal_sha256=values["seal_sha256"],
        job_id=values["job_id"],
        receipt_id=values["receipt_id"],
        plan_id=values["plan_id"],
        target_node_id=values["target_node_id"],
        sealed_job_state=values["sealed_job_state"],
        sealed_job_state_version=values["sealed_job_state_version"],
        observed_job_state=values["observed_job_state"],
        observed_job_state_version=values["observed_job_state_version"],
        observed_job_completion_sha256=values["observed_job_completion_sha256"],
        observed_terminal_evidence_sha256=values[
            "observed_terminal_evidence_sha256"
        ],
        observed_completion_journal_sha256=values[
            "observed_completion_journal_sha256"
        ],
        observed_audit_event_sha256=values["observed_audit_event_sha256"],
        status=status,
        reason=reason,
        exact_seal_current=current,
        fresh_decision_required=not current,
    )


class TerminalDecisionBoundaryTests(unittest.TestCase):
    def test_current_lineage_only_allows_terminal_closure_acknowledgement(self):
        revalidation = make_revalidation()
        decision = decide_operation_recovery_retry_terminal_boundary(revalidation)

        self.assertEqual(decision.revalidation_status, "current")
        self.assertEqual(
            decision.operator_action,
            "acknowledge_terminal_closure",
        )
        self.assertTrue(decision.terminal_closure_eligible)
        self.assertFalse(decision.fresh_reconciliation_required)
        self.assertFalse(decision.new_lineage_required)
        self.assertEqual(
            decision.revalidation_sha256,
            sha256(revalidation.to_dict()),
        )
        self._assert_non_executable(decision)

    def test_current_decision_identity_is_deterministic(self):
        revalidation = make_revalidation()
        values = [
            decide_operation_recovery_retry_terminal_boundary(
                revalidation
            ).to_dict()
            for _ in range(100)
        ]
        self.assertTrue(all(value == values[0] for value in values))

    def test_superseded_lineage_requires_fresh_operator_reconciliation(self):
        decision = decide_operation_recovery_retry_terminal_boundary(
            make_revalidation(status="superseded")
        )
        self.assertEqual(decision.revalidation_status, "superseded")
        self.assertEqual(
            decision.operator_action,
            "start_fresh_operator_reconciliation",
        )
        self.assertFalse(decision.terminal_closure_eligible)
        self.assertTrue(decision.fresh_reconciliation_required)
        self.assertTrue(decision.new_lineage_required)
        self._assert_non_executable(decision)

    def test_ambiguous_lineage_requires_new_lineage_without_retry_authority(self):
        decision = decide_operation_recovery_retry_terminal_boundary(
            make_revalidation(status="ambiguous")
        )
        self.assertEqual(decision.revalidation_status, "ambiguous")
        self.assertTrue(decision.fresh_reconciliation_required)
        self.assertTrue(decision.new_lineage_required)
        self.assertFalse(decision.fresh_admission_authorized)
        self._assert_non_executable(decision)

    def test_tampered_revalidation_authority_is_rejected(self):
        revalidation = make_revalidation()
        object.__setattr__(revalidation, "retry_authorized", True)
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalDecisionError,
            "unsafe_terminal_revalidation",
        ):
            decide_operation_recovery_retry_terminal_boundary(revalidation)

    def test_tampered_revalidation_identity_is_rejected(self):
        revalidation = make_revalidation()
        object.__setattr__(
            revalidation,
            "revalidation_id",
            "oprecoveryrevalidate-" + "f" * 24,
        )
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalDecisionError,
            "terminal_revalidation_identity_mismatch",
        ):
            decide_operation_recovery_retry_terminal_boundary(revalidation)

    def test_status_reason_mismatch_is_rejected(self):
        revalidation = make_revalidation(
            status="ambiguous",
            reason="durable_job_revision_advanced_after_seal",
        )
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalDecisionError,
            "ambiguous_terminal_revalidation_inconsistent",
        ):
            decide_operation_recovery_retry_terminal_boundary(revalidation)

    def test_boolean_revision_is_rejected(self):
        revalidation = make_revalidation()
        object.__setattr__(revalidation, "sealed_job_state_version", True)
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalDecisionError,
            "invalid_terminal_revalidation_revision",
        ):
            decide_operation_recovery_retry_terminal_boundary(revalidation)

    def test_semantically_impossible_ambiguous_revision_is_rejected(self):
        revalidation = make_revalidation(status="ambiguous")
        object.__setattr__(revalidation, "observed_job_state_version", 9)
        material = {
            key: value
            for key, value in revalidation.to_dict().items()
            if key not in {"schema", "revalidation_id"}
        }
        digest = sha256(material)
        object.__setattr__(
            revalidation,
            "revalidation_id",
            f"oprecoveryrevalidate-{digest[:24]}",
        )
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalDecisionError,
            "ambiguous_terminal_revalidation_observation_mismatch",
        ):
            decide_operation_recovery_retry_terminal_boundary(revalidation)

    def test_invalid_observed_digest_is_rejected(self):
        revalidation = make_revalidation()
        object.__setattr__(
            revalidation,
            "observed_audit_event_sha256",
            "not-a-sha256",
        )
        with self.assertRaisesRegex(
            OperationRecoveryRetryTerminalDecisionError,
            "invalid_terminal_revalidation_digest",
        ):
            decide_operation_recovery_retry_terminal_boundary(revalidation)

    def test_decision_contract_has_no_caller_selected_command_surface(self):
        decision = decide_operation_recovery_retry_terminal_boundary(
            make_revalidation()
        )
        value = decision.to_dict()
        for forbidden in ("command", "argv", "shell_command", "executable"):
            self.assertNotIn(forbidden, value)
        self._assert_non_executable(decision)

    def _assert_non_executable(self, decision) -> None:
        self.assertFalse(decision.previous_lineage_reusable)
        self.assertFalse(decision.fresh_admission_authorized)
        for name in (
            "contains_command_material",
            "accepts_caller_argv",
            "accepts_shell",
            "grants_execution_authority",
            "retry_authorized",
            "rollback_authorized",
            "production_mutation_enabled",
        ):
            self.assertFalse(getattr(decision, name))


if __name__ == "__main__":
    unittest.main()
