from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_admission import evaluate_safe_auto_repair_admission
from home_center.safe_auto_repair_audit import (
    SAFE_REPAIR_AUDIT_DETAILS_SCHEMA,
    SafeRepairAuditEvidenceError,
    safe_repair_audit_details,
)
from home_center.safe_auto_repair_job import (
    RepairExecutionOutcome,
    RepairJobState,
    build_safe_repair_job,
    record_safe_repair_execution,
    start_safe_repair_job,
    verify_safe_repair_post_condition,
)
from home_center.util import canonical_json


def _fixture():
    candidate = RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=7,
        evidence_sha256="1" * 64,
        action=RepairAction.REBUILD_DERIVED_INDEX,
        risk=RepairRisk.LOW,
        recovery_proven=True,
        post_condition_verifiable=True,
    )
    policy = SafeRepairPolicy(
        policy_id="policy-1",
        policy_sha256="2" * 64,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
    )
    recommendation = evaluate_safe_auto_repair(candidate=candidate, policy=policy)
    admission = evaluate_safe_auto_repair_admission(
        reviewed=recommendation,
        current_candidate=candidate,
        current_policy=policy,
    )
    job = build_safe_repair_job(
        admission=admission,
        idempotency_key="repair-key-0001",
        created_at_epoch=100,
    )
    return recommendation, job


class SafeRepairAuditEvidenceTests(unittest.TestCase):
    def test_projection_binds_exact_success_and_exposes_no_secret_authority(self) -> None:
        recommendation, job = _fixture()
        job = start_safe_repair_job(job, updated_at_epoch=101)
        job = record_safe_repair_execution(
            job,
            outcome=RepairExecutionOutcome.ACCEPTED,
            effect_receipt_sha256="3" * 64,
            updated_at_epoch=102,
        )
        job = verify_safe_repair_post_condition(
            job,
            evidence_sha256="4" * 64,
            verified=True,
            updated_at_epoch=103,
        )

        payload = safe_repair_audit_details(
            job=job,
            recommendation=recommendation,
        ).to_dict()

        self.assertEqual(SAFE_REPAIR_AUDIT_DETAILS_SCHEMA, payload["schema"])
        self.assertEqual(RepairJobState.SUCCEEDED.value, payload["job_state"])
        self.assertEqual("rebuild-derived-index", payload["action"])
        self.assertEqual("low", payload["risk"])
        self.assertEqual("3" * 64, payload["effect_receipt_sha256"])
        self.assertEqual("4" * 64, payload["post_condition_evidence_sha256"])
        self.assertTrue(payload["post_condition_verified"])
        self.assertTrue(payload["recovery_proven"])
        self.assertFalse(payload["raw_idempotency_key_persisted"])
        self.assertFalse(payload["credential_value_access_authorized"])
        self.assertFalse(payload["provider_execution_authorized"])
        self.assertFalse(payload["generic_infrastructure_mutation_authorized"])
        self.assertFalse(payload["external_publication_authorized"])
        self.assertFalse(payload["automatic_retry_authorized"])
        self.assertNotIn("idempotency_key", payload)
        self.assertNotIn("command", payload)
        self.assertNotIn("credential", payload)
        self.assertNotIn("provider_payload", payload)

    def test_projection_rejects_cross_bound_recommendation(self) -> None:
        recommendation, job = _fixture()
        other_candidate = replace(
            recommendation.candidate,
            resource_generation=recommendation.candidate.resource_generation + 1,
        )
        other_policy = SafeRepairPolicy(
            policy_id=recommendation.policy_id,
            policy_sha256=recommendation.policy_sha256,
            allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
        )
        other = evaluate_safe_auto_repair(
            candidate=other_candidate,
            policy=other_policy,
        )

        with self.assertRaisesRegex(
            SafeRepairAuditEvidenceError,
            "safe_repair_audit_recommendation_mismatch",
        ):
            safe_repair_audit_details(job=job, recommendation=other)

    def test_projection_rejects_tampered_recommendation_digest(self) -> None:
        recommendation, job = _fixture()
        tampered = replace(job, recommendation_sha256="f" * 64)

        with self.assertRaisesRegex(
            SafeRepairAuditEvidenceError,
            "safe_repair_audit_recommendation_digest_mismatch",
        ):
            safe_repair_audit_details(job=tampered, recommendation=recommendation)

    def test_projection_digest_matches_canonical_recommendation_payload(self) -> None:
        recommendation, job = _fixture()
        expected = hashlib.sha256(
            canonical_json(recommendation.to_dict()).encode("utf-8")
        ).hexdigest()

        details = safe_repair_audit_details(
            job=job,
            recommendation=recommendation,
        )

        self.assertEqual(expected, details.recommendation_sha256)
        self.assertEqual(RepairJobState.ADMITTED, details.job_state)
        self.assertFalse(details.post_condition_verified)


if __name__ == "__main__":
    unittest.main()
