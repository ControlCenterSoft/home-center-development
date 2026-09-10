from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.home_service_state import HomeServiceInstanceStateStore
from home_center.home_service_transition_apply import HomeServiceTransitionApplyReceipt
from home_center.home_service_transition_audit import HomeServiceAuditedTransitionApply
from home_center.home_service_transition_completion import (
    HomeServiceTransitionCompletionContext,
    record_transition_completion_audit,
)
from home_center.home_service_transition_verify import (
    HomeServiceTransitionVerification,
    TransitionVerificationCode,
    TransitionVerificationStatus,
)
from home_center.home_services import HomeServiceCatalogError
from home_center.store import StateStore


class HomeServiceTransitionCompletionTests(unittest.TestCase):
    def _evidence(self, store: StateStore, *, status: TransitionVerificationStatus = TransitionVerificationStatus.VERIFIED):
        receipt = HomeServiceTransitionApplyReceipt(
            receipt_id="hstr-" + "a" * 24,
            authorization_id="hsta-001",
            commit_id="hstc-" + "b" * 24,
            decision_id="hstd-" + "c" * 24,
            instance_id="instance-001",
            target_state="installed",
            generation=2,
            resource_version="rv:instance:" + "d" * 24,
            applied=True,
            idempotent_replay=False,
        )
        preapply_event_id = store.audit(
            actor="admin",
            action="home-service.transition.apply.requested",
            target=receipt.instance_id,
            outcome="authorized",
            correlation_id="preapply-001",
            details={
                "reason": "Apply authorized transition",
                "authorization_id": receipt.authorization_id,
                "commit_id": receipt.commit_id,
                "decision_id": receipt.decision_id,
                "source_state": "planned",
                "target_state": receipt.target_state,
                "expected_generation": 1,
                "expected_resource_version": "rv:instance:" + "e" * 24,
                "next_generation": receipt.generation,
                "next_resource_version": receipt.resource_version,
            },
        )
        applied = HomeServiceAuditedTransitionApply(
            audit_event_id=preapply_event_id,
            correlation_id="preapply-001",
            receipt=receipt,
        )
        codes = () if status is TransitionVerificationStatus.VERIFIED else (TransitionVerificationCode.STATE_MISMATCH,)
        observed_state = receipt.target_state if status is TransitionVerificationStatus.VERIFIED else "degraded"
        verification = HomeServiceTransitionVerification(
            verification_id="hstv-" + "f" * 24,
            receipt_id=receipt.receipt_id,
            authorization_id=receipt.authorization_id,
            commit_id=receipt.commit_id,
            decision_id=receipt.decision_id,
            instance_id=receipt.instance_id,
            expected_state=receipt.target_state,
            expected_generation=receipt.generation,
            expected_resource_version=receipt.resource_version,
            observed_state=observed_state,
            observed_generation=receipt.generation,
            observed_resource_version=receipt.resource_version,
            status=status,
            mismatch_codes=codes,
        )
        return applied, verification

    def test_verified_completion_is_bound_into_audit_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            applied, verification = self._evidence(store)
            completion = record_transition_completion_audit(
                applied,
                verification,
                instances,
                HomeServiceTransitionCompletionContext(
                    actor="admin",
                    reason="Record read-back verification",
                    correlation_id="completion-001",
                ),
            )

            events = store.audit_events()
            self.assertEqual(2, len(events))
            event = events[0]
            self.assertEqual(completion.audit_event_id, event["event_id"])
            self.assertEqual("home-service.transition.apply.verified", event["action"])
            self.assertEqual("verified", event["outcome"])
            self.assertEqual(applied.audit_event_id, event["details"]["preapply_audit_event_id"])
            self.assertEqual(verification.verification_id, event["details"]["verification_id"])
            self.assertFalse(completion.service_state_mutation_authorized)
            self.assertFalse(completion.further_mutation_authorized)
            self.assertNotEqual("0" * 64, store.verify_audit_chain())
            store.close()

    def test_drifted_completion_records_drift_without_mutation_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            applied, verification = self._evidence(store, status=TransitionVerificationStatus.DRIFTED)
            completion = record_transition_completion_audit(
                applied,
                verification,
                instances,
                HomeServiceTransitionCompletionContext(
                    actor="admin",
                    reason="Record detected drift",
                    correlation_id="completion-002",
                ),
            )
            self.assertEqual("drifted", completion.status)
            self.assertEqual(("state_mismatch",), completion.mismatch_codes)
            self.assertEqual("home-service.transition.apply.drifted", store.audit_events()[0]["action"])
            store.close()

    def test_missing_preapply_event_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            applied, verification = self._evidence(store)
            forged = replace(applied, audit_event_id="missing-event")
            with self.assertRaisesRegex(HomeServiceCatalogError, "transition_preapply_audit_not_found"):
                record_transition_completion_audit(
                    forged,
                    verification,
                    instances,
                    HomeServiceTransitionCompletionContext(
                        actor="admin",
                        reason="Reject missing evidence",
                        correlation_id="completion-003",
                    ),
                )
            self.assertEqual(1, len(store.audit_events()))
            store.close()

    def test_verification_binding_mismatch_fails_before_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "home-test")
            instances = HomeServiceInstanceStateStore(store)
            applied, verification = self._evidence(store)
            mismatched = replace(verification, receipt_id="hstr-" + "0" * 24)
            with self.assertRaisesRegex(HomeServiceCatalogError, "transition_completion_binding_mismatch"):
                record_transition_completion_audit(
                    applied,
                    mismatched,
                    instances,
                    HomeServiceTransitionCompletionContext(
                        actor="admin",
                        reason="Reject mismatched evidence",
                        correlation_id="completion-004",
                    ),
                )
            self.assertEqual(1, len(store.audit_events()))
            store.close()


if __name__ == "__main__":
    unittest.main()
