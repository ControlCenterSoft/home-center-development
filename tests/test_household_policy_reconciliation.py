from __future__ import annotations

import hashlib
import unittest

from home_center.household_policy_reconciliation import (
    HouseholdPolicyReconciliationError,
    build_reconciliation_request,
    observation_from_dict,
    request_from_dict,
    verify_policy_reconciliation,
)
from home_center.util import canonical_json


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def desired() -> dict[str, object]:
    policy = {
        "schema": "home-center.household-composed-policy.v1",
        "policy_id": "hcpol-" + "1" * 24,
        "household_id": "household-a",
        "member_id": "member-a",
        "role": "child",
        "base_policy_id": "hpol-" + "2" * 24,
        "bundle_id": "hpb-" + "3" * 24,
        "internet_policy": "filtered",
        "vpn_allowed": False,
        "managed_device_required": True,
        "home_files_allowed": True,
        "smart_home_control_allowed": False,
        "administration_allowed": False,
        "external_publication_allowed": False,
        "enforcement_verified": False,
        "production_mutation_enabled": False,
        "explanation_ru": "Правила подготовлены.",
    }
    return {
        "schema": "home-center.household-policy-desired-state.v1",
        "household_id": "household-a",
        "member_id": "member-a",
        "generation": 7,
        "plan_id": "hpcp-" + "4" * 24,
        "policy": policy,
        "policy_sha256": digest(policy),
        "reason": "family policy",
        "enforcement_verified": False,
        "reconciliation_required": True,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


class ReconciliationTest(unittest.TestCase):
    def request(self):
        return build_reconciliation_request(
            desired_state=desired(),
            backend_id="policy.backend.v1",
            requested_at="2026-09-12T11:40:00Z",
            max_observed_age_seconds=120,
        )

    def observation(self, request, *, state="enforced", digest_value=None, observed_at="2026-09-12T11:40:30Z"):
        if digest_value is None and state == "enforced":
            digest_value = request.binding.policy_sha256
        return observation_from_dict({
            "schema": "home-center.household-policy-actual-state-observation.v1",
            "request_id": request.request_id,
            "backend_id": request.backend_id,
            "observed_at": observed_at,
            "observed_state": state,
            "binding": request.binding.to_dict(),
            "actual_policy_sha256": digest_value,
            "read_only": True,
        })

    def test_request_roundtrip_is_content_addressed(self):
        request = self.request()
        self.assertEqual(request_from_dict(request.to_dict()), request)
        self.assertTrue(request.request_id.startswith("hprq-"))

    def test_exact_verified_readback_is_only_success(self):
        request = self.request()
        evidence = verify_policy_reconciliation(
            request=request,
            observation=self.observation(request),
            trusted_now="2026-09-12T11:41:00Z",
        )
        self.assertEqual(evidence["status"], "verified")
        self.assertIs(evidence["enforcement_verified"], True)
        self.assertIs(evidence["reconciliation_required"], False)
        self.assertIs(evidence["backend_mutation_performed"], False)

    def test_digest_mismatch_is_not_success(self):
        request = self.request()
        evidence = verify_policy_reconciliation(
            request=request,
            observation=self.observation(request, digest_value="a" * 64),
            trusted_now="2026-09-12T11:41:00Z",
        )
        self.assertEqual(evidence["status"], "mismatch")
        self.assertEqual(evidence["blocker"], "actual-policy-digest-mismatch")
        self.assertIs(evidence["enforcement_verified"], False)

    def test_not_enforced_is_pending(self):
        request = self.request()
        evidence = verify_policy_reconciliation(
            request=request,
            observation=self.observation(request, state="not-enforced", digest_value=None),
            trusted_now="2026-09-12T11:41:00Z",
        )
        self.assertEqual(evidence["status"], "pending")
        self.assertIs(evidence["reconciliation_required"], True)

    def test_unknown_and_ambiguous_fail_closed(self):
        for state in ("unknown", "ambiguous"):
            with self.subTest(state=state):
                request = self.request()
                evidence = verify_policy_reconciliation(
                    request=request,
                    observation=self.observation(request, state=state, digest_value=None),
                    trusted_now="2026-09-12T11:41:00Z",
                )
                self.assertEqual(evidence["status"], "blocked")
                self.assertIs(evidence["enforcement_verified"], False)

    def test_stale_observation_rejected(self):
        request = self.request()
        with self.assertRaisesRegex(HouseholdPolicyReconciliationError, "policy_reconciliation_observation_stale"):
            verify_policy_reconciliation(
                request=request,
                observation=self.observation(request, observed_at="2026-09-12T11:38:00Z"),
                trusted_now="2026-09-12T11:41:00Z",
            )

    def test_future_observation_rejected(self):
        request = self.request()
        with self.assertRaisesRegex(HouseholdPolicyReconciliationError, "policy_reconciliation_future_evidence"):
            verify_policy_reconciliation(
                request=request,
                observation=self.observation(request, observed_at="2026-09-12T11:42:00Z"),
                trusted_now="2026-09-12T11:41:00Z",
            )

    def test_binding_substitution_rejected(self):
        request = self.request()
        raw = self.observation(request).to_dict()
        raw["binding"] = {**raw["binding"], "desired_generation": 8}
        observation = observation_from_dict(raw)
        with self.assertRaisesRegex(HouseholdPolicyReconciliationError, "policy_reconciliation_binding_mismatch"):
            verify_policy_reconciliation(
                request=request,
                observation=observation,
                trusted_now="2026-09-12T11:41:00Z",
            )

    def test_backend_substitution_rejected(self):
        request = self.request()
        raw = self.observation(request).to_dict()
        raw["backend_id"] = "another.backend"
        observation = observation_from_dict(raw)
        with self.assertRaisesRegex(HouseholdPolicyReconciliationError, "policy_reconciliation_backend_mismatch"):
            verify_policy_reconciliation(
                request=request,
                observation=observation,
                trusted_now="2026-09-12T11:41:00Z",
            )

    def test_request_substitution_rejected(self):
        request = self.request()
        raw = self.observation(request).to_dict()
        raw["request_id"] = "hprq-" + "f" * 24
        observation = observation_from_dict(raw)
        with self.assertRaisesRegex(HouseholdPolicyReconciliationError, "policy_reconciliation_request_mismatch"):
            verify_policy_reconciliation(
                request=request,
                observation=observation,
                trusted_now="2026-09-12T11:41:00Z",
            )

    def test_desired_digest_tamper_rejected_before_request(self):
        value = desired()
        value["policy_sha256"] = "f" * 64
        with self.assertRaisesRegex(HouseholdPolicyReconciliationError, "policy_desired_state_digest_mismatch"):
            build_reconciliation_request(
                desired_state=value,
                backend_id="policy.backend.v1",
                requested_at="2026-09-12T11:40:00Z",
                max_observed_age_seconds=120,
            )

    def test_already_verified_desired_state_not_accepted_as_new_request(self):
        value = desired()
        value["enforcement_verified"] = True
        value["reconciliation_required"] = False
        with self.assertRaisesRegex(HouseholdPolicyReconciliationError, "invalid_policy_desired_state"):
            build_reconciliation_request(
                desired_state=value,
                backend_id="policy.backend.v1",
                requested_at="2026-09-12T11:40:00Z",
                max_observed_age_seconds=120,
            )

    def test_enforced_requires_digest(self):
        request = self.request()
        raw = self.observation(request).to_dict()
        raw["actual_policy_sha256"] = None
        with self.assertRaisesRegex(HouseholdPolicyReconciliationError, "policy_actual_state_digest_required"):
            observation_from_dict(raw)

    def test_max_age_is_bounded(self):
        with self.assertRaisesRegex(HouseholdPolicyReconciliationError, "invalid_policy_reconciliation_max_age"):
            build_reconciliation_request(
                desired_state=desired(), backend_id="policy.backend.v1",
                requested_at="2026-09-12T11:40:00Z", max_observed_age_seconds=901,
            )

    def test_non_utc_timestamp_rejected(self):
        with self.assertRaisesRegex(HouseholdPolicyReconciliationError, "invalid_policy_reconciliation_requested_at"):
            build_reconciliation_request(
                desired_state=desired(), backend_id="policy.backend.v1",
                requested_at="2026-09-12T14:40:00+03:00", max_observed_age_seconds=60,
            )


if __name__ == "__main__":
    unittest.main()
