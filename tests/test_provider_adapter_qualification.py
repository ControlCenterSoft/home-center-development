from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "product/control-plane/src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from home_center.provider_adapter_qualification import (  # noqa: E402
    ProviderAdapterQualificationError,
    ProviderAdapterQualificationEvidence,
    evaluate_provider_adapter_qualification,
)

VERSION = "0.57.0"
REVISION = "7" * 40
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


def _evidence(**overrides: object) -> ProviderAdapterQualificationEvidence:
    values: dict[str, object] = {
        "version": VERSION,
        "revision": REVISION,
        "adapter_id": "android-mdm-primary",
        "adapter_version": "1.0.0",
        "candidate_artifact_sha256": DIGEST_A,
        "adapter_artifact_sha256": DIGEST_B,
        "execution_transcript_sha256": DIGEST_C,
        "environment_evidence_sha256": DIGEST_D,
        "real_provider_exercised": True,
        "real_target_exercised": True,
        "start_contract_validated": True,
        "cancel_contract_validated": True,
        "secret_reference_only": True,
        "secret_values_absent_from_evidence": True,
        "retry_safe_only_when_proven": True,
        "ambiguous_outcome_fail_closed": True,
        "post_condition_separate": True,
        "managed_state_change_forbidden": True,
    }
    values.update(overrides)
    return ProviderAdapterQualificationEvidence(**values)  # type: ignore[arg-type]


class ProviderAdapterQualificationTests(unittest.TestCase):
    def test_complete_real_provider_evidence_is_qualified_without_granting_authority(self) -> None:
        decision = evaluate_provider_adapter_qualification(_evidence())
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.blockers, ())
        self.assertEqual(decision.candidate_artifact_sha256, DIGEST_A)
        self.assertRegex(decision.evidence_sha256, r"^[0-9a-f]{64}$")
        self.assertNotEqual(decision.evidence_sha256, "0" * 64)
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

    def test_hosted_or_contract_only_evidence_cannot_qualify_provider(self) -> None:
        decision = evaluate_provider_adapter_qualification(
            _evidence(real_provider_exercised=False, real_target_exercised=False)
        )
        self.assertFalse(decision.qualified)
        self.assertEqual(decision.blockers, ("real_provider", "real_target"))
        self.assertEqual(decision.evidence_sha256, "0" * 64)

    def test_false_success_and_secret_safety_properties_are_fail_closed(self) -> None:
        decision = evaluate_provider_adapter_qualification(
            _evidence(
                secret_reference_only=False,
                secret_values_absent_from_evidence=False,
                ambiguous_outcome_fail_closed=False,
                post_condition_separate=False,
                managed_state_change_forbidden=False,
            )
        )
        self.assertEqual(
            decision.blockers,
            (
                "secret_reference_only",
                "secret_values_absent",
                "ambiguous_outcome_fail_closed",
                "post_condition_separate",
                "managed_state_change_forbidden",
            ),
        )

    def test_missing_exact_evidence_digests_are_blockers(self) -> None:
        decision = evaluate_provider_adapter_qualification(
            _evidence(candidate_artifact_sha256="", adapter_artifact_sha256="bad")
        )
        self.assertEqual(
            decision.blockers,
            ("candidate_artifact_digest", "adapter_artifact_digest"),
        )

    def test_candidate_artifact_digest_changes_provider_evidence_identity(self) -> None:
        first = evaluate_provider_adapter_qualification(_evidence())
        second = evaluate_provider_adapter_qualification(
            _evidence(candidate_artifact_sha256="e" * 64)
        )
        self.assertNotEqual(first.evidence_sha256, second.evidence_sha256)

    def test_invalid_identity_is_rejected_before_evaluation(self) -> None:
        with self.assertRaisesRegex(
            ProviderAdapterQualificationError, "provider_qualification_revision_invalid"
        ):
            evaluate_provider_adapter_qualification(_evidence(revision="latest"))
        with self.assertRaisesRegex(
            ProviderAdapterQualificationError, "provider_qualification_adapter_id_invalid"
        ):
            evaluate_provider_adapter_qualification(_evidence(adapter_id="Android MDM"))

    def test_serialized_decision_matches_closed_schema(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/releases/provider-adapter-qualification.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(
            evaluate_provider_adapter_qualification(_evidence()).to_dict()
        )


if __name__ == "__main__":
    unittest.main()
