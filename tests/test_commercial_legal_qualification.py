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

from home_center.commercial_legal_qualification import (  # noqa: E402
    BLOCKED,
    REVIEW_REQUIRED,
    CommercialLegalQualificationError,
    CommercialLegalQualificationEvidence,
    evaluate_commercial_legal_qualification,
)
from home_center.release_promotion_gate import APPROVED  # noqa: E402

VERSION = "0.57.0"
REVISION = "c" * 40
CANDIDATE_DIGEST = "a" * 64
REVIEW_DIGEST = "b" * 64


def _evidence(
    *,
    disposition: str = APPROVED,
    candidate_artifact_sha256: str = CANDIDATE_DIGEST,
    external_review_sha256: str = REVIEW_DIGEST,
    passed: bool = True,
) -> CommercialLegalQualificationEvidence:
    return CommercialLegalQualificationEvidence(
        version=VERSION,
        revision=REVISION,
        candidate_artifact_sha256=candidate_artifact_sha256,
        external_review_sha256=external_review_sha256,
        disposition=disposition,
        dependencies_reviewed=passed,
        redistribution_reviewed=passed,
        notices_prepared=passed,
        source_obligations_resolved=passed,
        sbom_reviewed=passed,
        legal_terms_dispositioned=passed,
        release_claims_reviewed=passed,
    )


class CommercialLegalQualificationTests(unittest.TestCase):
    def test_exact_approved_review_maps_to_existing_promotion_gate_contract(self) -> None:
        decision = evaluate_commercial_legal_qualification(_evidence())

        self.assertTrue(decision.qualified)
        self.assertEqual(decision.blockers, ())
        self.assertEqual(decision.disposition, APPROVED)
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

        promotion = decision.to_promotion_evidence(
            candidate_artifact_sha256=CANDIDATE_DIGEST
        )
        self.assertEqual(promotion.binding.version, VERSION)
        self.assertEqual(promotion.binding.revision, REVISION)
        self.assertEqual(promotion.disposition, APPROVED)
        self.assertEqual(promotion.evidence_sha256, decision.evidence_sha256)
        self.assertTrue(promotion.dependencies_reviewed)
        self.assertTrue(promotion.redistribution_reviewed)
        self.assertTrue(promotion.notices_prepared)
        self.assertTrue(promotion.source_obligations_resolved)
        self.assertTrue(promotion.sbom_reviewed)
        self.assertTrue(promotion.legal_terms_dispositioned)
        self.assertTrue(promotion.release_claims_reviewed)

    def test_approved_label_alone_cannot_create_qualified_evidence(self) -> None:
        decision = evaluate_commercial_legal_qualification(
            _evidence(external_review_sha256="", passed=False)
        )

        self.assertFalse(decision.qualified)
        self.assertEqual(
            decision.blockers,
            (
                "external_review_evidence",
                "dependencies_reviewed",
                "redistribution_reviewed",
                "notices_prepared",
                "source_obligations_resolved",
                "sbom_reviewed",
                "legal_terms_dispositioned",
                "release_claims_reviewed",
            ),
        )

        promotion = decision.to_promotion_evidence(
            candidate_artifact_sha256=CANDIDATE_DIGEST
        )
        self.assertEqual(promotion.disposition, REVIEW_REQUIRED)
        self.assertFalse(promotion.dependencies_reviewed)
        self.assertFalse(promotion.legal_terms_dispositioned)

    def test_non_approved_dispositions_remain_fail_closed(self) -> None:
        for disposition in (REVIEW_REQUIRED, BLOCKED):
            with self.subTest(disposition=disposition):
                decision = evaluate_commercial_legal_qualification(
                    _evidence(disposition=disposition)
                )
                self.assertFalse(decision.qualified)
                self.assertEqual(decision.blockers, ("commercial_disposition",))

    def test_cross_candidate_artifact_mapping_is_rejected(self) -> None:
        decision = evaluate_commercial_legal_qualification(_evidence())

        with self.assertRaisesRegex(
            CommercialLegalQualificationError,
            "commercial_candidate_artifact_binding",
        ):
            decision.to_promotion_evidence(candidate_artifact_sha256="d" * 64)

    def test_malformed_release_identity_is_rejected(self) -> None:
        malformed = CommercialLegalQualificationEvidence(
            version=VERSION,
            revision="latest",
            candidate_artifact_sha256=CANDIDATE_DIGEST,
            external_review_sha256=REVIEW_DIGEST,
            disposition=APPROVED,
            dependencies_reviewed=True,
            redistribution_reviewed=True,
            notices_prepared=True,
            source_obligations_resolved=True,
            sbom_reviewed=True,
            legal_terms_dispositioned=True,
            release_claims_reviewed=True,
        )
        with self.assertRaisesRegex(
            CommercialLegalQualificationError,
            "commercial_revision_invalid",
        ):
            evaluate_commercial_legal_qualification(malformed)

    def test_serialized_decision_matches_closed_schema(self) -> None:
        schema = json.loads(
            (
                ROOT
                / "contracts/releases/commercial-legal-qualification.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        decision = evaluate_commercial_legal_qualification(_evidence())
        jsonschema.Draft202012Validator(schema).validate(decision.to_dict())


if __name__ == "__main__":
    unittest.main()
