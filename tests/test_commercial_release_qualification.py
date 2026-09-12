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

from home_center.commercial_release_qualification import (  # noqa: E402
    CommercialReleaseEvidence,
    CommercialReleaseQualificationError,
    evaluate_commercial_release_qualification,
)

DIGESTS = tuple(chr(ord("a") + index) * 64 for index in range(9))


def _evidence(**overrides: object) -> CommercialReleaseEvidence:
    values: dict[str, object] = {
        "version": "0.57.0",
        "revision": "7" * 40,
        "candidate_artifact_sha256": DIGESTS[0],
        "dependencies_evidence_sha256": DIGESTS[1],
        "redistribution_evidence_sha256": DIGESTS[2],
        "notices_sha256": DIGESTS[3],
        "source_obligations_evidence_sha256": DIGESTS[4],
        "sbom_sha256": DIGESTS[5],
        "legal_terms_sha256": DIGESTS[6],
        "support_terms_sha256": DIGESTS[7],
        "release_claims_sha256": DIGESTS[8],
        "disposition": "approved",
        "dependencies_reviewed": True,
        "redistribution_reviewed": True,
        "notices_prepared": True,
        "source_obligations_resolved": True,
        "sbom_reviewed": True,
        "legal_terms_dispositioned": True,
        "support_terms_dispositioned": True,
        "release_claims_reviewed": True,
    }
    values.update(overrides)
    return CommercialReleaseEvidence(**values)  # type: ignore[arg-type]


class CommercialReleaseQualificationTests(unittest.TestCase):
    def test_complete_approved_evidence_qualifies_without_authority(self) -> None:
        decision = evaluate_commercial_release_qualification(_evidence())
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.blockers, ())
        self.assertRegex(decision.evidence_sha256, r"^[0-9a-f]{64}$")
        self.assertNotEqual(decision.evidence_sha256, "0" * 64)
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

    def test_approved_label_alone_does_not_qualify(self) -> None:
        decision = evaluate_commercial_release_qualification(
            _evidence(
                dependencies_reviewed=False,
                redistribution_reviewed=False,
                notices_prepared=False,
                source_obligations_resolved=False,
                sbom_reviewed=False,
                legal_terms_dispositioned=False,
                support_terms_dispositioned=False,
                release_claims_reviewed=False,
            )
        )
        self.assertFalse(decision.qualified)
        self.assertEqual(
            decision.blockers,
            (
                "dependencies_reviewed",
                "redistribution_reviewed",
                "notices_prepared",
                "source_obligations_resolved",
                "sbom_reviewed",
                "legal_terms_dispositioned",
                "support_terms_dispositioned",
                "release_claims_reviewed",
            ),
        )
        self.assertEqual(decision.evidence_sha256, "0" * 64)

    def test_support_terms_digest_is_not_enough_without_disposition(self) -> None:
        decision = evaluate_commercial_release_qualification(
            _evidence(support_terms_dispositioned=False)
        )
        self.assertFalse(decision.qualified)
        self.assertEqual(decision.blockers, ("support_terms_dispositioned",))
        self.assertEqual(decision.evidence_sha256, "0" * 64)

    def test_review_required_and_rejected_dispositions_fail_closed(self) -> None:
        for disposition in ("review-required", "rejected"):
            with self.subTest(disposition=disposition):
                decision = evaluate_commercial_release_qualification(
                    _evidence(disposition=disposition)
                )
                self.assertFalse(decision.qualified)
                self.assertEqual(decision.blockers, ("commercial_disposition",))

    def test_missing_document_digest_blocks_qualification(self) -> None:
        decision = evaluate_commercial_release_qualification(
            _evidence(legal_terms_sha256="")
        )
        self.assertEqual(decision.blockers, ("legal_terms_digest",))

    def test_candidate_digest_changes_evidence_identity(self) -> None:
        first = evaluate_commercial_release_qualification(_evidence())
        second = evaluate_commercial_release_qualification(
            _evidence(candidate_artifact_sha256="f" * 64)
        )
        self.assertNotEqual(first.evidence_sha256, second.evidence_sha256)

    def test_invalid_identity_or_disposition_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            CommercialReleaseQualificationError, "commercial_revision_invalid"
        ):
            evaluate_commercial_release_qualification(_evidence(revision="latest"))
        with self.assertRaisesRegex(
            CommercialReleaseQualificationError, "commercial_disposition_invalid"
        ):
            evaluate_commercial_release_qualification(_evidence(disposition="auto-approved"))

    def test_serialized_decision_matches_closed_schema(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/releases/commercial-release-qualification.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(
            evaluate_commercial_release_qualification(_evidence()).to_dict()
        )


if __name__ == "__main__":
    unittest.main()
