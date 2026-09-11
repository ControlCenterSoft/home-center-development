from __future__ import annotations

import unittest

from home_center.module_legal_compliance import build_module_legal_compliance_evidence
from home_center.module_legal_compliance_clearance import (
    BLOCKED,
    CLEAR,
    CLEARANCE_SCHEMA,
    REVIEW_REQUIRED,
    evaluate_module_legal_compliance_clearance,
)


def _evidence(**overrides: object):
    values: dict[str, object] = {
        "module_id": "media.torrent-client",
        "module_version": "1.2.3",
        "artifact_sha256": "1" * 64,
        "license_expression": "MIT",
        "authoritative_source": "https://example.invalid/upstream/torrent-client",
        "distribution_mode": "official-download",
        "commercial_use_disposition": "allowed",
        "redistribution_disposition": "allowed",
        "notice_required": False,
        "source_offer_required": False,
        "license_evidence_version": "1.0.0",
        "license_evidence_sha256": "2" * 64,
    }
    values.update(overrides)
    return build_module_legal_compliance_evidence(**values)  # type: ignore[arg-type]


class ModuleLegalComplianceClearanceTests(unittest.TestCase):
    def test_allowed_evidence_is_clear_but_never_authorizing(self) -> None:
        evidence = _evidence()
        result = evaluate_module_legal_compliance_clearance(evidence)

        self.assertEqual(result.schema, CLEARANCE_SCHEMA)
        self.assertEqual(result.status, CLEAR)
        self.assertEqual(result.reasons, ())
        self.assertEqual(result.evidence_id, evidence.evidence_id)
        self.assertEqual(result.module_id, evidence.module_id)
        self.assertEqual(result.module_version, evidence.module_version)
        self.assertEqual(result.artifact_sha256, evidence.artifact_sha256)
        self.assertEqual(
            result.license_evidence_version,
            evidence.license_evidence_version,
        )
        self.assertEqual(
            result.license_evidence_sha256,
            evidence.license_evidence_sha256,
        )
        self.assertFalse(result.release_authorized)
        self.assertFalse(result.external_publication_authorized)

    def test_serialized_clearance_keeps_exact_provenance_and_no_authority(self) -> None:
        evidence = _evidence()
        result = evaluate_module_legal_compliance_clearance(evidence).to_dict()

        self.assertEqual(result["schema"], CLEARANCE_SCHEMA)
        self.assertEqual(result["evidence_id"], evidence.evidence_id)
        self.assertEqual(result["module_id"], "media.torrent-client")
        self.assertEqual(result["module_version"], "1.2.3")
        self.assertEqual(result["artifact_sha256"], "1" * 64)
        self.assertEqual(result["license_evidence_version"], "1.0.0")
        self.assertEqual(result["license_evidence_sha256"], "2" * 64)
        self.assertEqual(result["status"], CLEAR)
        self.assertEqual(result["reasons"], [])
        self.assertEqual(result["obligations"], [])
        self.assertIs(result["release_authorized"], False)
        self.assertIs(result["external_publication_authorized"], False)

    def test_conditional_or_unknown_evidence_requires_review(self) -> None:
        result = evaluate_module_legal_compliance_clearance(
            _evidence(
                commercial_use_disposition="unknown",
                redistribution_disposition="conditional",
            )
        )

        self.assertEqual(result.status, REVIEW_REQUIRED)
        self.assertEqual(
            result.reasons,
            ("commercial-use-unknown", "redistribution-conditional"),
        )

    def test_prohibited_disposition_blocks(self) -> None:
        result = evaluate_module_legal_compliance_clearance(
            _evidence(redistribution_disposition="prohibited")
        )

        self.assertEqual(result.status, BLOCKED)
        self.assertEqual(result.reasons, ("redistribution-prohibited",))

    def test_notice_and_source_offer_are_explicit_obligations(self) -> None:
        result = evaluate_module_legal_compliance_clearance(
            _evidence(notice_required=True, source_offer_required=True)
        )

        self.assertEqual(result.status, CLEAR)
        self.assertEqual(
            result.obligations,
            ("notice-required", "source-offer-required"),
        )

    def test_tampered_evidence_is_rejected_by_underlying_validator(self) -> None:
        payload = _evidence().to_dict()
        payload["artifact_sha256"] = "9" * 64

        with self.assertRaises(ValueError):
            evaluate_module_legal_compliance_clearance(payload)


if __name__ == "__main__":
    unittest.main()
