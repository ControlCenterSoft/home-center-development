from __future__ import annotations

import unittest

from home_center.module_legal_compliance import build_module_legal_compliance_evidence
from home_center.module_legal_compliance_clearance import (
    evaluate_module_legal_compliance_clearance,
)
from home_center.module_legal_compliance_clearance_validation import (
    ModuleLegalComplianceClearanceValidationError,
    validate_module_legal_compliance_clearance,
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


class ModuleLegalComplianceClearanceValidationTests(unittest.TestCase):
    def test_round_trip_requires_exact_source_evidence(self) -> None:
        evidence = _evidence()
        clearance = evaluate_module_legal_compliance_clearance(evidence)
        validated = validate_module_legal_compliance_clearance(clearance.to_dict(), evidence=evidence)
        self.assertEqual(validated, clearance)
        self.assertFalse(validated.release_authorized)
        self.assertFalse(validated.external_publication_authorized)

    def test_tampered_status_is_rejected(self) -> None:
        evidence = _evidence()
        payload = evaluate_module_legal_compliance_clearance(evidence).to_dict()
        payload["status"] = "blocked"
        with self.assertRaisesRegex(ModuleLegalComplianceClearanceValidationError, "legal_compliance_clearance_rejected"):
            validate_module_legal_compliance_clearance(payload, evidence=evidence)

    def test_tampered_artifact_binding_is_rejected(self) -> None:
        evidence = _evidence()
        payload = evaluate_module_legal_compliance_clearance(evidence).to_dict()
        payload["artifact_sha256"] = "9" * 64
        with self.assertRaises(ModuleLegalComplianceClearanceValidationError):
            validate_module_legal_compliance_clearance(payload, evidence=evidence)

    def test_authority_escalation_is_rejected(self) -> None:
        evidence = _evidence()
        payload = evaluate_module_legal_compliance_clearance(evidence).to_dict()
        payload["release_authorized"] = True
        with self.assertRaises(ModuleLegalComplianceClearanceValidationError):
            validate_module_legal_compliance_clearance(payload, evidence=evidence)

    def test_unknown_field_is_rejected(self) -> None:
        evidence = _evidence()
        payload = evaluate_module_legal_compliance_clearance(evidence).to_dict()
        payload["unexpected"] = "value"
        with self.assertRaises(ModuleLegalComplianceClearanceValidationError):
            validate_module_legal_compliance_clearance(payload, evidence=evidence)

    def test_clearance_from_other_evidence_is_rejected(self) -> None:
        first = _evidence()
        second = _evidence(artifact_sha256="3" * 64)
        payload = evaluate_module_legal_compliance_clearance(first).to_dict()
        with self.assertRaises(ModuleLegalComplianceClearanceValidationError):
            validate_module_legal_compliance_clearance(payload, evidence=second)


if __name__ == "__main__":
    unittest.main()
