from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.module_legal_compliance import (
    DISTRIBUTION_MODES,
    ModuleLegalComplianceError,
    build_module_legal_compliance_evidence,
    validate_module_legal_compliance_evidence,
)


def _build(**overrides: object):
    values: dict[str, object] = {
        "module_id": "media.torrent-client",
        "module_version": "1.2.3",
        "artifact_sha256": "1" * 64,
        "license_expression": "GPL-3.0-only",
        "authoritative_source": "https://example.invalid/upstream/torrent-client",
        "distribution_mode": "official-download",
        "commercial_use_disposition": "allowed",
        "redistribution_disposition": "conditional",
        "notice_required": True,
        "source_offer_required": True,
        "license_evidence_version": "1.0.0",
        "license_evidence_sha256": "2" * 64,
    }
    values.update(overrides)
    return build_module_legal_compliance_evidence(**values)  # type: ignore[arg-type]


class ModuleLegalComplianceTests(unittest.TestCase):
    def test_evidence_is_deterministic_and_bound_to_artifact(self) -> None:
        first = _build()
        second = _build()
        changed = _build(artifact_sha256="3" * 64)

        self.assertEqual(first, second)
        self.assertNotEqual(first.evidence_id, changed.evidence_id)
        self.assertFalse(first.admission_authorized)
        self.assertFalse(first.installation_authorized)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.production_mutation_enabled)
        self.assertFalse(first.external_publication_authorized)

    def test_all_distribution_modes_are_supported_without_granting_authority(self) -> None:
        for mode in sorted(DISTRIBUTION_MODES):
            with self.subTest(mode=mode):
                result = _build(distribution_mode=mode)
                self.assertEqual(result.distribution_mode, mode)
                self.assertFalse(result.execution_authorized)

    def test_serialized_round_trip_is_canonical(self) -> None:
        original = _build()
        restored = validate_module_legal_compliance_evidence(original.to_dict())
        self.assertEqual(restored, original)

    def test_tampered_identity_is_rejected(self) -> None:
        payload = _build().to_dict()
        payload["artifact_sha256"] = "9" * 64
        with self.assertRaisesRegex(
            ModuleLegalComplianceError,
            "legal_compliance_evidence_rejected",
        ):
            validate_module_legal_compliance_evidence(payload)

    def test_authority_tampering_is_rejected(self) -> None:
        original = _build()
        tampered = replace(original, execution_authorized=True)
        with self.assertRaisesRegex(
            ModuleLegalComplianceError,
            "legal_compliance_evidence_rejected",
        ):
            validate_module_legal_compliance_evidence(tampered)

    def test_invalid_policy_values_are_rejected(self) -> None:
        cases = (
            ({"license_expression": " GPL-3.0-only"}, "license_expression_rejected"),
            ({"distribution_mode": "mirror"}, "distribution_mode_rejected"),
            ({"commercial_use_disposition": "maybe"}, "commercial_use_disposition_rejected"),
            ({"redistribution_disposition": "maybe"}, "redistribution_disposition_rejected"),
            ({"license_evidence_sha256": "not-a-digest"}, "license_evidence_digest_rejected"),
        )
        for values, code in cases:
            with self.subTest(values=values):
                with self.assertRaisesRegex(ModuleLegalComplianceError, code):
                    _build(**values)

    def test_schema_matches_runtime_and_is_closed(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "contracts/modules/module-legal-compliance-evidence.v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        result = _build().to_dict()

        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(result), set(schema["required"]))
        self.assertEqual(
            result["schema"],
            schema["properties"]["schema"]["const"],
        )
        self.assertRegex(result["evidence_id"], r"^mlce-[0-9a-f]{24}$")
        for name in (
            "admission_authorized",
            "installation_authorized",
            "execution_authorized",
            "production_mutation_enabled",
            "external_publication_authorized",
        ):
            self.assertEqual(schema["properties"][name], {"const": False})
            self.assertIs(result[name], False)


if __name__ == "__main__":
    unittest.main()
