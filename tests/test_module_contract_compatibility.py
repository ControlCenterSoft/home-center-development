from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.module_contract_compatibility import (
    DEFAULT_SUPPORTED_CONTRACTS,
    ModuleContractCompatibilityError,
    build_module_contract_compatibility_profile,
    negotiate_module_contracts,
)


def _request(**overrides: str) -> dict[str, str]:
    values = {
        "module_manifest": "home-center.module-manifest.v2",
        "module_admission_decision": (
            "home-center.module-admission-decision.v1"
        ),
    }
    values.update(overrides)
    return values


class ModuleContractCompatibilityTests(unittest.TestCase):
    def test_default_profile_is_deterministic_and_closed(self) -> None:
        first = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        second = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        self.assertEqual(first, second)
        self.assertTrue(first.profile_id.startswith("mccp-"))
        payload = first.to_dict()
        self.assertFalse(payload["admission_authorized"])
        self.assertFalse(payload["installation_authorized"])
        self.assertFalse(payload["execution_authorized"])
        self.assertFalse(payload["production_mutation_enabled"])
        self.assertFalse(payload["external_publication_authorized"])

    def test_default_profile_matches_current_admission_boundary(self) -> None:
        profile = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        supported = dict(profile.supported_contracts)
        self.assertEqual(
            supported["module_manifest"],
            ("home-center.module-manifest.v2",),
        )
        self.assertNotIn(
            "home-center.module-manifest.v1",
            supported["module_manifest"],
        )
        self.assertEqual(
            set(supported),
            set(DEFAULT_SUPPORTED_CONTRACTS),
        )

    def test_current_mandatory_contracts_are_compatible(self) -> None:
        profile = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        decision = negotiate_module_contracts(
            profile,
            requested_contracts=_request(),
        )
        self.assertTrue(decision.compatible)
        self.assertEqual(decision.status, "compatible")
        self.assertEqual(decision.unsupported_contracts, ())
        self.assertEqual(decision.reasons, ())

    def test_old_manifest_revision_is_fail_closed(self) -> None:
        profile = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        decision = negotiate_module_contracts(
            profile,
            requested_contracts=_request(
                module_manifest="home-center.module-manifest.v1"
            ),
        )
        self.assertFalse(decision.compatible)
        self.assertEqual(decision.status, "unsupported-contract")
        self.assertEqual(
            decision.unsupported_contracts,
            (("module_manifest", "home-center.module-manifest.v1"),),
        )

    def test_unknown_admission_revision_is_fail_closed(self) -> None:
        profile = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        decision = negotiate_module_contracts(
            profile,
            requested_contracts=_request(
                module_admission_decision=(
                    "home-center.module-admission-decision.v2"
                )
            ),
        )
        self.assertFalse(decision.compatible)
        self.assertEqual(
            decision.unsupported_contracts[0][0],
            "module_admission_decision",
        )

    def test_optional_requested_contract_is_checked(self) -> None:
        profile = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        decision = negotiate_module_contracts(
            profile,
            requested_contracts=_request(
                module_candidate_set_revalidation=(
                    "home-center.module-candidate-set-revalidation.v2"
                )
            ),
        )
        self.assertFalse(decision.compatible)
        self.assertEqual(len(decision.unsupported_contracts), 1)

    def test_unknown_contract_family_is_rejected(self) -> None:
        profile = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        request = _request()
        request["unknown"] = "home-center.unknown.v1"
        with self.assertRaises(ModuleContractCompatibilityError) as caught:
            negotiate_module_contracts(
                profile,
                requested_contracts=request,
            )
        self.assertEqual(caught.exception.code, "contract_family_rejected")

    def test_missing_mandatory_contract_is_rejected(self) -> None:
        profile = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        with self.assertRaises(ModuleContractCompatibilityError) as caught:
            negotiate_module_contracts(
                profile,
                requested_contracts={
                    "module_manifest": "home-center.module-manifest.v2"
                },
            )
        self.assertEqual(caught.exception.code, "mandatory_contracts_missing")

    def test_tampered_profile_is_rejected(self) -> None:
        profile = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        tampered = replace(profile, profile_id="mccp-" + "0" * 24)
        with self.assertRaises(ModuleContractCompatibilityError) as caught:
            negotiate_module_contracts(
                tampered,
                requested_contracts=_request(),
            )
        self.assertEqual(
            caught.exception.code,
            "contract_compatibility_profile_mismatch",
        )

    def test_decision_is_deterministic_and_non_authorizing(self) -> None:
        profile = build_module_contract_compatibility_profile(
            home_center_version="0.37.0"
        )
        request = _request(
            module_compatibility_snapshot=(
                "home-center.module-compatibility-snapshot.v1"
            )
        )
        first = negotiate_module_contracts(
            profile,
            requested_contracts=request,
        )
        second = negotiate_module_contracts(
            profile,
            requested_contracts=dict(reversed(list(request.items()))),
        )
        self.assertEqual(first, second)
        payload = first.to_dict()
        self.assertFalse(payload["admission_authorized"])
        self.assertFalse(payload["installation_authorized"])
        self.assertFalse(payload["execution_authorized"])
        self.assertFalse(payload["production_mutation_enabled"])
        self.assertFalse(payload["external_publication_authorized"])

    def test_contract_schemas_are_closed_and_non_authorizing(self) -> None:
        root = Path(__file__).resolve().parents[1]
        names = (
            "module-contract-compatibility-profile.v1.schema.json",
            "module-contract-negotiation-decision.v1.schema.json",
        )
        for name in names:
            path = root / "contracts" / "modules" / name
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(schema["additionalProperties"])
            properties = schema["properties"]
            for flag in (
                "admission_authorized",
                "installation_authorized",
                "execution_authorized",
                "production_mutation_enabled",
                "external_publication_authorized",
            ):
                self.assertEqual(properties[flag]["const"], False)


if __name__ == "__main__":
    unittest.main()
