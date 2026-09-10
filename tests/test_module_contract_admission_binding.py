from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from home_center.module_contract_admission_binding import (
    ModuleContractAdmissionBindingError,
    bind_module_contract_admission,
)


def _canonical_id(prefix: str, payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return prefix + hashlib.sha256(encoded).hexdigest()[:24]


def _profile(version: str = "0.38.0") -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": "home-center.module-contract-compatibility-profile.v1",
        "home_center_version": version,
        "supported_contracts": {
            "module_manifest": ["home-center.module-manifest.v2"],
            "module_admission_decision": [
                "home-center.module-admission-decision.v1"
            ],
        },
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    payload["profile_id"] = _canonical_id("mccp-", payload)
    return payload


def _negotiation(
    profile: dict[str, object],
    *,
    status: str = "compatible",
    manifest_schema: str = "home-center.module-manifest.v2",
    admission_schema: str = "home-center.module-admission-decision.v1",
) -> dict[str, object]:
    unsupported: list[dict[str, str]] = []
    reasons: list[str] = []
    if status != "compatible":
        unsupported = [
            {
                "family": "module_manifest",
                "schema": manifest_schema,
            }
        ]
        reasons = [
            f"unsupported_contract:module_manifest:{manifest_schema}"
        ]
    payload: dict[str, object] = {
        "schema": "home-center.module-contract-negotiation-decision.v1",
        "profile_id": profile["profile_id"],
        "home_center_version": profile["home_center_version"],
        "status": status,
        "requested_contracts": {
            "module_manifest": manifest_schema,
            "module_admission_decision": admission_schema,
        },
        "unsupported_contracts": unsupported,
        "reasons": reasons,
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    payload["decision_id"] = _canonical_id("mcnd-", payload)
    return payload


def _admission(
    *,
    version: str = "0.38.0",
    status: str = "compatible",
) -> dict[str, object]:
    reasons = [] if status == "compatible" else ["capability_missing"]
    missing = [] if status == "compatible" else ["network.lan"]
    payload: dict[str, object] = {
        "schema": "home-center.module-admission-decision.v1",
        "status": status,
        "module_id": "example.media",
        "module_version": "1.2.0",
        "publisher": "example",
        "manifest_binding_sha256": "a" * 64,
        "provenance_statement_sha256": "b" * 64,
        "verified_signing_key_ids": ["sha256:" + "c" * 64],
        "artifact_sha256": "d" * 64,
        "home_center_version": version,
        "architecture": "x86-64",
        "operating_system": "linux",
        "available_capabilities": ["network.lan"],
        "installed_modules": [],
        "missing_capabilities": missing,
        "unsatisfied_dependencies": [],
        "active_conflicts": [],
        "reasons": reasons,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    payload["decision_id"] = _canonical_id("madm-", payload)
    return payload


class ModuleContractAdmissionBindingTests(unittest.TestCase):
    def test_binding_is_deterministic_and_non_authorizing(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        admission = _admission()

        first = bind_module_contract_admission(
            profile,
            negotiation,
            admission,
        )
        second = bind_module_contract_admission(
            dict(reversed(list(profile.items()))),
            dict(reversed(list(negotiation.items()))),
            dict(reversed(list(admission.items()))),
        )

        self.assertEqual(first, second)
        self.assertTrue(first.binding_id.startswith("mcab-"))
        payload = first.to_dict()
        self.assertFalse(payload["admission_authorized"])
        self.assertFalse(payload["installation_authorized"])
        self.assertFalse(payload["execution_authorized"])
        self.assertFalse(payload["production_mutation_enabled"])
        self.assertFalse(payload["external_publication_authorized"])

    def test_blocked_admission_can_be_bound_as_evidence(self) -> None:
        profile = _profile()
        binding = bind_module_contract_admission(
            profile,
            _negotiation(profile),
            _admission(status="blocked"),
        )
        self.assertEqual(binding.admission_status, "blocked")
        self.assertFalse(binding.admission_authorized)

    def test_incompatible_negotiation_is_rejected(self) -> None:
        profile = _profile()
        negotiation = _negotiation(
            profile,
            status="unsupported-contract",
            manifest_schema="home-center.module-manifest.v3",
        )
        with self.assertRaises(ModuleContractAdmissionBindingError) as caught:
            bind_module_contract_admission(
                profile,
                negotiation,
                _admission(),
            )
        self.assertEqual(
            caught.exception.code,
            "contract_negotiation_incompatible",
        )

    def test_tampered_profile_id_is_rejected(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        profile["profile_id"] = "mccp-" + "0" * 24
        with self.assertRaises(ModuleContractAdmissionBindingError) as caught:
            bind_module_contract_admission(
                profile,
                negotiation,
                _admission(),
            )
        self.assertEqual(caught.exception.code, "contract_profile_rejected")

    def test_tampered_negotiation_is_rejected(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        negotiation["home_center_version"] = "0.38.1"
        with self.assertRaises(ModuleContractAdmissionBindingError) as caught:
            bind_module_contract_admission(
                profile,
                negotiation,
                _admission(),
            )
        self.assertEqual(
            caught.exception.code,
            "contract_negotiation_rejected",
        )

    def test_tampered_admission_is_rejected(self) -> None:
        profile = _profile()
        admission = _admission()
        admission["artifact_sha256"] = "e" * 64
        with self.assertRaises(ModuleContractAdmissionBindingError) as caught:
            bind_module_contract_admission(
                profile,
                _negotiation(profile),
                admission,
            )
        self.assertEqual(caught.exception.code, "module_admission_rejected")

    def test_home_center_version_mismatch_is_rejected(self) -> None:
        profile = _profile()
        with self.assertRaises(ModuleContractAdmissionBindingError) as caught:
            bind_module_contract_admission(
                profile,
                _negotiation(profile),
                _admission(version="0.37.0"),
            )
        self.assertEqual(
            caught.exception.code,
            "home_center_version_binding_mismatch",
        )

    def test_requested_revision_must_be_supported_by_profile(self) -> None:
        profile = _profile()
        negotiation = _negotiation(
            profile,
            manifest_schema="home-center.module-manifest.v3",
        )
        with self.assertRaises(ModuleContractAdmissionBindingError) as caught:
            bind_module_contract_admission(
                profile,
                negotiation,
                _admission(),
            )
        self.assertEqual(
            caught.exception.code,
            "contract_profile_binding_mismatch",
        )

    def test_admission_authority_tampering_is_rejected(self) -> None:
        profile = _profile()
        admission = _admission()
        admission["execution_authorized"] = True
        evidence = dict(admission)
        evidence.pop("decision_id")
        admission["decision_id"] = _canonical_id("madm-", evidence)
        with self.assertRaises(ModuleContractAdmissionBindingError) as caught:
            bind_module_contract_admission(
                profile,
                _negotiation(profile),
                admission,
            )
        self.assertEqual(caught.exception.code, "module_admission_rejected")

    def test_schema_is_closed_and_non_authorizing(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = (
            root
            / "contracts"
            / "modules"
            / "module-contract-admission-binding.v1.schema.json"
        )
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
