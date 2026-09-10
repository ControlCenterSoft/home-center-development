from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.module_contract_admission_binding import (
    bind_module_contract_admission,
)
from home_center.module_contract_admission_binding_revalidation import (
    ModuleContractAdmissionBindingRevalidationError,
    revalidate_module_contract_admission_binding,
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


def _profile(
    version: str = "0.39.0",
    *,
    manifest_revisions: tuple[str, ...] = (
        "home-center.module-manifest.v2",
    ),
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": "home-center.module-contract-compatibility-profile.v1",
        "home_center_version": version,
        "supported_contracts": {
            "module_manifest": list(manifest_revisions),
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
            "module_admission_decision": (
                "home-center.module-admission-decision.v1"
            ),
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
    version: str = "0.39.0",
    status: str = "compatible",
    module_version: str = "1.2.0",
    artifact: str = "d",
) -> dict[str, object]:
    reasons = [] if status == "compatible" else ["capability_missing"]
    missing = [] if status == "compatible" else ["network.lan"]
    payload: dict[str, object] = {
        "schema": "home-center.module-admission-decision.v1",
        "status": status,
        "module_id": "example.media",
        "module_version": module_version,
        "publisher": "example",
        "manifest_binding_sha256": "a" * 64,
        "provenance_statement_sha256": "b" * 64,
        "verified_signing_key_ids": ["sha256:" + "c" * 64],
        "artifact_sha256": artifact * 64,
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


def _binding(
    profile: dict[str, object],
    negotiation: dict[str, object],
    admission: dict[str, object],
):
    return bind_module_contract_admission(profile, negotiation, admission)


class ModuleContractAdmissionBindingRevalidationTests(unittest.TestCase):
    def test_unchanged_binding_is_current_and_deterministic(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        admission = _admission()
        binding = _binding(profile, negotiation, admission)

        first = revalidate_module_contract_admission_binding(
            profile,
            negotiation,
            admission,
            binding,
            fresh_profile=profile,
            fresh_negotiation=negotiation,
            fresh_admission=admission,
        )
        second = revalidate_module_contract_admission_binding(
            profile,
            negotiation,
            admission,
            binding,
            fresh_profile=dict(reversed(list(profile.items()))),
            fresh_negotiation=dict(reversed(list(negotiation.items()))),
            fresh_admission=dict(reversed(list(admission.items()))),
        )

        self.assertEqual(first, second)
        self.assertTrue(first.current)
        self.assertEqual(first.drift_reasons, ())
        self.assertTrue(first.revalidation_id.startswith("mcabr-"))
        payload = first.to_dict()
        self.assertFalse(payload["admission_authorized"])
        self.assertFalse(payload["installation_authorized"])
        self.assertFalse(payload["execution_authorized"])
        self.assertFalse(payload["production_mutation_enabled"])
        self.assertFalse(payload["external_publication_authorized"])

    def test_contract_profile_change_marks_binding_stale(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        admission = _admission()
        binding = _binding(profile, negotiation, admission)
        fresh_profile = _profile(
            manifest_revisions=(
                "home-center.module-manifest.v2",
                "home-center.module-manifest.v3",
            )
        )
        result = revalidate_module_contract_admission_binding(
            profile,
            negotiation,
            admission,
            binding,
            fresh_profile=fresh_profile,
            fresh_negotiation=_negotiation(fresh_profile),
            fresh_admission=admission,
        )
        self.assertEqual(result.status, "stale")
        self.assertIn("contract_profile_changed", result.drift_reasons)

    def test_manifest_contract_revision_change_is_stale(self) -> None:
        profile = _profile(
            manifest_revisions=(
                "home-center.module-manifest.v2",
                "home-center.module-manifest.v3",
            )
        )
        original_negotiation = _negotiation(profile)
        admission = _admission()
        binding = _binding(profile, original_negotiation, admission)
        fresh_negotiation = _negotiation(
            profile,
            manifest_schema="home-center.module-manifest.v3",
        )
        result = revalidate_module_contract_admission_binding(
            profile,
            original_negotiation,
            admission,
            binding,
            fresh_profile=profile,
            fresh_negotiation=fresh_negotiation,
            fresh_admission=admission,
        )
        self.assertIn(
            "module_manifest_contract_changed",
            result.drift_reasons,
        )
        self.assertIn(
            "contract_negotiation_changed",
            result.drift_reasons,
        )

    def test_home_center_version_change_is_stale(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        admission = _admission()
        binding = _binding(profile, negotiation, admission)
        fresh_profile = _profile(version="0.39.1")
        result = revalidate_module_contract_admission_binding(
            profile,
            negotiation,
            admission,
            binding,
            fresh_profile=fresh_profile,
            fresh_negotiation=_negotiation(fresh_profile),
            fresh_admission=_admission(version="0.39.1"),
        )
        self.assertIn("home_center_version_changed", result.drift_reasons)

    def test_artifact_change_is_stale(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        admission = _admission()
        binding = _binding(profile, negotiation, admission)
        result = revalidate_module_contract_admission_binding(
            profile,
            negotiation,
            admission,
            binding,
            fresh_profile=profile,
            fresh_negotiation=negotiation,
            fresh_admission=_admission(artifact="e"),
        )
        self.assertIn("artifact_changed", result.drift_reasons)
        self.assertIn("module_admission_changed", result.drift_reasons)

    def test_module_version_change_is_stale(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        admission = _admission()
        binding = _binding(profile, negotiation, admission)
        result = revalidate_module_contract_admission_binding(
            profile,
            negotiation,
            admission,
            binding,
            fresh_profile=profile,
            fresh_negotiation=negotiation,
            fresh_admission=_admission(module_version="1.3.0"),
        )
        self.assertIn("module_version_changed", result.drift_reasons)

    def test_admission_status_change_is_stale(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        admission = _admission()
        binding = _binding(profile, negotiation, admission)
        result = revalidate_module_contract_admission_binding(
            profile,
            negotiation,
            admission,
            binding,
            fresh_profile=profile,
            fresh_negotiation=negotiation,
            fresh_admission=_admission(status="blocked"),
        )
        self.assertIn("admission_status_changed", result.drift_reasons)

    def test_tampered_original_binding_is_rejected(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        admission = _admission()
        binding = _binding(profile, negotiation, admission)
        tampered = replace(binding, artifact_sha256="e" * 64)
        with self.assertRaises(
            ModuleContractAdmissionBindingRevalidationError
        ) as caught:
            revalidate_module_contract_admission_binding(
                profile,
                negotiation,
                admission,
                tampered,
                fresh_profile=profile,
                fresh_negotiation=negotiation,
                fresh_admission=admission,
            )
        self.assertEqual(
            caught.exception.code,
            "original_contract_admission_binding_rejected",
        )

    def test_tampered_original_source_evidence_is_rejected(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        admission = _admission()
        binding = _binding(profile, negotiation, admission)
        profile["home_center_version"] = "0.39.1"
        fresh_profile = _profile()
        with self.assertRaises(
            ModuleContractAdmissionBindingRevalidationError
        ) as caught:
            revalidate_module_contract_admission_binding(
                profile,
                negotiation,
                admission,
                binding,
                fresh_profile=fresh_profile,
                fresh_negotiation=_negotiation(fresh_profile),
                fresh_admission=admission,
            )
        self.assertEqual(
            caught.exception.code,
            "original_contract_admission_binding_rejected",
        )

    def test_invalid_fresh_binding_evidence_is_rejected(self) -> None:
        profile = _profile()
        negotiation = _negotiation(profile)
        admission = _admission()
        binding = _binding(profile, negotiation, admission)
        unsupported = _negotiation(
            profile,
            status="unsupported-contract",
            manifest_schema="home-center.module-manifest.v3",
        )
        with self.assertRaises(
            ModuleContractAdmissionBindingRevalidationError
        ) as caught:
            revalidate_module_contract_admission_binding(
                profile,
                negotiation,
                admission,
                binding,
                fresh_profile=profile,
                fresh_negotiation=unsupported,
                fresh_admission=admission,
            )
        self.assertEqual(
            caught.exception.code,
            "fresh_contract_admission_binding_rejected",
        )

    def test_schema_is_closed_and_non_authorizing(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = (
            root
            / "contracts"
            / "modules"
            / (
                "module-contract-admission-binding-revalidation."
                "v1.schema.json"
            )
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
