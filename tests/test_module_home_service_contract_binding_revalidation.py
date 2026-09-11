from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.module_home_service_contract_binding import (
    bind_module_home_service_contracts,
)
from home_center.module_home_service_contract_binding_revalidation import (
    ModuleHomeServiceContractBindingRevalidationError,
    revalidate_module_home_service_contract_binding,
)


def _hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


def _module_binding(
    *,
    home_center_version: str = "0.41.0",
    module_id: str = "example.module",
    module_version: str = "1.2.3",
    admission_status: str = "compatible",
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "home-center.module-contract-admission-binding.v1",
        "profile_id": "mccp-" + "1" * 24,
        "negotiation_decision_id": "mcnd-" + "2" * 24,
        "admission_decision_id": "madm-" + "3" * 24,
        "home_center_version": home_center_version,
        "module_manifest_schema": "home-center.module-manifest.v2",
        "module_admission_schema": "home-center.module-admission-decision.v1",
        "module_id": module_id,
        "module_version": module_version,
        "manifest_binding_sha256": "4" * 64,
        "artifact_sha256": "5" * 64,
        "admission_status": admission_status,
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    value["binding_id"] = "mcab-" + _hash(value)[:24]
    return value


def _service_profile() -> dict[str, object]:
    return {
        "service_id": "zigbee-bridge",
        "kind": "zigbee-bridge",
        "name": "ZigBee Bridge",
        "required_capabilities": [
            "devices.usb.v1",
            "network.lan.v1",
            "runtime.container.v1",
        ],
        "provided_capabilities": [
            "devices.zigbee.v1",
            "smart-home.bridge.v1",
        ],
        "minimum_storage_gib": 4,
        "publication_policy": "local-only",
        "backup_policy": "configuration",
        "lifecycle": [
            "install",
            "configure",
            "health",
            "update",
            "backup",
            "restore",
            "remove",
        ],
    }


def _original():
    module = _module_binding()
    profile = _service_profile()
    requirements = ("devices.zigbee.v1",)
    binding = bind_module_home_service_contracts(
        module,
        profile,
        requirements,
    )
    return module, profile, requirements, binding


def _revalidate(
    *,
    fresh_module: object | None = None,
    fresh_profile: object | None = None,
    fresh_requirements: tuple[str, ...] | None = None,
):
    module, profile, requirements, binding = _original()
    return revalidate_module_home_service_contract_binding(
        module,
        profile,
        requirements,
        binding,
        fresh_module_binding=module if fresh_module is None else fresh_module,
        fresh_service_profile=profile if fresh_profile is None else fresh_profile,
        fresh_required_service_contracts=(
            requirements if fresh_requirements is None else fresh_requirements
        ),
    )


class ModuleHomeServiceContractBindingRevalidationTests(unittest.TestCase):
    def test_unchanged_binding_is_current_and_deterministic(self) -> None:
        first = _revalidate()
        second = _revalidate()
        self.assertEqual(first, second)
        self.assertTrue(first.current)
        self.assertEqual(first.status, "current")
        self.assertEqual(first.drift_reasons, ())
        self.assertEqual(first.original_binding_id, first.fresh_binding_id)

    def test_service_profile_capability_drift_is_stale(self) -> None:
        profile = _service_profile()
        profile["provided_capabilities"] = [
            "devices.zigbee.v1",
            "smart-home.bridge.v1",
            "smart-home.scene.v1",
        ]
        result = _revalidate(fresh_profile=profile)
        self.assertEqual(result.status, "stale")
        self.assertIn("home_service_profile_changed", result.drift_reasons)
        self.assertIn("provided_service_contracts_changed", result.drift_reasons)

    def test_non_capability_profile_drift_is_stale_even_when_compatible(self) -> None:
        profile = _service_profile()
        profile["minimum_storage_gib"] = 8
        result = _revalidate(fresh_profile=profile)
        self.assertEqual(result.status, "stale")
        self.assertEqual(result.original_compatibility_status, "compatible")
        self.assertEqual(result.fresh_compatibility_status, "compatible")
        self.assertEqual(result.drift_reasons, ("home_service_profile_changed",))

    def test_required_contract_drift_is_stale_and_can_block(self) -> None:
        result = _revalidate(
            fresh_requirements=("devices.zigbee.v2",),
        )
        self.assertEqual(result.status, "stale")
        self.assertEqual(result.fresh_compatibility_status, "blocked")
        self.assertIn("required_service_contracts_changed", result.drift_reasons)
        self.assertIn("unsupported_service_contracts_changed", result.drift_reasons)
        self.assertIn("compatibility_status_changed", result.drift_reasons)

    def test_module_contract_binding_drift_is_stale(self) -> None:
        fresh_module = _module_binding(home_center_version="0.41.1")
        result = _revalidate(fresh_module=fresh_module)
        self.assertEqual(result.status, "stale")
        self.assertIn("module_contract_admission_binding_changed", result.drift_reasons)
        self.assertIn("home_center_version_changed", result.drift_reasons)

    def test_module_identity_and_version_drift_are_explicit(self) -> None:
        fresh_module = _module_binding(
            module_id="example.module.next",
            module_version="2.0.0",
        )
        result = _revalidate(fresh_module=fresh_module)
        self.assertEqual(result.status, "stale")
        self.assertIn("module_identity_changed", result.drift_reasons)
        self.assertIn("module_version_changed", result.drift_reasons)

    def test_tampered_original_binding_is_rejected(self) -> None:
        module, profile, requirements, binding = _original()
        tampered = replace(
            binding,
            binding_id="mhscb-" + "f" * 24,
        )
        with self.assertRaisesRegex(
            ModuleHomeServiceContractBindingRevalidationError,
            "original_home_service_binding_rejected",
        ):
            revalidate_module_home_service_contract_binding(
                module,
                profile,
                requirements,
                tampered,
                fresh_module_binding=module,
                fresh_service_profile=profile,
                fresh_required_service_contracts=requirements,
            )

    def test_tampered_original_profile_is_rejected(self) -> None:
        module, profile, requirements, binding = _original()
        changed = dict(profile)
        changed["minimum_storage_gib"] = 8
        with self.assertRaisesRegex(
            ModuleHomeServiceContractBindingRevalidationError,
            "original_home_service_binding_rejected",
        ):
            revalidate_module_home_service_contract_binding(
                module,
                changed,
                requirements,
                binding,
                fresh_module_binding=module,
                fresh_service_profile=changed,
                fresh_required_service_contracts=requirements,
            )

    def test_malformed_fresh_profile_is_rejected_fail_closed(self) -> None:
        profile = _service_profile()
        profile["provided_capabilities"] = [
            "smart-home.bridge.v1",
            "devices.zigbee.v1",
        ]
        with self.assertRaisesRegex(
            ModuleHomeServiceContractBindingRevalidationError,
            "fresh_home_service_binding_rejected",
        ):
            _revalidate(fresh_profile=profile)

    def test_authority_bearing_fresh_module_binding_is_rejected(self) -> None:
        module = _module_binding()
        module["execution_authorized"] = True
        evidence = dict(module)
        evidence.pop("binding_id")
        module["binding_id"] = "mcab-" + _hash(evidence)[:24]
        with self.assertRaisesRegex(
            ModuleHomeServiceContractBindingRevalidationError,
            "fresh_home_service_binding_rejected",
        ):
            _revalidate(fresh_module=module)

    def test_schema_is_closed_non_authorizing_and_matches_runtime_output(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "contracts/modules/"
            "module-home-service-contract-binding-revalidation.v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        result = _revalidate().to_dict()

        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(result), set(schema["required"]))
        self.assertEqual(result["schema"], schema["properties"]["schema"]["const"])
        self.assertIn(result["status"], schema["properties"]["status"]["enum"])
        self.assertRegex(result["revalidation_id"], r"^mhscbr-[0-9a-f]{24}$")
        self.assertRegex(result["original_binding_id"], r"^mhscb-[0-9a-f]{24}$")
        self.assertRegex(result["fresh_binding_id"], r"^mhscb-[0-9a-f]{24}$")
        self.assertEqual(result["drift_reasons"], [])
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
