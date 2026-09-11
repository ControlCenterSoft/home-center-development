from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from home_center.module_home_service_contract_requirements import (
    build_module_home_service_contract_requirement_set,
)
from home_center.module_home_service_requirement_binding import (
    bind_module_home_service_requirement_set,
)
from home_center.module_home_service_requirement_binding_revalidation import (
    ModuleHomeServiceRequirementBindingRevalidationError,
    revalidate_module_home_service_requirement_binding,
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
    home_center_version: str = "0.44.0",
    module_id: str = "example.module",
    module_version: str = "1.2.3",
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
        "admission_status": "compatible",
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    value["binding_id"] = "mcab-" + _hash(value)[:24]
    return value


def _service_profile(
    *,
    service_id: str = "zigbee-bridge",
    minimum_storage_gib: int = 4,
) -> dict[str, object]:
    return {
        "service_id": service_id,
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
        "minimum_storage_gib": minimum_storage_gib,
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


def _requirements(
    *,
    home_center_version: str = "0.44.0",
    module_id: str = "example.module",
    module_version: str = "1.2.3",
    service_id: str = "zigbee-bridge",
    contracts: tuple[str, ...] = ("devices.zigbee.v1",),
):
    return build_module_home_service_contract_requirement_set(
        home_center_version=home_center_version,
        module_id=module_id,
        module_version=module_version,
        service_id=service_id,
        required_service_contracts=contracts,
    )


def _original():
    requirements = _requirements()
    module = _module_binding()
    profile = _service_profile()
    binding = bind_module_home_service_requirement_set(
        requirements,
        module,
        profile,
    )
    return requirements, module, profile, binding


def _revalidate(
    *,
    fresh_requirements: object | None = None,
    fresh_module: object | None = None,
    fresh_profile: object | None = None,
):
    requirements, module, profile, binding = _original()
    return revalidate_module_home_service_requirement_binding(
        requirements,
        module,
        profile,
        binding,
        fresh_requirement_set=(
            requirements if fresh_requirements is None else fresh_requirements
        ),
        fresh_module_binding=module if fresh_module is None else fresh_module,
        fresh_service_profile=profile if fresh_profile is None else fresh_profile,
    )


class RequirementBindingRevalidationUnitTests(unittest.TestCase):
    def test_unchanged_binding_is_current_and_deterministic(self) -> None:
        first = _revalidate()
        second = _revalidate()
        self.assertEqual(first, second)
        self.assertTrue(first.current)
        self.assertEqual(first.status, "current")
        self.assertEqual(first.drift_reasons, ())
        self.assertEqual(
            first.original_requirement_binding_id,
            first.fresh_requirement_binding_id,
        )

    def test_requirement_contract_drift_is_stale(self) -> None:
        result = _revalidate(
            fresh_requirements=_requirements(
                contracts=("devices.zigbee.v2",)
            )
        )
        self.assertEqual(result.status, "stale")
        self.assertIn("requirement_set_changed", result.drift_reasons)
        self.assertIn(
            "required_service_contracts_changed",
            result.drift_reasons,
        )
        self.assertIn(
            "home_service_contract_binding_changed",
            result.drift_reasons,
        )
        self.assertIn("compatibility_status_changed", result.drift_reasons)

    def test_profile_drift_is_stale_without_requirement_drift(self) -> None:
        result = _revalidate(
            fresh_profile=_service_profile(minimum_storage_gib=8)
        )
        self.assertEqual(result.status, "stale")
        self.assertIn("home_service_profile_changed", result.drift_reasons)
        self.assertIn(
            "home_service_contract_binding_changed",
            result.drift_reasons,
        )
        self.assertNotIn("requirement_set_changed", result.drift_reasons)

    def test_version_and_module_drift_are_explicit(self) -> None:
        result = _revalidate(
            fresh_requirements=_requirements(
                home_center_version="0.44.1",
                module_id="example.module.next",
                module_version="2.0.0",
            ),
            fresh_module=_module_binding(
                home_center_version="0.44.1",
                module_id="example.module.next",
                module_version="2.0.0",
            ),
        )
        self.assertIn("home_center_version_changed", result.drift_reasons)
        self.assertIn("module_identity_changed", result.drift_reasons)
        self.assertIn("module_version_changed", result.drift_reasons)

    def test_tampered_original_binding_is_rejected(self) -> None:
        requirements, module, profile, binding = _original()
        tampered = replace(
            binding,
            requirement_binding_id="mhsrb-" + "f" * 24,
        )
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingRevalidationError,
            "original_requirement_binding_rejected",
        ):
            revalidate_module_home_service_requirement_binding(
                requirements,
                module,
                profile,
                tampered,
                fresh_requirement_set=requirements,
                fresh_module_binding=module,
                fresh_service_profile=profile,
            )

    def test_authority_bearing_fresh_requirement_is_rejected(self) -> None:
        requirements = _requirements().to_dict()
        requirements["execution_authorized"] = True
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingRevalidationError,
            "fresh_requirement_binding_rejected",
        ):
            _revalidate(fresh_requirements=requirements)


if __name__ == "__main__":
    unittest.main()
