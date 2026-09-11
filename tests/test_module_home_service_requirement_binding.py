from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

from home_center.module_home_service_contract_binding import (
    bind_module_home_service_contracts,
)
from home_center.module_home_service_contract_requirements import (
    build_module_home_service_contract_requirement_set,
)
from home_center.module_home_service_requirement_binding import (
    ModuleHomeServiceRequirementBindingError,
    bind_module_home_service_requirement_set,
    validate_module_home_service_requirement_binding,
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


def _module_binding(*, admission_status: str = "compatible") -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "home-center.module-contract-admission-binding.v1",
        "profile_id": "mccp-" + "1" * 24,
        "negotiation_decision_id": "mcnd-" + "2" * 24,
        "admission_decision_id": "madm-" + "3" * 24,
        "home_center_version": "0.43.0",
        "module_manifest_schema": "home-center.module-manifest.v2",
        "module_admission_schema": "home-center.module-admission-decision.v1",
        "module_id": "example.module",
        "module_version": "1.2.3",
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


def _requirements(
    *,
    home_center_version: str = "0.43.0",
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


def _binding(*, contracts: tuple[str, ...] = ("devices.zigbee.v1",)):
    return bind_module_home_service_requirement_set(
        _requirements(contracts=contracts),
        _module_binding(),
        _service_profile(),
    )


class ModuleHomeServiceRequirementBindingTests(unittest.TestCase):
    def test_binding_is_deterministic_and_binds_exact_compatibility(self) -> None:
        requirements = _requirements(
            contracts=("smart-home.bridge.v1", "devices.zigbee.v1")
        )
        first = bind_module_home_service_requirement_set(
            requirements,
            _module_binding(),
            _service_profile(),
        )
        second = bind_module_home_service_requirement_set(
            requirements,
            _module_binding(),
            _service_profile(),
        )
        compatibility = bind_module_home_service_contracts(
            _module_binding(),
            _service_profile(),
            requirements.required_service_contracts,
        )
        self.assertEqual(first, second)
        self.assertEqual(first.requirement_set_id, requirements.requirement_set_id)
        self.assertEqual(
            first.home_service_contract_binding_id,
            compatibility.binding_id,
        )
        self.assertEqual(first.compatibility_status, "compatible")

    def test_unsupported_requirement_is_bound_as_blocked_evidence(self) -> None:
        result = bind_module_home_service_requirement_set(
            _requirements(contracts=("devices.zigbee.v2",)),
            _module_binding(),
            _service_profile(),
        )
        self.assertEqual(result.compatibility_status, "blocked")
        self.assertFalse(result.admission_authorized)
        self.assertFalse(result.installation_authorized)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.production_mutation_enabled)
        self.assertFalse(result.external_publication_authorized)

    def test_blocked_admission_is_preserved_as_blocked_compatibility(self) -> None:
        result = bind_module_home_service_requirement_set(
            _requirements(),
            _module_binding(admission_status="blocked"),
            _service_profile(),
        )
        self.assertEqual(result.compatibility_status, "blocked")

    def test_profile_drift_changes_binding_not_requirement_identity(self) -> None:
        requirements = _requirements()
        first = bind_module_home_service_requirement_set(
            requirements,
            _module_binding(),
            _service_profile(),
        )
        changed = _service_profile()
        changed["minimum_storage_gib"] = 8
        second = bind_module_home_service_requirement_set(
            requirements,
            _module_binding(),
            changed,
        )
        self.assertEqual(first.requirement_set_id, second.requirement_set_id)
        self.assertNotEqual(first.service_profile_sha256, second.service_profile_sha256)
        self.assertNotEqual(
            first.home_service_contract_binding_id,
            second.home_service_contract_binding_id,
        )
        self.assertNotEqual(first.requirement_binding_id, second.requirement_binding_id)

    def test_requirement_context_mismatch_is_rejected(self) -> None:
        mismatches = (
            _requirements(home_center_version="0.42.0"),
            _requirements(module_id="other.module"),
            _requirements(module_version="1.2.4"),
            _requirements(service_id="minecraft-server"),
        )
        for requirements in mismatches:
            with self.subTest(requirement_set_id=requirements.requirement_set_id):
                with self.assertRaisesRegex(
                    ModuleHomeServiceRequirementBindingError,
                    "requirement_context_mismatch",
                ):
                    bind_module_home_service_requirement_set(
                        requirements,
                        _module_binding(),
                        _service_profile(),
                    )

    def test_tampered_requirement_set_is_rejected(self) -> None:
        requirements = _requirements().to_dict()
        requirements["required_service_contracts"] = ["devices.zigbee.v2"]
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingError,
            "requirement_set_rejected",
        ):
            bind_module_home_service_requirement_set(
                requirements,
                _module_binding(),
                _service_profile(),
            )

    def test_authority_bearing_requirement_set_is_rejected(self) -> None:
        requirements = _requirements().to_dict()
        requirements["execution_authorized"] = True
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingError,
            "requirement_set_rejected",
        ):
            bind_module_home_service_requirement_set(
                requirements,
                _module_binding(),
                _service_profile(),
            )

    def test_invalid_compatibility_context_is_rejected(self) -> None:
        module_binding = _module_binding()
        module_binding["artifact_sha256"] = "9" * 64
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingError,
            "home_service_compatibility_rejected",
        ):
            bind_module_home_service_requirement_set(
                _requirements(),
                module_binding,
                _service_profile(),
            )

    def test_serialized_binding_round_trips(self) -> None:
        original = _binding(
            contracts=("smart-home.bridge.v1", "devices.zigbee.v1")
        )
        validated = validate_module_home_service_requirement_binding(
            original.to_dict()
        )
        self.assertEqual(validated, original)

    def test_serialized_binding_tamper_is_rejected(self) -> None:
        payload = _binding().to_dict()
        payload["service_profile_sha256"] = "9" * 64
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingError,
            "requirement_binding_rejected",
        ):
            validate_module_home_service_requirement_binding(payload)

    def test_serialized_binding_noncanonical_contract_order_is_rejected(self) -> None:
        payload = _binding(
            contracts=("smart-home.bridge.v1", "devices.zigbee.v1")
        ).to_dict()
        payload["required_service_contracts"] = list(
            reversed(payload["required_service_contracts"])
        )
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingError,
            "requirement_binding_rejected",
        ):
            validate_module_home_service_requirement_binding(payload)

    def test_serialized_binding_authority_or_shape_tamper_is_rejected(self) -> None:
        for mutation in ("authority", "extra-field"):
            payload = _binding().to_dict()
            if mutation == "authority":
                payload["execution_authorized"] = True
            else:
                payload["unexpected"] = "value"
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(
                    ModuleHomeServiceRequirementBindingError,
                    "requirement_binding_rejected",
                ):
                    validate_module_home_service_requirement_binding(payload)

    def test_schema_is_closed_non_authorizing_and_matches_runtime_output(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "contracts/modules/"
            "module-home-service-contract-requirement-binding.v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        result = _binding().to_dict()

        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(result), set(schema["required"]))
        self.assertEqual(
            result["schema"], schema["properties"]["schema"]["const"]
        )
        self.assertRegex(
            result["requirement_binding_id"],
            re.compile(r"^mhsrb-[0-9a-f]{24}$"),
        )
        self.assertRegex(
            result["requirement_set_id"],
            re.compile(r"^mhscr-[0-9a-f]{24}$"),
        )
        self.assertRegex(
            result["home_service_contract_binding_id"],
            re.compile(r"^mhscb-[0-9a-f]{24}$"),
        )
        self.assertIn(result["compatibility_status"], ("compatible", "blocked"))
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
