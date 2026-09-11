from __future__ import annotations

import hashlib
import json
import unittest

from home_center.module_home_service_requirement_binding import (
    ModuleHomeServiceRequirementBindingError,
    validate_module_home_service_requirement_binding,
)


def _binding_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": "home-center.module-home-service-contract-requirement-binding.v1",
        "requirement_set_id": "mhscr-" + "1" * 24,
        "home_service_contract_binding_id": "mhscb-" + "2" * 24,
        "home_center_version": "0.43.0",
        "module_id": "example.module",
        "module_version": "1.2.3",
        "service_id": "zigbee-bridge",
        "service_profile_sha256": "3" * 64,
        "required_service_contracts": ["devices.zigbee.v1"],
        "compatibility_status": "compatible",
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    payload["requirement_binding_id"] = (
        "mhsrb-" + hashlib.sha256(encoded).hexdigest()[:24]
    )
    return payload


class RequirementBindingValidationEdgeTests(unittest.TestCase):
    def test_reference_payload_round_trips(self) -> None:
        payload = _binding_payload()
        validated = validate_module_home_service_requirement_binding(payload)
        self.assertEqual(validated.to_dict(), payload)

    def test_identifier_and_scalar_shape_edges_fail_closed(self) -> None:
        mutations: tuple[tuple[str, object], ...] = (
            ("requirement_set_id", "mhscr-" + "1" * 23),
            ("home_service_contract_binding_id", "mhscb-" + "G" * 24),
            ("home_center_version", "00.43.0"),
            ("module_id", "Example.Module"),
            ("module_version", "1.2.3-rc1"),
            ("service_id", "A"),
            ("service_profile_sha256", "A" * 64),
            ("compatibility_status", "unknown"),
        )
        for field, invalid in mutations:
            with self.subTest(field=field):
                payload = _binding_payload()
                payload[field] = invalid
                with self.assertRaisesRegex(
                    ModuleHomeServiceRequirementBindingError,
                    "requirement_binding_rejected",
                ):
                    validate_module_home_service_requirement_binding(payload)

    def test_contract_collection_edges_fail_closed(self) -> None:
        invalid_contracts: tuple[object, ...] = (
            [],
            ("devices.zigbee.v1",),
            ["devices.zigbee.v1", "devices.zigbee.v1"],
            ["devices.zigbee.v0"],
            ["Devices.zigbee.v1"],
            [f"capability.{index}.v1" for index in range(65)],
        )
        for contracts in invalid_contracts:
            with self.subTest(contracts=contracts):
                payload = _binding_payload()
                payload["required_service_contracts"] = contracts
                with self.assertRaisesRegex(
                    ModuleHomeServiceRequirementBindingError,
                    "requirement_binding_rejected",
                ):
                    validate_module_home_service_requirement_binding(payload)

    def test_authority_flags_require_literal_false(self) -> None:
        for field in (
            "admission_authorized",
            "installation_authorized",
            "execution_authorized",
            "production_mutation_enabled",
            "external_publication_authorized",
        ):
            for invalid in (0, None, "false"):
                with self.subTest(field=field, invalid=invalid):
                    payload = _binding_payload()
                    payload[field] = invalid
                    with self.assertRaisesRegex(
                        ModuleHomeServiceRequirementBindingError,
                        "requirement_binding_rejected",
                    ):
                        validate_module_home_service_requirement_binding(payload)


if __name__ == "__main__":
    unittest.main()
