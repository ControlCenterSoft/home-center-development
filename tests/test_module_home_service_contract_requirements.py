from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from home_center.module_home_service_contract_requirements import (
    ModuleHomeServiceContractRequirementError,
    build_module_home_service_contract_requirement_set,
    validate_module_home_service_contract_requirement_set,
)


def _build(**overrides: object):
    values: dict[str, object] = {
        "home_center_version": "0.42.0",
        "module_id": "example.module",
        "module_version": "1.2.3",
        "service_id": "zigbee-bridge",
        "required_service_contracts": (
            "devices.zigbee.v1",
            "smart-home.bridge.v1",
        ),
    }
    values.update(overrides)
    return build_module_home_service_contract_requirement_set(**values)


class ModuleHomeServiceContractRequirementTests(unittest.TestCase):
    def test_requirement_set_is_deterministic_and_canonical(self) -> None:
        first = _build(
            required_service_contracts=(
                "smart-home.bridge.v1",
                "devices.zigbee.v1",
            )
        )
        second = _build()
        self.assertEqual(first, second)
        self.assertEqual(
            first.required_service_contracts,
            ("devices.zigbee.v1", "smart-home.bridge.v1"),
        )
        self.assertTrue(first.requirement_set_id.startswith("mhscr-"))

    def test_contract_change_changes_exact_identity(self) -> None:
        first = _build()
        second = _build(required_service_contracts=("devices.zigbee.v2",))
        self.assertNotEqual(first.requirement_set_id, second.requirement_set_id)

    def test_context_identity_is_exact(self) -> None:
        original = _build()
        self.assertNotEqual(
            original.requirement_set_id,
            _build(home_center_version="0.42.1").requirement_set_id,
        )
        self.assertNotEqual(
            original.requirement_set_id,
            _build(module_version="1.2.4").requirement_set_id,
        )
        self.assertNotEqual(
            original.requirement_set_id,
            _build(service_id="zigbee-bridge-next").requirement_set_id,
        )

    def test_invalid_contract_sets_are_rejected(self) -> None:
        for requirements in (
            (),
            ("devices.zigbee.v1", "devices.zigbee.v1"),
            ("bad-contract",),
        ):
            with self.subTest(requirements=requirements):
                with self.assertRaisesRegex(
                    ModuleHomeServiceContractRequirementError,
                    "required_service_contracts_rejected",
                ):
                    _build(required_service_contracts=requirements)

    def test_contract_count_boundary_matches_schema(self) -> None:
        accepted = tuple(
            f"service.contract{index}.v1" for index in range(64)
        )
        self.assertEqual(
            len(_build(required_service_contracts=accepted).required_service_contracts),
            64,
        )
        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "required_service_contracts_rejected",
        ):
            _build(
                required_service_contracts=(
                    *accepted,
                    "service.contract64.v1",
                )
            )

    def test_contract_iterable_consumption_is_bounded(self) -> None:
        consumed = 0

        def endless_contracts():
            nonlocal consumed
            while True:
                consumed += 1
                yield f"service.contract{consumed}.v1"

        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "required_service_contracts_rejected",
        ):
            _build(required_service_contracts=endless_contracts())
        self.assertEqual(consumed, 65)

    def test_iterable_exception_is_rejected_stably(self) -> None:
        def broken_contracts():
            yield "devices.zigbee.v1"
            raise OSError("source failed")

        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "required_service_contracts_rejected",
        ):
            _build(required_service_contracts=broken_contracts())

    def test_non_string_unhashable_contract_is_rejected_stably(self) -> None:
        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "required_service_contracts_rejected",
        ):
            _build(required_service_contracts=(["devices.zigbee.v1"],))

    def test_string_subclasses_are_rejected(self) -> None:
        class StringSubclass(str):
            pass

        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "requirement_set_rejected",
        ):
            _build(home_center_version=StringSubclass("0.42.0"))
        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "required_service_contracts_rejected",
        ):
            _build(
                required_service_contracts=(
                    StringSubclass("devices.zigbee.v1"),
                )
            )

    def test_serialized_evidence_round_trips(self) -> None:
        original = _build()
        validated = validate_module_home_service_contract_requirement_set(
            original.to_dict()
        )
        self.assertEqual(validated, original)
        self.assertEqual(
            validate_module_home_service_contract_requirement_set(original),
            original,
        )

    def test_serialized_boundary_rejects_polymorphic_containers(self) -> None:
        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class PretendEvidence:
            def to_dict(self):
                return _build().to_dict()

        payload = _build().to_dict()
        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "requirement_set_rejected",
        ):
            validate_module_home_service_contract_requirement_set(
                DictSubclass(payload)
            )

        payload = _build().to_dict()
        payload["required_service_contracts"] = ListSubclass(
            payload["required_service_contracts"]
        )
        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "requirement_set_rejected",
        ):
            validate_module_home_service_contract_requirement_set(payload)

        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "requirement_set_rejected",
        ):
            validate_module_home_service_contract_requirement_set(
                PretendEvidence()
            )

    def test_noncanonical_serialized_order_is_rejected(self) -> None:
        payload = _build().to_dict()
        payload["required_service_contracts"] = list(
            reversed(payload["required_service_contracts"])
        )
        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "requirement_set_rejected",
        ):
            validate_module_home_service_contract_requirement_set(payload)

    def test_tampered_exact_identity_is_rejected(self) -> None:
        payload = _build().to_dict()
        payload["module_version"] = "9.9.9"
        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "requirement_set_rejected",
        ):
            validate_module_home_service_contract_requirement_set(payload)

    def test_authority_tampering_is_rejected(self) -> None:
        payload = _build().to_dict()
        payload["execution_authorized"] = True
        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "requirement_set_rejected",
        ):
            validate_module_home_service_contract_requirement_set(payload)

    def test_schema_is_closed_non_authorizing_and_matches_runtime_output(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "contracts/modules/"
            "module-home-service-contract-requirement-set.v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        result = _build().to_dict()

        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(result), set(schema["required"]))
        self.assertEqual(
            result["schema"], schema["properties"]["schema"]["const"]
        )
        self.assertRegex(
            result["requirement_set_id"],
            re.compile(r"^mhscr-[0-9a-f]{24}$"),
        )
        self.assertEqual(
            result["required_service_contracts"],
            sorted(result["required_service_contracts"]),
        )
        self.assertEqual(
            schema["properties"]["required_service_contracts"]["maxItems"],
            64,
        )
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
