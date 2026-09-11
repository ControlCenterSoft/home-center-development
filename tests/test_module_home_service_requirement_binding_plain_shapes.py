from __future__ import annotations

import hashlib
import json
import unittest

from home_center.module_home_service_requirement_binding import (
    ModuleHomeServiceRequirementBindingError,
    validate_module_home_service_requirement_binding,
)


class _DictSubclass(dict):
    pass


class _StrSubclass(str):
    pass


class _ListSubclass(list):
    pass


def _payload() -> dict[str, object]:
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


class RequirementBindingPlainShapeTests(unittest.TestCase):
    def assert_rejected(self, value: object) -> None:
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingError,
            "requirement_binding_rejected",
        ):
            validate_module_home_service_requirement_binding(value)

    def test_plain_dict_and_exact_runtime_value_are_accepted(self) -> None:
        payload = _payload()
        exact = validate_module_home_service_requirement_binding(payload)
        self.assertEqual(exact.to_dict(), payload)
        self.assertEqual(
            validate_module_home_service_requirement_binding(exact), exact
        )

    def test_mapping_subclass_is_rejected_without_coercion(self) -> None:
        self.assert_rejected(_DictSubclass(_payload()))

    def test_scalar_string_subclass_is_rejected(self) -> None:
        payload = _payload()
        payload["module_id"] = _StrSubclass("example.module")
        self.assert_rejected(payload)

    def test_contract_list_subclass_is_rejected(self) -> None:
        payload = _payload()
        payload["required_service_contracts"] = _ListSubclass(
            ["devices.zigbee.v1"]
        )
        self.assert_rejected(payload)


if __name__ == "__main__":
    unittest.main()
