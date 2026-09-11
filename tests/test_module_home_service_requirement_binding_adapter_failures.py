from __future__ import annotations

import hashlib
import json
import unittest
from collections.abc import Mapping

from home_center.module_home_service_requirement_binding import (
    ModuleHomeServiceRequirementBindingError,
    validate_module_home_service_requirement_binding,
)


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


class _ExplodingMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise RuntimeError("untrusted mapping read")

    def __iter__(self):
        raise RuntimeError("untrusted mapping iteration")

    def __len__(self) -> int:
        return 1


class _ExplodingAdapter:
    def to_dict(self) -> dict[str, object]:
        raise RuntimeError("untrusted adapter")


class _RecursiveAdapter:
    def to_dict(self) -> dict[str, object]:
        raise RecursionError("recursive adapter")


class _NonDictAdapter:
    def to_dict(self) -> list[tuple[str, object]]:
        return list(_payload().items())


class _NonCallableAdapter:
    to_dict = _payload()


class RequirementBindingAdapterFailureTests(unittest.TestCase):
    def assert_rejected(self, value: object) -> None:
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingError,
            "requirement_binding_rejected",
        ):
            validate_module_home_service_requirement_binding(value)

    def test_untrusted_mapping_runtime_failure_is_normalized(self) -> None:
        self.assert_rejected(_ExplodingMapping())

    def test_to_dict_runtime_failure_is_normalized(self) -> None:
        self.assert_rejected(_ExplodingAdapter())

    def test_recursive_adapter_failure_is_normalized(self) -> None:
        self.assert_rejected(_RecursiveAdapter())

    def test_to_dict_must_return_plain_dict_shape(self) -> None:
        self.assert_rejected(_NonDictAdapter())

    def test_to_dict_attribute_must_be_callable(self) -> None:
        self.assert_rejected(_NonCallableAdapter())

    def test_unrelated_object_is_rejected_without_coercion(self) -> None:
        self.assert_rejected(object())


if __name__ == "__main__":
    unittest.main()
