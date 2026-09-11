from __future__ import annotations

import unittest

from home_center.module_home_service_contract_requirements import (
    ModuleHomeServiceContractRequirementError,
    build_module_home_service_contract_requirement_set,
    validate_module_home_service_contract_requirement_set,
)


def _build(**overrides: object):
    values: dict[str, object] = {
        "home_center_version": "0.44.0",
        "module_id": "example.module",
        "module_version": "1.2.3",
        "service_id": "zigbee-bridge",
        "required_service_contracts": ("devices.zigbee.v1",),
    }
    values.update(overrides)
    return build_module_home_service_contract_requirement_set(**values)


class ModuleHomeServiceRequirementHardeningTests(unittest.TestCase):
    def test_contract_count_boundary_is_bounded_to_schema_limit(self) -> None:
        accepted = tuple(
            f"service.contract{index}.v1" for index in range(64)
        )
        self.assertEqual(
            len(
                _build(
                    required_service_contracts=accepted
                ).required_service_contracts
            ),
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

    def test_unbounded_contract_iterable_is_consumed_only_to_limit_plus_one(
        self,
    ) -> None:
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

    def test_iterator_failure_is_normalized_to_stable_rejection(self) -> None:
        def broken_contracts():
            yield "devices.zigbee.v1"
            raise OSError("source failed")

        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "required_service_contracts_rejected",
        ):
            _build(required_service_contracts=broken_contracts())

    def test_polymorphic_scalar_and_serialized_containers_are_rejected(
        self,
    ) -> None:
        class StringSubclass(str):
            pass

        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class PretendEvidence:
            def to_dict(self):
                return _build().to_dict()

        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "requirement_set_rejected",
        ):
            _build(home_center_version=StringSubclass("0.44.0"))

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


if __name__ == "__main__":
    unittest.main()
