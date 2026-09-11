from __future__ import annotations

import unittest

from home_center.module_home_service_contract_requirements import (
    ModuleHomeServiceContractRequirementError,
    build_module_home_service_contract_requirement_set,
    validate_module_home_service_contract_requirement_set,
)
from home_center.module_home_service_multi_requirements import (
    ModuleHomeServiceMultiRequirementError,
    build_module_home_service_multi_requirement_set,
    validate_module_home_service_multi_requirement_set,
)


def _single(service_id: str = "zigbee-bridge", **overrides: object):
    values: dict[str, object] = {
        "home_center_version": "0.45.0",
        "module_id": "example.module",
        "module_version": "1.2.3",
        "service_id": service_id,
        "required_service_contracts": ("devices.zigbee.v1",),
    }
    values.update(overrides)
    return build_module_home_service_contract_requirement_set(**values)


class ModuleHomeServiceBoundaryHardeningTests(unittest.TestCase):
    def test_single_service_contract_iterable_is_bounded(self) -> None:
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
            _single(required_service_contracts=endless_contracts())
        self.assertEqual(consumed, 65)

    def test_single_service_serialized_boundary_rejects_polymorphism(self) -> None:
        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class PretendEvidence:
            def to_dict(self):
                return _single().to_dict()

        payload = _single().to_dict()
        with self.assertRaisesRegex(
            ModuleHomeServiceContractRequirementError,
            "requirement_set_rejected",
        ):
            validate_module_home_service_contract_requirement_set(
                DictSubclass(payload)
            )

        payload = _single().to_dict()
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

    def test_multi_service_requirement_iterable_is_bounded(self) -> None:
        consumed = 0

        def endless_requirements():
            nonlocal consumed
            while True:
                consumed += 1
                yield _single(service_id=f"service-{consumed}")

        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "service_requirement_sets_rejected",
        ):
            build_module_home_service_multi_requirement_set(
                endless_requirements()
            )
        self.assertEqual(consumed, 65)

    def test_multi_service_iterator_failure_is_normalized(self) -> None:
        def broken_requirements():
            yield _single("service-one")
            raise OSError("source failed")

        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "service_requirement_sets_rejected",
        ):
            build_module_home_service_multi_requirement_set(
                broken_requirements()
            )

    def test_multi_service_serialized_boundary_rejects_polymorphism(self) -> None:
        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class PretendEvidence:
            def to_dict(self):
                return build_module_home_service_multi_requirement_set(
                    (_single(),)
                ).to_dict()

        aggregate = build_module_home_service_multi_requirement_set(
            (_single(),)
        )
        payload = aggregate.to_dict()
        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "multi_requirement_set_rejected",
        ):
            validate_module_home_service_multi_requirement_set(
                DictSubclass(payload)
            )

        payload = aggregate.to_dict()
        payload["service_requirement_sets"] = ListSubclass(
            payload["service_requirement_sets"]
        )
        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "service_requirement_sets_rejected",
        ):
            validate_module_home_service_multi_requirement_set(payload)

        payload = aggregate.to_dict()
        payload["service_requirement_sets"][0] = DictSubclass(
            payload["service_requirement_sets"][0]
        )
        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "service_requirement_set_rejected",
        ):
            validate_module_home_service_multi_requirement_set(payload)

        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "multi_requirement_set_rejected",
        ):
            validate_module_home_service_multi_requirement_set(
                PretendEvidence()
            )


if __name__ == "__main__":
    unittest.main()
