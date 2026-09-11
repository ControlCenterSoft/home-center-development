from __future__ import annotations

import json
import unittest
from pathlib import Path

from home_center.module_home_service_contract_requirements import (
    build_module_home_service_contract_requirement_set,
)
from home_center.module_home_service_multi_requirements import (
    ModuleHomeServiceMultiRequirementError,
    build_module_home_service_multi_requirement_set,
    validate_module_home_service_multi_requirement_set,
)


def _single(
    service_id: str,
    contracts: tuple[str, ...],
    **overrides: str,
):
    values = {
        "home_center_version": "0.45.0",
        "module_id": "example.module",
        "module_version": "1.2.3",
        "service_id": service_id,
        "required_service_contracts": contracts,
    }
    values.update(overrides)
    return build_module_home_service_contract_requirement_set(**values)


def _build():
    return build_module_home_service_multi_requirement_set(
        (
            _single(
                "zigbee-bridge",
                ("devices.zigbee.v1", "smart-home.bridge.v1"),
            ),
            _single("media-catalog", ("media.catalog.v1",)),
        )
    )


class ModuleHomeServiceMultiRequirementUnitTests(unittest.TestCase):
    def test_aggregate_is_deterministic_and_canonical(self) -> None:
        first = _build()
        second = build_module_home_service_multi_requirement_set(
            tuple(
                reversed(
                    (
                        _single(
                            "zigbee-bridge",
                            (
                                "smart-home.bridge.v1",
                                "devices.zigbee.v1",
                            ),
                        ),
                        _single(
                            "media-catalog",
                            ("media.catalog.v1",),
                        ),
                    )
                )
            )
        )
        self.assertEqual(first, second)
        self.assertEqual(
            [item.service_id for item in first.service_requirement_sets],
            ["media-catalog", "zigbee-bridge"],
        )
        self.assertTrue(first.multi_requirement_set_id.startswith("mhsmr-"))

    def test_nested_requirement_change_changes_identity(self) -> None:
        original = _build()
        changed = build_module_home_service_multi_requirement_set(
            (
                _single("zigbee-bridge", ("devices.zigbee.v2",)),
                _single("media-catalog", ("media.catalog.v1",)),
            )
        )
        self.assertNotEqual(
            original.multi_requirement_set_id,
            changed.multi_requirement_set_id,
        )

    def test_mixed_context_and_duplicate_service_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "requirement_context_mismatch",
        ):
            build_module_home_service_multi_requirement_set(
                (
                    _single("zigbee-bridge", ("devices.zigbee.v1",)),
                    _single(
                        "media-catalog",
                        ("media.catalog.v1",),
                        module_version="1.2.4",
                    ),
                )
            )
        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "duplicate_service_requirement",
        ):
            build_module_home_service_multi_requirement_set(
                (
                    _single("zigbee-bridge", ("devices.zigbee.v1",)),
                    _single("zigbee-bridge", ("devices.zigbee.v2",)),
                )
            )

    def test_serialized_evidence_round_trips_and_rejects_tamper(self) -> None:
        original = _build()
        self.assertEqual(
            validate_module_home_service_multi_requirement_set(
                original.to_dict()
            ),
            original,
        )

        payload = original.to_dict()
        payload["service_requirement_sets"] = list(
            reversed(payload["service_requirement_sets"])
        )
        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "multi_requirement_set_rejected",
        ):
            validate_module_home_service_multi_requirement_set(payload)

        payload = original.to_dict()
        payload["service_requirement_sets"][0][
            "requirement_set_id"
        ] = "mhscr-" + "0" * 24
        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "service_requirement_set_rejected",
        ):
            validate_module_home_service_multi_requirement_set(payload)

    def test_authority_tampering_is_rejected(self) -> None:
        payload = _build().to_dict()
        payload["execution_authorized"] = True
        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "multi_requirement_set_rejected",
        ):
            validate_module_home_service_multi_requirement_set(payload)

    def test_schema_is_closed_and_non_authorizing(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "contracts/modules/"
            "module-home-service-contract-multi-requirement-set.v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        result = _build().to_dict()
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(result), set(schema["required"]))
        self.assertEqual(
            result["schema"],
            schema["properties"]["schema"]["const"],
        )
        self.assertEqual(
            schema["properties"]["service_requirement_sets"]["maxItems"],
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
