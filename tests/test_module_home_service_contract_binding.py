from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from home_center.module_home_service_contract_binding import (
    ModuleHomeServiceContractBindingError,
    bind_module_home_service_contracts,
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
        "home_center_version": "0.40.0",
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


class ModuleHomeServiceContractBindingTests(unittest.TestCase):
    def test_compatible_binding_is_deterministic_and_canonical(self) -> None:
        first = bind_module_home_service_contracts(
            _module_binding(),
            _service_profile(),
            ("smart-home.bridge.v1", "devices.zigbee.v1"),
        )
        second = bind_module_home_service_contracts(
            _module_binding(),
            _service_profile(),
            ("devices.zigbee.v1", "smart-home.bridge.v1"),
        )
        self.assertEqual(first, second)
        self.assertEqual(first.status, "compatible")
        self.assertEqual(first.reasons, ())
        self.assertEqual(first.unsupported_service_contracts, ())
        self.assertEqual(
            first.required_service_contracts,
            ("devices.zigbee.v1", "smart-home.bridge.v1"),
        )

    def test_unsupported_contract_blocks_without_authorizing(self) -> None:
        result = bind_module_home_service_contracts(
            _module_binding(),
            _service_profile(),
            ("devices.zigbee.v2",),
        )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.reasons, ("unsupported_service_contract",))
        self.assertEqual(result.unsupported_service_contracts, ("devices.zigbee.v2",))
        self.assertFalse(result.admission_authorized)
        self.assertFalse(result.installation_authorized)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.production_mutation_enabled)
        self.assertFalse(result.external_publication_authorized)

    def test_blocked_module_admission_keeps_service_binding_blocked(self) -> None:
        result = bind_module_home_service_contracts(
            _module_binding(admission_status="blocked"),
            _service_profile(),
            ("devices.zigbee.v1",),
        )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.reasons, ("module_admission_blocked",))

    def test_exact_profile_identity_changes_with_profile_contract(self) -> None:
        first = bind_module_home_service_contracts(
            _module_binding(),
            _service_profile(),
            ("devices.zigbee.v1",),
        )
        changed = _service_profile()
        changed["minimum_storage_gib"] = 8
        second = bind_module_home_service_contracts(
            _module_binding(),
            changed,
            ("devices.zigbee.v1",),
        )
        self.assertNotEqual(first.service_profile_sha256, second.service_profile_sha256)
        self.assertNotEqual(first.binding_id, second.binding_id)

    def test_tampered_module_binding_is_rejected(self) -> None:
        binding = _module_binding()
        binding["artifact_sha256"] = "9" * 64
        with self.assertRaisesRegex(
            ModuleHomeServiceContractBindingError,
            "module_contract_binding_rejected",
        ):
            bind_module_home_service_contracts(
                binding,
                _service_profile(),
                ("devices.zigbee.v1",),
            )

    def test_authority_tampering_is_rejected(self) -> None:
        binding = _module_binding()
        binding["execution_authorized"] = True
        evidence = dict(binding)
        evidence.pop("binding_id")
        binding["binding_id"] = "mcab-" + _hash(evidence)[:24]
        with self.assertRaisesRegex(
            ModuleHomeServiceContractBindingError,
            "module_contract_binding_rejected",
        ):
            bind_module_home_service_contracts(
                binding,
                _service_profile(),
                ("devices.zigbee.v1",),
            )

    def test_noncanonical_service_profile_is_rejected(self) -> None:
        profile = _service_profile()
        profile["provided_capabilities"] = [
            "smart-home.bridge.v1",
            "devices.zigbee.v1",
        ]
        with self.assertRaisesRegex(
            ModuleHomeServiceContractBindingError,
            "home_service_profile_rejected",
        ):
            bind_module_home_service_contracts(
                _module_binding(),
                profile,
                ("devices.zigbee.v1",),
            )

    def test_invalid_required_service_contracts_are_rejected(self) -> None:
        for requirements in (
            (),
            ("devices.zigbee.v1", "devices.zigbee.v1"),
            ("bad-contract",),
        ):
            with self.subTest(requirements=requirements):
                with self.assertRaisesRegex(
                    ModuleHomeServiceContractBindingError,
                    "required_service_contracts_rejected",
                ):
                    bind_module_home_service_contracts(
                        _module_binding(),
                        _service_profile(),
                        requirements,
                    )

    def test_schema_is_closed_non_authorizing_and_matches_runtime_output(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "contracts/modules/module-home-service-contract-binding.v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        result = bind_module_home_service_contracts(
            _module_binding(),
            _service_profile(),
            ("devices.zigbee.v1",),
        ).to_dict()

        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(result), set(schema["required"]))
        self.assertEqual(result["schema"], schema["properties"]["schema"]["const"])
        self.assertIn(result["status"], schema["properties"]["status"]["enum"])
        self.assertRegex(result["binding_id"], r"^mhscb-[0-9a-f]{24}$")
        self.assertRegex(result["service_profile_sha256"], r"^[0-9a-f]{64}$")
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
