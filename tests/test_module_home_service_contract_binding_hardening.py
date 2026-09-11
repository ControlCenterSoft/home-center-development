from __future__ import annotations

import hashlib
import json
import unittest

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


def _module_binding() -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "home-center.module-contract-admission-binding.v1",
        "profile_id": "mccp-" + "1" * 24,
        "negotiation_decision_id": "mcnd-" + "2" * 24,
        "admission_decision_id": "madm-" + "3" * 24,
        "home_center_version": "0.44.0",
        "module_manifest_schema": "home-center.module-manifest.v2",
        "module_admission_schema": "home-center.module-admission-decision.v1",
        "module_id": "example.module",
        "module_version": "1.2.3",
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


def _service_profile() -> dict[str, object]:
    return {
        "service_id": "zigbee-bridge",
        "kind": "zigbee-bridge",
        "name": "ZigBee Bridge",
        "required_capabilities": [
            "devices.usb.v1",
            "network.lan.v1",
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


class ModuleHomeServiceContractBindingHardeningTests(unittest.TestCase):
    def test_required_contract_iterable_is_bounded(self) -> None:
        consumed = 0

        def endless_contracts():
            nonlocal consumed
            while True:
                consumed += 1
                yield f"service.contract{consumed}.v1"

        with self.assertRaisesRegex(
            ModuleHomeServiceContractBindingError,
            "required_service_contracts_rejected",
        ):
            bind_module_home_service_contracts(
                _module_binding(),
                _service_profile(),
                endless_contracts(),
            )
        self.assertEqual(consumed, 65)

    def test_required_contract_iterator_failure_is_normalized(self) -> None:
        def broken_contracts():
            yield "devices.zigbee.v1"
            raise OSError("source failed")

        with self.assertRaisesRegex(
            ModuleHomeServiceContractBindingError,
            "required_service_contracts_rejected",
        ):
            bind_module_home_service_contracts(
                _module_binding(),
                _service_profile(),
                broken_contracts(),
            )

    def test_unhashable_profile_capability_is_rejected_stably(self) -> None:
        profile = _service_profile()
        profile["provided_capabilities"] = [["devices.zigbee.v1"]]
        with self.assertRaisesRegex(
            ModuleHomeServiceContractBindingError,
            "home_service_profile_rejected",
        ):
            bind_module_home_service_contracts(
                _module_binding(),
                profile,
                ("devices.zigbee.v1",),
            )


if __name__ == "__main__":
    unittest.main()
