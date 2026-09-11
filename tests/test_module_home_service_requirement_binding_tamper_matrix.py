from __future__ import annotations

import hashlib
import json
import unittest

from home_center.module_home_service_requirement_binding import (
    ModuleHomeServiceRequirementBindingError,
    validate_module_home_service_requirement_binding,
)


AUTHORITY_FLAGS = (
    "admission_authorized",
    "installation_authorized",
    "execution_authorized",
    "production_mutation_enabled",
    "external_publication_authorized",
)


def _payload(*, status: str = "compatible") -> dict[str, object]:
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
        "compatibility_status": status,
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    payload["requirement_binding_id"] = _identity(payload)
    return payload


def _identity(payload: dict[str, object]) -> str:
    evidence = dict(payload)
    evidence.pop("requirement_binding_id", None)
    encoded = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return "mhsrb-" + hashlib.sha256(encoded).hexdigest()[:24]


class _SerializableBinding:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def to_dict(self) -> dict[str, object]:
        return dict(self._payload)


class RequirementBindingTamperMatrixTests(unittest.TestCase):
    def test_valid_semantic_drift_without_identity_refresh_fails_closed(self) -> None:
        mutations: tuple[tuple[str, object], ...] = (
            ("requirement_set_id", "mhscr-" + "a" * 24),
            ("home_service_contract_binding_id", "mhscb-" + "b" * 24),
            ("home_center_version", "0.43.1"),
            ("module_id", "example.module.next"),
            ("module_version", "1.2.4"),
            ("service_id", "mqtt-bridge"),
            ("service_profile_sha256", "4" * 64),
            ("required_service_contracts", ["devices.zigbee.v2"]),
            ("compatibility_status", "blocked"),
        )
        for field, replacement in mutations:
            with self.subTest(field=field):
                payload = _payload()
                original_id = payload["requirement_binding_id"]
                payload[field] = replacement
                self.assertEqual(payload["requirement_binding_id"], original_id)
                with self.assertRaisesRegex(
                    ModuleHomeServiceRequirementBindingError,
                    "requirement_binding_rejected",
                ):
                    validate_module_home_service_requirement_binding(payload)

    def test_closed_field_set_rejects_missing_and_extra_fields(self) -> None:
        missing = _payload()
        missing.pop("service_profile_sha256")
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingError,
            "requirement_binding_rejected",
        ):
            validate_module_home_service_requirement_binding(missing)

        extra = _payload()
        extra["runtime_authority"] = False
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingError,
            "requirement_binding_rejected",
        ):
            validate_module_home_service_requirement_binding(extra)

    def test_blocked_evidence_remains_valid_and_non_authorizing(self) -> None:
        payload = _payload(status="blocked")
        validated = validate_module_home_service_requirement_binding(payload)
        self.assertEqual(validated.compatibility_status, "blocked")
        self.assertEqual(validated.to_dict(), payload)
        serialized = validated.to_dict()
        for flag in AUTHORITY_FLAGS:
            with self.subTest(flag=flag):
                self.assertIs(serialized[flag], False)

    def test_to_dict_adapter_has_same_validation_boundary(self) -> None:
        payload = _payload()
        direct = validate_module_home_service_requirement_binding(payload)
        adapted = validate_module_home_service_requirement_binding(
            _SerializableBinding(payload)
        )
        self.assertEqual(adapted, direct)

        tampered = _payload()
        tampered["module_version"] = "1.2.4"
        with self.assertRaisesRegex(
            ModuleHomeServiceRequirementBindingError,
            "requirement_binding_rejected",
        ):
            validate_module_home_service_requirement_binding(
                _SerializableBinding(tampered)
            )


if __name__ == "__main__":
    unittest.main()
