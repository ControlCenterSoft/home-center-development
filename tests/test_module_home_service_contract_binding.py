from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

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


def test_compatible_binding_is_deterministic_and_canonical() -> None:
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
    assert first == second
    assert first.status == "compatible"
    assert first.reasons == ()
    assert first.unsupported_service_contracts == ()
    assert first.required_service_contracts == (
        "devices.zigbee.v1",
        "smart-home.bridge.v1",
    )


def test_unsupported_contract_blocks_without_authorizing() -> None:
    result = bind_module_home_service_contracts(
        _module_binding(),
        _service_profile(),
        ("devices.zigbee.v2",),
    )
    assert result.status == "blocked"
    assert result.reasons == ("unsupported_service_contract",)
    assert result.unsupported_service_contracts == ("devices.zigbee.v2",)
    assert result.admission_authorized is False
    assert result.installation_authorized is False
    assert result.execution_authorized is False
    assert result.production_mutation_enabled is False
    assert result.external_publication_authorized is False


def test_blocked_module_admission_keeps_service_binding_blocked() -> None:
    result = bind_module_home_service_contracts(
        _module_binding(admission_status="blocked"),
        _service_profile(),
        ("devices.zigbee.v1",),
    )
    assert result.status == "blocked"
    assert result.reasons == ("module_admission_blocked",)


def test_exact_profile_identity_changes_with_profile_contract() -> None:
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
    assert first.service_profile_sha256 != second.service_profile_sha256
    assert first.binding_id != second.binding_id


def test_tampered_module_binding_is_rejected() -> None:
    binding = _module_binding()
    binding["artifact_sha256"] = "9" * 64
    with pytest.raises(
        ModuleHomeServiceContractBindingError,
        match="module_contract_binding_rejected",
    ):
        bind_module_home_service_contracts(
            binding,
            _service_profile(),
            ("devices.zigbee.v1",),
        )


def test_authority_tampering_is_rejected() -> None:
    binding = _module_binding()
    binding["execution_authorized"] = True
    evidence = dict(binding)
    evidence.pop("binding_id")
    binding["binding_id"] = "mcab-" + _hash(evidence)[:24]
    with pytest.raises(
        ModuleHomeServiceContractBindingError,
        match="module_contract_binding_rejected",
    ):
        bind_module_home_service_contracts(
            binding,
            _service_profile(),
            ("devices.zigbee.v1",),
        )


def test_noncanonical_service_profile_is_rejected() -> None:
    profile = _service_profile()
    profile["provided_capabilities"] = [
        "smart-home.bridge.v1",
        "devices.zigbee.v1",
    ]
    with pytest.raises(
        ModuleHomeServiceContractBindingError,
        match="home_service_profile_rejected",
    ):
        bind_module_home_service_contracts(
            _module_binding(),
            profile,
            ("devices.zigbee.v1",),
        )


@pytest.mark.parametrize(
    "requirements",
    [
        (),
        ("devices.zigbee.v1", "devices.zigbee.v1"),
        ("bad-contract",),
    ],
)
def test_invalid_required_service_contracts_are_rejected(
    requirements: tuple[str, ...],
) -> None:
    with pytest.raises(
        ModuleHomeServiceContractBindingError,
        match="required_service_contracts_rejected",
    ):
        bind_module_home_service_contracts(
            _module_binding(),
            _service_profile(),
            requirements,
        )


def test_schema_is_closed_non_authorizing_and_accepts_runtime_output() -> None:
    schema_path = (
        Path(__file__).parents[1]
        / "contracts/modules/module-home-service-contract-binding.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    result = bind_module_home_service_contracts(
        _module_binding(),
        _service_profile(),
        ("devices.zigbee.v1",),
    )
    jsonschema.Draft202012Validator(schema).validate(result.to_dict())
    assert schema["additionalProperties"] is False
    for name in (
        "admission_authorized",
        "installation_authorized",
        "execution_authorized",
        "production_mutation_enabled",
        "external_publication_authorized",
    ):
        assert schema["properties"][name] == {"const": False}
