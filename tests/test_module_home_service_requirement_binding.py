from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from home_center.module_home_service_contract_binding import (
    bind_module_home_service_contracts,
)
from home_center.module_home_service_contract_requirements import (
    build_module_home_service_contract_requirement_set,
)
from home_center.module_home_service_requirement_binding import (
    ModuleHomeServiceRequirementBindingError,
    bind_module_home_service_requirement_set,
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
        "home_center_version": "0.43.0",
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


def _requirements(
    *,
    home_center_version: str = "0.43.0",
    module_id: str = "example.module",
    module_version: str = "1.2.3",
    service_id: str = "zigbee-bridge",
    contracts: tuple[str, ...] = ("devices.zigbee.v1",),
):
    return build_module_home_service_contract_requirement_set(
        home_center_version=home_center_version,
        module_id=module_id,
        module_version=module_version,
        service_id=service_id,
        required_service_contracts=contracts,
    )


def test_binding_is_deterministic_and_binds_exact_compatibility() -> None:
    requirements = _requirements(
        contracts=("smart-home.bridge.v1", "devices.zigbee.v1")
    )
    first = bind_module_home_service_requirement_set(
        requirements,
        _module_binding(),
        _service_profile(),
    )
    second = bind_module_home_service_requirement_set(
        requirements,
        _module_binding(),
        _service_profile(),
    )
    compatibility = bind_module_home_service_contracts(
        _module_binding(),
        _service_profile(),
        requirements.required_service_contracts,
    )
    assert first == second
    assert first.requirement_set_id == requirements.requirement_set_id
    assert first.home_service_contract_binding_id == compatibility.binding_id
    assert first.compatibility_status == "compatible"


def test_unsupported_requirement_is_bound_as_blocked_evidence() -> None:
    result = bind_module_home_service_requirement_set(
        _requirements(contracts=("devices.zigbee.v2",)),
        _module_binding(),
        _service_profile(),
    )
    assert result.compatibility_status == "blocked"
    assert result.admission_authorized is False
    assert result.installation_authorized is False
    assert result.execution_authorized is False
    assert result.production_mutation_enabled is False
    assert result.external_publication_authorized is False


def test_blocked_admission_is_preserved_as_blocked_compatibility() -> None:
    result = bind_module_home_service_requirement_set(
        _requirements(),
        _module_binding(admission_status="blocked"),
        _service_profile(),
    )
    assert result.compatibility_status == "blocked"


def test_profile_drift_changes_binding_but_not_requirement_identity() -> None:
    requirements = _requirements()
    first = bind_module_home_service_requirement_set(
        requirements,
        _module_binding(),
        _service_profile(),
    )
    changed = _service_profile()
    changed["minimum_storage_gib"] = 8
    second = bind_module_home_service_requirement_set(
        requirements,
        _module_binding(),
        changed,
    )
    assert first.requirement_set_id == second.requirement_set_id
    assert first.service_profile_sha256 != second.service_profile_sha256
    assert first.home_service_contract_binding_id != (
        second.home_service_contract_binding_id
    )
    assert first.requirement_binding_id != second.requirement_binding_id


@pytest.mark.parametrize(
    "requirements",
    [
        _requirements(home_center_version="0.42.0"),
        _requirements(module_id="other.module"),
        _requirements(module_version="1.2.4"),
        _requirements(service_id="minecraft-server"),
    ],
)
def test_requirement_context_mismatch_is_rejected(requirements: object) -> None:
    with pytest.raises(
        ModuleHomeServiceRequirementBindingError,
        match="requirement_context_mismatch",
    ):
        bind_module_home_service_requirement_set(
            requirements,
            _module_binding(),
            _service_profile(),
        )


def test_tampered_requirement_set_is_rejected() -> None:
    requirements = _requirements().to_dict()
    requirements["required_service_contracts"] = ["devices.zigbee.v2"]
    with pytest.raises(
        ModuleHomeServiceRequirementBindingError,
        match="requirement_set_rejected",
    ):
        bind_module_home_service_requirement_set(
            requirements,
            _module_binding(),
            _service_profile(),
        )


def test_authority_bearing_requirement_set_is_rejected() -> None:
    requirements = _requirements().to_dict()
    requirements["execution_authorized"] = True
    with pytest.raises(
        ModuleHomeServiceRequirementBindingError,
        match="requirement_set_rejected",
    ):
        bind_module_home_service_requirement_set(
            requirements,
            _module_binding(),
            _service_profile(),
        )


def test_invalid_compatibility_context_is_rejected() -> None:
    module_binding = _module_binding()
    module_binding["artifact_sha256"] = "9" * 64
    with pytest.raises(
        ModuleHomeServiceRequirementBindingError,
        match="home_service_compatibility_rejected",
    ):
        bind_module_home_service_requirement_set(
            _requirements(),
            module_binding,
            _service_profile(),
        )


def test_schema_is_closed_non_authorizing_and_accepts_runtime_output() -> None:
    schema_path = (
        Path(__file__).parents[1]
        / "contracts/modules/"
        "module-home-service-contract-requirement-binding.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    result = bind_module_home_service_requirement_set(
        _requirements(),
        _module_binding(),
        _service_profile(),
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
