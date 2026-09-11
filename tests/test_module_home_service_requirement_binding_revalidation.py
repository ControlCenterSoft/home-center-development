from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

from home_center.module_home_service_contract_requirements import (
    build_module_home_service_contract_requirement_set,
)
from home_center.module_home_service_requirement_binding import (
    bind_module_home_service_requirement_set,
)
from home_center.module_home_service_requirement_binding_revalidation import (
    ModuleHomeServiceRequirementBindingRevalidationError,
    revalidate_module_home_service_requirement_binding,
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


def _module_binding(
    *,
    home_center_version: str = "0.44.0",
    module_id: str = "example.module",
    module_version: str = "1.2.3",
    artifact_sha256: str = "5" * 64,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "home-center.module-contract-admission-binding.v1",
        "profile_id": "mccp-" + "1" * 24,
        "negotiation_decision_id": "mcnd-" + "2" * 24,
        "admission_decision_id": "madm-" + "3" * 24,
        "home_center_version": home_center_version,
        "module_manifest_schema": "home-center.module-manifest.v2",
        "module_admission_schema": "home-center.module-admission-decision.v1",
        "module_id": module_id,
        "module_version": module_version,
        "manifest_binding_sha256": "4" * 64,
        "artifact_sha256": artifact_sha256,
        "admission_status": "compatible",
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    value["binding_id"] = "mcab-" + _hash(value)[:24]
    return value


def _service_profile(
    *,
    service_id: str = "zigbee-bridge",
) -> dict[str, object]:
    return {
        "service_id": service_id,
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
    home_center_version: str = "0.44.0",
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


def _original():
    requirements = _requirements()
    module = _module_binding()
    profile = _service_profile()
    binding = bind_module_home_service_requirement_set(
        requirements,
        module,
        profile,
    )
    return requirements, module, profile, binding


def _revalidate(
    *,
    fresh_requirements: object | None = None,
    fresh_module: object | None = None,
    fresh_profile: object | None = None,
):
    requirements, module, profile, binding = _original()
    return revalidate_module_home_service_requirement_binding(
        requirements,
        module,
        profile,
        binding,
        fresh_requirement_set=(
            requirements if fresh_requirements is None else fresh_requirements
        ),
        fresh_module_binding=module if fresh_module is None else fresh_module,
        fresh_service_profile=profile if fresh_profile is None else fresh_profile,
    )


def test_unchanged_requirement_binding_is_current_and_deterministic() -> None:
    first = _revalidate()
    second = _revalidate()
    assert first == second
    assert first.current is True
    assert first.status == "current"
    assert first.drift_reasons == ()
    assert first.original_requirement_binding_id == (
        first.fresh_requirement_binding_id
    )


def test_requirement_only_contract_drift_is_stale() -> None:
    fresh = _requirements(contracts=("devices.zigbee.v2",))
    result = _revalidate(fresh_requirements=fresh)
    assert result.status == "stale"
    assert "requirement_set_changed" in result.drift_reasons
    assert "required_service_contracts_changed" in result.drift_reasons
    assert "home_service_contract_binding_changed" in result.drift_reasons
    assert "compatibility_status_changed" in result.drift_reasons


def test_service_profile_drift_is_stale_without_requirement_drift() -> None:
    profile = _service_profile()
    profile["minimum_storage_gib"] = 8
    result = _revalidate(fresh_profile=profile)
    assert result.status == "stale"
    assert "home_service_profile_changed" in result.drift_reasons
    assert "home_service_contract_binding_changed" in result.drift_reasons
    assert "requirement_set_changed" not in result.drift_reasons


def test_admission_binding_drift_is_visible_through_compatibility_identity() -> None:
    module = _module_binding(artifact_sha256="9" * 64)
    result = _revalidate(fresh_module=module)
    assert result.status == "stale"
    assert result.drift_reasons == ("home_service_contract_binding_changed",)


def test_home_center_version_drift_is_explicit() -> None:
    fresh_requirements = _requirements(home_center_version="0.44.1")
    fresh_module = _module_binding(home_center_version="0.44.1")
    result = _revalidate(
        fresh_requirements=fresh_requirements,
        fresh_module=fresh_module,
    )
    assert result.status == "stale"
    assert "home_center_version_changed" in result.drift_reasons
    assert "requirement_set_changed" in result.drift_reasons


def test_module_identity_and_version_drift_are_explicit() -> None:
    fresh_requirements = _requirements(
        module_id="example.module.next",
        module_version="2.0.0",
    )
    fresh_module = _module_binding(
        module_id="example.module.next",
        module_version="2.0.0",
    )
    result = _revalidate(
        fresh_requirements=fresh_requirements,
        fresh_module=fresh_module,
    )
    assert "module_identity_changed" in result.drift_reasons
    assert "module_version_changed" in result.drift_reasons


def test_service_identity_drift_is_explicit() -> None:
    fresh_requirements = _requirements(service_id="zigbee-bridge-next")
    fresh_profile = _service_profile(service_id="zigbee-bridge-next")
    result = _revalidate(
        fresh_requirements=fresh_requirements,
        fresh_profile=fresh_profile,
    )
    assert "home_service_identity_changed" in result.drift_reasons
    assert "home_service_profile_changed" in result.drift_reasons


def test_tampered_original_requirement_binding_is_rejected() -> None:
    requirements, module, profile, binding = _original()
    tampered = replace(
        binding,
        requirement_binding_id="mhsrb-" + "f" * 24,
    )
    with pytest.raises(
        ModuleHomeServiceRequirementBindingRevalidationError,
        match="original_requirement_binding_rejected",
    ):
        revalidate_module_home_service_requirement_binding(
            requirements,
            module,
            profile,
            tampered,
            fresh_requirement_set=requirements,
            fresh_module_binding=module,
            fresh_service_profile=profile,
        )


def test_tampered_original_requirement_set_is_rejected() -> None:
    requirements, module, profile, binding = _original()
    tampered = requirements.to_dict()
    tampered["required_service_contracts"] = ["devices.zigbee.v2"]
    with pytest.raises(
        ModuleHomeServiceRequirementBindingRevalidationError,
        match="original_requirement_binding_rejected",
    ):
        revalidate_module_home_service_requirement_binding(
            tampered,
            module,
            profile,
            binding,
            fresh_requirement_set=tampered,
            fresh_module_binding=module,
            fresh_service_profile=profile,
        )


def test_malformed_fresh_profile_is_rejected_fail_closed() -> None:
    profile = _service_profile()
    profile["provided_capabilities"] = [
        "smart-home.bridge.v1",
        "devices.zigbee.v1",
    ]
    with pytest.raises(
        ModuleHomeServiceRequirementBindingRevalidationError,
        match="fresh_requirement_binding_rejected",
    ):
        _revalidate(fresh_profile=profile)


def test_authority_bearing_fresh_requirement_set_is_rejected() -> None:
    requirements = _requirements().to_dict()
    requirements["execution_authorized"] = True
    with pytest.raises(
        ModuleHomeServiceRequirementBindingRevalidationError,
        match="fresh_requirement_binding_rejected",
    ):
        _revalidate(fresh_requirements=requirements)


def test_schema_is_closed_non_authorizing_and_accepts_runtime_output() -> None:
    schema_path = (
        Path(__file__).parents[1]
        / "contracts/modules/"
        "module-home-service-contract-requirement-binding-revalidation.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    result = _revalidate()
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
