from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

from home_center.module_home_service_contract_binding import (
    bind_module_home_service_contracts,
)
from home_center.module_home_service_contract_binding_revalidation import (
    ModuleHomeServiceContractBindingRevalidationError,
    revalidate_module_home_service_contract_binding,
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
    home_center_version: str = "0.41.0",
    module_id: str = "example.module",
    module_version: str = "1.2.3",
    admission_status: str = "compatible",
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


def _original():
    module = _module_binding()
    profile = _service_profile()
    requirements = ("devices.zigbee.v1",)
    binding = bind_module_home_service_contracts(
        module,
        profile,
        requirements,
    )
    return module, profile, requirements, binding


def _revalidate(
    *,
    fresh_module: object | None = None,
    fresh_profile: object | None = None,
    fresh_requirements: tuple[str, ...] | None = None,
):
    module, profile, requirements, binding = _original()
    return revalidate_module_home_service_contract_binding(
        module,
        profile,
        requirements,
        binding,
        fresh_module_binding=module if fresh_module is None else fresh_module,
        fresh_service_profile=profile if fresh_profile is None else fresh_profile,
        fresh_required_service_contracts=(
            requirements if fresh_requirements is None else fresh_requirements
        ),
    )


def test_unchanged_binding_is_current_and_deterministic() -> None:
    first = _revalidate()
    second = _revalidate()
    assert first == second
    assert first.current is True
    assert first.status == "current"
    assert first.drift_reasons == ()
    assert first.original_binding_id == first.fresh_binding_id


def test_service_profile_capability_drift_is_stale() -> None:
    profile = _service_profile()
    profile["provided_capabilities"] = [
        "devices.zigbee.v1",
        "smart-home.bridge.v1",
        "smart-home.scene.v1",
    ]
    result = _revalidate(fresh_profile=profile)
    assert result.status == "stale"
    assert "home_service_profile_changed" in result.drift_reasons
    assert "provided_service_contracts_changed" in result.drift_reasons


def test_non_capability_profile_drift_is_stale_even_when_compatible() -> None:
    profile = _service_profile()
    profile["minimum_storage_gib"] = 8
    result = _revalidate(fresh_profile=profile)
    assert result.status == "stale"
    assert result.original_compatibility_status == "compatible"
    assert result.fresh_compatibility_status == "compatible"
    assert result.drift_reasons == ("home_service_profile_changed",)


def test_required_contract_drift_is_stale_and_can_block() -> None:
    result = _revalidate(
        fresh_requirements=("devices.zigbee.v2",),
    )
    assert result.status == "stale"
    assert result.fresh_compatibility_status == "blocked"
    assert "required_service_contracts_changed" in result.drift_reasons
    assert "unsupported_service_contracts_changed" in result.drift_reasons
    assert "compatibility_status_changed" in result.drift_reasons


def test_module_contract_binding_drift_is_stale() -> None:
    fresh_module = _module_binding(home_center_version="0.41.1")
    result = _revalidate(fresh_module=fresh_module)
    assert result.status == "stale"
    assert "module_contract_admission_binding_changed" in result.drift_reasons
    assert "home_center_version_changed" in result.drift_reasons


def test_module_identity_and_version_drift_are_explicit() -> None:
    fresh_module = _module_binding(
        module_id="example.module.next",
        module_version="2.0.0",
    )
    result = _revalidate(fresh_module=fresh_module)
    assert result.status == "stale"
    assert "module_identity_changed" in result.drift_reasons
    assert "module_version_changed" in result.drift_reasons


def test_tampered_original_binding_is_rejected() -> None:
    module, profile, requirements, binding = _original()
    tampered = replace(
        binding,
        binding_id="mhscb-" + "f" * 24,
    )
    with pytest.raises(
        ModuleHomeServiceContractBindingRevalidationError,
        match="original_home_service_binding_rejected",
    ):
        revalidate_module_home_service_contract_binding(
            module,
            profile,
            requirements,
            tampered,
            fresh_module_binding=module,
            fresh_service_profile=profile,
            fresh_required_service_contracts=requirements,
        )


def test_tampered_original_profile_is_rejected() -> None:
    module, profile, requirements, binding = _original()
    changed = dict(profile)
    changed["minimum_storage_gib"] = 8
    with pytest.raises(
        ModuleHomeServiceContractBindingRevalidationError,
        match="original_home_service_binding_rejected",
    ):
        revalidate_module_home_service_contract_binding(
            module,
            changed,
            requirements,
            binding,
            fresh_module_binding=module,
            fresh_service_profile=changed,
            fresh_required_service_contracts=requirements,
        )


def test_malformed_fresh_profile_is_rejected_fail_closed() -> None:
    profile = _service_profile()
    profile["provided_capabilities"] = [
        "smart-home.bridge.v1",
        "devices.zigbee.v1",
    ]
    with pytest.raises(
        ModuleHomeServiceContractBindingRevalidationError,
        match="fresh_home_service_binding_rejected",
    ):
        _revalidate(fresh_profile=profile)


def test_authority_bearing_fresh_module_binding_is_rejected() -> None:
    module = _module_binding()
    module["execution_authorized"] = True
    evidence = dict(module)
    evidence.pop("binding_id")
    module["binding_id"] = "mcab-" + _hash(evidence)[:24]
    with pytest.raises(
        ModuleHomeServiceContractBindingRevalidationError,
        match="fresh_home_service_binding_rejected",
    ):
        _revalidate(fresh_module=module)


def test_schema_is_closed_non_authorizing_and_accepts_runtime_output() -> None:
    schema_path = (
        Path(__file__).parents[1]
        / "contracts/modules/"
        "module-home-service-contract-binding-revalidation.v1.schema.json"
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
