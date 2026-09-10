from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from home_center.module_home_service_contract_requirements import (
    build_module_home_service_contract_requirement_set,
)
from home_center.module_home_service_multi_compatibility import (
    bind_module_home_service_multi_compatibility,
)
from home_center.module_home_service_multi_compatibility_revalidation import (
    ModuleHomeServiceMultiCompatibilityRevalidationError,
    revalidate_module_home_service_multi_compatibility,
    validate_module_home_service_multi_compatibility_revalidation,
)
from home_center.module_home_service_multi_requirements import (
    build_module_home_service_multi_requirement_set,
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
    home_center_version: str = "0.49.0",
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
        "module_admission_schema": (
            "home-center.module-admission-decision.v1"
        ),
        "module_id": "example.module",
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


def _profile(
    service_id: str,
    *,
    provided: tuple[str, ...],
    minimum_storage_gib: int = 4,
) -> dict[str, object]:
    if service_id == "zigbee-bridge":
        kind = "zigbee-bridge"
        name = "ZigBee Bridge"
    else:
        kind = "minecraft-server"
        name = "Minecraft Server"
    return {
        "service_id": service_id,
        "kind": kind,
        "name": name,
        "required_capabilities": [],
        "provided_capabilities": list(sorted(provided)),
        "minimum_storage_gib": minimum_storage_gib,
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


def _single(
    service_id: str,
    contracts: tuple[str, ...],
    *,
    home_center_version: str = "0.49.0",
    module_version: str = "1.2.3",
):
    return build_module_home_service_contract_requirement_set(
        home_center_version=home_center_version,
        module_id="example.module",
        module_version=module_version,
        service_id=service_id,
        required_service_contracts=contracts,
    )


def _requirements(
    *,
    home_center_version: str = "0.49.0",
    module_version: str = "1.2.3",
    zigbee_contract: str = "devices.zigbee.v1",
):
    return build_module_home_service_multi_requirement_set(
        (
            _single(
                "zigbee-bridge",
                (zigbee_contract, "smart-home.bridge.v1"),
                home_center_version=home_center_version,
                module_version=module_version,
            ),
            _single(
                "minecraft-server",
                ("game.minecraft.v1",),
                home_center_version=home_center_version,
                module_version=module_version,
            ),
        )
    )


def _profiles(
    *,
    zigbee_storage: int = 4,
) -> tuple[dict[str, object], ...]:
    return (
        _profile(
            "zigbee-bridge",
            provided=(
                "devices.zigbee.v1",
                "smart-home.bridge.v1",
            ),
            minimum_storage_gib=zigbee_storage,
        ),
        _profile(
            "minecraft-server",
            provided=("game.minecraft.v1",),
        ),
    )


def _binding(
    requirements=None,
    module_binding=None,
    profiles=None,
):
    return bind_module_home_service_multi_compatibility(
        requirements or _requirements(),
        module_binding or _module_binding(),
        profiles or _profiles(),
    )


def _revalidate(
    *,
    fresh_requirements=None,
    fresh_module_binding=None,
    fresh_profiles=None,
    original_binding=None,
):
    original_requirements = _requirements()
    original_module_binding = _module_binding()
    original_profiles = _profiles()
    return revalidate_module_home_service_multi_compatibility(
        original_requirements,
        original_module_binding,
        original_profiles,
        original_binding
        or _binding(
            original_requirements,
            original_module_binding,
            original_profiles,
        ),
        fresh_multi_requirement_set=fresh_requirements
        or original_requirements,
        fresh_module_binding=fresh_module_binding
        or original_module_binding,
        fresh_service_profiles=fresh_profiles or original_profiles,
    )


def test_unchanged_aggregate_is_current_and_deterministic() -> None:
    first = _revalidate()
    second = _revalidate()
    assert first == second
    assert first.status == "current"
    assert first.drift_reasons == ()
    assert (
        first.original_multi_compatibility_binding_id
        == first.fresh_multi_compatibility_binding_id
    )


def test_requirement_only_drift_is_stale() -> None:
    result = _revalidate(
        fresh_requirements=_requirements(zigbee_contract="devices.zigbee.v2")
    )
    assert result.status == "stale"
    assert "multi_requirement_set_changed" in result.drift_reasons
    assert "service_compatibility_evidence_changed" in result.drift_reasons
    assert "compatibility_status_changed" in result.drift_reasons


def test_profile_drift_is_stale_even_when_still_compatible() -> None:
    result = _revalidate(fresh_profiles=_profiles(zigbee_storage=8))
    assert result.status == "stale"
    assert result.fresh_compatibility_status == "compatible"
    assert "service_compatibility_evidence_changed" in result.drift_reasons
    assert "compatibility_status_changed" not in result.drift_reasons


def test_admission_drift_is_stale() -> None:
    result = _revalidate(
        fresh_module_binding=_module_binding(admission_status="blocked")
    )
    assert result.status == "stale"
    assert result.fresh_compatibility_status == "blocked"
    assert "service_compatibility_evidence_changed" in result.drift_reasons
    assert "blocked_service_set_changed" in result.drift_reasons


def test_home_center_version_drift_is_stale() -> None:
    result = _revalidate(
        fresh_requirements=_requirements(home_center_version="0.50.0"),
        fresh_module_binding=_module_binding(home_center_version="0.50.0"),
    )
    assert result.status == "stale"
    assert "home_center_version_changed" in result.drift_reasons


def test_module_version_drift_is_stale() -> None:
    result = _revalidate(
        fresh_requirements=_requirements(module_version="1.2.4"),
        fresh_module_binding=_module_binding(module_version="1.2.4"),
    )
    assert result.status == "stale"
    assert "module_version_changed" in result.drift_reasons


def test_tampered_original_binding_is_rejected() -> None:
    original = _binding().to_dict()
    original["compatibility_status"] = "blocked"
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityRevalidationError,
        match="original_multi_compatibility_binding_rejected",
    ):
        _revalidate(original_binding=original)


def test_missing_fresh_profile_is_rejected() -> None:
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityRevalidationError,
        match="fresh_multi_compatibility_binding_rejected",
    ):
        _revalidate(fresh_profiles=(_profiles()[0],))


def test_revalidation_is_non_authorizing() -> None:
    result = _revalidate()
    assert result.admission_authorized is False
    assert result.installation_authorized is False
    assert result.execution_authorized is False
    assert result.production_mutation_enabled is False
    assert result.external_publication_authorized is False


def test_serialized_revalidation_round_trip() -> None:
    result = _revalidate(fresh_profiles=_profiles(zigbee_storage=8))
    assert (
        validate_module_home_service_multi_compatibility_revalidation(
            result.to_dict()
        )
        == result
    )


def test_serialized_authority_tampering_is_rejected() -> None:
    payload = _revalidate().to_dict()
    payload["execution_authorized"] = True
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityRevalidationError,
        match="multi_compatibility_revalidation_evidence_rejected",
    ):
        validate_module_home_service_multi_compatibility_revalidation(payload)


def test_serialized_identity_tampering_is_rejected() -> None:
    payload = _revalidate().to_dict()
    payload["fresh_service_evidence_sha256"] = "0" * 64
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityRevalidationError,
        match="multi_compatibility_revalidation_evidence_rejected",
    ):
        validate_module_home_service_multi_compatibility_revalidation(payload)


def test_schema_is_closed_and_non_authorizing_without_extra_dependency() -> None:
    schema_path = (
        Path(__file__).parents[1]
        / "contracts/modules/"
        "module-home-service-contract-multi-compatibility-binding-"
        "revalidation.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    result = _revalidate().to_dict()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(result)
    assert schema["properties"]["schema"]["const"] == result["schema"]
    for name in (
        "admission_authorized",
        "installation_authorized",
        "execution_authorized",
        "production_mutation_enabled",
        "external_publication_authorized",
    ):
        assert schema["properties"][name] == {"const": False}
