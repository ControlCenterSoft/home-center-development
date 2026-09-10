from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from home_center.module_home_service_contract_requirements import (
    build_module_home_service_contract_requirement_set,
)
from home_center.module_home_service_multi_compatibility import (
    ModuleHomeServiceMultiCompatibilityError,
    bind_module_home_service_multi_compatibility,
    validate_module_home_service_multi_compatibility_binding,
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
    admission_status: str = "compatible",
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "home-center.module-contract-admission-binding.v1",
        "profile_id": "mccp-" + "1" * 24,
        "negotiation_decision_id": "mcnd-" + "2" * 24,
        "admission_decision_id": "madm-" + "3" * 24,
        "home_center_version": "0.46.0",
        "module_manifest_schema": "home-center.module-manifest.v2",
        "module_admission_schema": (
            "home-center.module-admission-decision.v1"
        ),
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


def _profile(
    service_id: str,
    *,
    provided: tuple[str, ...],
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


def _single(
    service_id: str,
    contracts: tuple[str, ...],
):
    return build_module_home_service_contract_requirement_set(
        home_center_version="0.46.0",
        module_id="example.module",
        module_version="1.2.3",
        service_id=service_id,
        required_service_contracts=contracts,
    )


def _requirements():
    return build_module_home_service_multi_requirement_set(
        (
            _single(
                "zigbee-bridge",
                ("devices.zigbee.v1", "smart-home.bridge.v1"),
            ),
            _single("minecraft-server", ("game.minecraft.v1",)),
        )
    )


def _profiles() -> tuple[dict[str, object], ...]:
    return (
        _profile(
            "zigbee-bridge",
            provided=(
                "devices.zigbee.v1",
                "smart-home.bridge.v1",
            ),
        ),
        _profile(
            "minecraft-server",
            provided=("game.minecraft.v1",),
        ),
    )


def test_aggregate_is_deterministic_and_canonical() -> None:
    first = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(),
        _profiles(),
    )
    second = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(),
        tuple(reversed(_profiles())),
    )
    assert first == second
    assert [
        item.service_id
        for item in first.service_compatibility_bindings
    ] == ["minecraft-server", "zigbee-bridge"]
    assert first.multi_compatibility_binding_id.startswith("mhsmcb-")


def test_all_required_services_compatible() -> None:
    result = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(),
        _profiles(),
    )
    assert result.compatibility_status == "compatible"
    assert result.blocked_service_ids == ()


def test_one_unsupported_service_blocks_aggregate() -> None:
    profiles = list(_profiles())
    profiles[0] = _profile(
        "zigbee-bridge",
        provided=("devices.zigbee.v1",),
    )
    result = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(),
        profiles,
    )
    assert result.compatibility_status == "blocked"
    assert result.blocked_service_ids == ("zigbee-bridge",)


def test_blocked_module_admission_blocks_every_service() -> None:
    result = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(admission_status="blocked"),
        _profiles(),
    )
    assert result.compatibility_status == "blocked"
    assert result.blocked_service_ids == (
        "minecraft-server",
        "zigbee-bridge",
    )


def test_missing_service_profile_is_rejected() -> None:
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityError,
        match="service_profile_set_mismatch",
    ):
        bind_module_home_service_multi_compatibility(
            _requirements(),
            _module_binding(),
            (_profiles()[0],),
        )


def test_extra_service_profile_is_rejected() -> None:
    extra = _profile(
        "another-service",
        provided=("another.contract.v1",),
    )
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityError,
        match="service_profile_set_mismatch",
    ):
        bind_module_home_service_multi_compatibility(
            _requirements(),
            _module_binding(),
            (*_profiles(), extra),
        )


def test_duplicate_service_profile_is_rejected() -> None:
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityError,
        match="duplicate_service_profile",
    ):
        bind_module_home_service_multi_compatibility(
            _requirements(),
            _module_binding(),
            (_profiles()[0], _profiles()[0]),
        )


def test_tampered_multi_requirement_set_is_rejected() -> None:
    requirements = _requirements().to_dict()
    requirements["multi_requirement_set_id"] = "mhsmr-" + "0" * 24
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityError,
        match="multi_requirement_set_rejected",
    ):
        bind_module_home_service_multi_compatibility(
            requirements,
            _module_binding(),
            _profiles(),
        )


def test_authority_bearing_multi_requirement_set_is_rejected() -> None:
    requirements = _requirements().to_dict()
    requirements["execution_authorized"] = True
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityError,
        match="multi_requirement_set_rejected",
    ):
        bind_module_home_service_multi_compatibility(
            requirements,
            _module_binding(),
            _profiles(),
        )


def test_invalid_module_binding_is_rejected_fail_closed() -> None:
    module_binding = _module_binding()
    module_binding["artifact_sha256"] = "9" * 64
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityError,
        match="service_compatibility_rejected",
    ):
        bind_module_home_service_multi_compatibility(
            _requirements(),
            module_binding,
            _profiles(),
        )


def test_serialized_evidence_round_trips() -> None:
    result = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(),
        _profiles(),
    )
    assert validate_module_home_service_multi_compatibility_binding(
        result.to_dict()
    ) == result


def test_noncanonical_serialized_service_order_is_rejected() -> None:
    payload = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(),
        _profiles(),
    ).to_dict()
    payload["service_compatibility_bindings"] = list(
        reversed(payload["service_compatibility_bindings"])
    )
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityError,
        match="multi_compatibility_binding_rejected",
    ):
        validate_module_home_service_multi_compatibility_binding(payload)


def test_serialized_blocked_service_ids_must_match_children() -> None:
    profiles = list(_profiles())
    profiles[0] = _profile(
        "zigbee-bridge",
        provided=("devices.zigbee.v1",),
    )
    payload = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(),
        profiles,
    ).to_dict()
    payload["blocked_service_ids"] = []
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityError,
        match="multi_compatibility_binding_rejected",
    ):
        validate_module_home_service_multi_compatibility_binding(payload)


def test_serialized_identity_tampering_is_rejected() -> None:
    payload = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(),
        _profiles(),
    ).to_dict()
    payload["multi_compatibility_binding_id"] = "mhsmcb-" + "0" * 24
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityError,
        match="multi_compatibility_binding_rejected",
    ):
        validate_module_home_service_multi_compatibility_binding(payload)


def test_authority_tampering_is_rejected() -> None:
    payload = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(),
        _profiles(),
    ).to_dict()
    payload["installation_authorized"] = True
    with pytest.raises(
        ModuleHomeServiceMultiCompatibilityError,
        match="multi_compatibility_binding_rejected",
    ):
        validate_module_home_service_multi_compatibility_binding(payload)


def test_schema_is_closed_non_authorizing_and_accepts_runtime_output() -> None:
    schema_path = (
        Path(__file__).parents[1]
        / "contracts/modules/"
        "module-home-service-contract-multi-compatibility-binding.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    result = bind_module_home_service_multi_compatibility(
        _requirements(),
        _module_binding(),
        _profiles(),
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
