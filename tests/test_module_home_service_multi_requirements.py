from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

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


def test_multi_requirement_set_is_deterministic_and_canonical() -> None:
    first = _build()
    second = build_module_home_service_multi_requirement_set(
        tuple(reversed((
            _single(
                "zigbee-bridge",
                ("smart-home.bridge.v1", "devices.zigbee.v1"),
            ),
            _single("media-catalog", ("media.catalog.v1",)),
        )))
    )
    assert first == second
    assert [
        item.service_id for item in first.service_requirement_sets
    ] == ["media-catalog", "zigbee-bridge"]
    assert first.multi_requirement_set_id.startswith("mhsmr-")


def test_nested_requirement_change_changes_exact_identity() -> None:
    original = _build()
    changed = build_module_home_service_multi_requirement_set(
        (
            _single("zigbee-bridge", ("devices.zigbee.v2",)),
            _single("media-catalog", ("media.catalog.v1",)),
        )
    )
    assert original.multi_requirement_set_id != changed.multi_requirement_set_id


@pytest.mark.parametrize(
    "field,value",
    [
        ("home_center_version", "0.45.1"),
        ("module_id", "other.module"),
        ("module_version", "1.2.4"),
    ],
)
def test_mixed_requirement_context_is_rejected(
    field: str,
    value: str,
) -> None:
    mismatched = _single(
        "media-catalog",
        ("media.catalog.v1",),
        **{field: value},
    )
    with pytest.raises(
        ModuleHomeServiceMultiRequirementError,
        match="requirement_context_mismatch",
    ):
        build_module_home_service_multi_requirement_set(
            (
                _single("zigbee-bridge", ("devices.zigbee.v1",)),
                mismatched,
            )
        )


def test_duplicate_service_requirement_is_rejected() -> None:
    with pytest.raises(
        ModuleHomeServiceMultiRequirementError,
        match="duplicate_service_requirement",
    ):
        build_module_home_service_multi_requirement_set(
            (
                _single("zigbee-bridge", ("devices.zigbee.v1",)),
                _single("zigbee-bridge", ("devices.zigbee.v2",)),
            )
        )


def test_empty_aggregate_is_rejected() -> None:
    with pytest.raises(
        ModuleHomeServiceMultiRequirementError,
        match="service_requirement_sets_rejected",
    ):
        build_module_home_service_multi_requirement_set(())


def test_serialized_evidence_round_trips() -> None:
    original = _build()
    assert validate_module_home_service_multi_requirement_set(
        original.to_dict()
    ) == original


def test_noncanonical_serialized_service_order_is_rejected() -> None:
    payload = _build().to_dict()
    payload["service_requirement_sets"] = list(
        reversed(payload["service_requirement_sets"])
    )
    with pytest.raises(
        ModuleHomeServiceMultiRequirementError,
        match="multi_requirement_set_rejected",
    ):
        validate_module_home_service_multi_requirement_set(payload)


def test_tampered_nested_requirement_identity_is_rejected() -> None:
    payload = _build().to_dict()
    payload["service_requirement_sets"][0][
        "requirement_set_id"
    ] = "mhscr-" + ("0" * 24)
    with pytest.raises(
        ModuleHomeServiceMultiRequirementError,
        match="service_requirement_set_rejected",
    ):
        validate_module_home_service_multi_requirement_set(payload)


def test_authority_tampering_is_rejected() -> None:
    payload = _build().to_dict()
    payload["execution_authorized"] = True
    with pytest.raises(
        ModuleHomeServiceMultiRequirementError,
        match="multi_requirement_set_rejected",
    ):
        validate_module_home_service_multi_requirement_set(payload)


def test_unknown_serialized_field_is_rejected() -> None:
    payload = _build().to_dict()
    payload["placement"] = "node-a"
    with pytest.raises(
        ModuleHomeServiceMultiRequirementError,
        match="multi_requirement_set_rejected",
    ):
        validate_module_home_service_multi_requirement_set(payload)


def test_schema_is_closed_non_authorizing_and_accepts_runtime_output() -> None:
    schema_path = (
        Path(__file__).parents[1]
        / "contracts/modules/"
        "module-home-service-contract-multi-requirement-set.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    result = _build()
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
