from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.module_home_service_contract_requirements import (
    ModuleHomeServiceContractRequirementError,
    build_module_home_service_contract_requirement_set,
    validate_module_home_service_contract_requirement_set,
)


def _build(**overrides: object):
    values: dict[str, object] = {
        "home_center_version": "0.42.0",
        "module_id": "example.module",
        "module_version": "1.2.3",
        "service_id": "zigbee-bridge",
        "required_service_contracts": (
            "devices.zigbee.v1",
            "smart-home.bridge.v1",
        ),
    }
    values.update(overrides)
    return build_module_home_service_contract_requirement_set(**values)


def test_requirement_set_is_deterministic_and_canonical() -> None:
    first = _build(
        required_service_contracts=(
            "smart-home.bridge.v1",
            "devices.zigbee.v1",
        )
    )
    second = _build()
    assert first == second
    assert first.required_service_contracts == (
        "devices.zigbee.v1",
        "smart-home.bridge.v1",
    )
    assert first.requirement_set_id.startswith("mhscr-")


def test_contract_change_changes_exact_identity() -> None:
    first = _build()
    second = _build(required_service_contracts=("devices.zigbee.v2",))
    assert first.requirement_set_id != second.requirement_set_id


def test_context_identity_is_exact() -> None:
    original = _build()
    assert original.requirement_set_id != _build(
        home_center_version="0.42.1"
    ).requirement_set_id
    assert original.requirement_set_id != _build(
        module_version="1.2.4"
    ).requirement_set_id
    assert original.requirement_set_id != _build(
        service_id="zigbee-bridge-next"
    ).requirement_set_id


@pytest.mark.parametrize(
    "requirements",
    [
        (),
        ("devices.zigbee.v1", "devices.zigbee.v1"),
        ("bad-contract",),
    ],
)
def test_invalid_contract_sets_are_rejected(
    requirements: tuple[str, ...],
) -> None:
    with pytest.raises(
        ModuleHomeServiceContractRequirementError,
        match="required_service_contracts_rejected",
    ):
        _build(required_service_contracts=requirements)


def test_serialized_evidence_round_trips() -> None:
    original = _build()
    validated = validate_module_home_service_contract_requirement_set(
        original.to_dict()
    )
    assert validated == original


def test_noncanonical_serialized_order_is_rejected() -> None:
    payload = _build().to_dict()
    payload["required_service_contracts"] = list(
        reversed(payload["required_service_contracts"])
    )
    with pytest.raises(
        ModuleHomeServiceContractRequirementError,
        match="requirement_set_rejected",
    ):
        validate_module_home_service_contract_requirement_set(payload)


def test_tampered_exact_identity_is_rejected() -> None:
    payload = _build().to_dict()
    payload["module_version"] = "9.9.9"
    with pytest.raises(
        ModuleHomeServiceContractRequirementError,
        match="requirement_set_rejected",
    ):
        validate_module_home_service_contract_requirement_set(payload)


def test_authority_tampering_is_rejected() -> None:
    payload = _build().to_dict()
    payload["execution_authorized"] = True
    with pytest.raises(
        ModuleHomeServiceContractRequirementError,
        match="requirement_set_rejected",
    ):
        validate_module_home_service_contract_requirement_set(payload)


def test_schema_is_closed_non_authorizing_and_accepts_runtime_output() -> None:
    schema_path = (
        Path(__file__).parents[1]
        / "contracts/modules/"
        "module-home-service-contract-requirement-set.v1.schema.json"
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
