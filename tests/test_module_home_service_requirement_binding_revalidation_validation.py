from __future__ import annotations

import hashlib
import json

import pytest

from home_center.module_home_service_requirement_binding_revalidation import (
    ModuleHomeServiceRequirementBindingRevalidationError,
)
from home_center.module_home_service_requirement_binding_revalidation_validation import (
    validate_module_home_service_requirement_binding_revalidation,
)


def _hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def _with_id(payload: dict[str, object]) -> dict[str, object]:
    value = dict(payload)
    value.pop("revalidation_id", None)
    value["revalidation_id"] = "mhsrbr-" + _hash(value)[:24]
    return value


def _current_payload() -> dict[str, object]:
    value: dict[str, object] = {
        "schema": (
            "home-center.module-home-service-contract-"
            "requirement-binding-revalidation.v1"
        ),
        "status": "current",
        "original_requirement_binding_id": "mhsrb-" + "1" * 24,
        "fresh_requirement_binding_id": "mhsrb-" + "1" * 24,
        "original_requirement_set_id": "mhscr-" + "2" * 24,
        "fresh_requirement_set_id": "mhscr-" + "2" * 24,
        "original_home_service_contract_binding_id": "mhscb-" + "3" * 24,
        "fresh_home_service_contract_binding_id": "mhscb-" + "3" * 24,
        "original_home_center_version": "0.44.0",
        "fresh_home_center_version": "0.44.0",
        "original_module_id": "example.module",
        "fresh_module_id": "example.module",
        "original_module_version": "1.2.3",
        "fresh_module_version": "1.2.3",
        "original_service_id": "zigbee-bridge",
        "fresh_service_id": "zigbee-bridge",
        "original_service_profile_sha256": "a" * 64,
        "fresh_service_profile_sha256": "a" * 64,
        "original_required_service_contracts": ["devices.zigbee.v1"],
        "fresh_required_service_contracts": ["devices.zigbee.v1"],
        "original_compatibility_status": "compatible",
        "fresh_compatibility_status": "compatible",
        "drift_reasons": [],
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    return _with_id(value)


def test_current_serialized_revalidation_round_trips() -> None:
    payload = _current_payload()
    validated = validate_module_home_service_requirement_binding_revalidation(
        payload
    )
    assert validated.current is True
    assert validated.to_dict() == payload


def test_stale_serialized_revalidation_requires_exact_drift_reason() -> None:
    payload = _current_payload()
    payload["status"] = "stale"
    payload["fresh_home_service_contract_binding_id"] = "mhscb-" + "4" * 24
    payload["drift_reasons"] = ["home_service_contract_binding_changed"]
    payload = _with_id(payload)

    validated = validate_module_home_service_requirement_binding_revalidation(
        payload
    )
    assert validated.current is False
    assert validated.drift_reasons == ("home_service_contract_binding_changed",)


def test_rehashed_payload_cannot_hide_semantic_drift() -> None:
    payload = _current_payload()
    payload["fresh_module_version"] = "2.0.0"
    payload = _with_id(payload)

    with pytest.raises(
        ModuleHomeServiceRequirementBindingRevalidationError,
        match="requirement_binding_revalidation_rejected",
    ):
        validate_module_home_service_requirement_binding_revalidation(payload)


def test_rehashed_payload_cannot_invent_drift_reason() -> None:
    payload = _current_payload()
    payload["status"] = "stale"
    payload["drift_reasons"] = ["module_version_changed"]
    payload = _with_id(payload)

    with pytest.raises(
        ModuleHomeServiceRequirementBindingRevalidationError,
        match="requirement_binding_revalidation_rejected",
    ):
        validate_module_home_service_requirement_binding_revalidation(payload)


def test_authority_bearing_serialized_revalidation_is_rejected() -> None:
    payload = _current_payload()
    payload["execution_authorized"] = True
    payload = _with_id(payload)

    with pytest.raises(
        ModuleHomeServiceRequirementBindingRevalidationError,
        match="requirement_binding_revalidation_rejected",
    ):
        validate_module_home_service_requirement_binding_revalidation(payload)


def test_noncanonical_drift_reason_order_is_rejected() -> None:
    payload = _current_payload()
    payload["status"] = "stale"
    payload["fresh_module_version"] = "2.0.0"
    payload["fresh_service_id"] = "zigbee-bridge-next"
    payload["drift_reasons"] = [
        "module_version_changed",
        "home_service_identity_changed",
    ]
    payload = _with_id(payload)

    with pytest.raises(
        ModuleHomeServiceRequirementBindingRevalidationError,
        match="requirement_binding_revalidation_rejected",
    ):
        validate_module_home_service_requirement_binding_revalidation(payload)
