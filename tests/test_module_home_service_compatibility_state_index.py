from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from home_center.module_home_service_compatibility_state_index import (
    ModuleHomeServiceCompatibilityStateIndexError,
    build_module_home_service_compatibility_state_index,
    validate_module_home_service_compatibility_state_index,
)


ROOT = Path(__file__).resolve().parents[1]


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def _state(
    module_id: str,
    *,
    home_center_version: str = "0.55.0",
    status: str = "compatible",
    identity_seed: str = "1",
) -> dict[str, object]:
    if status == "stale":
        freshness = "stale"
        effective_status = "stale"
        observed = "compatible"
        blocked: list[str] = []
        drift = ["service_set_changed"]
        fresh_binding = "mhsmcb-" + "4" * 24
    elif status == "blocked":
        freshness = "current"
        effective_status = "blocked"
        observed = "blocked"
        blocked = ["home.service"]
        drift = []
        fresh_binding = "mhsmcb-" + identity_seed * 24
    else:
        freshness = "current"
        effective_status = "compatible"
        observed = "compatible"
        blocked = []
        drift = []
        fresh_binding = "mhsmcb-" + identity_seed * 24

    source_binding = "mhsmcb-" + identity_seed * 24
    evidence = {
        "schema": "home-center.module-home-service-compatibility-state.v1",
        "home_center_version": home_center_version,
        "module_id": module_id,
        "module_version": "1.2.3",
        "source_multi_compatibility_binding_id": source_binding,
        "fresh_multi_compatibility_binding_id": fresh_binding,
        "revalidation_id": "mhsmcbr-" + identity_seed * 24,
        "freshness": freshness,
        "effective_status": effective_status,
        "observed_compatibility_status": observed,
        "service_ids": ["home.service"],
        "blocked_service_ids": blocked,
        "drift_reasons": drift,
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    resource_version = _sha(evidence)
    return {
        **evidence,
        "state_id": "mhscs-" + resource_version[:24],
        "resource_version": resource_version,
        "etag": f'"mhscs-{resource_version}"',
    }


def test_empty_index_is_explicit_not_implicitly_compatible() -> None:
    index = build_module_home_service_compatibility_state_index(
        home_center_version="0.55.0",
        states=(),
    )
    assert index.summary_status == "empty"
    assert index.module_count == 0
    assert index.compatible_count == 0
    assert index.blocked_count == 0
    assert index.stale_count == 0
    assert index.execution_authorized is False
    assert validate_module_home_service_compatibility_state_index(index) == index


def test_index_is_order_independent_and_module_sorted() -> None:
    alpha = _state("alpha.module", identity_seed="1")
    beta = _state("beta.module", identity_seed="2")
    first = build_module_home_service_compatibility_state_index(
        home_center_version="0.55.0",
        states=(beta, alpha),
    )
    second = build_module_home_service_compatibility_state_index(
        home_center_version="0.55.0",
        states=(alpha, beta),
    )
    assert first == second
    assert [state.module_id for state in first.states] == ["alpha.module", "beta.module"]
    assert first.summary_status == "compatible"
    assert first.compatible_count == 2
    assert first.index_id == "mhscsi-" + first.resource_version[:24]
    assert first.etag == f'"mhscsi-{first.resource_version}"'


def test_stale_has_fail_closed_priority_over_blocked_and_compatible() -> None:
    index = build_module_home_service_compatibility_state_index(
        home_center_version="0.55.0",
        states=(
            _state("compatible.module", identity_seed="1"),
            _state("blocked.module", status="blocked", identity_seed="2"),
            _state("stale.module", status="stale", identity_seed="3"),
        ),
    )
    assert index.summary_status == "stale"
    assert index.compatible_count == 1
    assert index.blocked_count == 1
    assert index.stale_count == 1


def test_blocked_has_priority_when_no_state_is_stale() -> None:
    index = build_module_home_service_compatibility_state_index(
        home_center_version="0.55.0",
        states=(
            _state("compatible.module", identity_seed="1"),
            _state("blocked.module", status="blocked", identity_seed="2"),
        ),
    )
    assert index.summary_status == "blocked"
    assert index.stale_count == 0


def test_duplicate_module_identity_is_rejected() -> None:
    with pytest.raises(
        ModuleHomeServiceCompatibilityStateIndexError,
        match="compatibility_state_index_duplicate_module",
    ):
        build_module_home_service_compatibility_state_index(
            home_center_version="0.55.0",
            states=(
                _state("same.module", identity_seed="1"),
                _state("same.module", identity_seed="2"),
            ),
        )


def test_mixed_home_center_versions_are_rejected() -> None:
    with pytest.raises(
        ModuleHomeServiceCompatibilityStateIndexError,
        match="compatibility_state_index_version_mismatch",
    ):
        build_module_home_service_compatibility_state_index(
            home_center_version="0.55.0",
            states=(_state("other.module", home_center_version="0.54.0"),),
        )


def test_validator_rejects_noncanonical_member_order() -> None:
    index = build_module_home_service_compatibility_state_index(
        home_center_version="0.55.0",
        states=(
            _state("alpha.module", identity_seed="1"),
            _state("beta.module", identity_seed="2"),
        ),
    ).to_dict()
    index["states"] = list(reversed(index["states"]))
    with pytest.raises(
        ModuleHomeServiceCompatibilityStateIndexError,
        match="compatibility_state_index_noncanonical_order",
    ):
        validate_module_home_service_compatibility_state_index(index)


def test_validator_rejects_summary_count_tampering() -> None:
    payload = build_module_home_service_compatibility_state_index(
        home_center_version="0.55.0",
        states=(_state("alpha.module"),),
    ).to_dict()
    payload["compatible_count"] = 0
    with pytest.raises(
        ModuleHomeServiceCompatibilityStateIndexError,
        match="compatibility_state_index_summary_rejected",
    ):
        validate_module_home_service_compatibility_state_index(payload)


def test_validator_rejects_resource_identity_tampering() -> None:
    payload = build_module_home_service_compatibility_state_index(
        home_center_version="0.55.0",
        states=(_state("alpha.module"),),
    ).to_dict()
    payload["resource_version"] = "f" * 64
    payload["etag"] = '"mhscsi-' + "f" * 64 + '"'
    with pytest.raises(
        ModuleHomeServiceCompatibilityStateIndexError,
        match="compatibility_state_index_identity_rejected",
    ):
        validate_module_home_service_compatibility_state_index(payload)


def test_validator_rejects_authority_or_unknown_field_tampering() -> None:
    original = build_module_home_service_compatibility_state_index(
        home_center_version="0.55.0",
        states=(_state("alpha.module"),),
    ).to_dict()

    authority = dict(original)
    authority["execution_authorized"] = True
    with pytest.raises(ModuleHomeServiceCompatibilityStateIndexError):
        validate_module_home_service_compatibility_state_index(authority)

    unknown = dict(original)
    unknown["unexpected"] = True
    with pytest.raises(ModuleHomeServiceCompatibilityStateIndexError):
        validate_module_home_service_compatibility_state_index(unknown)


def test_contract_is_closed_and_non_authorizing() -> None:
    schema = json.loads(
        (
            ROOT
            / "contracts/modules/module-home-service-compatibility-state-index.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    assert schema["additionalProperties"] is False
    assert schema["properties"]["summary_status"]["enum"] == [
        "empty",
        "compatible",
        "blocked",
        "stale",
    ]
    for flag in (
        "admission_authorized",
        "installation_authorized",
        "execution_authorized",
        "production_mutation_enabled",
        "external_publication_authorized",
    ):
        assert schema["properties"][flag] == {"const": False}
