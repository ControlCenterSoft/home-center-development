from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from home_center import module_home_service_compatibility_index as index_module
from home_center.module_home_service_compatibility_index import (
    ModuleHomeServiceCompatibilityIndexError,
    build_module_home_service_compatibility_index,
    validate_module_home_service_compatibility_index,
)


def _state(
    module_id: str,
    *,
    home_center_version: str = "0.55.0",
    module_version: str = "1.0.0",
    freshness: str = "current",
    blocked: tuple[str, ...] = (),
    marker: str = "a",
) -> SimpleNamespace:
    resource_version = marker * 64
    observed = "blocked" if blocked else "compatible"
    effective = observed if freshness == "current" else "stale"
    return SimpleNamespace(
        state_id="mhscs-" + resource_version[:24],
        resource_version=resource_version,
        etag=f'"mhscs-{resource_version}"',
        home_center_version=home_center_version,
        module_id=module_id,
        module_version=module_version,
        freshness=freshness,
        effective_status=effective,
        observed_compatibility_status=observed,
        service_ids=("home.lighting", "home.media"),
        blocked_service_ids=blocked,
    )


def _wire_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        index_module,
        "validate_module_home_service_compatibility_state",
        lambda value: value,
    )


def _build(
    monkeypatch: pytest.MonkeyPatch,
    states: list[SimpleNamespace],
):
    _wire_validator(monkeypatch)
    return build_module_home_service_compatibility_index(
        states,
        home_center_version="0.55.0",
    )


def test_empty_index_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    first = _build(monkeypatch, [])
    second = _build(monkeypatch, [])

    assert first == second
    assert first.module_count == 0
    assert first.overall_status == "compatible"
    assert first.index_id == "mhsci-" + first.resource_version[:24]
    assert first.etag == f'"mhsci-{first.resource_version}"'
    assert validate_module_home_service_compatibility_index(first) == first


def test_builder_canonicalizes_module_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = _build(
        monkeypatch,
        [
            _state("zeta.module", marker="b"),
            _state("alpha.module", marker="a"),
        ],
    )

    assert [item.module_id for item in value.items] == [
        "alpha.module",
        "zeta.module",
    ]


def test_stale_state_dominates_overall_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = _build(
        monkeypatch,
        [
            _state(
                "alpha.module",
                freshness="stale",
                marker="a",
            ),
            _state(
                "beta.module",
                blocked=("home.media",),
                marker="b",
            ),
        ],
    )

    assert value.overall_status == "stale"


def test_blocked_state_sets_blocked_overall_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = _build(
        monkeypatch,
        [
            _state("alpha.module", marker="a"),
            _state(
                "beta.module",
                blocked=("home.media",),
                marker="b",
            ),
        ],
    )

    assert value.overall_status == "blocked"


def test_builder_rejects_duplicate_module_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        ModuleHomeServiceCompatibilityIndexError,
        match="duplicate_module_compatibility_state",
    ):
        _build(
            monkeypatch,
            [
                _state("alpha.module", marker="a"),
                _state("alpha.module", marker="b"),
            ],
        )


def test_builder_rejects_mixed_home_center_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        ModuleHomeServiceCompatibilityIndexError,
        match="compatibility_index_context_mismatch",
    ):
        _build(
            monkeypatch,
            [
                _state(
                    "alpha.module",
                    home_center_version="0.54.0",
                )
            ],
        )


def test_serialized_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    value = _build(
        monkeypatch,
        [
            _state("alpha.module", marker="a"),
            _state("beta.module", marker="b"),
        ],
    )

    checked = validate_module_home_service_compatibility_index(
        value.to_dict()
    )

    assert checked == value


def test_validator_rejects_resource_version_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _build(
        monkeypatch,
        [_state("alpha.module")],
    ).to_dict()
    payload["resource_version"] = "f" * 64

    with pytest.raises(ModuleHomeServiceCompatibilityIndexError):
        validate_module_home_service_compatibility_index(payload)


def test_validator_rejects_etag_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _build(
        monkeypatch,
        [_state("alpha.module")],
    ).to_dict()
    payload["etag"] = '"other"'

    with pytest.raises(ModuleHomeServiceCompatibilityIndexError):
        validate_module_home_service_compatibility_index(payload)


def test_validator_rejects_noncanonical_module_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _build(
        monkeypatch,
        [
            _state("alpha.module", marker="a"),
            _state("beta.module", marker="b"),
        ],
    ).to_dict()
    payload["items"] = list(reversed(payload["items"]))

    with pytest.raises(ModuleHomeServiceCompatibilityIndexError):
        validate_module_home_service_compatibility_index(payload)


def test_validator_rejects_item_status_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _build(
        monkeypatch,
        [_state("alpha.module")],
    ).to_dict()
    payload["items"][0]["observed_compatibility_status"] = "blocked"

    with pytest.raises(ModuleHomeServiceCompatibilityIndexError):
        validate_module_home_service_compatibility_index(payload)


def test_validator_rejects_empty_service_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _build(
        monkeypatch,
        [_state("alpha.module")],
    ).to_dict()
    payload["items"][0]["service_ids"] = []

    with pytest.raises(ModuleHomeServiceCompatibilityIndexError):
        validate_module_home_service_compatibility_index(payload)


def test_validator_rejects_authority_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _build(
        monkeypatch,
        [_state("alpha.module")],
    ).to_dict()
    payload["execution_authorized"] = True

    with pytest.raises(ModuleHomeServiceCompatibilityIndexError):
        validate_module_home_service_compatibility_index(payload)


def test_validator_rejects_unknown_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _build(
        monkeypatch,
        [_state("alpha.module")],
    ).to_dict()
    payload["unexpected"] = "field"

    with pytest.raises(ModuleHomeServiceCompatibilityIndexError):
        validate_module_home_service_compatibility_index(payload)


def test_schema_is_closed_and_non_authorizing() -> None:
    schema_path = (
        Path(__file__).parents[1]
        / "contracts/modules"
        / "module-home-service-compatibility-index.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["additionalProperties"] is False
    assert schema["$defs"]["item"]["additionalProperties"] is False
    for flag in index_module.AUTHORITY_FLAGS:
        assert schema["properties"][flag] == {"const": False}
