from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from home_center import module_home_service_compatibility_state as state_module
from home_center.module_home_service_compatibility_state import (
    ModuleHomeServiceCompatibilityStateError,
    build_module_home_service_compatibility_state,
    validate_module_home_service_compatibility_state,
)


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


@dataclass(frozen=True)
class _Service:
    service_id: str
    compatibility_status: str = "compatible"

    def to_dict(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "compatibility_status": self.compatibility_status,
        }


def _binding(*, blocked: tuple[str, ...] = ()) -> SimpleNamespace:
    services = (
        _Service(
            "home.lighting",
            "blocked" if "home.lighting" in blocked else "compatible",
        ),
        _Service("home.media", "blocked" if "home.media" in blocked else "compatible"),
    )
    status = "blocked" if blocked else "compatible"
    return SimpleNamespace(
        multi_compatibility_binding_id="mhsmcb-" + "1" * 24,
        multi_requirement_set_id="mhsmr-" + "2" * 24,
        home_center_version="0.50.0",
        module_id="example.module",
        module_version="1.2.3",
        service_compatibility_bindings=services,
        blocked_service_ids=blocked,
        compatibility_status=status,
    )


def _revalidation(
    binding: SimpleNamespace,
    *,
    status: str = "current",
    fresh_compatibility: str | None = None,
    fresh_binding_id: str | None = None,
    fresh_services: tuple[str, ...] | None = None,
    fresh_blocked: tuple[str, ...] | None = None,
    drift: tuple[str, ...] | None = None,
) -> SimpleNamespace:
    original_services = tuple(
        item.service_id for item in binding.service_compatibility_bindings
    )
    original_sha = _sha(
        [item.to_dict() for item in binding.service_compatibility_bindings]
    )
    if fresh_services is None:
        fresh_services = original_services
    if fresh_blocked is None:
        fresh_blocked = binding.blocked_service_ids
    if fresh_compatibility is None:
        fresh_compatibility = binding.compatibility_status
    if fresh_binding_id is None:
        fresh_binding_id = binding.multi_compatibility_binding_id
    if drift is None:
        drift = () if status == "current" else ("service_set_changed",)
    return SimpleNamespace(
        revalidation_id="mhsmcbr-" + "3" * 24,
        status=status,
        original_multi_compatibility_binding_id=(
            binding.multi_compatibility_binding_id
        ),
        fresh_multi_compatibility_binding_id=fresh_binding_id,
        original_multi_requirement_set_id=binding.multi_requirement_set_id,
        fresh_multi_requirement_set_id=binding.multi_requirement_set_id,
        original_home_center_version=binding.home_center_version,
        fresh_home_center_version=binding.home_center_version,
        original_module_id=binding.module_id,
        fresh_module_id=binding.module_id,
        original_module_version=binding.module_version,
        fresh_module_version=binding.module_version,
        original_service_ids=original_services,
        fresh_service_ids=fresh_services,
        original_service_evidence_sha256=original_sha,
        fresh_service_evidence_sha256=original_sha,
        original_blocked_service_ids=binding.blocked_service_ids,
        fresh_blocked_service_ids=fresh_blocked,
        original_compatibility_status=binding.compatibility_status,
        fresh_compatibility_status=fresh_compatibility,
        drift_reasons=drift,
    )


def _wire_validators(
    monkeypatch: pytest.MonkeyPatch,
    binding: SimpleNamespace,
    revalidation: SimpleNamespace,
) -> None:
    monkeypatch.setattr(
        state_module,
        "validate_module_home_service_multi_compatibility_binding",
        lambda value: binding,
    )
    monkeypatch.setattr(
        state_module,
        "validate_module_home_service_multi_compatibility_revalidation",
        lambda value: revalidation,
    )


def test_current_compatible_state_is_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    _wire_validators(monkeypatch, binding, revalidation)

    first = build_module_home_service_compatibility_state({}, {})
    second = build_module_home_service_compatibility_state({}, {})

    assert first == second
    assert first.freshness == "current"
    assert first.effective_status == "compatible"
    assert first.observed_compatibility_status == "compatible"
    assert first.state_id == "mhscs-" + first.resource_version[:24]
    assert first.etag == f'"mhscs-{first.resource_version}"'
    assert validate_module_home_service_compatibility_state(first) == first


def test_current_blocked_state_preserves_blocked_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding(blocked=("home.lighting",))
    revalidation = _revalidation(binding)
    _wire_validators(monkeypatch, binding, revalidation)

    value = build_module_home_service_compatibility_state({}, {})

    assert value.effective_status == "blocked"
    assert value.blocked_service_ids == ("home.lighting",)


def test_stale_state_fails_closed_even_if_fresh_observation_is_compatible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding(blocked=("home.lighting",))
    revalidation = _revalidation(
        binding,
        status="stale",
        fresh_compatibility="compatible",
        fresh_binding_id="mhsmcb-" + "4" * 24,
        fresh_blocked=(),
    )
    _wire_validators(monkeypatch, binding, revalidation)

    value = build_module_home_service_compatibility_state({}, {})

    assert value.freshness == "stale"
    assert value.effective_status == "stale"
    assert value.observed_compatibility_status == "compatible"


def test_builder_rejects_original_binding_context_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    revalidation.original_module_id = "other.module"
    _wire_validators(monkeypatch, binding, revalidation)

    with pytest.raises(
        ModuleHomeServiceCompatibilityStateError,
        match="compatibility_state_context_mismatch",
    ):
        build_module_home_service_compatibility_state({}, {})


def test_builder_rejects_service_evidence_context_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    revalidation.original_service_evidence_sha256 = "f" * 64
    _wire_validators(monkeypatch, binding, revalidation)

    with pytest.raises(
        ModuleHomeServiceCompatibilityStateError,
        match="compatibility_state_context_mismatch",
    ):
        build_module_home_service_compatibility_state({}, {})


def test_validator_rejects_resource_identity_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    _wire_validators(monkeypatch, binding, revalidation)
    payload = build_module_home_service_compatibility_state({}, {}).to_dict()
    payload["resource_version"] = "f" * 64

    with pytest.raises(ModuleHomeServiceCompatibilityStateError):
        validate_module_home_service_compatibility_state(payload)


def test_validator_rejects_etag_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    _wire_validators(monkeypatch, binding, revalidation)
    payload = build_module_home_service_compatibility_state({}, {}).to_dict()
    payload["etag"] = '"other"'

    with pytest.raises(ModuleHomeServiceCompatibilityStateError):
        validate_module_home_service_compatibility_state(payload)


def test_validator_rejects_authority_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    _wire_validators(monkeypatch, binding, revalidation)
    payload = build_module_home_service_compatibility_state({}, {}).to_dict()
    payload["execution_authorized"] = True

    with pytest.raises(ModuleHomeServiceCompatibilityStateError):
        validate_module_home_service_compatibility_state(payload)


def test_validator_rejects_unknown_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    _wire_validators(monkeypatch, binding, revalidation)
    payload = build_module_home_service_compatibility_state({}, {}).to_dict()
    payload["unexpected"] = "field"

    with pytest.raises(ModuleHomeServiceCompatibilityStateError):
        validate_module_home_service_compatibility_state(payload)


def test_validator_rejects_noncanonical_service_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    _wire_validators(monkeypatch, binding, revalidation)
    payload = build_module_home_service_compatibility_state({}, {}).to_dict()
    payload["service_ids"] = list(reversed(payload["service_ids"]))

    with pytest.raises(ModuleHomeServiceCompatibilityStateError):
        validate_module_home_service_compatibility_state(payload)


def test_validator_rejects_current_state_with_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    _wire_validators(monkeypatch, binding, revalidation)
    payload = build_module_home_service_compatibility_state({}, {}).to_dict()
    payload["drift_reasons"] = ["service_set_changed"]

    evidence = copy.deepcopy(payload)
    for field in ("state_id", "resource_version", "etag"):
        evidence.pop(field)
    resource_version = _sha(evidence)
    payload["resource_version"] = resource_version
    payload["state_id"] = "mhscs-" + resource_version[:24]
    payload["etag"] = f'"mhscs-{resource_version}"'

    with pytest.raises(ModuleHomeServiceCompatibilityStateError):
        validate_module_home_service_compatibility_state(payload)



def test_validator_rejects_observed_status_blocked_set_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    _wire_validators(monkeypatch, binding, revalidation)
    payload = build_module_home_service_compatibility_state({}, {}).to_dict()
    payload["observed_compatibility_status"] = "blocked"
    payload["effective_status"] = "blocked"

    evidence = copy.deepcopy(payload)
    for field in ("state_id", "resource_version", "etag"):
        evidence.pop(field)
    resource_version = _sha(evidence)
    payload["resource_version"] = resource_version
    payload["state_id"] = "mhscs-" + resource_version[:24]
    payload["etag"] = f'"mhscs-{resource_version}"'

    with pytest.raises(ModuleHomeServiceCompatibilityStateError):
        validate_module_home_service_compatibility_state(payload)


def test_validator_rejects_unknown_drift_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    revalidation = _revalidation(binding)
    revalidation.status = "stale"
    revalidation.drift_reasons = ("service_set_changed",)
    _wire_validators(monkeypatch, binding, revalidation)
    payload = build_module_home_service_compatibility_state({}, {}).to_dict()
    payload["drift_reasons"] = ["unknown_future_reason"]

    evidence = copy.deepcopy(payload)
    for field in ("state_id", "resource_version", "etag"):
        evidence.pop(field)
    resource_version = _sha(evidence)
    payload["resource_version"] = resource_version
    payload["state_id"] = "mhscs-" + resource_version[:24]
    payload["etag"] = f'"mhscs-{resource_version}"'

    with pytest.raises(ModuleHomeServiceCompatibilityStateError):
        validate_module_home_service_compatibility_state(payload)

def test_schema_is_closed_and_non_authorizing() -> None:
    schema_path = (
        Path(__file__).parents[1]
        / "contracts/modules"
        / "module-home-service-compatibility-state.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["additionalProperties"] is False
    for flag in state_module.AUTHORITY_FLAGS:
        assert schema["properties"][flag] == {"const": False}
