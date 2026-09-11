"""Aggregate module compatibility across multiple Home Services."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .module_home_service_contract_requirements import (
    ModuleHomeServiceContractRequirementError,
    build_module_home_service_contract_requirement_set,
)
from .module_home_service_multi_requirements import (
    ModuleHomeServiceMultiRequirementError,
    validate_module_home_service_multi_requirement_set,
)
from .module_home_service_requirement_binding import (
    ModuleHomeServiceRequirementBindingError,
    bind_module_home_service_requirement_set,
)


MULTI_COMPATIBILITY_SCHEMA = (
    "home-center.module-home-service-contract-multi-compatibility-binding.v1"
)
ID24 = re.compile(r"^[0-9a-f]{24}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
MODULE_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$"
)
SERVICE_ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
SERVICE_CONTRACT = re.compile(
    r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$"
)
AUTHORITY_FLAGS = (
    "admission_authorized",
    "installation_authorized",
    "execution_authorized",
    "production_mutation_enabled",
    "external_publication_authorized",
)
MULTI_COMPATIBILITY_FIELDS = frozenset(
    {
        "schema",
        "multi_compatibility_binding_id",
        "multi_requirement_set_id",
        "home_center_version",
        "module_id",
        "module_version",
        "service_compatibility_bindings",
        "blocked_service_ids",
        "compatibility_status",
        *AUTHORITY_FLAGS,
    }
)
SERVICE_COMPATIBILITY_FIELDS = frozenset(
    {
        "service_id",
        "requirement_set_id",
        "requirement_binding_id",
        "home_service_contract_binding_id",
        "service_profile_sha256",
        "required_service_contracts",
        "compatibility_status",
    }
)


class ModuleHomeServiceMultiCompatibilityError(ValueError):
    """Stable rejection code for aggregate compatibility failures."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class HomeServiceCompatibilityReference:
    """Canonical compatibility projection for one required Home Service."""

    service_id: str
    requirement_set_id: str
    requirement_binding_id: str
    home_service_contract_binding_id: str
    service_profile_sha256: str
    required_service_contracts: tuple[str, ...]
    compatibility_status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "requirement_set_id": self.requirement_set_id,
            "requirement_binding_id": self.requirement_binding_id,
            "home_service_contract_binding_id": (
                self.home_service_contract_binding_id
            ),
            "service_profile_sha256": self.service_profile_sha256,
            "required_service_contracts": list(
                self.required_service_contracts
            ),
            "compatibility_status": self.compatibility_status,
        }


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceMultiCompatibilityBinding:
    """Evidence-only aggregate compatibility for all service dependencies."""

    multi_compatibility_binding_id: str
    multi_requirement_set_id: str
    home_center_version: str
    module_id: str
    module_version: str
    service_compatibility_bindings: tuple[
        HomeServiceCompatibilityReference, ...
    ]
    blocked_service_ids: tuple[str, ...]
    compatibility_status: str
    schema: str = MULTI_COMPATIBILITY_SCHEMA
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "multi_compatibility_binding_id": (
                self.multi_compatibility_binding_id
            ),
            "multi_requirement_set_id": self.multi_requirement_set_id,
            "home_center_version": self.home_center_version,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "service_compatibility_bindings": [
                item.to_dict()
                for item in self.service_compatibility_bindings
            ],
            "blocked_service_ids": list(self.blocked_service_ids),
            "compatibility_status": self.compatibility_status,
            "admission_authorized": self.admission_authorized,
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": (
                self.external_publication_authorized
            ),
        }


def _reject(code: str = "multi_compatibility_binding_rejected") -> None:
    raise ModuleHomeServiceMultiCompatibilityError(code)


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (
        TypeError,
        ValueError,
        UnicodeEncodeError,
        RecursionError,
    ) as exc:
        raise ModuleHomeServiceMultiCompatibilityError(
            "multi_compatibility_binding_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: object, code: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        raw = dict(value)
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise ModuleHomeServiceMultiCompatibilityError(code)
        try:
            raw = to_dict()
        except (TypeError, ValueError) as exc:
            raise ModuleHomeServiceMultiCompatibilityError(code) from exc
    if not isinstance(raw, dict):
        raise ModuleHomeServiceMultiCompatibilityError(code)
    return raw


def _identifier(value: object, prefix: str, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or ID24.fullmatch(value[len(prefix) :]) is None
    ):
        raise ModuleHomeServiceMultiCompatibilityError(code)
    return value


def _semver(value: object) -> str:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        _reject()
    return value


def _module_id(value: object) -> str:
    if not isinstance(value, str) or MODULE_ID.fullmatch(value) is None:
        _reject()
    return value


def _service_id(value: object) -> str:
    if not isinstance(value, str) or SERVICE_ID.fullmatch(value) is None:
        _reject()
    return value


def _required_contracts(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        _reject()
    contracts = tuple(value)
    if (
        not 1 <= len(contracts) <= 64
        or len(contracts) != len(set(contracts))
        or any(
            not isinstance(item, str)
            or SERVICE_CONTRACT.fullmatch(item) is None
            for item in contracts
        )
        or list(sorted(contracts)) != value
    ):
        _reject()
    return contracts


def _profile_set(
    values: Iterable[object],
) -> dict[str, dict[str, Any]]:
    if isinstance(values, (str, bytes, Mapping)):
        _reject("service_profiles_rejected")
    try:
        raw = tuple(values)
    except TypeError as exc:
        raise ModuleHomeServiceMultiCompatibilityError(
            "service_profiles_rejected"
        ) from exc
    if not 1 <= len(raw) <= 64:
        _reject("service_profiles_rejected")

    profiles: dict[str, dict[str, Any]] = {}
    for value in raw:
        payload = _mapping(value, "service_profile_rejected")
        service_id = payload.get("service_id")
        if (
            not isinstance(service_id, str)
            or SERVICE_ID.fullmatch(service_id) is None
        ):
            _reject("service_profile_rejected")
        if service_id in profiles:
            _reject("duplicate_service_profile")
        profiles[service_id] = payload
    return profiles


def bind_module_home_service_multi_compatibility(
    multi_requirement_set: object,
    module_binding: object,
    service_profiles: Iterable[object],
) -> ModuleHomeServiceMultiCompatibilityBinding:
    """Bind every service requirement to exact compatibility evidence."""

    try:
        requirements = validate_module_home_service_multi_requirement_set(
            multi_requirement_set
        )
    except (
        ModuleHomeServiceMultiRequirementError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceMultiCompatibilityError(
            "multi_requirement_set_rejected"
        ) from exc

    profiles = _profile_set(service_profiles)
    required_service_ids = tuple(
        item.service_id for item in requirements.service_requirement_sets
    )
    if set(profiles) != set(required_service_ids):
        _reject("service_profile_set_mismatch")

    bindings: list[HomeServiceCompatibilityReference] = []
    for reference in requirements.service_requirement_sets:
        try:
            requirement_set = (
                build_module_home_service_contract_requirement_set(
                    home_center_version=requirements.home_center_version,
                    module_id=requirements.module_id,
                    module_version=requirements.module_version,
                    service_id=reference.service_id,
                    required_service_contracts=(
                        reference.required_service_contracts
                    ),
                )
            )
        except (
            ModuleHomeServiceContractRequirementError,
            TypeError,
            ValueError,
        ) as exc:
            raise ModuleHomeServiceMultiCompatibilityError(
                "service_requirement_set_rejected"
            ) from exc

        if requirement_set.requirement_set_id != reference.requirement_set_id:
            _reject("service_requirement_set_rejected")

        try:
            binding = bind_module_home_service_requirement_set(
                requirement_set,
                module_binding,
                profiles[reference.service_id],
            )
        except (
            ModuleHomeServiceRequirementBindingError,
            TypeError,
            ValueError,
        ) as exc:
            raise ModuleHomeServiceMultiCompatibilityError(
                "service_compatibility_rejected"
            ) from exc

        context = (
            (binding.requirement_set_id, reference.requirement_set_id),
            (binding.home_center_version, requirements.home_center_version),
            (binding.module_id, requirements.module_id),
            (binding.module_version, requirements.module_version),
            (binding.service_id, reference.service_id),
            (
                binding.required_service_contracts,
                reference.required_service_contracts,
            ),
        )
        if any(actual != expected for actual, expected in context):
            _reject("service_compatibility_rejected")

        bindings.append(
            HomeServiceCompatibilityReference(
                service_id=binding.service_id,
                requirement_set_id=binding.requirement_set_id,
                requirement_binding_id=binding.requirement_binding_id,
                home_service_contract_binding_id=(
                    binding.home_service_contract_binding_id
                ),
                service_profile_sha256=binding.service_profile_sha256,
                required_service_contracts=(
                    binding.required_service_contracts
                ),
                compatibility_status=binding.compatibility_status,
            )
        )

    canonical_bindings = tuple(
        sorted(bindings, key=lambda item: item.service_id)
    )
    blocked_service_ids = tuple(
        item.service_id
        for item in canonical_bindings
        if item.compatibility_status != "compatible"
    )
    compatibility_status = (
        "compatible" if not blocked_service_ids else "blocked"
    )
    evidence = {
        "schema": MULTI_COMPATIBILITY_SCHEMA,
        "multi_requirement_set_id": requirements.multi_requirement_set_id,
        "home_center_version": requirements.home_center_version,
        "module_id": requirements.module_id,
        "module_version": requirements.module_version,
        "service_compatibility_bindings": [
            item.to_dict() for item in canonical_bindings
        ],
        "blocked_service_ids": list(blocked_service_ids),
        "compatibility_status": compatibility_status,
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    aggregate_id = "mhsmcb-" + _canonical_sha256(evidence)[:24]
    return ModuleHomeServiceMultiCompatibilityBinding(
        multi_compatibility_binding_id=aggregate_id,
        multi_requirement_set_id=requirements.multi_requirement_set_id,
        home_center_version=requirements.home_center_version,
        module_id=requirements.module_id,
        module_version=requirements.module_version,
        service_compatibility_bindings=canonical_bindings,
        blocked_service_ids=blocked_service_ids,
        compatibility_status=compatibility_status,
    )


def _serialized_service_bindings(
    value: object,
) -> tuple[HomeServiceCompatibilityReference, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        _reject()
    result: list[HomeServiceCompatibilityReference] = []
    for raw in value:
        if not isinstance(raw, Mapping):
            _reject()
        payload = dict(raw)
        if set(payload) != SERVICE_COMPATIBILITY_FIELDS:
            _reject()
        service_id = _service_id(payload.get("service_id"))
        requirement_set_id = _identifier(
            payload.get("requirement_set_id"),
            "mhscr-",
            "multi_compatibility_binding_rejected",
        )
        requirement_binding_id = _identifier(
            payload.get("requirement_binding_id"),
            "mhsrb-",
            "multi_compatibility_binding_rejected",
        )
        home_service_binding_id = _identifier(
            payload.get("home_service_contract_binding_id"),
            "mhscb-",
            "multi_compatibility_binding_rejected",
        )
        profile_sha = payload.get("service_profile_sha256")
        if (
            not isinstance(profile_sha, str)
            or DIGEST.fullmatch(profile_sha) is None
        ):
            _reject()
        required = _required_contracts(
            payload.get("required_service_contracts")
        )
        status = payload.get("compatibility_status")
        if status not in {"compatible", "blocked"}:
            _reject()
        result.append(
            HomeServiceCompatibilityReference(
                service_id=service_id,
                requirement_set_id=requirement_set_id,
                requirement_binding_id=requirement_binding_id,
                home_service_contract_binding_id=home_service_binding_id,
                service_profile_sha256=profile_sha,
                required_service_contracts=required,
                compatibility_status=status,
            )
        )
    service_ids = [item.service_id for item in result]
    if (
        len(service_ids) != len(set(service_ids))
        or service_ids != sorted(service_ids)
    ):
        _reject()
    return tuple(result)


def validate_module_home_service_multi_compatibility_binding(
    value: object,
) -> ModuleHomeServiceMultiCompatibilityBinding:
    """Validate closed serialized aggregate evidence and canonical identity."""

    payload = _mapping(value, "multi_compatibility_binding_rejected")
    if (
        set(payload) != MULTI_COMPATIBILITY_FIELDS
        or payload.get("schema") != MULTI_COMPATIBILITY_SCHEMA
        or any(payload.get(flag) is not False for flag in AUTHORITY_FLAGS)
    ):
        _reject()

    aggregate_id = _identifier(
        payload.get("multi_compatibility_binding_id"),
        "mhsmcb-",
        "multi_compatibility_binding_rejected",
    )
    multi_requirement_set_id = _identifier(
        payload.get("multi_requirement_set_id"),
        "mhsmr-",
        "multi_compatibility_binding_rejected",
    )
    version = _semver(payload.get("home_center_version"))
    module_id = _module_id(payload.get("module_id"))
    module_version = _semver(payload.get("module_version"))
    bindings = _serialized_service_bindings(
        payload.get("service_compatibility_bindings")
    )
    blocked_service_ids = payload.get("blocked_service_ids")
    if not isinstance(blocked_service_ids, list):
        _reject()
    expected_blocked = [
        item.service_id
        for item in bindings
        if item.compatibility_status != "compatible"
    ]
    if blocked_service_ids != expected_blocked:
        _reject()

    compatibility_status = payload.get("compatibility_status")
    expected_status = "compatible" if not expected_blocked else "blocked"
    if compatibility_status != expected_status:
        _reject()

    evidence = dict(payload)
    evidence.pop("multi_compatibility_binding_id")
    expected_id = "mhsmcb-" + _canonical_sha256(evidence)[:24]
    if aggregate_id != expected_id:
        _reject()

    result = ModuleHomeServiceMultiCompatibilityBinding(
        multi_compatibility_binding_id=aggregate_id,
        multi_requirement_set_id=multi_requirement_set_id,
        home_center_version=version,
        module_id=module_id,
        module_version=module_version,
        service_compatibility_bindings=bindings,
        blocked_service_ids=tuple(blocked_service_ids),
        compatibility_status=compatibility_status,
    )
    if result.to_dict() != payload:
        _reject()
    return result
