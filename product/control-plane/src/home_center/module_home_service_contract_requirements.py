"""Canonical exact identity for module Home Service contract requirements."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


REQUIREMENT_SET_SCHEMA = (
    "home-center.module-home-service-contract-requirement-set.v1"
)
ID24 = re.compile(r"^[0-9a-f]{24}$")
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
REQUIREMENT_SET_FIELDS = frozenset(
    {
        "schema",
        "requirement_set_id",
        "home_center_version",
        "module_id",
        "module_version",
        "service_id",
        "required_service_contracts",
        *AUTHORITY_FLAGS,
    }
)


class ModuleHomeServiceContractRequirementError(ValueError):
    """Stable rejection code for invalid requirement-set evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceContractRequirementSet:
    """Evidence-only exact identity for one module's service requirements."""

    requirement_set_id: str
    home_center_version: str
    module_id: str
    module_version: str
    service_id: str
    required_service_contracts: tuple[str, ...]
    schema: str = REQUIREMENT_SET_SCHEMA
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "requirement_set_id": self.requirement_set_id,
            "home_center_version": self.home_center_version,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "service_id": self.service_id,
            "required_service_contracts": list(
                self.required_service_contracts
            ),
            "admission_authorized": self.admission_authorized,
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": (
                self.external_publication_authorized
            ),
        }


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
        raise ModuleHomeServiceContractRequirementError(
            "requirement_set_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _semver(value: object) -> str:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        raise ModuleHomeServiceContractRequirementError(
            "requirement_set_rejected"
        )
    return value


def _module_id(value: object) -> str:
    if not isinstance(value, str) or MODULE_ID.fullmatch(value) is None:
        raise ModuleHomeServiceContractRequirementError(
            "requirement_set_rejected"
        )
    return value


def _service_id(value: object) -> str:
    if not isinstance(value, str) or SERVICE_ID.fullmatch(value) is None:
        raise ModuleHomeServiceContractRequirementError(
            "requirement_set_rejected"
        )
    return value


def _required_contracts(value: Iterable[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise ModuleHomeServiceContractRequirementError(
            "required_service_contracts_rejected"
        )
    try:
        raw = tuple(value)
    except (TypeError, ValueError, RuntimeError, RecursionError) as exc:
        raise ModuleHomeServiceContractRequirementError(
            "required_service_contracts_rejected"
        ) from exc
    if (
        not 1 <= len(raw) <= 64
        or any(
            not isinstance(item, str)
            or SERVICE_CONTRACT.fullmatch(item) is None
            for item in raw
        )
    ):
        raise ModuleHomeServiceContractRequirementError(
            "required_service_contracts_rejected"
        )
    if len(raw) != len(set(raw)):
        raise ModuleHomeServiceContractRequirementError(
            "required_service_contracts_rejected"
        )
    return tuple(sorted(raw))


def build_module_home_service_contract_requirement_set(
    *,
    home_center_version: str,
    module_id: str,
    module_version: str,
    service_id: str,
    required_service_contracts: Iterable[str],
) -> ModuleHomeServiceContractRequirementSet:
    """Build deterministic, non-authorizing service requirement evidence."""

    version = _semver(home_center_version)
    canonical_module_id = _module_id(module_id)
    canonical_module_version = _semver(module_version)
    canonical_service_id = _service_id(service_id)
    contracts = _required_contracts(required_service_contracts)
    evidence = {
        "schema": REQUIREMENT_SET_SCHEMA,
        "home_center_version": version,
        "module_id": canonical_module_id,
        "module_version": canonical_module_version,
        "service_id": canonical_service_id,
        "required_service_contracts": list(contracts),
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    requirement_set_id = "mhscr-" + _canonical_sha256(evidence)[:24]
    return ModuleHomeServiceContractRequirementSet(
        requirement_set_id=requirement_set_id,
        home_center_version=version,
        module_id=canonical_module_id,
        module_version=canonical_module_version,
        service_id=canonical_service_id,
        required_service_contracts=contracts,
    )


def validate_module_home_service_contract_requirement_set(
    value: object,
) -> ModuleHomeServiceContractRequirementSet:
    """Validate serialized requirement evidence and its canonical identity."""

    if isinstance(value, Mapping):
        payload: dict[str, Any] = dict(value)
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise ModuleHomeServiceContractRequirementError(
                "requirement_set_rejected"
            )
        try:
            raw = to_dict()
        except (TypeError, ValueError) as exc:
            raise ModuleHomeServiceContractRequirementError(
                "requirement_set_rejected"
            ) from exc
        if not isinstance(raw, dict):
            raise ModuleHomeServiceContractRequirementError(
                "requirement_set_rejected"
            )
        payload = raw

    if (
        set(payload) != REQUIREMENT_SET_FIELDS
        or payload.get("schema") != REQUIREMENT_SET_SCHEMA
        or any(payload.get(flag) is not False for flag in AUTHORITY_FLAGS)
    ):
        raise ModuleHomeServiceContractRequirementError(
            "requirement_set_rejected"
        )

    requirement_set_id = payload.get("requirement_set_id")
    if (
        not isinstance(requirement_set_id, str)
        or not requirement_set_id.startswith("mhscr-")
        or ID24.fullmatch(requirement_set_id[6:]) is None
    ):
        raise ModuleHomeServiceContractRequirementError(
            "requirement_set_rejected"
        )

    result = build_module_home_service_contract_requirement_set(
        home_center_version=_semver(payload.get("home_center_version")),
        module_id=_module_id(payload.get("module_id")),
        module_version=_semver(payload.get("module_version")),
        service_id=_service_id(payload.get("service_id")),
        required_service_contracts=_required_contracts(
            payload.get("required_service_contracts", ())
        ),
    )
    if list(result.required_service_contracts) != payload.get(
        "required_service_contracts"
    ):
        raise ModuleHomeServiceContractRequirementError(
            "requirement_set_rejected"
        )
    if result.requirement_set_id != requirement_set_id:
        raise ModuleHomeServiceContractRequirementError(
            "requirement_set_rejected"
        )
    return result
