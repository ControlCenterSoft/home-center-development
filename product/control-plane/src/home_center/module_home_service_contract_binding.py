"""Bind exact module admission evidence to Home Service interface contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from itertools import islice
from typing import Any, Iterable, Mapping


BINDING_SCHEMA = "home-center.module-home-service-contract-binding.v1"
MODULE_BINDING_SCHEMA = "home-center.module-contract-admission-binding.v1"
SERVICE_PROFILE_SCHEMA = "home-center.home-service-catalog.v1"
MAX_REQUIRED_SERVICE_CONTRACTS = 64

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

MODULE_BINDING_FIELDS = frozenset(
    {
        "schema",
        "binding_id",
        "profile_id",
        "negotiation_decision_id",
        "admission_decision_id",
        "home_center_version",
        "module_manifest_schema",
        "module_admission_schema",
        "module_id",
        "module_version",
        "manifest_binding_sha256",
        "artifact_sha256",
        "admission_status",
        "admission_authorized",
        "installation_authorized",
        "execution_authorized",
        "production_mutation_enabled",
        "external_publication_authorized",
    }
)
SERVICE_PROFILE_FIELDS = frozenset(
    {
        "service_id",
        "kind",
        "name",
        "required_capabilities",
        "provided_capabilities",
        "minimum_storage_gib",
        "publication_policy",
        "backup_policy",
        "lifecycle",
    }
)
AUTHORITY_FLAGS = (
    "admission_authorized",
    "installation_authorized",
    "execution_authorized",
    "production_mutation_enabled",
    "external_publication_authorized",
)
SERVICE_KINDS = frozenset(
    {
        "yandex-smart-home",
        "torrserver",
        "torrent-client",
        "zigbee-bridge",
        "minecraft-server",
        "android-mdm",
    }
)
PUBLICATION_POLICIES = frozenset({"local-only", "explicit"})
BACKUP_POLICIES = frozenset({"none", "configuration", "state"})
REQUIRED_LIFECYCLE = (
    "install",
    "configure",
    "health",
    "update",
    "backup",
    "restore",
    "remove",
)


class ModuleHomeServiceContractBindingError(ValueError):
    """Stable rejection code for malformed or inconsistent binding evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceContractBinding:
    """Evidence-only compatibility binding for one module and Home Service."""

    binding_id: str
    module_contract_admission_binding_id: str
    home_center_version: str
    module_id: str
    module_version: str
    service_profile_schema: str
    service_profile_sha256: str
    service_id: str
    service_kind: str
    required_service_contracts: tuple[str, ...]
    provided_service_contracts: tuple[str, ...]
    unsupported_service_contracts: tuple[str, ...]
    status: str
    reasons: tuple[str, ...]
    schema: str = BINDING_SCHEMA
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "binding_id": self.binding_id,
            "module_contract_admission_binding_id": (
                self.module_contract_admission_binding_id
            ),
            "home_center_version": self.home_center_version,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "service_profile_schema": self.service_profile_schema,
            "service_profile_sha256": self.service_profile_sha256,
            "service_id": self.service_id,
            "service_kind": self.service_kind,
            "required_service_contracts": list(
                self.required_service_contracts
            ),
            "provided_service_contracts": list(
                self.provided_service_contracts
            ),
            "unsupported_service_contracts": list(
                self.unsupported_service_contracts
            ),
            "status": self.status,
            "reasons": list(self.reasons),
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
        raise ModuleHomeServiceContractBindingError(
            "binding_evidence_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _payload(value: object, code: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        raw = dict(value)
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise ModuleHomeServiceContractBindingError(code)
        try:
            raw = to_dict()
        except (TypeError, ValueError) as exc:
            raise ModuleHomeServiceContractBindingError(code) from exc
    if not isinstance(raw, dict):
        raise ModuleHomeServiceContractBindingError(code)
    return raw


def _identifier(value: object, prefix: str, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or ID24.fullmatch(value[len(prefix) :]) is None
    ):
        raise ModuleHomeServiceContractBindingError(code)
    return value


def _semver(value: object, code: str) -> str:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        raise ModuleHomeServiceContractBindingError(code)
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ModuleHomeServiceContractBindingError(code)
    return value


def _string_list(
    value: object,
    *,
    pattern: re.Pattern[str],
    code: str,
    minimum: int = 0,
    maximum: int = 128,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ModuleHomeServiceContractBindingError(code)
    result = tuple(value)
    if (
        not minimum <= len(result) <= maximum
        or any(
            not isinstance(item, str)
            or pattern.fullmatch(item) is None
            for item in result
        )
    ):
        raise ModuleHomeServiceContractBindingError(code)
    if len(result) != len(set(result)):
        raise ModuleHomeServiceContractBindingError(code)
    return tuple(sorted(result))


def _validate_module_binding(value: object) -> dict[str, Any]:
    payload = _payload(value, "module_contract_binding_rejected")
    if set(payload) != MODULE_BINDING_FIELDS:
        raise ModuleHomeServiceContractBindingError(
            "module_contract_binding_rejected"
        )
    if payload.get("schema") != MODULE_BINDING_SCHEMA:
        raise ModuleHomeServiceContractBindingError(
            "module_contract_binding_rejected"
        )
    _identifier(
        payload.get("binding_id"),
        "mcab-",
        "module_contract_binding_rejected",
    )
    _identifier(
        payload.get("profile_id"),
        "mccp-",
        "module_contract_binding_rejected",
    )
    _identifier(
        payload.get("negotiation_decision_id"),
        "mcnd-",
        "module_contract_binding_rejected",
    )
    _identifier(
        payload.get("admission_decision_id"),
        "madm-",
        "module_contract_binding_rejected",
    )
    _semver(
        payload.get("home_center_version"),
        "module_contract_binding_rejected",
    )
    module_id = payload.get("module_id")
    if (
        not isinstance(module_id, str)
        or MODULE_ID.fullmatch(module_id) is None
    ):
        raise ModuleHomeServiceContractBindingError(
            "module_contract_binding_rejected"
        )
    _semver(
        payload.get("module_version"),
        "module_contract_binding_rejected",
    )
    _digest(
        payload.get("manifest_binding_sha256"),
        "module_contract_binding_rejected",
    )
    _digest(
        payload.get("artifact_sha256"),
        "module_contract_binding_rejected",
    )
    if payload.get("admission_status") not in {"compatible", "blocked"}:
        raise ModuleHomeServiceContractBindingError(
            "module_contract_binding_rejected"
        )
    if any(payload.get(flag) is not False for flag in AUTHORITY_FLAGS):
        raise ModuleHomeServiceContractBindingError(
            "module_contract_binding_rejected"
        )
    evidence = dict(payload)
    binding_id = str(evidence.pop("binding_id"))
    expected = "mcab-" + _canonical_sha256(evidence)[:24]
    if binding_id != expected:
        raise ModuleHomeServiceContractBindingError(
            "module_contract_binding_rejected"
        )
    return payload


def _validate_service_profile(value: object) -> dict[str, Any]:
    payload = _payload(value, "home_service_profile_rejected")
    if set(payload) != SERVICE_PROFILE_FIELDS:
        raise ModuleHomeServiceContractBindingError(
            "home_service_profile_rejected"
        )
    service_id = payload.get("service_id")
    if (
        not isinstance(service_id, str)
        or SERVICE_ID.fullmatch(service_id) is None
    ):
        raise ModuleHomeServiceContractBindingError(
            "home_service_profile_rejected"
        )
    if payload.get("kind") not in SERVICE_KINDS:
        raise ModuleHomeServiceContractBindingError(
            "home_service_profile_rejected"
        )
    name = payload.get("name")
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 80
        or name != name.strip()
    ):
        raise ModuleHomeServiceContractBindingError(
            "home_service_profile_rejected"
        )
    for field_name in ("required_capabilities", "provided_capabilities"):
        contracts = _string_list(
            payload.get(field_name),
            pattern=SERVICE_CONTRACT,
            code="home_service_profile_rejected",
        )
        if list(contracts) != payload.get(field_name):
            raise ModuleHomeServiceContractBindingError(
                "home_service_profile_rejected"
            )
    storage = payload.get("minimum_storage_gib")
    if (
        isinstance(storage, bool)
        or not isinstance(storage, int)
        or not 1 <= storage <= 1_048_576
    ):
        raise ModuleHomeServiceContractBindingError(
            "home_service_profile_rejected"
        )
    if payload.get("publication_policy") not in PUBLICATION_POLICIES:
        raise ModuleHomeServiceContractBindingError(
            "home_service_profile_rejected"
        )
    if payload.get("backup_policy") not in BACKUP_POLICIES:
        raise ModuleHomeServiceContractBindingError(
            "home_service_profile_rejected"
        )
    lifecycle = payload.get("lifecycle")
    if lifecycle != list(REQUIRED_LIFECYCLE):
        raise ModuleHomeServiceContractBindingError(
            "home_service_profile_rejected"
        )
    return payload


def _required_contracts(value: Iterable[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes, bytearray, dict)):
        raise ModuleHomeServiceContractBindingError(
            "required_service_contracts_rejected"
        )
    try:
        raw = tuple(
            islice(iter(value), MAX_REQUIRED_SERVICE_CONTRACTS + 1)
        )
    except Exception as exc:
        raise ModuleHomeServiceContractBindingError(
            "required_service_contracts_rejected"
        ) from exc
    return _string_list(
        raw,
        pattern=SERVICE_CONTRACT,
        code="required_service_contracts_rejected",
        minimum=1,
        maximum=MAX_REQUIRED_SERVICE_CONTRACTS,
    )


def bind_module_home_service_contracts(
    module_binding: object,
    service_profile: object,
    required_service_contracts: Iterable[str],
) -> ModuleHomeServiceContractBinding:
    """Bind one exact module admission to versioned Home Service contracts."""

    module_payload = _validate_module_binding(module_binding)
    service_payload = _validate_service_profile(service_profile)
    required = _required_contracts(required_service_contracts)
    provided = tuple(service_payload["provided_capabilities"])
    unsupported = tuple(sorted(set(required).difference(provided)))

    reasons: list[str] = []
    if module_payload["admission_status"] != "compatible":
        reasons.append("module_admission_blocked")
    if unsupported:
        reasons.append("unsupported_service_contract")
    status = "compatible" if not reasons else "blocked"

    service_profile_sha256 = _canonical_sha256(
        {
            "schema": SERVICE_PROFILE_SCHEMA,
            "profile": service_payload,
        }
    )
    evidence = {
        "schema": BINDING_SCHEMA,
        "module_contract_admission_binding_id": module_payload[
            "binding_id"
        ],
        "home_center_version": module_payload["home_center_version"],
        "module_id": module_payload["module_id"],
        "module_version": module_payload["module_version"],
        "service_profile_schema": SERVICE_PROFILE_SCHEMA,
        "service_profile_sha256": service_profile_sha256,
        "service_id": service_payload["service_id"],
        "service_kind": service_payload["kind"],
        "required_service_contracts": list(required),
        "provided_service_contracts": list(provided),
        "unsupported_service_contracts": list(unsupported),
        "status": status,
        "reasons": reasons,
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    binding_id = "mhscb-" + _canonical_sha256(evidence)[:24]
    return ModuleHomeServiceContractBinding(
        binding_id=binding_id,
        module_contract_admission_binding_id=str(
            module_payload["binding_id"]
        ),
        home_center_version=str(module_payload["home_center_version"]),
        module_id=str(module_payload["module_id"]),
        module_version=str(module_payload["module_version"]),
        service_profile_schema=SERVICE_PROFILE_SCHEMA,
        service_profile_sha256=service_profile_sha256,
        service_id=str(service_payload["service_id"]),
        service_kind=str(service_payload["kind"]),
        required_service_contracts=required,
        provided_service_contracts=provided,
        unsupported_service_contracts=unsupported,
        status=status,
        reasons=tuple(reasons),
    )
