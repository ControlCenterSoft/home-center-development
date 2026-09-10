"""Exact binding between module contract negotiation and admission evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


ID24 = re.compile(r"^[0-9a-f]{24}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
MODULE_ID = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SCHEMA_ID = re.compile(
    r"^home-center\.[a-z0-9]+(?:-[a-z0-9]+)*\.v[1-9][0-9]*$"
)

PROFILE_SCHEMA = "home-center.module-contract-compatibility-profile.v1"
NEGOTIATION_SCHEMA = "home-center.module-contract-negotiation-decision.v1"
ADMISSION_SCHEMA = "home-center.module-admission-decision.v1"
BINDING_SCHEMA = "home-center.module-contract-admission-binding.v1"

PROFILE_FIELDS = frozenset(
    {
        "schema",
        "profile_id",
        "home_center_version",
        "supported_contracts",
        "admission_authorized",
        "installation_authorized",
        "execution_authorized",
        "production_mutation_enabled",
        "external_publication_authorized",
    }
)
NEGOTIATION_FIELDS = frozenset(
    {
        "schema",
        "decision_id",
        "profile_id",
        "home_center_version",
        "status",
        "requested_contracts",
        "unsupported_contracts",
        "reasons",
        "admission_authorized",
        "installation_authorized",
        "execution_authorized",
        "production_mutation_enabled",
        "external_publication_authorized",
    }
)
ADMISSION_FIELDS = frozenset(
    {
        "schema",
        "decision_id",
        "status",
        "module_id",
        "module_version",
        "publisher",
        "manifest_binding_sha256",
        "provenance_statement_sha256",
        "verified_signing_key_ids",
        "artifact_sha256",
        "home_center_version",
        "architecture",
        "operating_system",
        "available_capabilities",
        "installed_modules",
        "missing_capabilities",
        "unsatisfied_dependencies",
        "active_conflicts",
        "reasons",
        "installation_authorized",
        "execution_authorized",
        "production_mutation_enabled",
        "external_publication_authorized",
    }
)
AUTHORITY_FLAGS = (
    "installation_authorized",
    "execution_authorized",
    "production_mutation_enabled",
    "external_publication_authorized",
)


class ModuleContractAdmissionBindingError(ValueError):
    """Stable rejection code for malformed or mismatched binding evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleContractAdmissionBinding:
    """Evidence-only binding of compatible negotiation to one admission."""

    binding_id: str
    profile_id: str
    negotiation_decision_id: str
    admission_decision_id: str
    home_center_version: str
    module_manifest_schema: str
    module_admission_schema: str
    module_id: str
    module_version: str
    manifest_binding_sha256: str
    artifact_sha256: str
    admission_status: str
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
            "profile_id": self.profile_id,
            "negotiation_decision_id": self.negotiation_decision_id,
            "admission_decision_id": self.admission_decision_id,
            "home_center_version": self.home_center_version,
            "module_manifest_schema": self.module_manifest_schema,
            "module_admission_schema": self.module_admission_schema,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "manifest_binding_sha256": self.manifest_binding_sha256,
            "artifact_sha256": self.artifact_sha256,
            "admission_status": self.admission_status,
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
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ModuleContractAdmissionBindingError(
            "binding_evidence_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _payload(value: object, code: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        raw = dict(value)
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise ModuleContractAdmissionBindingError(code)
        try:
            raw = to_dict()
        except (TypeError, ValueError) as exc:
            raise ModuleContractAdmissionBindingError(code) from exc
    if not isinstance(raw, dict):
        raise ModuleContractAdmissionBindingError(code)
    return raw


def _exact_fields(
    payload: Mapping[str, object],
    expected: frozenset[str],
    code: str,
) -> None:
    if set(payload) != expected:
        raise ModuleContractAdmissionBindingError(code)


def _schema(value: object, expected: str, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or SCHEMA_ID.fullmatch(value) is None
        or value != expected
    ):
        raise ModuleContractAdmissionBindingError(code)
    return value


def _semver(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 64
        or SEMVER.fullmatch(value) is None
    ):
        raise ModuleContractAdmissionBindingError(code)
    return value


def _identifier(value: object, prefix: str, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or ID24.fullmatch(value[len(prefix) :]) is None
    ):
        raise ModuleContractAdmissionBindingError(code)
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ModuleContractAdmissionBindingError(code)
    return value


def _assert_non_authorizing(
    payload: Mapping[str, object],
    *,
    include_admission: bool,
    code: str,
) -> None:
    flags = AUTHORITY_FLAGS + (("admission_authorized",) if include_admission else ())
    if any(payload.get(flag) is not False for flag in flags):
        raise ModuleContractAdmissionBindingError(code)


def _assert_canonical_id(
    payload: Mapping[str, object],
    *,
    id_field: str,
    prefix: str,
    code: str,
) -> str:
    identifier = _identifier(payload.get(id_field), prefix, code)
    evidence = dict(payload)
    evidence.pop(id_field)
    expected = prefix + _canonical_sha256(evidence)[:24]
    if identifier != expected:
        raise ModuleContractAdmissionBindingError(code)
    return identifier


def _validate_profile(value: object) -> dict[str, Any]:
    payload = _payload(value, "contract_profile_rejected")
    _exact_fields(payload, PROFILE_FIELDS, "contract_profile_rejected")
    _schema(payload.get("schema"), PROFILE_SCHEMA, "contract_profile_rejected")
    _semver(payload.get("home_center_version"), "contract_profile_rejected")
    _assert_non_authorizing(
        payload,
        include_admission=True,
        code="contract_profile_rejected",
    )
    supported = payload.get("supported_contracts")
    if not isinstance(supported, dict) or not supported:
        raise ModuleContractAdmissionBindingError("contract_profile_rejected")
    for family, revisions in supported.items():
        if not isinstance(family, str) or not isinstance(revisions, list):
            raise ModuleContractAdmissionBindingError("contract_profile_rejected")
        if (
            not revisions
            or len(revisions) > 16
            or len(revisions) != len(set(revisions))
            or any(
                not isinstance(item, str)
                or SCHEMA_ID.fullmatch(item) is None
                for item in revisions
            )
        ):
            raise ModuleContractAdmissionBindingError("contract_profile_rejected")
    _assert_canonical_id(
        payload,
        id_field="profile_id",
        prefix="mccp-",
        code="contract_profile_rejected",
    )
    return payload


def _validate_negotiation(value: object) -> dict[str, Any]:
    payload = _payload(value, "contract_negotiation_rejected")
    _exact_fields(
        payload,
        NEGOTIATION_FIELDS,
        "contract_negotiation_rejected",
    )
    _schema(
        payload.get("schema"),
        NEGOTIATION_SCHEMA,
        "contract_negotiation_rejected",
    )
    _semver(
        payload.get("home_center_version"),
        "contract_negotiation_rejected",
    )
    _identifier(
        payload.get("profile_id"),
        "mccp-",
        "contract_negotiation_rejected",
    )
    _assert_non_authorizing(
        payload,
        include_admission=True,
        code="contract_negotiation_rejected",
    )
    if payload.get("status") not in {"compatible", "unsupported-contract"}:
        raise ModuleContractAdmissionBindingError(
            "contract_negotiation_rejected"
        )
    requested = payload.get("requested_contracts")
    unsupported = payload.get("unsupported_contracts")
    reasons = payload.get("reasons")
    if (
        not isinstance(requested, dict)
        or not isinstance(unsupported, list)
        or not isinstance(reasons, list)
    ):
        raise ModuleContractAdmissionBindingError(
            "contract_negotiation_rejected"
        )
    if not {"module_manifest", "module_admission_decision"}.issubset(requested):
        raise ModuleContractAdmissionBindingError(
            "contract_negotiation_rejected"
        )
    if any(
        not isinstance(family, str)
        or not isinstance(revision, str)
        or SCHEMA_ID.fullmatch(revision) is None
        for family, revision in requested.items()
    ):
        raise ModuleContractAdmissionBindingError(
            "contract_negotiation_rejected"
        )
    _assert_canonical_id(
        payload,
        id_field="decision_id",
        prefix="mcnd-",
        code="contract_negotiation_rejected",
    )
    return payload


def _validate_admission(value: object) -> dict[str, Any]:
    payload = _payload(value, "module_admission_rejected")
    _exact_fields(payload, ADMISSION_FIELDS, "module_admission_rejected")
    _schema(payload.get("schema"), ADMISSION_SCHEMA, "module_admission_rejected")
    _semver(payload.get("home_center_version"), "module_admission_rejected")
    if payload.get("status") not in {"compatible", "blocked"}:
        raise ModuleContractAdmissionBindingError("module_admission_rejected")
    module_id = payload.get("module_id")
    if not isinstance(module_id, str) or MODULE_ID.fullmatch(module_id) is None:
        raise ModuleContractAdmissionBindingError("module_admission_rejected")
    _semver(payload.get("module_version"), "module_admission_rejected")
    _digest(
        payload.get("manifest_binding_sha256"),
        "module_admission_rejected",
    )
    _digest(payload.get("artifact_sha256"), "module_admission_rejected")
    _assert_non_authorizing(
        payload,
        include_admission=False,
        code="module_admission_rejected",
    )
    _assert_canonical_id(
        payload,
        id_field="decision_id",
        prefix="madm-",
        code="module_admission_rejected",
    )
    return payload


def bind_module_contract_admission(
    profile: object,
    negotiation: object,
    admission: object,
) -> ModuleContractAdmissionBinding:
    """Bind a compatible contract negotiation to one exact admission decision."""

    profile_payload = _validate_profile(profile)
    negotiation_payload = _validate_negotiation(negotiation)
    admission_payload = _validate_admission(admission)

    if negotiation_payload["status"] != "compatible":
        raise ModuleContractAdmissionBindingError(
            "contract_negotiation_incompatible"
        )
    if negotiation_payload["unsupported_contracts"] or negotiation_payload["reasons"]:
        raise ModuleContractAdmissionBindingError(
            "contract_negotiation_incompatible"
        )
    if negotiation_payload["profile_id"] != profile_payload["profile_id"]:
        raise ModuleContractAdmissionBindingError(
            "contract_profile_binding_mismatch"
        )
    if (
        negotiation_payload["home_center_version"]
        != profile_payload["home_center_version"]
        or admission_payload["home_center_version"]
        != profile_payload["home_center_version"]
    ):
        raise ModuleContractAdmissionBindingError(
            "home_center_version_binding_mismatch"
        )

    requested = negotiation_payload["requested_contracts"]
    supported = profile_payload["supported_contracts"]
    assert isinstance(requested, dict)
    assert isinstance(supported, dict)
    for family, revision in requested.items():
        revisions = supported.get(family)
        if not isinstance(revisions, list) or revision not in revisions:
            raise ModuleContractAdmissionBindingError(
                "contract_profile_binding_mismatch"
            )

    manifest_schema = requested["module_manifest"]
    admission_schema = requested["module_admission_decision"]
    if admission_schema != admission_payload["schema"]:
        raise ModuleContractAdmissionBindingError(
            "module_admission_schema_mismatch"
        )

    evidence = {
        "schema": BINDING_SCHEMA,
        "profile_id": profile_payload["profile_id"],
        "negotiation_decision_id": negotiation_payload["decision_id"],
        "admission_decision_id": admission_payload["decision_id"],
        "home_center_version": profile_payload["home_center_version"],
        "module_manifest_schema": manifest_schema,
        "module_admission_schema": admission_schema,
        "module_id": admission_payload["module_id"],
        "module_version": admission_payload["module_version"],
        "manifest_binding_sha256": admission_payload[
            "manifest_binding_sha256"
        ],
        "artifact_sha256": admission_payload["artifact_sha256"],
        "admission_status": admission_payload["status"],
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    binding_id = "mcab-" + _canonical_sha256(evidence)[:24]
    return ModuleContractAdmissionBinding(
        binding_id=binding_id,
        profile_id=str(profile_payload["profile_id"]),
        negotiation_decision_id=str(negotiation_payload["decision_id"]),
        admission_decision_id=str(admission_payload["decision_id"]),
        home_center_version=str(profile_payload["home_center_version"]),
        module_manifest_schema=str(manifest_schema),
        module_admission_schema=str(admission_schema),
        module_id=str(admission_payload["module_id"]),
        module_version=str(admission_payload["module_version"]),
        manifest_binding_sha256=str(
            admission_payload["manifest_binding_sha256"]
        ),
        artifact_sha256=str(admission_payload["artifact_sha256"]),
        admission_status=str(admission_payload["status"]),
    )
