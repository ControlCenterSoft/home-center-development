"""Deterministic, evidence-only legal/compliance metadata for Home Center modules."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping


LEGAL_COMPLIANCE_SCHEMA = "home-center.module-legal-compliance-evidence.v1"
MODULE_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$"
)
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
DIGEST = re.compile(r"^[0-9a-f]{64}$")
ID24 = re.compile(r"^[0-9a-f]{24}$")
SPDX_SHAPE = re.compile(r"^[A-Za-z0-9.+(): -]{1,256}$")
DISTRIBUTION_MODES = frozenset(
    {"bundled", "system-package", "official-download", "customer-provided"}
)
DISPOSITIONS = frozenset({"allowed", "conditional", "prohibited", "unknown"})
AUTHORITY_FLAGS = (
    "admission_authorized",
    "installation_authorized",
    "execution_authorized",
    "production_mutation_enabled",
    "external_publication_authorized",
)
EVIDENCE_FIELDS = frozenset(
    {
        "schema",
        "evidence_id",
        "module_id",
        "module_version",
        "artifact_sha256",
        "license_expression",
        "authoritative_source",
        "distribution_mode",
        "commercial_use_disposition",
        "redistribution_disposition",
        "notice_required",
        "source_offer_required",
        "license_evidence_version",
        "license_evidence_sha256",
        *AUTHORITY_FLAGS,
    }
)


class ModuleLegalComplianceError(ValueError):
    """Stable rejection code for malformed legal/compliance evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleLegalComplianceEvidence:
    """Exact legal/compliance evidence bound to one module artifact."""

    evidence_id: str
    module_id: str
    module_version: str
    artifact_sha256: str
    license_expression: str
    authoritative_source: str
    distribution_mode: str
    commercial_use_disposition: str
    redistribution_disposition: str
    notice_required: bool
    source_offer_required: bool
    license_evidence_version: str
    license_evidence_sha256: str
    schema: str = LEGAL_COMPLIANCE_SCHEMA
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_id": self.evidence_id,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "artifact_sha256": self.artifact_sha256,
            "license_expression": self.license_expression,
            "authoritative_source": self.authoritative_source,
            "distribution_mode": self.distribution_mode,
            "commercial_use_disposition": self.commercial_use_disposition,
            "redistribution_disposition": self.redistribution_disposition,
            "notice_required": self.notice_required,
            "source_offer_required": self.source_offer_required,
            "license_evidence_version": self.license_evidence_version,
            "license_evidence_sha256": self.license_evidence_sha256,
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
        raise ModuleLegalComplianceError("legal_compliance_evidence_rejected") from exc
    return hashlib.sha256(encoded).hexdigest()


def _plain_string(value: object, code: str, *, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ModuleLegalComplianceError(code)
    return value


def _module_id(value: object) -> str:
    if type(value) is not str or MODULE_ID.fullmatch(value) is None:
        raise ModuleLegalComplianceError("module_identity_rejected")
    return value


def _semver(value: object, code: str) -> str:
    if type(value) is not str or SEMVER.fullmatch(value) is None:
        raise ModuleLegalComplianceError(code)
    return value


def _digest(value: object, code: str) -> str:
    if type(value) is not str or DIGEST.fullmatch(value) is None:
        raise ModuleLegalComplianceError(code)
    return value


def _license_expression(value: object) -> str:
    text = _plain_string(value, "license_expression_rejected", maximum=256)
    canonical = " ".join(text.split())
    if canonical != text or SPDX_SHAPE.fullmatch(text) is None:
        raise ModuleLegalComplianceError("license_expression_rejected")
    return text


def _payload(value: object) -> dict[str, object]:
    if isinstance(value, ModuleLegalComplianceEvidence):
        return value.to_dict()
    if isinstance(value, Mapping):
        return dict(value)
    raise ModuleLegalComplianceError("legal_compliance_evidence_rejected")


def build_module_legal_compliance_evidence(
    *,
    module_id: str,
    module_version: str,
    artifact_sha256: str,
    license_expression: str,
    authoritative_source: str,
    distribution_mode: str,
    commercial_use_disposition: str,
    redistribution_disposition: str,
    notice_required: bool,
    source_offer_required: bool,
    license_evidence_version: str,
    license_evidence_sha256: str,
) -> ModuleLegalComplianceEvidence:
    """Build deterministic metadata without granting admission or release authority."""

    canonical_module_id = _module_id(module_id)
    canonical_module_version = _semver(module_version, "module_version_rejected")
    canonical_artifact_sha256 = _digest(
        artifact_sha256, "artifact_digest_rejected"
    )
    canonical_license_expression = _license_expression(license_expression)
    canonical_source = _plain_string(
        authoritative_source, "authoritative_source_rejected", maximum=1024
    )
    if distribution_mode not in DISTRIBUTION_MODES:
        raise ModuleLegalComplianceError("distribution_mode_rejected")
    if commercial_use_disposition not in DISPOSITIONS:
        raise ModuleLegalComplianceError("commercial_use_disposition_rejected")
    if redistribution_disposition not in DISPOSITIONS:
        raise ModuleLegalComplianceError("redistribution_disposition_rejected")
    if type(notice_required) is not bool or type(source_offer_required) is not bool:
        raise ModuleLegalComplianceError("notice_source_offer_rejected")
    canonical_evidence_version = _semver(
        license_evidence_version, "license_evidence_version_rejected"
    )
    canonical_evidence_digest = _digest(
        license_evidence_sha256, "license_evidence_digest_rejected"
    )

    evidence = {
        "schema": LEGAL_COMPLIANCE_SCHEMA,
        "module_id": canonical_module_id,
        "module_version": canonical_module_version,
        "artifact_sha256": canonical_artifact_sha256,
        "license_expression": canonical_license_expression,
        "authoritative_source": canonical_source,
        "distribution_mode": distribution_mode,
        "commercial_use_disposition": commercial_use_disposition,
        "redistribution_disposition": redistribution_disposition,
        "notice_required": notice_required,
        "source_offer_required": source_offer_required,
        "license_evidence_version": canonical_evidence_version,
        "license_evidence_sha256": canonical_evidence_digest,
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    evidence_id = "mlce-" + _canonical_sha256(evidence)[:24]
    return ModuleLegalComplianceEvidence(
        evidence_id=evidence_id,
        module_id=canonical_module_id,
        module_version=canonical_module_version,
        artifact_sha256=canonical_artifact_sha256,
        license_expression=canonical_license_expression,
        authoritative_source=canonical_source,
        distribution_mode=distribution_mode,
        commercial_use_disposition=commercial_use_disposition,
        redistribution_disposition=redistribution_disposition,
        notice_required=notice_required,
        source_offer_required=source_offer_required,
        license_evidence_version=canonical_evidence_version,
        license_evidence_sha256=canonical_evidence_digest,
    )


def validate_module_legal_compliance_evidence(
    value: object,
) -> ModuleLegalComplianceEvidence:
    """Validate serialized evidence and reject tampering fail-closed."""

    payload = _payload(value)
    if (
        any(type(key) is not str for key in payload)
        or set(payload) != EVIDENCE_FIELDS
        or payload.get("schema") != LEGAL_COMPLIANCE_SCHEMA
        or any(payload.get(flag) is not False for flag in AUTHORITY_FLAGS)
    ):
        raise ModuleLegalComplianceError("legal_compliance_evidence_rejected")

    evidence_id = payload.get("evidence_id")
    if (
        type(evidence_id) is not str
        or not evidence_id.startswith("mlce-")
        or ID24.fullmatch(evidence_id[5:]) is None
    ):
        raise ModuleLegalComplianceError("legal_compliance_evidence_rejected")

    result = build_module_legal_compliance_evidence(
        module_id=_module_id(payload.get("module_id")),
        module_version=_semver(payload.get("module_version"), "module_version_rejected"),
        artifact_sha256=_digest(payload.get("artifact_sha256"), "artifact_digest_rejected"),
        license_expression=_license_expression(payload.get("license_expression")),
        authoritative_source=_plain_string(
            payload.get("authoritative_source"),
            "authoritative_source_rejected",
            maximum=1024,
        ),
        distribution_mode=str(payload.get("distribution_mode")),
        commercial_use_disposition=str(payload.get("commercial_use_disposition")),
        redistribution_disposition=str(payload.get("redistribution_disposition")),
        notice_required=payload.get("notice_required"),
        source_offer_required=payload.get("source_offer_required"),
        license_evidence_version=_semver(
            payload.get("license_evidence_version"),
            "license_evidence_version_rejected",
        ),
        license_evidence_sha256=_digest(
            payload.get("license_evidence_sha256"),
            "license_evidence_digest_rejected",
        ),
    )
    if result.evidence_id != evidence_id:
        raise ModuleLegalComplianceError("legal_compliance_evidence_rejected")
    return result
