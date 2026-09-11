"""Advisory legal/compliance clearance derived from validated module evidence.

This evaluator is intentionally non-authorizing. It does not grant admission,
installation, execution, production mutation, publication, or release authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from home_center.module_legal_compliance import (
    ModuleLegalComplianceEvidence,
    validate_module_legal_compliance_evidence,
)

CLEARANCE_SCHEMA = "home-center.module-legal-compliance-clearance.v1"
CLEAR = "clear"
REVIEW_REQUIRED = "review-required"
BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class ModuleLegalComplianceClearance:
    evidence_id: str
    module_id: str
    module_version: str
    artifact_sha256: str
    license_evidence_version: str
    license_evidence_sha256: str
    status: str
    reasons: tuple[str, ...]
    obligations: tuple[str, ...]
    schema: str = CLEARANCE_SCHEMA
    release_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_id": self.evidence_id,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "artifact_sha256": self.artifact_sha256,
            "license_evidence_version": self.license_evidence_version,
            "license_evidence_sha256": self.license_evidence_sha256,
            "status": self.status,
            "reasons": list(self.reasons),
            "obligations": list(self.obligations),
            "release_authorized": self.release_authorized,
            "external_publication_authorized": self.external_publication_authorized,
        }


def evaluate_module_legal_compliance_clearance(value: object) -> ModuleLegalComplianceClearance:
    evidence: ModuleLegalComplianceEvidence = validate_module_legal_compliance_evidence(value)
    reasons: list[str] = []
    obligations: list[str] = []
    if evidence.commercial_use_disposition == "prohibited":
        reasons.append("commercial-use-prohibited")
    if evidence.redistribution_disposition == "prohibited":
        reasons.append("redistribution-prohibited")
    if reasons:
        status = BLOCKED
    elif evidence.commercial_use_disposition in {"conditional", "unknown"} or evidence.redistribution_disposition in {"conditional", "unknown"}:
        status = REVIEW_REQUIRED
        if evidence.commercial_use_disposition == "conditional":
            reasons.append("commercial-use-conditional")
        elif evidence.commercial_use_disposition == "unknown":
            reasons.append("commercial-use-unknown")
        if evidence.redistribution_disposition == "conditional":
            reasons.append("redistribution-conditional")
        elif evidence.redistribution_disposition == "unknown":
            reasons.append("redistribution-unknown")
    else:
        status = CLEAR
    if evidence.notice_required:
        obligations.append("notice-required")
    if evidence.source_offer_required:
        obligations.append("source-offer-required")
    return ModuleLegalComplianceClearance(
        evidence_id=evidence.evidence_id,
        module_id=evidence.module_id,
        module_version=evidence.module_version,
        artifact_sha256=evidence.artifact_sha256,
        license_evidence_version=evidence.license_evidence_version,
        license_evidence_sha256=evidence.license_evidence_sha256,
        status=status,
        reasons=tuple(reasons),
        obligations=tuple(obligations),
    )
