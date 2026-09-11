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

CLEAR = "clear"
REVIEW_REQUIRED = "review-required"
BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class ModuleLegalComplianceClearance:
    """Deterministic advisory disposition for one validated evidence object."""

    evidence_id: str
    status: str
    reasons: tuple[str, ...]
    obligations: tuple[str, ...]
    release_authorized: bool = False
    external_publication_authorized: bool = False


def evaluate_module_legal_compliance_clearance(
    value: object,
) -> ModuleLegalComplianceClearance:
    """Evaluate legal/compliance evidence without creating execution authority."""

    evidence: ModuleLegalComplianceEvidence = (
        validate_module_legal_compliance_evidence(value)
    )

    reasons: list[str] = []
    obligations: list[str] = []

    if evidence.commercial_use_disposition == "prohibited":
        reasons.append("commercial-use-prohibited")
    if evidence.redistribution_disposition == "prohibited":
        reasons.append("redistribution-prohibited")

    if reasons:
        status = BLOCKED
    elif (
        evidence.commercial_use_disposition in {"conditional", "unknown"}
        or evidence.redistribution_disposition in {"conditional", "unknown"}
    ):
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
        status=status,
        reasons=tuple(reasons),
        obligations=tuple(obligations),
    )
