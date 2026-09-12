"""Exact-bound commercial/legal qualification evidence for Home Center releases.

This module does not approve legal terms, publish a release, contact a provider,
or create any production authority. It only turns an already-reviewed external
commercial/legal package into deterministic, fail-closed release evidence that
can be consumed by the existing promotion gate.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from home_center.release_promotion_gate import (
    APPROVED,
    CommercialEvidence,
    ReleaseBinding,
)

SCHEMA = "home-center.commercial-legal-qualification.v1"
REVIEW_REQUIRED = "review-required"
BLOCKED = "blocked"

_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class CommercialLegalQualificationError(ValueError):
    """Reject malformed or cross-candidate commercial/legal evidence."""


@dataclass(frozen=True, slots=True)
class CommercialLegalQualificationEvidence:
    """Bounded inputs copied from an external, already-reviewed evidence package."""

    version: str
    revision: str
    candidate_artifact_sha256: str
    external_review_sha256: str
    disposition: str
    dependencies_reviewed: bool
    redistribution_reviewed: bool
    notices_prepared: bool
    source_obligations_resolved: bool
    sbom_reviewed: bool
    legal_terms_dispositioned: bool
    release_claims_reviewed: bool


@dataclass(frozen=True, slots=True)
class CommercialLegalQualificationDecision:
    """Machine-readable commercial/legal release evidence without authority."""

    version: str
    revision: str
    candidate_artifact_sha256: str
    external_review_sha256: str
    disposition: str
    evidence_sha256: str
    dependencies_reviewed: bool
    redistribution_reviewed: bool
    notices_prepared: bool
    source_obligations_resolved: bool
    sbom_reviewed: bool
    legal_terms_dispositioned: bool
    release_claims_reviewed: bool
    qualified: bool
    blockers: tuple[str, ...]
    schema: str = SCHEMA
    release_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "version": self.version,
            "revision": self.revision,
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
            "external_review_sha256": self.external_review_sha256,
            "disposition": self.disposition,
            "evidence_sha256": self.evidence_sha256,
            "dependencies_reviewed": self.dependencies_reviewed,
            "redistribution_reviewed": self.redistribution_reviewed,
            "notices_prepared": self.notices_prepared,
            "source_obligations_resolved": self.source_obligations_resolved,
            "sbom_reviewed": self.sbom_reviewed,
            "legal_terms_dispositioned": self.legal_terms_dispositioned,
            "release_claims_reviewed": self.release_claims_reviewed,
            "qualified": self.qualified,
            "blockers": list(self.blockers),
            "release_authorized": False,
            "external_publication_authorized": False,
        }

    def to_promotion_evidence(
        self,
        *,
        candidate_artifact_sha256: str,
    ) -> CommercialEvidence:
        """Convert only an exact-artifact decision into promotion-gate evidence."""

        if not _valid_sha256(candidate_artifact_sha256):
            raise CommercialLegalQualificationError(
                "commercial_candidate_artifact_digest_invalid"
            )
        if candidate_artifact_sha256 != self.candidate_artifact_sha256:
            raise CommercialLegalQualificationError(
                "commercial_candidate_artifact_binding"
            )

        return CommercialEvidence(
            binding=ReleaseBinding(version=self.version, revision=self.revision),
            disposition=self.disposition if self.qualified else REVIEW_REQUIRED,
            evidence_sha256=self.evidence_sha256,
            dependencies_reviewed=self.dependencies_reviewed,
            redistribution_reviewed=self.redistribution_reviewed,
            notices_prepared=self.notices_prepared,
            source_obligations_resolved=self.source_obligations_resolved,
            sbom_reviewed=self.sbom_reviewed,
            legal_terms_dispositioned=self.legal_terms_dispositioned,
            release_claims_reviewed=self.release_claims_reviewed,
        )


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _validate_identity(evidence: CommercialLegalQualificationEvidence) -> None:
    if _SEMVER.fullmatch(evidence.version) is None:
        raise CommercialLegalQualificationError("commercial_version_invalid")
    if _REVISION.fullmatch(evidence.revision) is None:
        raise CommercialLegalQualificationError("commercial_revision_invalid")
    if evidence.disposition not in {APPROVED, REVIEW_REQUIRED, BLOCKED}:
        raise CommercialLegalQualificationError("commercial_disposition_invalid")


def _aggregate_evidence_sha256(
    evidence: CommercialLegalQualificationEvidence,
) -> str:
    canonical = {
        "candidate_artifact_sha256": evidence.candidate_artifact_sha256,
        "dependencies_reviewed": evidence.dependencies_reviewed,
        "disposition": evidence.disposition,
        "external_review_sha256": evidence.external_review_sha256,
        "legal_terms_dispositioned": evidence.legal_terms_dispositioned,
        "notices_prepared": evidence.notices_prepared,
        "redistribution_reviewed": evidence.redistribution_reviewed,
        "release_claims_reviewed": evidence.release_claims_reviewed,
        "revision": evidence.revision,
        "sbom_reviewed": evidence.sbom_reviewed,
        "source_obligations_resolved": evidence.source_obligations_resolved,
        "version": evidence.version,
    }
    payload = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def evaluate_commercial_legal_qualification(
    evidence: CommercialLegalQualificationEvidence,
) -> CommercialLegalQualificationDecision:
    """Evaluate exact-bound review evidence without granting release authority."""

    if not isinstance(evidence, CommercialLegalQualificationEvidence):
        raise CommercialLegalQualificationError("commercial_evidence_invalid")
    _validate_identity(evidence)

    blockers: list[str] = []
    if not _valid_sha256(evidence.candidate_artifact_sha256):
        blockers.append("candidate_artifact_digest")
    if not _valid_sha256(evidence.external_review_sha256):
        blockers.append("external_review_evidence")
    if evidence.disposition != APPROVED:
        blockers.append("commercial_disposition")

    checks = (
        ("dependencies_reviewed", evidence.dependencies_reviewed),
        ("redistribution_reviewed", evidence.redistribution_reviewed),
        ("notices_prepared", evidence.notices_prepared),
        ("source_obligations_resolved", evidence.source_obligations_resolved),
        ("sbom_reviewed", evidence.sbom_reviewed),
        ("legal_terms_dispositioned", evidence.legal_terms_dispositioned),
        ("release_claims_reviewed", evidence.release_claims_reviewed),
    )
    for blocker, passed in checks:
        if passed is not True:
            blockers.append(blocker)

    if _valid_sha256(evidence.candidate_artifact_sha256) and _valid_sha256(
        evidence.external_review_sha256
    ):
        evidence_sha256 = _aggregate_evidence_sha256(evidence)
    else:
        evidence_sha256 = "0" * 64

    return CommercialLegalQualificationDecision(
        version=evidence.version,
        revision=evidence.revision,
        candidate_artifact_sha256=evidence.candidate_artifact_sha256,
        external_review_sha256=evidence.external_review_sha256,
        disposition=evidence.disposition,
        evidence_sha256=evidence_sha256,
        dependencies_reviewed=evidence.dependencies_reviewed,
        redistribution_reviewed=evidence.redistribution_reviewed,
        notices_prepared=evidence.notices_prepared,
        source_obligations_resolved=evidence.source_obligations_resolved,
        sbom_reviewed=evidence.sbom_reviewed,
        legal_terms_dispositioned=evidence.legal_terms_dispositioned,
        release_claims_reviewed=evidence.release_claims_reviewed,
        qualified=not blockers,
        blockers=tuple(blockers),
    )
