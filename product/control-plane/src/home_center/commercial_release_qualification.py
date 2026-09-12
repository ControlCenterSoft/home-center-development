"""Fail-closed commercial/legal qualification for an exact Home Center candidate.

This module validates machine-readable review evidence. It does not perform legal
review, approve terms, grant publication authority, or infer approval from the
mere presence of documents.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

SCHEMA = "home-center.commercial-release-qualification.v1"
APPROVED = "approved"
DISPOSITIONS = {APPROVED, "review-required", "rejected"}
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class CommercialReleaseQualificationError(ValueError):
    """Reject malformed commercial release evidence before evaluation."""


@dataclass(frozen=True, slots=True)
class CommercialReleaseEvidence:
    version: str
    revision: str
    candidate_artifact_sha256: str
    dependencies_evidence_sha256: str
    redistribution_evidence_sha256: str
    notices_sha256: str
    source_obligations_evidence_sha256: str
    sbom_sha256: str
    legal_terms_sha256: str
    support_terms_sha256: str
    release_claims_sha256: str
    disposition: str
    dependencies_reviewed: bool
    redistribution_reviewed: bool
    notices_prepared: bool
    source_obligations_resolved: bool
    sbom_reviewed: bool
    legal_terms_dispositioned: bool
    release_claims_reviewed: bool


@dataclass(frozen=True, slots=True)
class CommercialReleaseQualificationDecision:
    version: str
    revision: str
    candidate_artifact_sha256: str
    disposition: str
    evidence_sha256: str
    qualified: bool
    blockers: tuple[str, ...]
    dependencies_reviewed: bool
    redistribution_reviewed: bool
    notices_prepared: bool
    source_obligations_resolved: bool
    sbom_reviewed: bool
    legal_terms_dispositioned: bool
    release_claims_reviewed: bool
    schema: str = SCHEMA
    release_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "version": self.version,
            "revision": self.revision,
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
            "disposition": self.disposition,
            "evidence_sha256": self.evidence_sha256,
            "qualified": self.qualified,
            "blockers": list(self.blockers),
            "dependencies_reviewed": self.dependencies_reviewed,
            "redistribution_reviewed": self.redistribution_reviewed,
            "notices_prepared": self.notices_prepared,
            "source_obligations_resolved": self.source_obligations_resolved,
            "sbom_reviewed": self.sbom_reviewed,
            "legal_terms_dispositioned": self.legal_terms_dispositioned,
            "release_claims_reviewed": self.release_claims_reviewed,
            "release_authorized": False,
            "external_publication_authorized": False,
        }


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def evaluate_commercial_release_qualification(
    evidence: CommercialReleaseEvidence,
) -> CommercialReleaseQualificationDecision:
    """Evaluate exact-bound commercial evidence without creating release authority."""

    if not isinstance(evidence, CommercialReleaseEvidence):
        raise CommercialReleaseQualificationError("commercial_evidence_invalid")
    if _SEMVER.fullmatch(evidence.version) is None:
        raise CommercialReleaseQualificationError("commercial_version_invalid")
    if _REVISION.fullmatch(evidence.revision) is None:
        raise CommercialReleaseQualificationError("commercial_revision_invalid")
    if evidence.disposition not in DISPOSITIONS:
        raise CommercialReleaseQualificationError("commercial_disposition_invalid")

    blockers: list[str] = []
    digest_fields = (
        ("candidate_artifact_digest", evidence.candidate_artifact_sha256),
        ("dependencies_evidence_digest", evidence.dependencies_evidence_sha256),
        ("redistribution_evidence_digest", evidence.redistribution_evidence_sha256),
        ("notices_digest", evidence.notices_sha256),
        ("source_obligations_evidence_digest", evidence.source_obligations_evidence_sha256),
        ("sbom_digest", evidence.sbom_sha256),
        ("legal_terms_digest", evidence.legal_terms_sha256),
        ("support_terms_digest", evidence.support_terms_sha256),
        ("release_claims_digest", evidence.release_claims_sha256),
    )
    for blocker, value in digest_fields:
        if not _valid_sha256(value):
            blockers.append(blocker)

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

    if blockers:
        evidence_sha256 = "0" * 64
    else:
        canonical = {
            "version": evidence.version,
            "revision": evidence.revision,
            "candidate_artifact_sha256": evidence.candidate_artifact_sha256,
            "dependencies_evidence_sha256": evidence.dependencies_evidence_sha256,
            "redistribution_evidence_sha256": evidence.redistribution_evidence_sha256,
            "notices_sha256": evidence.notices_sha256,
            "source_obligations_evidence_sha256": evidence.source_obligations_evidence_sha256,
            "sbom_sha256": evidence.sbom_sha256,
            "legal_terms_sha256": evidence.legal_terms_sha256,
            "support_terms_sha256": evidence.support_terms_sha256,
            "release_claims_sha256": evidence.release_claims_sha256,
            "disposition": evidence.disposition,
        }
        payload = json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        evidence_sha256 = hashlib.sha256(payload).hexdigest()

    return CommercialReleaseQualificationDecision(
        version=evidence.version,
        revision=evidence.revision,
        candidate_artifact_sha256=evidence.candidate_artifact_sha256,
        disposition=evidence.disposition,
        evidence_sha256=evidence_sha256,
        qualified=not blockers,
        blockers=tuple(blockers),
        dependencies_reviewed=evidence.dependencies_reviewed,
        redistribution_reviewed=evidence.redistribution_reviewed,
        notices_prepared=evidence.notices_prepared,
        source_obligations_resolved=evidence.source_obligations_resolved,
        sbom_reviewed=evidence.sbom_reviewed,
        legal_terms_dispositioned=evidence.legal_terms_dispositioned,
        release_claims_reviewed=evidence.release_claims_reviewed,
    )
