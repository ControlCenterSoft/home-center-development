"""Exact-bound qualification gate for Home Center 0.62 identity providers.

This module consumes bounded evidence from a real provider/target exercise and
creates the only qualification-bound adapter wrapper intended for future
production API wiring.  It does not perform provider calls during qualification,
does not grant release/publication authority, and never turns provider acceptance
into account-provisioning success without a separate read-back.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from .role_identity_provisioning import IdentityProviderCapability, IdentityProviderKind
from .role_identity_provisioning_runtime import RoleIdentityProvisioningRuntimeAdapter
from .util import canonical_json

SCHEMA = "home-center.role-identity-provider-qualification.v1"
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")


class IdentityProviderQualificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class IdentityProviderQualificationEvidence:
    version: str
    revision: str
    candidate_artifact_sha256: str
    provider_id: str
    provider_version: str
    provider_kind: IdentityProviderKind
    provider_evidence_sha256: str
    adapter_artifact_sha256: str
    execution_transcript_sha256: str
    environment_evidence_sha256: str
    recovery_evidence_sha256: str
    real_provider_exercised: bool
    real_target_exercised: bool
    account_absence_preflight_validated: bool
    start_contract_validated: bool
    readback_contract_validated: bool
    secret_reference_only: bool
    secret_values_absent_from_evidence: bool
    durable_job_before_side_effect: bool
    ambiguous_outcome_fail_closed: bool
    automatic_retry_forbidden: bool
    provider_acceptance_not_success: bool
    post_condition_readback_required: bool
    emergency_admin_isolated: bool
    arbitrary_privilege_grant_forbidden: bool
    external_publication_forbidden: bool
    recovery_semantics_validated: bool


@dataclass(frozen=True, slots=True)
class IdentityProviderQualificationDecision:
    version: str
    revision: str
    candidate_artifact_sha256: str
    provider_id: str
    provider_version: str
    provider_kind: str
    provider_evidence_sha256: str
    adapter_artifact_sha256: str
    qualification_evidence_sha256: str
    qualified: bool
    blockers: tuple[str, ...]
    schema: str = SCHEMA
    provider_execution_authorized: bool = False
    durable_state_change_authorized: bool = False
    emergency_admin_mutation_authorized: bool = False
    privilege_grant_authorized: bool = False
    release_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "version": self.version,
            "revision": self.revision,
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_kind": self.provider_kind,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "adapter_artifact_sha256": self.adapter_artifact_sha256,
            "qualification_evidence_sha256": self.qualification_evidence_sha256,
            "qualified": self.qualified,
            "blockers": list(self.blockers),
            "provider_execution_authorized": False,
            "durable_state_change_authorized": False,
            "emergency_admin_mutation_authorized": False,
            "privilege_grant_authorized": False,
            "release_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class QualificationBoundIdentityProviderAdapter:
    """Concrete adapter plus exact immutable qualification decision."""

    adapter: RoleIdentityProvisioningRuntimeAdapter
    provider: IdentityProviderCapability
    decision: IdentityProviderQualificationDecision

    def start(self, request: object) -> object:
        return self.adapter.start(request)  # type: ignore[arg-type]

    def observe(self, *, provider_operation_id: str, account_name: str) -> object:
        return self.adapter.observe(
            provider_operation_id=provider_operation_id,
            account_name=account_name,
        )


def _sha(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _identity_valid(evidence: IdentityProviderQualificationEvidence) -> bool:
    return bool(
        isinstance(evidence.version, str)
        and _SEMVER.fullmatch(evidence.version)
        and isinstance(evidence.revision, str)
        and _REVISION.fullmatch(evidence.revision)
        and _sha(evidence.candidate_artifact_sha256)
        and isinstance(evidence.provider_id, str)
        and _IDENTIFIER.fullmatch(evidence.provider_id)
        and isinstance(evidence.provider_version, str)
        and _SEMVER.fullmatch(evidence.provider_version)
        and isinstance(evidence.provider_kind, IdentityProviderKind)
        and _sha(evidence.provider_evidence_sha256)
        and _sha(evidence.adapter_artifact_sha256)
        and _sha(evidence.execution_transcript_sha256)
        and _sha(evidence.environment_evidence_sha256)
        and _sha(evidence.recovery_evidence_sha256)
    )


def evaluate_identity_provider_qualification(
    evidence: IdentityProviderQualificationEvidence,
) -> IdentityProviderQualificationDecision:
    """Evaluate real-provider evidence without granting runtime authority."""

    if not isinstance(evidence, IdentityProviderQualificationEvidence):
        raise IdentityProviderQualificationError("identity_provider_qualification_evidence_invalid")
    if not _identity_valid(evidence):
        raise IdentityProviderQualificationError("identity_provider_qualification_identity_invalid")

    checks = (
        ("real_provider", evidence.real_provider_exercised),
        ("real_target", evidence.real_target_exercised),
        ("account_absence_preflight", evidence.account_absence_preflight_validated),
        ("start_contract", evidence.start_contract_validated),
        ("readback_contract", evidence.readback_contract_validated),
        ("secret_reference_only", evidence.secret_reference_only),
        ("secret_values_absent", evidence.secret_values_absent_from_evidence),
        ("durable_job_before_side_effect", evidence.durable_job_before_side_effect),
        ("ambiguous_outcome_fail_closed", evidence.ambiguous_outcome_fail_closed),
        ("automatic_retry_forbidden", evidence.automatic_retry_forbidden),
        ("provider_acceptance_not_success", evidence.provider_acceptance_not_success),
        ("post_condition_readback", evidence.post_condition_readback_required),
        ("emergency_admin_isolated", evidence.emergency_admin_isolated),
        ("privilege_grant_forbidden", evidence.arbitrary_privilege_grant_forbidden),
        ("external_publication_forbidden", evidence.external_publication_forbidden),
        ("recovery_semantics", evidence.recovery_semantics_validated),
    )
    blockers = tuple(name for name, passed in checks if passed is not True)
    digest_material = {
        "schema": SCHEMA,
        "version": evidence.version,
        "revision": evidence.revision,
        "candidate_artifact_sha256": evidence.candidate_artifact_sha256,
        "provider_id": evidence.provider_id,
        "provider_version": evidence.provider_version,
        "provider_kind": evidence.provider_kind.value,
        "provider_evidence_sha256": evidence.provider_evidence_sha256,
        "adapter_artifact_sha256": evidence.adapter_artifact_sha256,
        "execution_transcript_sha256": evidence.execution_transcript_sha256,
        "environment_evidence_sha256": evidence.environment_evidence_sha256,
        "recovery_evidence_sha256": evidence.recovery_evidence_sha256,
        "checks": {name: passed for name, passed in checks},
    }
    evidence_sha = hashlib.sha256(canonical_json(digest_material).encode("utf-8")).hexdigest()
    return IdentityProviderQualificationDecision(
        version=evidence.version,
        revision=evidence.revision,
        candidate_artifact_sha256=evidence.candidate_artifact_sha256,
        provider_id=evidence.provider_id,
        provider_version=evidence.provider_version,
        provider_kind=evidence.provider_kind.value,
        provider_evidence_sha256=evidence.provider_evidence_sha256,
        adapter_artifact_sha256=evidence.adapter_artifact_sha256,
        qualification_evidence_sha256=evidence_sha,
        qualified=not blockers,
        blockers=blockers,
    )


def decision_from_dict(value: object) -> IdentityProviderQualificationDecision:
    required = {
        "schema", "version", "revision", "candidate_artifact_sha256", "provider_id",
        "provider_version", "provider_kind", "provider_evidence_sha256",
        "adapter_artifact_sha256", "qualification_evidence_sha256", "qualified", "blockers",
        "provider_execution_authorized", "durable_state_change_authorized",
        "emergency_admin_mutation_authorized", "privilege_grant_authorized",
        "release_authorized", "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != SCHEMA:
        raise IdentityProviderQualificationError("identity_provider_qualification_decision_invalid")
    if any(
        value.get(name) is not False
        for name in (
            "provider_execution_authorized", "durable_state_change_authorized",
            "emergency_admin_mutation_authorized", "privilege_grant_authorized",
            "release_authorized", "external_publication_authorized",
        )
    ):
        raise IdentityProviderQualificationError("identity_provider_qualification_decision_invalid")
    blockers = value.get("blockers")
    if not isinstance(blockers, list) or any(not isinstance(item, str) or not item for item in blockers):
        raise IdentityProviderQualificationError("identity_provider_qualification_decision_invalid")
    try:
        decision = IdentityProviderQualificationDecision(
            version=value["version"],
            revision=value["revision"],
            candidate_artifact_sha256=value["candidate_artifact_sha256"],
            provider_id=value["provider_id"],
            provider_version=value["provider_version"],
            provider_kind=value["provider_kind"],
            provider_evidence_sha256=value["provider_evidence_sha256"],
            adapter_artifact_sha256=value["adapter_artifact_sha256"],
            qualification_evidence_sha256=value["qualification_evidence_sha256"],
            qualified=value["qualified"],
            blockers=tuple(blockers),
        )
    except (KeyError, TypeError) as exc:
        raise IdentityProviderQualificationError("identity_provider_qualification_decision_invalid") from exc
    if (
        decision.provider_kind not in {item.value for item in IdentityProviderKind}
        or not _SEMVER.fullmatch(decision.version)
        or not _REVISION.fullmatch(decision.revision)
        or not _SHA256.fullmatch(decision.candidate_artifact_sha256)
        or not _IDENTIFIER.fullmatch(decision.provider_id)
        or not _SEMVER.fullmatch(decision.provider_version)
        or not _SHA256.fullmatch(decision.provider_evidence_sha256)
        or not _SHA256.fullmatch(decision.adapter_artifact_sha256)
        or not _SHA256.fullmatch(decision.qualification_evidence_sha256)
        or type(decision.qualified) is not bool
        or decision.qualified != (len(decision.blockers) == 0)
        or decision.to_dict() != value
    ):
        raise IdentityProviderQualificationError("identity_provider_qualification_decision_invalid")
    return decision


def bind_qualified_identity_provider_adapter(
    *,
    adapter: object,
    provider: IdentityProviderCapability,
    decision: IdentityProviderQualificationDecision,
    expected_version: str,
    expected_revision: str,
    expected_candidate_artifact_sha256: str,
    expected_adapter_artifact_sha256: str,
) -> QualificationBoundIdentityProviderAdapter:
    """Bind a concrete adapter only to an exact qualified provider/candidate tuple."""

    if not isinstance(provider, IdentityProviderCapability) or not isinstance(
        decision, IdentityProviderQualificationDecision
    ):
        raise IdentityProviderQualificationError("identity_provider_qualification_binding_invalid")
    if (
        decision.qualified is not True
        or decision.blockers
        or decision.version != expected_version
        or decision.revision != expected_revision
        or decision.candidate_artifact_sha256 != expected_candidate_artifact_sha256
        or decision.adapter_artifact_sha256 != expected_adapter_artifact_sha256
        or decision.provider_id != provider.provider_id
        or decision.provider_version != provider.provider_version
        or decision.provider_kind != provider.provider_kind.value
        or decision.provider_evidence_sha256 != provider.evidence_sha256
        or not callable(getattr(adapter, "start", None))
        or not callable(getattr(adapter, "observe", None))
    ):
        raise IdentityProviderQualificationError("identity_provider_qualification_binding_invalid")
    return QualificationBoundIdentityProviderAdapter(
        adapter=adapter,  # type: ignore[arg-type]
        provider=provider,
        decision=decision,
    )
