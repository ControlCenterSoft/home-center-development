"""Fail-closed qualification evidence for Home Center 0.62 identity providers.

The evaluator is intentionally side-effect-free. It consumes bounded evidence from
an external real-provider qualification exercise and can produce a trusted
``IdentityProviderCapability`` only when the exact Home Center candidate, provider
artifact, real target, create/read-back behavior and safety boundaries were all
proven. A positive result grants no execution, infrastructure or publication
authority by itself.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .household import HouseholdRole
from .role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
)

SCHEMA = "home-center.role-identity-provider-qualification.v1"
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_ID = re.compile(r"[a-z][a-z0-9_.:-]{1,127}\Z")


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
    supported_roles: tuple[HouseholdRole, ...]
    account_create_supported: bool
    portable_home_supported: bool
    portable_profile_supported: bool
    secret_reference_supported: bool
    adapter_artifact_sha256: str
    execution_transcript_sha256: str
    readback_transcript_sha256: str
    environment_evidence_sha256: str
    real_provider_exercised: bool
    real_target_exercised: bool
    account_absence_preflight_exercised: bool
    create_contract_validated: bool
    readback_contract_validated: bool
    secret_reference_only: bool
    secret_values_absent_from_evidence: bool
    one_shot_mutation_preserved: bool
    ambiguous_outcome_fail_closed: bool
    exact_operation_binding_verified: bool
    account_identity_verified: bool
    home_directory_verified: bool
    profile_verified: bool
    emergency_admin_isolated: bool
    arbitrary_privilege_grant_forbidden: bool
    unrelated_account_mutation_forbidden: bool
    external_publication_forbidden: bool
    portable_home_exercised: bool = False
    portable_profile_exercised: bool = False


@dataclass(frozen=True, slots=True)
class IdentityProviderQualificationDecision:
    version: str
    revision: str
    candidate_artifact_sha256: str
    provider_id: str
    provider_version: str
    provider_kind: IdentityProviderKind
    supported_roles: tuple[HouseholdRole, ...]
    account_create_supported: bool
    portable_home_supported: bool
    portable_profile_supported: bool
    secret_reference_supported: bool
    evidence_sha256: str
    qualified: bool
    blockers: tuple[str, ...]
    schema: str = SCHEMA
    execution_authorized: bool = False
    infrastructure_mutation_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "version": self.version,
            "revision": self.revision,
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_kind": self.provider_kind.value,
            "supported_roles": [role.value for role in self.supported_roles],
            "account_create_supported": self.account_create_supported,
            "portable_home_supported": self.portable_home_supported,
            "portable_profile_supported": self.portable_profile_supported,
            "secret_reference_supported": self.secret_reference_supported,
            "evidence_sha256": self.evidence_sha256,
            "qualified": self.qualified,
            "blockers": list(self.blockers),
            "execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    def to_capability(self) -> IdentityProviderCapability:
        """Materialize server-side provider capability only from qualified evidence."""

        if not self.qualified or self.blockers or self.evidence_sha256 == "0" * 64:
            raise IdentityProviderQualificationError("identity_provider_not_qualified")
        return IdentityProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            provider_kind=self.provider_kind,
            supported_roles=self.supported_roles,
            account_create_supported=self.account_create_supported,
            portable_home_supported=self.portable_home_supported,
            portable_profile_supported=self.portable_profile_supported,
            secret_reference_supported=self.secret_reference_supported,
            evidence_sha256=self.evidence_sha256,
        )


def _sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _validate_identity(evidence: IdentityProviderQualificationEvidence) -> None:
    if _SEMVER.fullmatch(evidence.version) is None:
        raise IdentityProviderQualificationError("identity_provider_qualification_version_invalid")
    if _REVISION.fullmatch(evidence.revision) is None:
        raise IdentityProviderQualificationError("identity_provider_qualification_revision_invalid")
    if _PROVIDER_ID.fullmatch(evidence.provider_id) is None:
        raise IdentityProviderQualificationError("identity_provider_qualification_provider_id_invalid")
    if _SEMVER.fullmatch(evidence.provider_version) is None:
        raise IdentityProviderQualificationError("identity_provider_qualification_provider_version_invalid")
    if not isinstance(evidence.provider_kind, IdentityProviderKind):
        raise IdentityProviderQualificationError("identity_provider_qualification_provider_kind_invalid")
    if (
        not isinstance(evidence.supported_roles, tuple)
        or not evidence.supported_roles
        or any(not isinstance(role, HouseholdRole) for role in evidence.supported_roles)
        or len(set(evidence.supported_roles)) != len(evidence.supported_roles)
    ):
        raise IdentityProviderQualificationError("identity_provider_qualification_roles_invalid")
    bool_fields = (
        evidence.account_create_supported,
        evidence.portable_home_supported,
        evidence.portable_profile_supported,
        evidence.secret_reference_supported,
        evidence.real_provider_exercised,
        evidence.real_target_exercised,
        evidence.account_absence_preflight_exercised,
        evidence.create_contract_validated,
        evidence.readback_contract_validated,
        evidence.secret_reference_only,
        evidence.secret_values_absent_from_evidence,
        evidence.one_shot_mutation_preserved,
        evidence.ambiguous_outcome_fail_closed,
        evidence.exact_operation_binding_verified,
        evidence.account_identity_verified,
        evidence.home_directory_verified,
        evidence.profile_verified,
        evidence.emergency_admin_isolated,
        evidence.arbitrary_privilege_grant_forbidden,
        evidence.unrelated_account_mutation_forbidden,
        evidence.external_publication_forbidden,
        evidence.portable_home_exercised,
        evidence.portable_profile_exercised,
    )
    if any(type(value) is not bool for value in bool_fields):
        raise IdentityProviderQualificationError("identity_provider_qualification_boolean_invalid")


def evaluate_identity_provider_qualification(
    evidence: IdentityProviderQualificationEvidence,
) -> IdentityProviderQualificationDecision:
    """Evaluate exact-bound real-provider evidence without creating authority."""

    if not isinstance(evidence, IdentityProviderQualificationEvidence):
        raise IdentityProviderQualificationError("identity_provider_qualification_evidence_invalid")
    _validate_identity(evidence)

    blockers: list[str] = []
    for blocker, value in (
        ("candidate_artifact_digest", evidence.candidate_artifact_sha256),
        ("adapter_artifact_digest", evidence.adapter_artifact_sha256),
        ("execution_transcript_digest", evidence.execution_transcript_sha256),
        ("readback_transcript_digest", evidence.readback_transcript_sha256),
        ("environment_evidence_digest", evidence.environment_evidence_sha256),
    ):
        if not _sha256(value):
            blockers.append(blocker)

    checks = (
        ("account_create_capability", evidence.account_create_supported),
        ("real_provider", evidence.real_provider_exercised),
        ("real_target", evidence.real_target_exercised),
        ("account_absence_preflight", evidence.account_absence_preflight_exercised),
        ("create_contract", evidence.create_contract_validated),
        ("readback_contract", evidence.readback_contract_validated),
        ("secret_reference_only", evidence.secret_reference_only),
        ("secret_values_absent", evidence.secret_values_absent_from_evidence),
        ("one_shot_mutation", evidence.one_shot_mutation_preserved),
        ("ambiguous_outcome_fail_closed", evidence.ambiguous_outcome_fail_closed),
        ("exact_operation_binding", evidence.exact_operation_binding_verified),
        ("account_identity", evidence.account_identity_verified),
        ("home_directory", evidence.home_directory_verified),
        ("profile", evidence.profile_verified),
        ("emergency_admin_isolation", evidence.emergency_admin_isolated),
        ("privilege_grant_forbidden", evidence.arbitrary_privilege_grant_forbidden),
        ("unrelated_account_mutation_forbidden", evidence.unrelated_account_mutation_forbidden),
        ("external_publication_forbidden", evidence.external_publication_forbidden),
    )
    for blocker, passed in checks:
        if passed is not True:
            blockers.append(blocker)

    if evidence.portable_home_supported and not evidence.portable_home_exercised:
        blockers.append("portable_home_not_exercised")
    if evidence.portable_profile_supported and not evidence.portable_profile_exercised:
        blockers.append("portable_profile_not_exercised")
    if evidence.secret_reference_supported and not evidence.secret_reference_only:
        if "secret_reference_only" not in blockers:
            blockers.append("secret_reference_only")

    roles = tuple(sorted(evidence.supported_roles, key=lambda role: role.value))
    if blockers:
        evidence_sha256 = "0" * 64
    else:
        canonical = {
            "version": evidence.version,
            "revision": evidence.revision,
            "candidate_artifact_sha256": evidence.candidate_artifact_sha256,
            "provider_id": evidence.provider_id,
            "provider_version": evidence.provider_version,
            "provider_kind": evidence.provider_kind.value,
            "supported_roles": [role.value for role in roles],
            "account_create_supported": evidence.account_create_supported,
            "portable_home_supported": evidence.portable_home_supported,
            "portable_profile_supported": evidence.portable_profile_supported,
            "secret_reference_supported": evidence.secret_reference_supported,
            "adapter_artifact_sha256": evidence.adapter_artifact_sha256,
            "execution_transcript_sha256": evidence.execution_transcript_sha256,
            "readback_transcript_sha256": evidence.readback_transcript_sha256,
            "environment_evidence_sha256": evidence.environment_evidence_sha256,
        }
        payload = json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        evidence_sha256 = hashlib.sha256(payload).hexdigest()

    return IdentityProviderQualificationDecision(
        version=evidence.version,
        revision=evidence.revision,
        candidate_artifact_sha256=evidence.candidate_artifact_sha256,
        provider_id=evidence.provider_id,
        provider_version=evidence.provider_version,
        provider_kind=evidence.provider_kind,
        supported_roles=roles,
        account_create_supported=evidence.account_create_supported,
        portable_home_supported=evidence.portable_home_supported,
        portable_profile_supported=evidence.portable_profile_supported,
        secret_reference_supported=evidence.secret_reference_supported,
        evidence_sha256=evidence_sha256,
        qualified=not blockers,
        blockers=tuple(blockers),
    )
