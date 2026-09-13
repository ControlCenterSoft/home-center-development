"""Exact candidate/adapter qualification binding for Home Center 0.59 enforcement.

This module prepares a non-authorizing handoff between real-backend qualification
and the policy enforcement runtime.  A binding is content-addressed by the
qualification decision and is intended to be persisted in the enforcement plan,
confirmation and Job preflight before a future runner-qualified integration wires
it into mutation execution.

The binding does not grant backend mutation, release or publication authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .policy_backend_qualification import (
    SCHEMA as POLICY_BACKEND_QUALIFICATION_SCHEMA,
    PolicyBackendQualificationDecision,
    QualificationBoundPolicyMutationAdapter,
)

SCHEMA = "home-center.household-policy-enforcement-qualification-binding.v1"
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")


class HouseholdPolicyEnforcementQualificationBindingError(ValueError):
    """Reject malformed, stale or self-declared enforcement qualification binding."""


@dataclass(frozen=True, slots=True)
class HouseholdPolicyEnforcementQualificationBinding:
    version: str
    revision: str
    candidate_artifact_sha256: str
    backend_id: str
    adapter_version: str
    adapter_artifact_sha256: str
    qualification_evidence_sha256: str
    schema: str = SCHEMA
    qualification_schema: str = POLICY_BACKEND_QUALIFICATION_SCHEMA
    backend_mutation_authorized: bool = False
    automatic_retry_authorized: bool = False
    enforcement_success_claim_authorized: bool = False
    release_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "version": self.version,
            "revision": self.revision,
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
            "backend_id": self.backend_id,
            "adapter_version": self.adapter_version,
            "adapter_artifact_sha256": self.adapter_artifact_sha256,
            "qualification_schema": self.qualification_schema,
            "qualification_evidence_sha256": self.qualification_evidence_sha256,
            "backend_mutation_authorized": False,
            "automatic_retry_authorized": False,
            "enforcement_success_claim_authorized": False,
            "release_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class QualificationBoundPolicyAdapterRegistration:
    """Concrete adapter plus immutable exact qualification binding."""

    adapter: QualificationBoundPolicyMutationAdapter
    binding: HouseholdPolicyEnforcementQualificationBinding


def _valid_binding_identity(binding: HouseholdPolicyEnforcementQualificationBinding) -> bool:
    return bool(
        binding.schema == SCHEMA
        and binding.qualification_schema == POLICY_BACKEND_QUALIFICATION_SCHEMA
        and _SEMVER.fullmatch(binding.version)
        and _REVISION.fullmatch(binding.revision)
        and _SHA256.fullmatch(binding.candidate_artifact_sha256)
        and _IDENTIFIER.fullmatch(binding.backend_id)
        and _SEMVER.fullmatch(binding.adapter_version)
        and _SHA256.fullmatch(binding.adapter_artifact_sha256)
        and _SHA256.fullmatch(binding.qualification_evidence_sha256)
        and binding.backend_mutation_authorized is False
        and binding.automatic_retry_authorized is False
        and binding.enforcement_success_claim_authorized is False
        and binding.release_authorized is False
        and binding.external_publication_authorized is False
    )


def build_qualification_bound_policy_adapter_registration(
    adapter: object,
    decision: PolicyBackendQualificationDecision,
    *,
    expected_version: str,
    expected_revision: str,
    expected_candidate_artifact_sha256: str,
    expected_backend_id: str,
    expected_adapter_version: str,
    expected_adapter_artifact_sha256: str,
) -> QualificationBoundPolicyAdapterRegistration:
    """Create the only accepted registration shape from exact qualified evidence.

    ``QualificationBoundPolicyMutationAdapter`` performs the existing exact
    decision/candidate/adapter checks.  This function adds an immutable projection
    suitable for persistence in a future enforcement plan and for restart-safe
    revalidation before backend invocation.
    """

    wrapper = QualificationBoundPolicyMutationAdapter(
        adapter,
        decision,
        expected_version=expected_version,
        expected_revision=expected_revision,
        expected_candidate_artifact_sha256=expected_candidate_artifact_sha256,
        expected_backend_id=expected_backend_id,
        expected_adapter_version=expected_adapter_version,
        expected_adapter_artifact_sha256=expected_adapter_artifact_sha256,
    )
    binding = HouseholdPolicyEnforcementQualificationBinding(
        version=decision.version,
        revision=decision.revision,
        candidate_artifact_sha256=decision.candidate_artifact_sha256,
        backend_id=wrapper.adapter_id,
        adapter_version=wrapper.adapter_version,
        adapter_artifact_sha256=wrapper.adapter_artifact_sha256,
        qualification_evidence_sha256=wrapper.qualification_evidence_sha256,
    )
    if not _valid_binding_identity(binding):
        raise HouseholdPolicyEnforcementQualificationBindingError(
            "household_policy_enforcement_qualification_binding_invalid"
        )
    return QualificationBoundPolicyAdapterRegistration(adapter=wrapper, binding=binding)


def qualification_binding_from_dict(value: object) -> HouseholdPolicyEnforcementQualificationBinding:
    """Parse a closed persisted binding; unknown fields fail closed."""

    required = {
        "schema",
        "version",
        "revision",
        "candidate_artifact_sha256",
        "backend_id",
        "adapter_version",
        "adapter_artifact_sha256",
        "qualification_schema",
        "qualification_evidence_sha256",
        "backend_mutation_authorized",
        "automatic_retry_authorized",
        "enforcement_success_claim_authorized",
        "release_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise HouseholdPolicyEnforcementQualificationBindingError(
            "household_policy_enforcement_qualification_binding_invalid"
        )
    try:
        binding = HouseholdPolicyEnforcementQualificationBinding(
            version=value["version"],
            revision=value["revision"],
            candidate_artifact_sha256=value["candidate_artifact_sha256"],
            backend_id=value["backend_id"],
            adapter_version=value["adapter_version"],
            adapter_artifact_sha256=value["adapter_artifact_sha256"],
            qualification_evidence_sha256=value["qualification_evidence_sha256"],
            schema=value["schema"],
            qualification_schema=value["qualification_schema"],
            backend_mutation_authorized=value["backend_mutation_authorized"],
            automatic_retry_authorized=value["automatic_retry_authorized"],
            enforcement_success_claim_authorized=value["enforcement_success_claim_authorized"],
            release_authorized=value["release_authorized"],
            external_publication_authorized=value["external_publication_authorized"],
        )
    except (KeyError, TypeError) as exc:
        raise HouseholdPolicyEnforcementQualificationBindingError(
            "household_policy_enforcement_qualification_binding_invalid"
        ) from exc
    if not _valid_binding_identity(binding):
        raise HouseholdPolicyEnforcementQualificationBindingError(
            "household_policy_enforcement_qualification_binding_invalid"
        )
    return binding


def revalidate_qualification_bound_policy_adapter_registration(
    registration: object,
    persisted_binding: object,
) -> HouseholdPolicyEnforcementQualificationBinding:
    """Fail closed if a persisted plan is replayed with another adapter/evidence.

    This check is deliberately side-effect free and performs no backend call.  It is
    intended to run immediately before durable Job admission and again before the
    single mutation invocation in the future enforcement integration.
    """

    if not isinstance(registration, QualificationBoundPolicyAdapterRegistration):
        raise HouseholdPolicyEnforcementQualificationBindingError(
            "household_policy_enforcement_qualification_registration_invalid"
        )
    if not isinstance(registration.adapter, QualificationBoundPolicyMutationAdapter):
        raise HouseholdPolicyEnforcementQualificationBindingError(
            "household_policy_enforcement_qualification_registration_invalid"
        )
    stored = qualification_binding_from_dict(persisted_binding)
    if registration.binding != stored:
        raise HouseholdPolicyEnforcementQualificationBindingError(
            "household_policy_enforcement_qualification_binding_stale"
        )
    adapter = registration.adapter
    if (
        getattr(adapter, "qualification_binding_schema", None)
        != POLICY_BACKEND_QUALIFICATION_SCHEMA
        or adapter.adapter_id != stored.backend_id
        or adapter.adapter_version != stored.adapter_version
        or adapter.adapter_artifact_sha256 != stored.adapter_artifact_sha256
        or adapter.qualification_evidence_sha256 != stored.qualification_evidence_sha256
    ):
        raise HouseholdPolicyEnforcementQualificationBindingError(
            "household_policy_enforcement_qualification_binding_stale"
        )
    return stored


def bounded_binding_summary(binding: object) -> dict[str, Any]:
    """Return review-safe identity only; never include credentials or provider payloads."""

    parsed = (
        binding
        if isinstance(binding, HouseholdPolicyEnforcementQualificationBinding)
        else qualification_binding_from_dict(binding)
    )
    if not _valid_binding_identity(parsed):
        raise HouseholdPolicyEnforcementQualificationBindingError(
            "household_policy_enforcement_qualification_binding_invalid"
        )
    return {
        "schema": parsed.schema,
        "version": parsed.version,
        "revision": parsed.revision,
        "candidate_artifact_sha256": parsed.candidate_artifact_sha256,
        "backend_id": parsed.backend_id,
        "adapter_version": parsed.adapter_version,
        "adapter_artifact_sha256": parsed.adapter_artifact_sha256,
        "qualification_evidence_sha256": parsed.qualification_evidence_sha256,
    }
