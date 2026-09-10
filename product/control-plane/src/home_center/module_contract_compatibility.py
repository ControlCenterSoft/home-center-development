"""Versioned module-contract compatibility negotiation for Home Center admission."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping, Sequence


SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
CONTRACT_SCHEMA_ID = re.compile(
    r"^home-center\.[a-z0-9]+(?:-[a-z0-9]+)*\.v[1-9][0-9]*$"
)

CONTRACT_FAMILIES = (
    "module_manifest",
    "module_admission_decision",
    "module_admission_revalidation",
    "module_compatibility_snapshot",
    "module_admission_snapshot_binding",
    "module_admission_set_revalidation",
    "module_candidate_set_decision",
    "module_candidate_set_revalidation",
    "module_compatibility_policy_snapshot",
    "module_policy_candidate_set_decision",
    "module_policy_candidate_set_revalidation",
)
MANDATORY_NEGOTIATION_FAMILIES = (
    "module_manifest",
    "module_admission_decision",
)
DEFAULT_SUPPORTED_CONTRACTS: dict[str, tuple[str, ...]] = {
    "module_manifest": ("home-center.module-manifest.v2",),
    "module_admission_decision": (
        "home-center.module-admission-decision.v1",
    ),
    "module_admission_revalidation": (
        "home-center.module-admission-revalidation.v1",
    ),
    "module_compatibility_snapshot": (
        "home-center.module-compatibility-snapshot.v1",
    ),
    "module_admission_snapshot_binding": (
        "home-center.module-admission-snapshot-binding.v1",
    ),
    "module_admission_set_revalidation": (
        "home-center.module-admission-set-revalidation.v1",
    ),
    "module_candidate_set_decision": (
        "home-center.module-candidate-set-decision.v1",
    ),
    "module_candidate_set_revalidation": (
        "home-center.module-candidate-set-revalidation.v1",
    ),
    "module_compatibility_policy_snapshot": (
        "home-center.module-compatibility-policy-snapshot.v1",
    ),
    "module_policy_candidate_set_decision": (
        "home-center.module-policy-candidate-set-decision.v1",
    ),
    "module_policy_candidate_set_revalidation": (
        "home-center.module-policy-candidate-set-revalidation.v1",
    ),
}


class ModuleContractCompatibilityError(ValueError):
    """Stable rejection code for malformed contract-compatibility evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleContractCompatibilityProfile:
    """Canonical supported-contract identity for one Home Center version."""

    profile_id: str
    home_center_version: str
    supported_contracts: tuple[tuple[str, tuple[str, ...]], ...]
    schema: str = "home-center.module-contract-compatibility-profile.v1"
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "profile_id": self.profile_id,
            "home_center_version": self.home_center_version,
            "supported_contracts": {
                family: list(revisions)
                for family, revisions in self.supported_contracts
            },
            "admission_authorized": self.admission_authorized,
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": (
                self.external_publication_authorized
            ),
        }


@dataclass(frozen=True, slots=True)
class ModuleContractNegotiationDecision:
    """Fail-closed pre-admission decision for requested contract revisions."""

    decision_id: str
    profile_id: str
    home_center_version: str
    status: str
    requested_contracts: tuple[tuple[str, str], ...]
    unsupported_contracts: tuple[tuple[str, str], ...]
    reasons: tuple[str, ...]
    schema: str = "home-center.module-contract-negotiation-decision.v1"
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    @property
    def compatible(self) -> bool:
        return self.status == "compatible"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "decision_id": self.decision_id,
            "profile_id": self.profile_id,
            "home_center_version": self.home_center_version,
            "status": self.status,
            "requested_contracts": {
                family: revision
                for family, revision in self.requested_contracts
            },
            "unsupported_contracts": [
                {"family": family, "schema": revision}
                for family, revision in self.unsupported_contracts
            ],
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
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ModuleContractCompatibilityError(
            "contract_compatibility_evidence_rejected"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _version(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 64
        or SEMVER.fullmatch(value) is None
    ):
        raise ModuleContractCompatibilityError(
            "home_center_version_rejected"
        )
    return value


def _family(value: object) -> str:
    if not isinstance(value, str) or value not in CONTRACT_FAMILIES:
        raise ModuleContractCompatibilityError(
            "contract_family_rejected"
        )
    return value


def _schema_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or CONTRACT_SCHEMA_ID.fullmatch(value) is None
    ):
        raise ModuleContractCompatibilityError(
            "contract_schema_rejected"
        )
    return value


def _normalize_supported_contracts(
    values: Mapping[str, Sequence[str]],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if not isinstance(values, Mapping) or set(values) != set(CONTRACT_FAMILIES):
        raise ModuleContractCompatibilityError(
            "supported_contract_families_rejected"
        )
    normalized: list[tuple[str, tuple[str, ...]]] = []
    for raw_family, raw_revisions in values.items():
        family = _family(raw_family)
        if isinstance(raw_revisions, (str, bytes)):
            raise ModuleContractCompatibilityError(
                "supported_contract_revisions_rejected"
            )
        revisions = tuple(_schema_id(item) for item in raw_revisions)
        if (
            not revisions
            or len(revisions) > 16
            or len(revisions) != len(set(revisions))
        ):
            raise ModuleContractCompatibilityError(
                "supported_contract_revisions_rejected"
            )
        normalized.append((family, tuple(sorted(revisions))))
    return tuple(sorted(normalized))


def _profile_evidence(
    *,
    home_center_version: str,
    supported_contracts: tuple[tuple[str, tuple[str, ...]], ...],
) -> dict[str, object]:
    return {
        "schema": "home-center.module-contract-compatibility-profile.v1",
        "home_center_version": home_center_version,
        "supported_contracts": {
            family: list(revisions)
            for family, revisions in supported_contracts
        },
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }


def build_module_contract_compatibility_profile(
    *,
    home_center_version: str,
    supported_contracts: Mapping[str, Sequence[str]] | None = None,
) -> ModuleContractCompatibilityProfile:
    """Build a canonical, side-effect-free contract compatibility profile."""

    version = _version(home_center_version)
    source = (
        DEFAULT_SUPPORTED_CONTRACTS
        if supported_contracts is None
        else supported_contracts
    )
    normalized = _normalize_supported_contracts(source)
    evidence = _profile_evidence(
        home_center_version=version,
        supported_contracts=normalized,
    )
    profile_id = "mccp-" + _canonical_sha256(evidence)[:24]
    return ModuleContractCompatibilityProfile(
        profile_id=profile_id,
        home_center_version=version,
        supported_contracts=normalized,
    )


def _reconstruct_profile(
    profile: ModuleContractCompatibilityProfile,
) -> ModuleContractCompatibilityProfile:
    if not isinstance(profile, ModuleContractCompatibilityProfile):
        raise ModuleContractCompatibilityError(
            "contract_compatibility_profile_rejected"
        )
    reconstructed = build_module_contract_compatibility_profile(
        home_center_version=profile.home_center_version,
        supported_contracts=dict(profile.supported_contracts),
    )
    if reconstructed != profile:
        raise ModuleContractCompatibilityError(
            "contract_compatibility_profile_mismatch"
        )
    return reconstructed


def _normalize_requested_contracts(
    values: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    if not isinstance(values, Mapping) or len(values) > len(CONTRACT_FAMILIES):
        raise ModuleContractCompatibilityError(
            "requested_contracts_rejected"
        )
    if not set(MANDATORY_NEGOTIATION_FAMILIES).issubset(values):
        raise ModuleContractCompatibilityError(
            "mandatory_contracts_missing"
        )
    normalized: list[tuple[str, str]] = []
    for raw_family, raw_revision in values.items():
        family = _family(raw_family)
        revision = _schema_id(raw_revision)
        normalized.append((family, revision))
    return tuple(sorted(normalized))


def negotiate_module_contracts(
    profile: ModuleContractCompatibilityProfile,
    *,
    requested_contracts: Mapping[str, str],
) -> ModuleContractNegotiationDecision:
    """Negotiate contract revisions before any module admission decision."""

    profile = _reconstruct_profile(profile)
    requested = _normalize_requested_contracts(requested_contracts)
    supported = {
        family: set(revisions)
        for family, revisions in profile.supported_contracts
    }
    unsupported = tuple(
        (family, revision)
        for family, revision in requested
        if revision not in supported[family]
    )
    reasons = tuple(
        f"unsupported_contract:{family}:{revision}"
        for family, revision in unsupported
    )
    status = "compatible" if not unsupported else "unsupported-contract"
    evidence = {
        "schema": "home-center.module-contract-negotiation-decision.v1",
        "profile_id": profile.profile_id,
        "home_center_version": profile.home_center_version,
        "status": status,
        "requested_contracts": {
            family: revision for family, revision in requested
        },
        "unsupported_contracts": [
            {"family": family, "schema": revision}
            for family, revision in unsupported
        ],
        "reasons": list(reasons),
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    decision_id = "mcnd-" + _canonical_sha256(evidence)[:24]
    return ModuleContractNegotiationDecision(
        decision_id=decision_id,
        profile_id=profile.profile_id,
        home_center_version=profile.home_center_version,
        status=status,
        requested_contracts=requested,
        unsupported_contracts=unsupported,
        reasons=reasons,
    )
