"""Authoritative server-derived candidate source for Home Center 0.64.

The source converts a closed snapshot of Home Center-owned derived state into a
``RepairCandidate``.  It is intentionally read-only: current or unknown state
produces no candidate, and the resulting candidate never grants execution,
provider, infrastructure, credential, or publication authority.

Recovery evidence is not inferred.  A stale or missing derived object without a
verified recovery digest remains a candidate, but it is marked
``recovery_proven=False`` so the existing eligibility policy blocks automatic
repair.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .safe_auto_repair import RepairAction, RepairCandidate, RepairRisk
from .util import canonical_json

SAFE_REPAIR_DERIVED_STATE_OBSERVATION_SCHEMA = (
    "home-center.safe-repair-derived-state-observation.v1"
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\\Z")


class SafeRepairCandidateSourceError(ValueError):
    """Stable fail-closed rejection code for malformed server observations."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DerivedStateSource(StrEnum):
    """Closed Home Center-owned sources eligible for bounded local repair."""

    STATE_STORE_DERIVED_INDEX = "state-store-derived-index"
    STATE_STORE_LOCAL_READ_MODEL = "state-store-local-read-model"


class DerivedStateStatus(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    MISSING = "missing"
    UNKNOWN = "unknown"


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SafeRepairCandidateSourceError(code)
    return value


def _sha256(value: object, code: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SafeRepairCandidateSourceError(code)
    return value


@dataclass(frozen=True, slots=True)
class DerivedStateObservation:
    """Exact read-only observation emitted by a Home Center server store."""

    household_id: str
    resource_id: str
    resource_generation: int
    source: DerivedStateSource
    status: DerivedStateStatus
    expected_content_sha256: str
    actual_content_sha256: str | None
    observed_at_epoch: int
    recovery_evidence_sha256: str | None = None
    schema: str = field(
        default=SAFE_REPAIR_DERIVED_STATE_OBSERVATION_SCHEMA,
        init=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "household_id",
            _identifier(self.household_id, "safe_repair_source_household_id_invalid"),
        )
        object.__setattr__(
            self,
            "resource_id",
            _identifier(self.resource_id, "safe_repair_source_resource_id_invalid"),
        )
        if type(self.resource_generation) is not int or self.resource_generation < 0:
            raise SafeRepairCandidateSourceError(
                "safe_repair_source_resource_generation_invalid"
            )
        if not isinstance(self.source, DerivedStateSource):
            raise SafeRepairCandidateSourceError("safe_repair_source_kind_invalid")
        if not isinstance(self.status, DerivedStateStatus):
            raise SafeRepairCandidateSourceError("safe_repair_source_status_invalid")
        if type(self.observed_at_epoch) is not int or self.observed_at_epoch < 0:
            raise SafeRepairCandidateSourceError("safe_repair_source_timestamp_invalid")

        expected = _sha256(
            self.expected_content_sha256,
            "safe_repair_source_expected_digest_invalid",
        )
        actual = _sha256(
            self.actual_content_sha256,
            "safe_repair_source_actual_digest_invalid",
            optional=True,
        )
        recovery = _sha256(
            self.recovery_evidence_sha256,
            "safe_repair_source_recovery_digest_invalid",
            optional=True,
        )
        object.__setattr__(self, "expected_content_sha256", expected)
        object.__setattr__(self, "actual_content_sha256", actual)
        object.__setattr__(self, "recovery_evidence_sha256", recovery)

        if self.status in {DerivedStateStatus.CURRENT, DerivedStateStatus.STALE}:
            if actual is None:
                raise SafeRepairCandidateSourceError(
                    "safe_repair_source_actual_digest_required"
                )
        if self.status is DerivedStateStatus.CURRENT and actual != expected:
            raise SafeRepairCandidateSourceError(
                "safe_repair_source_current_digest_mismatch"
            )
        if self.status is DerivedStateStatus.STALE and actual == expected:
            raise SafeRepairCandidateSourceError("safe_repair_source_stale_digest_match")
        if self.status is DerivedStateStatus.MISSING and actual is not None:
            raise SafeRepairCandidateSourceError(
                "safe_repair_source_missing_actual_digest_present"
            )

    def evidence_material(self) -> dict[str, object]:
        """Return closed evidence material with explicit absent authorities."""

        return {
            "schema": self.schema,
            "household_id": self.household_id,
            "resource_id": self.resource_id,
            "resource_generation": self.resource_generation,
            "source": self.source.value,
            "status": self.status.value,
            "expected_content_sha256": self.expected_content_sha256,
            "actual_content_sha256": self.actual_content_sha256,
            "observed_at_epoch": self.observed_at_epoch,
            "recovery_evidence_sha256": self.recovery_evidence_sha256,
            "execution_authorized": False,
            "credential_value_access_authorized": False,
            "provider_execution_authorized": False,
            "generic_infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


_ACTION_BY_SOURCE = {
    DerivedStateSource.STATE_STORE_DERIVED_INDEX: RepairAction.REBUILD_DERIVED_INDEX,
    DerivedStateSource.STATE_STORE_LOCAL_READ_MODEL: RepairAction.REFRESH_LOCAL_READ_MODEL,
}


def derive_safe_repair_candidate(
    observation: DerivedStateObservation,
) -> RepairCandidate | None:
    """Create exact-bound eligibility input; never authorize or execute a repair."""

    if not isinstance(observation, DerivedStateObservation):
        raise TypeError("safe_repair_source_observation_invalid")
    if observation.status in {DerivedStateStatus.CURRENT, DerivedStateStatus.UNKNOWN}:
        return None

    evidence_sha256 = hashlib.sha256(
        canonical_json(observation.evidence_material()).encode("utf-8")
    ).hexdigest()
    return RepairCandidate(
        household_id=observation.household_id,
        resource_id=observation.resource_id,
        resource_generation=observation.resource_generation,
        evidence_sha256=evidence_sha256,
        action=_ACTION_BY_SOURCE[observation.source],
        risk=RepairRisk.LOW,
        recovery_proven=observation.recovery_evidence_sha256 is not None,
        post_condition_verifiable=True,
        provider_execution_required=False,
        infrastructure_mutation_required=False,
        external_publication_required=False,
    )


__all__ = [
    "DerivedStateObservation",
    "DerivedStateSource",
    "DerivedStateStatus",
    "SAFE_REPAIR_DERIVED_STATE_OBSERVATION_SCHEMA",
    "SafeRepairCandidateSourceError",
    "derive_safe_repair_candidate",
]
