"""Versioned durable-state boundary for Home Center household data.

The store in this module models the product persistence contract without touching
provider infrastructure. It provides deterministic snapshot identities and
optimistic concurrency so Household/Intent work can reject stale writes before
later execution integration is introduced.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.household import Household


HOUSEHOLD_SNAPSHOT_SCHEMA = "home-center.household-snapshot.v1"
HOUSEHOLD_COMMIT_SCHEMA = "home-center.household-commit.v1"
MAX_GENERATION = 2**63 - 1


def _canonical_digest(household: Household, generation: int, previous_snapshot_id: str | None) -> str:
    canonical = {
        "household": household.to_dict(),
        "generation": generation,
        "previous_snapshot_id": previous_snapshot_id,
    }
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _commit_digest(
    *,
    operation: str,
    household_id: str,
    previous_resource_version: str | None,
    resource_version: str,
    generation: int,
    snapshot_id: str,
) -> str:
    canonical = {
        "operation": operation,
        "household_id": household_id,
        "previous_resource_version": previous_resource_version,
        "resource_version": resource_version,
        "generation": generation,
        "snapshot_id": snapshot_id,
    }
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class HouseholdSnapshot:
    snapshot_id: str
    resource_version: str
    household_id: str
    generation: int
    previous_snapshot_id: str | None
    household: Household
    schema: str = field(default=HOUSEHOLD_SNAPSHOT_SCHEMA, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        """Fail closed when callers attempt to construct forged snapshot evidence."""

        if not isinstance(self.household, Household):
            raise TypeError("invalid_household")
        household_id = _identifier(self.household_id, "invalid_household_id")
        if household_id != self.household.household_id:
            raise HomeServiceCatalogError("household_identity_conflict")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or not 1 <= self.generation <= MAX_GENERATION
        ):
            raise HomeServiceCatalogError("invalid_household_generation")
        if self.generation == 1:
            if self.previous_snapshot_id is not None:
                raise HomeServiceCatalogError("invalid_household_previous_snapshot")
            previous_snapshot_id = None
        else:
            previous_snapshot_id = _identifier(
                self.previous_snapshot_id,
                "invalid_household_previous_snapshot",
            )
        snapshot_id = _identifier(self.snapshot_id, "invalid_household_snapshot_id")
        resource_version = _identifier(
            self.resource_version,
            "invalid_household_resource_version",
        )
        digest = _canonical_digest(self.household, self.generation, previous_snapshot_id)
        if snapshot_id != "hsnap-" + digest[:24] or resource_version != "hrv-" + digest[24:48]:
            raise HomeServiceCatalogError("household_snapshot_evidence_mismatch")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "household_id": self.household_id,
            "generation": self.generation,
            "previous_snapshot_id": self.previous_snapshot_id,
            "household": self.household.to_dict(),
            "infrastructure_mutation_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class HouseholdCommit:
    commit_id: str
    operation: str
    household_id: str
    previous_resource_version: str | None
    resource_version: str
    generation: int
    snapshot_id: str
    schema: str = field(default=HOUSEHOLD_COMMIT_SCHEMA, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        """Keep commit evidence self-consistent even when directly constructed."""

        if self.operation not in {"create", "replace"}:
            raise HomeServiceCatalogError("invalid_household_commit_operation")
        household_id = _identifier(self.household_id, "invalid_household_id")
        resource_version = _identifier(self.resource_version, "invalid_household_resource_version")
        snapshot_id = _identifier(self.snapshot_id, "invalid_household_snapshot_id")
        commit_id = _identifier(self.commit_id, "invalid_household_commit_id")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or not 1 <= self.generation <= MAX_GENERATION
        ):
            raise HomeServiceCatalogError("invalid_household_generation")

        previous_resource_version = self.previous_resource_version
        if self.operation == "create":
            if previous_resource_version is not None or self.generation != 1:
                raise HomeServiceCatalogError("invalid_household_commit_transition")
        else:
            if self.generation < 2:
                raise HomeServiceCatalogError("invalid_household_commit_transition")
            previous_resource_version = _identifier(
                previous_resource_version,
                "invalid_household_resource_version",
            )

        digest = _commit_digest(
            operation=self.operation,
            household_id=household_id,
            previous_resource_version=previous_resource_version,
            resource_version=resource_version,
            generation=self.generation,
            snapshot_id=snapshot_id,
        )
        if commit_id != "hcommit-" + digest[:24]:
            raise HomeServiceCatalogError("household_commit_evidence_mismatch")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "commit_id": self.commit_id,
            "operation": self.operation,
            "household_id": self.household_id,
            "previous_resource_version": self.previous_resource_version,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "snapshot_id": self.snapshot_id,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def build_household_snapshot(
    household: Household,
    *,
    generation: int,
    previous_snapshot_id: str | None,
) -> HouseholdSnapshot:
    """Build deterministic Household snapshot evidence without storing it."""

    if not isinstance(household, Household):
        raise TypeError("invalid_household")
    if isinstance(generation, bool) or not isinstance(generation, int) or not 1 <= generation <= MAX_GENERATION:
        raise HomeServiceCatalogError("invalid_household_generation")
    if generation == 1:
        if previous_snapshot_id is not None:
            raise HomeServiceCatalogError("invalid_household_previous_snapshot")
    else:
        previous_snapshot_id = _identifier(previous_snapshot_id, "invalid_household_previous_snapshot")
    digest = _canonical_digest(household, generation, previous_snapshot_id)
    return HouseholdSnapshot(
        snapshot_id="hsnap-" + digest[:24],
        resource_version="hrv-" + digest[24:48],
        household_id=household.household_id,
        generation=generation,
        previous_snapshot_id=previous_snapshot_id,
        household=household,
    )


def build_household_commit(
    operation: str,
    previous_resource_version: str | None,
    snapshot: HouseholdSnapshot,
) -> HouseholdCommit:
    """Build deterministic commit evidence for a snapshot transition."""

    if operation not in {"create", "replace"}:
        raise HomeServiceCatalogError("invalid_household_commit_operation")
    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    if operation == "create":
        if previous_resource_version is not None or snapshot.generation != 1:
            raise HomeServiceCatalogError("invalid_household_commit_transition")
    else:
        if previous_resource_version is None or snapshot.generation < 2:
            raise HomeServiceCatalogError("invalid_household_commit_transition")
        previous_resource_version = _identifier(
            previous_resource_version,
            "invalid_household_resource_version",
        )
    digest = _commit_digest(
        operation=operation,
        household_id=snapshot.household_id,
        previous_resource_version=previous_resource_version,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        snapshot_id=snapshot.snapshot_id,
    )
    return HouseholdCommit(
        commit_id="hcommit-" + digest[:24],
        operation=operation,
        household_id=snapshot.household_id,
        previous_resource_version=previous_resource_version,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        snapshot_id=snapshot.snapshot_id,
    )


def build_household_replacement(
    current: HouseholdSnapshot,
    household: Household,
    *,
    expected_resource_version: str,
) -> tuple[HouseholdSnapshot, HouseholdCommit]:
    """Pure optimistic-concurrency replacement used by durable runtimes.

    The caller supplies the exact validated current snapshot. No state is
    mutated here, making the function reusable by persistent implementations.
    """

    if not isinstance(current, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    if not isinstance(household, Household):
        raise TypeError("invalid_household")
    if household.household_id != current.household_id:
        raise HomeServiceCatalogError("household_identity_conflict")
    expected = _identifier(expected_resource_version, "invalid_household_resource_version")
    if expected != current.resource_version:
        raise HomeServiceCatalogError("household_resource_version_conflict")
    if current.generation >= MAX_GENERATION:
        raise HomeServiceCatalogError("household_generation_exhausted")
    snapshot = build_household_snapshot(
        household,
        generation=current.generation + 1,
        previous_snapshot_id=current.snapshot_id,
    )
    commit = build_household_commit("replace", current.resource_version, snapshot)
    return snapshot, commit


class HouseholdStore:
    """In-memory reference implementation of the versioned household state contract."""

    def __init__(self) -> None:
        self._snapshots: dict[str, HouseholdSnapshot] = {}

    def read(self, household_id: str) -> HouseholdSnapshot:
        normalized = _identifier(household_id, "invalid_household_id")
        try:
            return self._snapshots[normalized]
        except KeyError as exc:
            raise HomeServiceCatalogError("household_not_found") from exc

    def create(self, household: Household) -> HouseholdCommit:
        if not isinstance(household, Household):
            raise TypeError("invalid_household")
        if household.household_id in self._snapshots:
            raise HomeServiceCatalogError("household_already_exists")
        snapshot = build_household_snapshot(household, generation=1, previous_snapshot_id=None)
        self._snapshots[household.household_id] = snapshot
        return build_household_commit("create", None, snapshot)

    def replace(self, household: Household, *, expected_resource_version: str) -> HouseholdCommit:
        current = self.read(household.household_id)
        snapshot, commit = build_household_replacement(
            current,
            household,
            expected_resource_version=expected_resource_version,
        )
        self._snapshots[household.household_id] = snapshot
        return commit
