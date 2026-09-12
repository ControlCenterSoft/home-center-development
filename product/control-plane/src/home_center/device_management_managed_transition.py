"""Fail-closed 0.58 transition from verified enrollment to managed Household state.

This boundary never treats provider command acceptance as success.  It consumes
only a positively verified post-condition result, revalidates the exact
Household snapshot and parent authorization, then prepares a single optimistic
CAS replacement that flips exactly one ManagedDevice from ``managed=False`` to
``managed=True``.

The module does not apply PolicyBundle/EffectivePolicy, mutate provider state,
resolve credentials, publish services, or bypass the durable Household store.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .home_services import HomeServiceCatalogError, _identifier
from .household import Household, ManagedDevice, effective_policy
from .household_store import HouseholdCommit, HouseholdSnapshot, build_household_replacement
from .device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationResult,
)

MANAGED_TRANSITION_PLAN_SCHEMA = (
    "home-center.device-management-enrollment-managed-transition-plan.v1"
)
MANAGED_TRANSITION_RECEIPT_SCHEMA = (
    "home-center.device-management-enrollment-managed-transition-receipt.v1"
)


class DeviceManagementManagedTransitionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DeviceManagementManagedTransitionPlan:
    transition_id: str
    verification_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    device_id: str
    member_id: str
    provider_id: str
    provider_operation_id: str
    schema: str = field(default=MANAGED_TRANSITION_PLAN_SCHEMA, init=False)
    managed_before: bool = field(default=False, init=False)
    managed_after: bool = field(default=True, init=False)
    post_condition_verified: bool = field(default=True, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    provider_mutation_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "transition_id": self.transition_id,
            "verification_id": self.verification_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "managed_before": False,
            "managed_after": True,
            "post_condition_verified": True,
            "policy_application_authorized": False,
            "provider_mutation_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementManagedTransitionReceipt:
    transition_id: str
    verification_id: str
    household_id: str
    previous_snapshot_id: str
    previous_resource_version: str
    previous_generation: int
    snapshot_id: str
    resource_version: str
    generation: int
    commit_id: str
    device_id: str
    member_id: str
    schema: str = field(default=MANAGED_TRANSITION_RECEIPT_SCHEMA, init=False)
    outcome: str = field(default="applied", init=False)
    managed: bool = field(default=True, init=False)
    post_condition_verified: bool = field(default=True, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    provider_mutation_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "transition_id": self.transition_id,
            "verification_id": self.verification_id,
            "outcome": "applied",
            "household_id": self.household_id,
            "previous_snapshot_id": self.previous_snapshot_id,
            "previous_resource_version": self.previous_resource_version,
            "previous_generation": self.previous_generation,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "commit_id": self.commit_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "managed": True,
            "post_condition_verified": True,
            "policy_application_authorized": False,
            "provider_mutation_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _verified_result(
    value: object,
) -> DeviceManagementEnrollmentVerificationResult:
    if not isinstance(value, DeviceManagementEnrollmentVerificationResult):
        raise DeviceManagementManagedTransitionError(
            "device_management_enrollment_verification_result_invalid"
        )
    evidence = value.to_dict()
    if (
        evidence.get("state") != "verified"
        or evidence.get("enrollment_completed") is not True
        or evidence.get("post_condition_verified") is not True
        or evidence.get("managed_state_change_authorized") is not True
        or evidence.get("policy_application_authorized") is not False
        or evidence.get("infrastructure_mutation_authorized") is not False
        or evidence.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementManagedTransitionError(
            "device_management_enrollment_not_verified"
        )
    return value


def _device(snapshot: HouseholdSnapshot, device_id: str) -> ManagedDevice:
    normalized = _identifier(device_id, "invalid_household_device_id")
    for device in snapshot.household.devices:
        if device.device_id == normalized:
            return device
    raise DeviceManagementManagedTransitionError(
        "device_management_enrollment_device_not_found"
    )


def _transition_id(
    *,
    result: DeviceManagementEnrollmentVerificationResult,
    snapshot: HouseholdSnapshot,
    actor_member_id: str,
) -> str:
    canonical = {
        "verification_id": result.verification_id,
        "household_id": snapshot.household_id,
        "snapshot_id": snapshot.snapshot_id,
        "resource_version": snapshot.resource_version,
        "generation": snapshot.generation,
        "actor_member_id": actor_member_id,
        "device_id": result.device_id,
        "member_id": result.member_id,
        "provider_id": result.provider_id,
        "provider_operation_id": result.provider_operation_id,
        "managed_before": False,
        "managed_after": True,
    }
    encoded = json.dumps(
        canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return "dmmanaged-" + hashlib.sha256(encoded).hexdigest()[:24]


def build_managed_transition_plan(
    snapshot: HouseholdSnapshot,
    verification_result: object,
    *,
    actor_member_id: str,
) -> DeviceManagementManagedTransitionPlan:
    """Authorize one exact managed-state CAS from verified enrollment evidence."""

    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    result = _verified_result(verification_result)
    actor_id = _identifier(actor_member_id, "invalid_household_member_id")

    if (
        result.household_id != snapshot.household_id
        or result.snapshot_id != snapshot.snapshot_id
        or result.resource_version != snapshot.resource_version
        or result.generation != snapshot.generation
    ):
        raise DeviceManagementManagedTransitionError(
            "device_management_enrollment_managed_transition_stale"
        )

    try:
        actor_policy = effective_policy(snapshot.household, actor_id)
    except HomeServiceCatalogError as exc:
        raise DeviceManagementManagedTransitionError(exc.code) from exc
    if not actor_policy.administration_allowed:
        raise DeviceManagementManagedTransitionError(
            "device_management_enrollment_managed_transition_not_authorized"
        )

    device = _device(snapshot, result.device_id)
    if device.member_id != result.member_id:
        raise DeviceManagementManagedTransitionError(
            "device_management_enrollment_verification_binding_mismatch"
        )
    if device.managed:
        raise DeviceManagementManagedTransitionError(
            "device_management_enrollment_managed_transition_already_managed"
        )

    transition_id = _transition_id(
        result=result,
        snapshot=snapshot,
        actor_member_id=actor_id,
    )
    return DeviceManagementManagedTransitionPlan(
        transition_id=transition_id,
        verification_id=result.verification_id,
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id=actor_id,
        device_id=result.device_id,
        member_id=result.member_id,
        provider_id=result.provider_id,
        provider_operation_id=result.provider_operation_id,
    )


def apply_managed_transition(
    current: HouseholdSnapshot,
    plan: DeviceManagementManagedTransitionPlan,
    verification_result: object,
    *,
    actor_member_id: str,
) -> tuple[
    HouseholdSnapshot,
    HouseholdCommit,
    DeviceManagementManagedTransitionReceipt,
]:
    """Prepare the exact Household replacement and immutable transition receipt.

    The returned snapshot/commit still need to be persisted by the durable
    Household store with ``plan.resource_version`` as its compare-and-swap
    precondition. No provider or policy side effect is performed here.
    """

    if not isinstance(current, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    if not isinstance(plan, DeviceManagementManagedTransitionPlan):
        raise TypeError("invalid_device_management_managed_transition_plan")

    actor_id = _identifier(actor_member_id, "invalid_household_member_id")
    if actor_id != plan.actor_member_id:
        raise DeviceManagementManagedTransitionError(
            "device_management_enrollment_managed_transition_actor_mismatch"
        )
    if (
        current.household_id != plan.household_id
        or current.snapshot_id != plan.snapshot_id
        or current.resource_version != plan.resource_version
        or current.generation != plan.generation
    ):
        raise DeviceManagementManagedTransitionError(
            "device_management_enrollment_managed_transition_stale"
        )

    rebuilt = build_managed_transition_plan(
        current,
        verification_result,
        actor_member_id=actor_id,
    )
    if rebuilt != plan:
        raise DeviceManagementManagedTransitionError(
            "device_management_enrollment_managed_transition_evidence_mismatch"
        )

    devices: list[ManagedDevice] = []
    for device in current.household.devices:
        if device.device_id == plan.device_id:
            devices.append(
                ManagedDevice(
                    device_id=device.device_id,
                    member_id=device.member_id,
                    display_name=device.display_name,
                    managed=True,
                )
            )
        else:
            devices.append(device)

    replacement = Household(
        household_id=current.household_id,
        members=current.household.members,
        devices=tuple(devices),
    )
    snapshot, commit = build_household_replacement(
        current,
        replacement,
        expected_resource_version=plan.resource_version,
    )
    receipt = DeviceManagementManagedTransitionReceipt(
        transition_id=plan.transition_id,
        verification_id=plan.verification_id,
        household_id=plan.household_id,
        previous_snapshot_id=current.snapshot_id,
        previous_resource_version=current.resource_version,
        previous_generation=current.generation,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        commit_id=commit.commit_id,
        device_id=plan.device_id,
        member_id=plan.member_id,
    )
    return snapshot, commit, receipt
