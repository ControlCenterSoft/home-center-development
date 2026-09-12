"""Strict untrusted-payload parsing for Home Center 0.59 Policy Composer.

Every parser is fail-closed: unknown fields, authority flag changes, malformed
identities and canonical-evidence mismatches are rejected before domain objects
are returned.
"""

from __future__ import annotations

from .household import HouseholdRole, InternetPolicy
from .policy_composer import (
    POLICY_BUNDLE_SCHEMA,
    POLICY_CHANGE_CONFIRMATION_SCHEMA,
    POLICY_CHANGE_PLAN_SCHEMA,
    POLICY_DESIRED_STATE_SCHEMA,
    PolicyBundle,
    PolicyChangeConfirmation,
    PolicyChangePlan,
    PolicyComposerError,
    PolicyDesiredState,
)


def _mapping(value: object, code: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PolicyComposerError(code)
    return value


def _exact(value: dict[str, object], expected: set[str], schema: str, code: str) -> None:
    if set(value) != expected or value.get("schema") != schema:
        raise PolicyComposerError(code)


def policy_bundle_from_dict(value: object) -> PolicyBundle:
    code = "invalid_policy_bundle"
    raw = _mapping(value, code)
    _exact(
        raw,
        {
            "schema",
            "bundle_id",
            "role",
            "internet_policy",
            "vpn_allowed",
            "managed_device_required",
            "home_files_allowed",
            "smart_home_control_allowed",
            "administration_allowed",
            "external_publication_allowed",
        },
        POLICY_BUNDLE_SCHEMA,
        code,
    )
    if raw.get("external_publication_allowed") is not False:
        raise PolicyComposerError(code)
    try:
        return PolicyBundle(
            bundle_id=raw["bundle_id"],
            role=HouseholdRole(raw["role"]),
            internet_policy=InternetPolicy(raw["internet_policy"]),
            vpn_allowed=raw["vpn_allowed"],
            managed_device_required=raw["managed_device_required"],
            home_files_allowed=raw["home_files_allowed"],
            smart_home_control_allowed=raw["smart_home_control_allowed"],
            administration_allowed=raw["administration_allowed"],
        )
    except PolicyComposerError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyComposerError(code) from exc


def policy_desired_state_from_dict(value: object) -> PolicyDesiredState:
    code = "invalid_policy_desired_state"
    raw = _mapping(value, code)
    _exact(
        raw,
        {
            "schema",
            "desired_state_id",
            "household_id",
            "member_id",
            "snapshot_id",
            "resource_version",
            "generation",
            "bundle",
            "provider_execution_authorized",
            "infrastructure_mutation_authorized",
            "external_publication_authorized",
        },
        POLICY_DESIRED_STATE_SCHEMA,
        code,
    )
    if (
        raw.get("provider_execution_authorized") is not False
        or raw.get("infrastructure_mutation_authorized") is not False
        or raw.get("external_publication_authorized") is not False
    ):
        raise PolicyComposerError(code)
    try:
        return PolicyDesiredState(
            desired_state_id=raw["desired_state_id"],
            household_id=raw["household_id"],
            member_id=raw["member_id"],
            snapshot_id=raw["snapshot_id"],
            resource_version=raw["resource_version"],
            generation=raw["generation"],
            bundle=policy_bundle_from_dict(raw["bundle"]),
        )
    except PolicyComposerError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyComposerError(code) from exc


def policy_change_plan_from_dict(value: object) -> PolicyChangePlan:
    code = "invalid_policy_change_plan"
    raw = _mapping(value, code)
    _exact(
        raw,
        {
            "schema",
            "plan_id",
            "household_id",
            "snapshot_id",
            "resource_version",
            "generation",
            "actor_member_id",
            "target_member_id",
            "current_policy_id",
            "current_bundle_id",
            "desired_state",
            "cozy_summary_ru",
            "recovery_bundle_id",
            "confirmation_required",
            "desired_state_write_authorized",
            "provider_execution_authorized",
            "infrastructure_mutation_authorized",
            "external_publication_authorized",
        },
        POLICY_CHANGE_PLAN_SCHEMA,
        code,
    )
    if (
        raw.get("confirmation_required") is not True
        or raw.get("desired_state_write_authorized") is not False
        or raw.get("provider_execution_authorized") is not False
        or raw.get("infrastructure_mutation_authorized") is not False
        or raw.get("external_publication_authorized") is not False
        or raw.get("recovery_bundle_id") != raw.get("current_bundle_id")
    ):
        raise PolicyComposerError(code)
    summary = raw.get("cozy_summary_ru")
    if not isinstance(summary, list) or not summary or any(not isinstance(item, str) for item in summary):
        raise PolicyComposerError(code)
    try:
        return PolicyChangePlan(
            plan_id=raw["plan_id"],
            household_id=raw["household_id"],
            snapshot_id=raw["snapshot_id"],
            resource_version=raw["resource_version"],
            generation=raw["generation"],
            actor_member_id=raw["actor_member_id"],
            target_member_id=raw["target_member_id"],
            current_policy_id=raw["current_policy_id"],
            current_bundle_id=raw["current_bundle_id"],
            desired_state=policy_desired_state_from_dict(raw["desired_state"]),
            cozy_summary_ru=tuple(summary),
        )
    except PolicyComposerError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyComposerError(code) from exc


def policy_change_confirmation_from_dict(value: object) -> PolicyChangeConfirmation:
    code = "invalid_policy_change_confirmation"
    raw = _mapping(value, code)
    _exact(
        raw,
        {
            "schema",
            "confirmation_id",
            "plan_id",
            "actor_member_id",
            "target_member_id",
            "snapshot_id",
            "resource_version",
            "generation",
            "desired_state_id",
            "audit_event_id",
            "desired_state_write_authorized",
            "provider_execution_authorized",
            "infrastructure_mutation_authorized",
            "external_publication_authorized",
            "automatic_recovery_authorized",
        },
        POLICY_CHANGE_CONFIRMATION_SCHEMA,
        code,
    )
    if (
        raw.get("desired_state_write_authorized") is not True
        or raw.get("provider_execution_authorized") is not False
        or raw.get("infrastructure_mutation_authorized") is not False
        or raw.get("external_publication_authorized") is not False
        or raw.get("automatic_recovery_authorized") is not False
    ):
        raise PolicyComposerError(code)
    try:
        return PolicyChangeConfirmation(
            confirmation_id=raw["confirmation_id"],
            plan_id=raw["plan_id"],
            actor_member_id=raw["actor_member_id"],
            target_member_id=raw["target_member_id"],
            snapshot_id=raw["snapshot_id"],
            resource_version=raw["resource_version"],
            generation=raw["generation"],
            desired_state_id=raw["desired_state_id"],
            audit_event_id=raw["audit_event_id"],
        )
    except PolicyComposerError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyComposerError(code) from exc
