"""Fail-closed provider-backed enrollment execution planning and adapter boundary.

This module deliberately separates provider selection from provider execution.  A
confirmed selection is only evidence of *which* provider the user chose.  An
execution plan must be created and explicitly confirmed before an adapter may be
called.  Secret values never cross this boundary: adapters receive only bounded
secret references.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Protocol

from .device_management_provider import DeviceManagementProviderCatalog
from .home_services import HomeServiceCatalogError, _identifier


EXECUTION_PLAN_SCHEMA = "home-center.device-management-enrollment-execution-plan.v1"
ADAPTER_START_REQUEST_SCHEMA = "home-center.device-management-enrollment-adapter-start-request.v1"
ADAPTER_START_RESULT_SCHEMA = "home-center.device-management-enrollment-adapter-start-result.v1"
EXECUTION_RECEIPT_SCHEMA = "home-center.device-management-enrollment-execution-receipt.v1"

SELECTION_ID = re.compile(r"^dmpsel-[0-9a-f]{24}$")
PLAN_ID = re.compile(r"^dmpexec-[0-9a-f]{24}$")
CATALOG_ID = re.compile(r"^dmpcat-[0-9a-f]{24}$")
SECRET_REFERENCE = re.compile(r"^secret://[A-Za-z0-9][A-Za-z0-9._/-]{0,239}$")
PROVIDER_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RFC3339_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_CREDENTIAL_REFERENCES = 16
MIN_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 1800
ONE_TIME_ARTIFACT_KINDS = frozenset({"none", "token", "qr"})


class DeviceManagementEnrollmentExecutionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class CredentialReference:
    name: str
    reference: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "reference": self.reference}


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentExecutionPlan:
    plan_id: str
    selection_proposal_id: str
    enrollment_proposal_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    device_id: str
    member_id: str
    catalog_id: str
    provider_id: str
    enrollment_mode: str
    credential_references: tuple[CredentialReference, ...]
    timeout_seconds: int
    one_time_artifact: str
    schema: str = field(default=EXECUTION_PLAN_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    durable_job_required: bool = field(default=True, init=False)
    audit_required: bool = field(default=True, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "selection_proposal_id": self.selection_proposal_id,
            "enrollment_proposal_id": self.enrollment_proposal_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "catalog_id": self.catalog_id,
            "provider_id": self.provider_id,
            "enrollment_mode": self.enrollment_mode,
            "credential_references": [item.to_dict() for item in self.credential_references],
            "timeout_seconds": self.timeout_seconds,
            "one_time_artifact": self.one_time_artifact,
            "confirmation_required": True,
            "durable_job_required": True,
            "audit_required": True,
            "provider_execution_authorized": False,
            "credential_value_access_authorized": False,
            "policy_application_authorized": False,
            "managed_state_change_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentAdapterStartRequest:
    job_id: str
    plan_id: str
    provider_id: str
    device_id: str
    member_id: str
    enrollment_mode: str
    credential_references: tuple[CredentialReference, ...]
    timeout_seconds: int
    deadline_at: str
    one_time_artifact: str
    schema: str = field(default=ADAPTER_START_REQUEST_SCHEMA, init=False)
    provider_execution_authorized: bool = field(default=True, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "plan_id": self.plan_id,
            "provider_id": self.provider_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "enrollment_mode": self.enrollment_mode,
            "credential_references": [item.to_dict() for item in self.credential_references],
            "timeout_seconds": self.timeout_seconds,
            "deadline_at": self.deadline_at,
            "one_time_artifact": self.one_time_artifact,
            "provider_execution_authorized": True,
            "credential_value_access_authorized": False,
            "policy_application_authorized": False,
            "managed_state_change_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentAdapterStartResult:
    provider_operation_id: str
    one_time_artifact_kind: str
    one_time_artifact_reference: str | None
    one_time_artifact_expires_at: str | None
    schema: str = field(default=ADAPTER_START_RESULT_SCHEMA, init=False)
    state: str = field(default="accepted", init=False)
    post_condition_verified: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        artifact: dict[str, object] | None = None
        if self.one_time_artifact_kind != "none":
            artifact = {
                "kind": self.one_time_artifact_kind,
                "reference": self.one_time_artifact_reference,
                "expires_at": self.one_time_artifact_expires_at,
                "single_use": True,
            }
        return {
            "schema": self.schema,
            "state": "accepted",
            "provider_operation_id": self.provider_operation_id,
            "one_time_artifact": artifact,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        }


class DeviceManagementEnrollmentProviderAdapter(Protocol):
    """Typed provider boundary; implementations resolve secret refs outside this module."""

    def start(self, request: DeviceManagementEnrollmentAdapterStartRequest) -> object: ...

    def cancel(self, *, provider_operation_id: str, job_id: str) -> object: ...


def _provider_id(value: object) -> str:
    try:
        return _identifier(value, "invalid_device_management_provider_id")
    except HomeServiceCatalogError as exc:
        raise DeviceManagementEnrollmentExecutionError(exc.code) from exc


def _mode(value: object) -> str:
    try:
        return _identifier(value, "invalid_device_management_enrollment_mode")
    except HomeServiceCatalogError as exc:
        raise DeviceManagementEnrollmentExecutionError(exc.code) from exc


def normalize_credential_references(value: object) -> tuple[CredentialReference, ...]:
    if not isinstance(value, list) or len(value) > MAX_CREDENTIAL_REFERENCES:
        raise DeviceManagementEnrollmentExecutionError("invalid_device_management_credential_references")
    normalized: list[CredentialReference] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != {"name", "reference"}:
            raise DeviceManagementEnrollmentExecutionError("invalid_device_management_credential_reference")
        try:
            name = _identifier(raw.get("name"), "invalid_device_management_credential_reference_name")
        except HomeServiceCatalogError as exc:
            raise DeviceManagementEnrollmentExecutionError(exc.code) from exc
        reference = raw.get("reference")
        if (
            name in seen
            or not isinstance(reference, str)
            or SECRET_REFERENCE.fullmatch(reference) is None
            or ".." in reference.split("secret://", 1)[1].split("/")
        ):
            raise DeviceManagementEnrollmentExecutionError("invalid_device_management_credential_reference")
        seen.add(name)
        normalized.append(CredentialReference(name=name, reference=reference))
    return tuple(sorted(normalized, key=lambda item: item.name))


def _confirmed_selection(value: object) -> dict[str, object]:
    expected = {
        "schema", "proposal_id", "resolution_plan_id", "enrollment_proposal_id", "device_id", "member_id",
        "selected_provider_id", "snapshot_id", "resource_version", "generation", "catalog_id", "audit_event_id",
        "outcome", "provider_selected", "provider_execution_authorized", "credential_access_authorized",
        "enrollment_authorized", "policy_application_authorized", "managed_state_change_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementEnrollmentExecutionError("device_management_provider_selection_receipt_invalid")
    if (
        value.get("schema") != "home-center.device-management-provider-selection-confirmation.v1"
        or not isinstance(value.get("proposal_id"), str)
        or SELECTION_ID.fullmatch(value["proposal_id"]) is None
        or not isinstance(value.get("enrollment_proposal_id"), str)
        or not value["enrollment_proposal_id"]
        or not isinstance(value.get("device_id"), str)
        or not value["device_id"]
        or not isinstance(value.get("member_id"), str)
        or not value["member_id"]
        or not isinstance(value.get("snapshot_id"), str)
        or not value["snapshot_id"]
        or not isinstance(value.get("resource_version"), str)
        or not value["resource_version"]
        or isinstance(value.get("generation"), bool)
        or not isinstance(value.get("generation"), int)
        or value["generation"] < 1
        or not isinstance(value.get("catalog_id"), str)
        or CATALOG_ID.fullmatch(value["catalog_id"]) is None
        or not isinstance(value.get("audit_event_id"), str)
        or not value["audit_event_id"]
        or value.get("outcome") not in {"provider-selected", "already-confirmed"}
        or value.get("provider_selected") is not True
        or value.get("provider_execution_authorized") is not False
        or value.get("credential_access_authorized") is not False
        or value.get("enrollment_authorized") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("managed_state_change_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementEnrollmentExecutionError("device_management_provider_selection_receipt_invalid")
    return dict(value)


def _plan_identity(
    *,
    selection: dict[str, object],
    household_id: str,
    actor_member_id: str,
    provider_id: str,
    enrollment_mode: str,
    credential_references: tuple[CredentialReference, ...],
    timeout_seconds: int,
    one_time_artifact: str,
) -> str:
    canonical = {
        "selection_proposal_id": selection["proposal_id"],
        "enrollment_proposal_id": selection["enrollment_proposal_id"],
        "household_id": household_id,
        "snapshot_id": selection["snapshot_id"],
        "resource_version": selection["resource_version"],
        "generation": selection["generation"],
        "actor_member_id": actor_member_id,
        "device_id": selection["device_id"],
        "member_id": selection["member_id"],
        "catalog_id": selection["catalog_id"],
        "provider_id": provider_id,
        "enrollment_mode": enrollment_mode,
        "credential_references": [item.to_dict() for item in credential_references],
        "timeout_seconds": timeout_seconds,
        "one_time_artifact": one_time_artifact,
    }
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return "dmpexec-" + hashlib.sha256(encoded).hexdigest()[:24]


def build_enrollment_execution_plan(
    *,
    selection_confirmation: object,
    catalog: DeviceManagementProviderCatalog,
    household_id: str,
    snapshot_id: str,
    resource_version: str,
    generation: int,
    actor_member_id: str,
    enrollment_mode: object,
    credential_references: object,
    timeout_seconds: object,
    one_time_artifact: object,
) -> DeviceManagementEnrollmentExecutionPlan:
    selection = _confirmed_selection(selection_confirmation)
    if not isinstance(catalog, DeviceManagementProviderCatalog):
        raise DeviceManagementEnrollmentExecutionError("invalid_device_management_provider_catalog")
    if (
        selection["snapshot_id"] != snapshot_id
        or selection["resource_version"] != resource_version
        or selection["generation"] != generation
        or not isinstance(household_id, str)
        or not household_id
        or not isinstance(actor_member_id, str)
        or not actor_member_id
    ):
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_execution_stale")
    if selection["catalog_id"] != catalog.catalog_id:
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_execution_stale")

    provider_id = _provider_id(selection["selected_provider_id"])
    provider = next((item for item in catalog.providers if item.provider_id == provider_id), None)
    if provider is None or not provider.ready:
        raise DeviceManagementEnrollmentExecutionError("device_management_provider_not_available")
    mode = _mode(enrollment_mode)
    if mode not in provider.enrollment_modes:
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_mode_not_supported")
    references = normalize_credential_references(credential_references)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not (
        MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise DeviceManagementEnrollmentExecutionError("invalid_device_management_enrollment_timeout")
    if not isinstance(one_time_artifact, str) or one_time_artifact not in ONE_TIME_ARTIFACT_KINDS:
        raise DeviceManagementEnrollmentExecutionError("invalid_device_management_one_time_artifact")

    plan_id = _plan_identity(
        selection=selection,
        household_id=household_id,
        actor_member_id=actor_member_id,
        provider_id=provider_id,
        enrollment_mode=mode,
        credential_references=references,
        timeout_seconds=timeout_seconds,
        one_time_artifact=one_time_artifact,
    )
    return DeviceManagementEnrollmentExecutionPlan(
        plan_id=plan_id,
        selection_proposal_id=selection["proposal_id"],
        enrollment_proposal_id=selection["enrollment_proposal_id"],
        household_id=household_id,
        snapshot_id=snapshot_id,
        resource_version=resource_version,
        generation=generation,
        actor_member_id=actor_member_id,
        device_id=selection["device_id"],
        member_id=selection["member_id"],
        catalog_id=selection["catalog_id"],
        provider_id=provider_id,
        enrollment_mode=mode,
        credential_references=references,
        timeout_seconds=timeout_seconds,
        one_time_artifact=one_time_artifact,
    )


def execution_plan_from_dict(value: object) -> DeviceManagementEnrollmentExecutionPlan:
    expected = {
        "schema", "plan_id", "selection_proposal_id", "enrollment_proposal_id", "household_id", "snapshot_id",
        "resource_version", "generation", "actor_member_id", "device_id", "member_id", "catalog_id", "provider_id",
        "enrollment_mode", "credential_references", "timeout_seconds", "one_time_artifact", "confirmation_required",
        "durable_job_required", "audit_required", "provider_execution_authorized", "credential_value_access_authorized",
        "policy_application_authorized", "managed_state_change_authorized", "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != EXECUTION_PLAN_SCHEMA:
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_execution_plan_rejected")
    if (
        not isinstance(value.get("plan_id"), str)
        or PLAN_ID.fullmatch(value["plan_id"]) is None
        or not isinstance(value.get("selection_proposal_id"), str)
        or SELECTION_ID.fullmatch(value["selection_proposal_id"]) is None
        or not isinstance(value.get("enrollment_proposal_id"), str)
        or not value["enrollment_proposal_id"]
        or not isinstance(value.get("household_id"), str)
        or not value["household_id"]
        or not isinstance(value.get("snapshot_id"), str)
        or not value["snapshot_id"]
        or not isinstance(value.get("resource_version"), str)
        or not value["resource_version"]
        or isinstance(value.get("generation"), bool)
        or not isinstance(value.get("generation"), int)
        or value["generation"] < 1
        or not isinstance(value.get("actor_member_id"), str)
        or not value["actor_member_id"]
        or not isinstance(value.get("device_id"), str)
        or not value["device_id"]
        or not isinstance(value.get("member_id"), str)
        or not value["member_id"]
        or not isinstance(value.get("catalog_id"), str)
        or CATALOG_ID.fullmatch(value["catalog_id"]) is None
        or value.get("confirmation_required") is not True
        or value.get("durable_job_required") is not True
        or value.get("audit_required") is not True
        or value.get("provider_execution_authorized") is not False
        or value.get("credential_value_access_authorized") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("managed_state_change_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_execution_plan_rejected")
    provider_id = _provider_id(value.get("provider_id"))
    enrollment_mode = _mode(value.get("enrollment_mode"))
    references = normalize_credential_references(value.get("credential_references"))
    timeout_seconds = value.get("timeout_seconds")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not (
        MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_execution_plan_rejected")
    one_time_artifact = value.get("one_time_artifact")
    if not isinstance(one_time_artifact, str) or one_time_artifact not in ONE_TIME_ARTIFACT_KINDS:
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_execution_plan_rejected")
    plan = DeviceManagementEnrollmentExecutionPlan(
        plan_id=value["plan_id"],
        selection_proposal_id=value["selection_proposal_id"],
        enrollment_proposal_id=value["enrollment_proposal_id"],
        household_id=value["household_id"],
        snapshot_id=value["snapshot_id"],
        resource_version=value["resource_version"],
        generation=value["generation"],
        actor_member_id=value["actor_member_id"],
        device_id=value["device_id"],
        member_id=value["member_id"],
        catalog_id=value["catalog_id"],
        provider_id=provider_id,
        enrollment_mode=enrollment_mode,
        credential_references=references,
        timeout_seconds=timeout_seconds,
        one_time_artifact=one_time_artifact,
    )
    selection = {
        "proposal_id": plan.selection_proposal_id,
        "enrollment_proposal_id": plan.enrollment_proposal_id,
        "snapshot_id": plan.snapshot_id,
        "resource_version": plan.resource_version,
        "generation": plan.generation,
        "device_id": plan.device_id,
        "member_id": plan.member_id,
        "catalog_id": plan.catalog_id,
    }
    expected_id = _plan_identity(
        selection=selection,
        household_id=plan.household_id,
        actor_member_id=plan.actor_member_id,
        provider_id=plan.provider_id,
        enrollment_mode=plan.enrollment_mode,
        credential_references=plan.credential_references,
        timeout_seconds=plan.timeout_seconds,
        one_time_artifact=plan.one_time_artifact,
    )
    if plan.plan_id != expected_id or plan.to_dict() != value:
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_execution_plan_rejected")
    return plan


def adapter_result_from_dict(value: object, *, requested_artifact: str) -> DeviceManagementEnrollmentAdapterStartResult:
    expected = {
        "schema", "state", "provider_operation_id", "one_time_artifact",
        "post_condition_verified", "managed_state_change_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_adapter_result_rejected")
    operation_id = value.get("provider_operation_id")
    if (
        value.get("schema") != ADAPTER_START_RESULT_SCHEMA
        or value.get("state") != "accepted"
        or not isinstance(operation_id, str)
        or PROVIDER_OPERATION_ID.fullmatch(operation_id) is None
        or value.get("post_condition_verified") is not False
        or value.get("managed_state_change_authorized") is not False
    ):
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_adapter_result_rejected")
    artifact = value.get("one_time_artifact")
    if requested_artifact == "none":
        if artifact is not None:
            raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_adapter_result_rejected")
        kind = "none"
        reference = None
        expires_at = None
    else:
        if not isinstance(artifact, dict) or set(artifact) != {"kind", "reference", "expires_at", "single_use"}:
            raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_adapter_result_rejected")
        kind = artifact.get("kind")
        reference = artifact.get("reference")
        expires_at = artifact.get("expires_at")
        if (
            kind != requested_artifact
            or kind not in {"token", "qr"}
            or not isinstance(reference, str)
            or SECRET_REFERENCE.fullmatch(reference) is None
            or not isinstance(expires_at, str)
            or RFC3339_UTC_SECONDS.fullmatch(expires_at) is None
            or artifact.get("single_use") is not True
        ):
            raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_adapter_result_rejected")
    result = DeviceManagementEnrollmentAdapterStartResult(
        provider_operation_id=operation_id,
        one_time_artifact_kind=kind,
        one_time_artifact_reference=reference,
        one_time_artifact_expires_at=expires_at,
    )
    if result.to_dict() != value:
        raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_adapter_result_rejected")
    return result
