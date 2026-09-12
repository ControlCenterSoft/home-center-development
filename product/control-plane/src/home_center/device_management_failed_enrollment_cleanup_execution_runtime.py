"""Bounded NR2 execution of an already-authorized failed-enrollment cleanup.

The cleanup verification boundary proves that the provider is freshly observed as
``unmanaged`` or ``absent``.  This module may then remove only the transient
one-time artifact reference that Home Center persisted while accepting the original
provider enrollment command.  It deliberately preserves the enrollment plan,
provider-selection evidence, rejected post-condition evidence, Household/device
records, Jobs and Audit history.

No provider call is made here and no managed/policy/infrastructure/publication state
is changed.  The reference is scrubbed atomically from every durable Home Center
location that copied it: the enrollment execution receipt, the original provider
acceptance Job result and the rejected post-condition verification envelope.
"""
from __future__ import annotations

import json
import re
import threading
from typing import Any

from .device_management_deenrollment import (
    DeviceManagementDeenrollmentError,
    authorize_failed_enrollment_cleanup,
    build_failed_enrollment_cleanup_plan,
)
from .device_management_enrollment_execution_runtime import (
    RETRY_ACTION,
    START_ACTION,
    STATE_SCHEMA as EXECUTION_STATE_SCHEMA,
    _key as execution_key,
)
from .device_management_enrollment_post_condition_runtime import (
    STATE_SCHEMA as VERIFICATION_STATE_SCHEMA,
    _key as verification_key,
)
from .device_management_failed_enrollment_cleanup_runtime import (
    STATE_SCHEMA as CLEANUP_STATE_SCHEMA,
    _key as cleanup_key,
)
from .home_services import HomeServiceCatalogError
from .household import effective_policy
from .household_runtime import HOUSEHOLD_STATE_KEY, _snapshot_from_dict, _state_from_dict
from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now

EXECUTE_REQUEST_SCHEMA = (
    "home-center.device-management-failed-enrollment-cleanup-runtime-execute-request.v1"
)
EXECUTION_RECEIPT_SCHEMA = (
    "home-center.device-management-failed-enrollment-cleanup-execution-receipt.v1"
)
ACTION = "household.device.management.enrollment.cleanup.execute"
IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _clone(value: object) -> Any:
    return json.loads(canonical_json(value))


class DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService:
    """Remove only transient one-time enrollment references after verified cleanup authority."""

    def __init__(self, store: StateStore, *, now=utc_now) -> None:
        self.store = store
        self._now = now
        self._lock = threading.RLock()

    def _state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "household_not_configured"
            )
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc

    @staticmethod
    def _actor_member(actor: str, snapshot: object, bindings: tuple[object, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "household_actor_not_bound"
            )
        try:
            policy = effective_policy(snapshot.household, member_id)
        except HomeServiceCatalogError as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(exc.code) from exc
        if not policy.administration_allowed:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_not_authorized"
            )
        return member_id

    def _load_cleanup(self, plan_id: object):
        try:
            key = cleanup_key(plan_id)
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_plan_not_found"
            ) from exc
        envelope = self.store.get_meta(key)
        if not isinstance(envelope, dict) or envelope.get("schema") != CLEANUP_STATE_SCHEMA:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_plan_not_found"
            )
        raw_plan = envelope.get("plan")
        rejected = envelope.get("verification_receipt")
        if not isinstance(raw_plan, dict) or not isinstance(rejected, dict):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_state_invalid"
            )
        try:
            plan = build_failed_enrollment_cleanup_plan(
                rejected_verification_receipt=rejected,
                cleanup_generation=raw_plan.get("cleanup_generation"),
                created_at=raw_plan.get("created_at"),
                max_observed_age_seconds=raw_plan.get("max_observed_age_seconds"),
            )
        except DeviceManagementDeenrollmentError as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(exc.code) from exc
        if plan.to_dict() != raw_plan:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_state_invalid"
            )
        return key, envelope, plan

    def _revalidate_authority(self, *, actor: str, envelope: dict[str, Any], plan: object) -> None:
        if envelope.get("status") != "authorized":
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_not_authorized"
            )
        snapshot, bindings = self._state()
        actor_member_id = self._actor_member(actor, snapshot, bindings)
        if actor_member_id != envelope.get("actor_member_id"):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_actor_mismatch"
            )
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_state_invalid"
            ) from exc
        if snapshot != base or [item.to_dict() for item in bindings] != envelope.get("bindings"):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_stale"
            )
        if plan.cleanup_generation != snapshot.generation:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_stale"
            )
        device = next(
            (item for item in snapshot.household.devices if item.device_id == plan.device_id),
            None,
        )
        if device is None:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "household_device_not_found"
            )
        if device.member_id != plan.member_id:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_binding_mismatch"
            )
        if device.managed:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_device_already_managed"
            )

        readback = envelope.get("readback_result")
        stored_receipt = envelope.get("receipt")
        if not isinstance(readback, dict) or not isinstance(stored_receipt, dict):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_state_invalid"
            )
        try:
            current_receipt = authorize_failed_enrollment_cleanup(
                plan=plan,
                readback=readback,
                now=self._now(),
            )
        except DeviceManagementDeenrollmentError as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(exc.code) from exc
        if current_receipt.to_dict() != stored_receipt or not current_receipt.cleanup_authorized:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_authorization_expired"
            )

        verification_id = envelope.get("verification_id")
        try:
            vkey = verification_key(verification_id)
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_verification_not_found"
            ) from exc
        verification = self.store.get_meta(vkey)
        if (
            not isinstance(verification, dict)
            or verification.get("schema") != VERIFICATION_STATE_SCHEMA
            or verification.get("status") != "rejected"
            or verification.get("receipt") != envelope.get("verification_receipt")
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_binding_mismatch"
            )

    @staticmethod
    def _artifact(value: object) -> tuple[str, str | None]:
        if value is None:
            return "none", None
        expected = {"kind", "reference", "expires_at", "single_use"}
        if not isinstance(value, dict) or set(value) != expected:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_transient_state_invalid"
            )
        kind = value.get("kind")
        reference = value.get("reference")
        expires_at = value.get("expires_at")
        if (
            kind not in {"token", "qr"}
            or not isinstance(reference, str)
            or not reference
            or not isinstance(expires_at, str)
            or not expires_at
            or value.get("single_use") is not True
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_transient_state_invalid"
            )
        return str(kind), reference

    def _source(self, envelope: dict[str, Any], plan: object):
        verification_id = envelope.get("verification_id")
        try:
            execution_meta_key = execution_key(plan.enrollment_plan_id)
            verification_meta_key = verification_key(verification_id)
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_binding_mismatch"
            ) from exc

        execution = self.store.get_meta(execution_meta_key)
        verification = self.store.get_meta(verification_meta_key)
        if (
            not isinstance(execution, dict)
            or execution.get("schema") != EXECUTION_STATE_SCHEMA
            or execution.get("status") != "provider-accepted"
            or not isinstance(verification, dict)
            or verification.get("schema") != VERIFICATION_STATE_SCHEMA
            or verification.get("status") != "rejected"
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_transient_state_invalid"
            )
        receipt = execution.get("receipt")
        copied_receipt = verification.get("execution_receipt")
        if not isinstance(receipt, dict) or not isinstance(copied_receipt, dict):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_transient_state_invalid"
            )
        required = {
            "plan_id": plan.enrollment_plan_id,
            "provider_id": plan.provider_id,
            "provider_operation_id": plan.provider_operation_id,
            "device_id": plan.device_id,
            "member_id": plan.member_id,
        }
        if any(receipt.get(name) != value for name, value in required.items()):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_binding_mismatch"
            )
        source_job_id = receipt.get("job_id")
        if not isinstance(source_job_id, str) or not source_job_id:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_transient_state_invalid"
            )
        job = self.store.job(source_job_id)
        if (
            not isinstance(job, dict)
            or job.get("state") != "succeeded"
            or job.get("job_type") not in {START_ACTION, RETRY_ACTION}
            or not isinstance(job.get("result"), dict)
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_transient_state_invalid"
            )
        result = job["result"]
        if result.get("provider_operation_id") != plan.provider_operation_id:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_binding_mismatch"
            )

        receipt_kind, receipt_reference = self._artifact(receipt.get("one_time_artifact"))
        copied_kind, copied_reference = self._artifact(copied_receipt.get("one_time_artifact"))
        result_kind, result_reference = self._artifact(result.get("one_time_artifact"))
        references = {value for value in (receipt_reference, copied_reference, result_reference) if value is not None}
        kinds = {value for value in (receipt_kind, copied_kind, result_kind) if value != "none"}
        if len(references) > 1 or len(kinds) > 1:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_transient_state_mismatch"
            )
        if references and any(value is None for value in (receipt_reference, copied_reference, result_reference)):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_transient_state_mismatch"
            )
        return {
            "execution_meta_key": execution_meta_key,
            "verification_meta_key": verification_meta_key,
            "source_job_id": source_job_id,
            "execution": execution,
            "verification": verification,
            "job_result": result,
            "artifact_kind": next(iter(kinds), "none"),
            "reference_present": bool(references),
        }

    def _scrub(self, source: dict[str, Any]) -> None:
        if not source["reference_present"]:
            return
        execution = _clone(source["execution"])
        verification = _clone(source["verification"])
        job_result = _clone(source["job_result"])
        execution["receipt"]["one_time_artifact"] = None
        verification["execution_receipt"]["one_time_artifact"] = None
        job_result["one_time_artifact"] = None
        now = utc_now()

        # This is deliberately one SQLite transaction.  Exposing a generic mutable
        # Job-result API would grant broader authority than this bounded redaction needs.
        with self.store._lock:  # noqa: SLF001 - same-package, narrowly bounded transaction
            connection = self.store._connection  # noqa: SLF001
            connection.execute("BEGIN IMMEDIATE")
            try:
                erow = connection.execute(
                    "SELECT value_json FROM cluster_meta WHERE key=?",
                    (source["execution_meta_key"],),
                ).fetchone()
                vrow = connection.execute(
                    "SELECT value_json FROM cluster_meta WHERE key=?",
                    (source["verification_meta_key"],),
                ).fetchone()
                jrow = connection.execute(
                    "SELECT state,result_json FROM jobs WHERE job_id=?",
                    (source["source_job_id"],),
                ).fetchone()
                if (
                    erow is None
                    or vrow is None
                    or jrow is None
                    or json.loads(erow[0]) != source["execution"]
                    or json.loads(vrow[0]) != source["verification"]
                    or jrow["state"] != "succeeded"
                    or json.loads(jrow["result_json"]) != source["job_result"]
                ):
                    raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                        "device_management_cleanup_transient_state_changed"
                    )
                connection.execute(
                    "UPDATE cluster_meta SET value_json=?,updated_at=? WHERE key=?",
                    (canonical_json(execution), now, source["execution_meta_key"]),
                )
                connection.execute(
                    "UPDATE cluster_meta SET value_json=?,updated_at=? WHERE key=?",
                    (canonical_json(verification), now, source["verification_meta_key"]),
                )
                connection.execute(
                    "UPDATE jobs SET result_json=?,updated_at=? WHERE job_id=? AND state='succeeded'",
                    (canonical_json(job_result), now, source["source_job_id"]),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _assert_scrubbed(self, envelope: dict[str, Any], plan: object) -> None:
        source = self._source(envelope, plan)
        if source["reference_present"]:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_transient_reference_still_present"
            )

    def _receipt(self, *, plan: object, job: dict[str, Any], artifact_kind: str) -> dict[str, object]:
        return {
            "schema": EXECUTION_RECEIPT_SCHEMA,
            "state": "cleaned",
            "job_id": job["job_id"],
            "cleanup_plan_id": plan.plan_id,
            "enrollment_plan_id": plan.enrollment_plan_id,
            "provider_id": plan.provider_id,
            "provider_operation_id": plan.provider_operation_id,
            "device_id": plan.device_id,
            "member_id": plan.member_id,
            "artifact_kind": artifact_kind,
            "one_time_reference_removed": artifact_kind != "none",
            "provider_mutation_performed": False,
            "managed_state_changed": False,
            "policy_mutation_performed": False,
            "device_record_removed": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
        }

    def _finish(
        self,
        *,
        cleanup_key_value: str,
        envelope: dict[str, Any],
        plan: object,
        job: dict[str, Any],
        artifact_kind: str,
        actor: str,
        correlation_id: str,
    ) -> dict[str, object]:
        current = job
        if current["state"] == "running":
            current = self.store.transition_action_job(
                current["job_id"],
                expected_state="running",
                new_state="verifying",
                result={
                    "schema": "home-center.device-management-failed-enrollment-cleanup-execution-result.v1",
                    "state": "transient-reference-scrubbed",
                    "cleanup_plan_id": plan.plan_id,
                    "artifact_kind": artifact_kind,
                    "provider_mutation_performed": False,
                    "managed_state_changed": False,
                },
                steps=[
                    {"step": "revalidate-cleanup-authority", "state": "succeeded"},
                    {"step": "scrub-transient-reference", "state": "succeeded"},
                    {"step": "verify-redaction", "state": "running"},
                ],
            )
        self._assert_scrubbed(envelope, plan)
        if current["state"] == "verifying":
            current = self.store.transition_action_job(
                current["job_id"],
                expected_state="verifying",
                new_state="succeeded",
                evidence={
                    "schema": "home-center.device-management-failed-enrollment-cleanup-execution-evidence.v1",
                    "cleanup_plan_id": plan.plan_id,
                    "enrollment_plan_id": plan.enrollment_plan_id,
                    "provider_operation_id": plan.provider_operation_id,
                    "artifact_kind": artifact_kind,
                    "one_time_reference_present": False,
                    "provider_mutation_performed": False,
                    "managed_state_changed": False,
                    "policy_mutation_performed": False,
                    "device_record_removed": False,
                },
                steps=[
                    {"step": "revalidate-cleanup-authority", "state": "succeeded"},
                    {"step": "scrub-transient-reference", "state": "succeeded"},
                    {"step": "verify-redaction", "state": "succeeded"},
                ],
            )
        receipt = self._receipt(plan=plan, job=current, artifact_kind=artifact_kind)
        latest = self.store.get_meta(cleanup_key_value)
        if not isinstance(latest, dict) or latest.get("schema") != CLEANUP_STATE_SCHEMA:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_state_invalid"
            )
        existing = latest.get("execution_receipt")
        if existing is not None and existing != receipt:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "device_management_cleanup_execution_state_invalid"
            )
        completed = dict(latest)
        completed.update(
            execution_job_id=current["job_id"],
            execution_receipt=receipt,
            transient_cleanup_completed=True,
        )
        self.store.set_meta(cleanup_key_value, completed)
        self.store.audit(
            actor=actor,
            action=ACTION,
            target=plan.device_id,
            outcome="accepted",
            correlation_id=correlation_id,
            details={
                "cleanup_plan_id": plan.plan_id,
                "job_id": current["job_id"],
                "enrollment_plan_id": plan.enrollment_plan_id,
                "provider_id": plan.provider_id,
                "artifact_kind": artifact_kind,
                "one_time_reference_present": False,
                "provider_mutation_performed": False,
                "managed_state_changed": False,
                "device_record_removed": False,
            },
        )
        return receipt

    def execute(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        required = {"schema", "plan_id", "confirmed", "idempotency_key"}
        if (
            set(request) != required
            or request.get("schema") != EXECUTE_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "invalid_device_management_cleanup_execution_request"
            )
        idempotency_key = request.get("idempotency_key")
        if not isinstance(idempotency_key, str) or IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                "invalid_device_management_cleanup_idempotency_key"
            )

        with self._lock:
            key, envelope, plan = self._load_cleanup(request.get("plan_id"))
            existing_receipt = envelope.get("execution_receipt")
            if envelope.get("transient_cleanup_completed") is True and isinstance(existing_receipt, dict):
                return dict(existing_receipt)

            self._revalidate_authority(actor=actor, envelope=envelope, plan=plan)
            source = self._source(envelope, plan)
            request_hash = canonical_json(
                {
                    "cleanup_plan_id": plan.plan_id,
                    "enrollment_plan_id": plan.enrollment_plan_id,
                    "idempotency_key": idempotency_key,
                }
            )
            job, created = self.store.create_action_job(
                action_id=ACTION,
                actor=actor,
                reason="explicit bounded failed-enrollment transient cleanup",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                preflight={
                    "schema": "home-center.device-management-failed-enrollment-cleanup-execution-preflight.v1",
                    "cleanup_plan_id": plan.plan_id,
                    "enrollment_plan_id": plan.enrollment_plan_id,
                    "provider_id": plan.provider_id,
                    "provider_operation_id": plan.provider_operation_id,
                    "artifact_kind": source["artifact_kind"],
                    "one_time_reference_present": source["reference_present"],
                    "provider_mutation_authorized": False,
                    "managed_state_change_authorized": False,
                    "device_record_removal_authorized": False,
                },
                steps=[
                    {"step": "revalidate-cleanup-authority", "state": "succeeded"},
                    {"step": "scrub-transient-reference", "state": "pending"},
                    {"step": "verify-redaction", "state": "pending"},
                ],
            )
            if not created:
                if job["state"] == "succeeded":
                    return self._finish(
                        cleanup_key_value=key,
                        envelope=envelope,
                        plan=plan,
                        job=job,
                        artifact_kind=str(job["preflight"].get("artifact_kind", "none")),
                        actor=actor,
                        correlation_id=correlation_id,
                    )
                if job["state"] == "failed":
                    raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                        "device_management_cleanup_previous_attempt_failed"
                    )
                if job["state"] == "preflight":
                    job = self.store.transition_action_job(
                        job["job_id"], expected_state="preflight", new_state="running"
                    )
                elif job["state"] not in {"running", "verifying"}:
                    raise DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError(
                        "device_management_cleanup_execution_in_progress"
                    )
            else:
                job = self.store.transition_action_job(
                    job["job_id"], expected_state="preflight", new_state="running"
                )

            source = self._source(envelope, plan)
            self._scrub(source)
            return self._finish(
                cleanup_key_value=key,
                envelope=envelope,
                plan=plan,
                job=job,
                artifact_kind=str(job["preflight"].get("artifact_kind", source["artifact_kind"])),
                actor=actor,
                correlation_id=correlation_id,
            )
