"""Durable 0.58 post-condition verification runtime.

The 0.57 execution receipt proves only provider command acceptance. This layer
requires a separate read-only provider verification, persists that evidence, and
changes Household ``managed`` state only after exact snapshot/binding checks.

Provider verification adapters are explicitly observational. They never receive
Household mutation authority; only Home Center commits the managed-state change.
"""
from __future__ import annotations

import hashlib
import threading
from typing import Any

from .device_management_enrollment_execution import (
    DeviceManagementEnrollmentExecutionError,
    execution_plan_from_dict,
)
from .device_management_enrollment_execution_runtime import (
    STATE_SCHEMA as EXECUTION_STATE_SCHEMA,
    _key as execution_key,
)
from .device_management_enrollment_verification import (
    DeviceManagementEnrollmentAdapterVerifyRequest,
    DeviceManagementEnrollmentVerificationAdapter,
    DeviceManagementEnrollmentVerificationError,
    DeviceManagementEnrollmentVerificationPlan,
    adapter_request_for_plan,
    adapter_verification_result_from_dict,
    apply_verified_managed_state,
    build_enrollment_verification_plan,
)
from .household_runtime import (
    ActorBinding,
    HOUSEHOLD_STATE_KEY,
    _persisted,
    _snapshot_from_dict,
    _state_from_dict,
)
from .store import IdempotencyConflict, StateStore
from .util import canonical_json


PLAN_REQUEST_SCHEMA = "home-center.device-management-enrollment-verification-plan-request.v1"
CONFIRM_REQUEST_SCHEMA = "home-center.device-management-enrollment-verification-confirm-request.v1"
STATE_SCHEMA = "home-center.device-management-enrollment-verification-state.v1"
KEY_PREFIX = "cozy.household.device-enrollment-verification."
VERIFY_ACTION = "household.device.management.enrollment.verify"


class DeviceManagementEnrollmentVerificationRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _key(verification_id: object) -> str:
    if not isinstance(verification_id, str) or not verification_id.startswith("dmpverify-") or len(verification_id) != 34:
        raise DeviceManagementEnrollmentVerificationRuntimeError(
            "invalid_device_management_enrollment_verification_id"
        )
    suffix = verification_id.removeprefix("dmpverify-")
    if len(suffix) != 24 or any(char not in "0123456789abcdef" for char in suffix):
        raise DeviceManagementEnrollmentVerificationRuntimeError(
            "invalid_device_management_enrollment_verification_id"
        )
    return KEY_PREFIX + verification_id


def _hash(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class DeviceManagementEnrollmentVerificationRuntimeService:
    """Confirmation-gated verification and Household managed-state transition."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()
        self._adapters: dict[str, DeviceManagementEnrollmentVerificationAdapter] = {}

    def register_adapter(self, provider_id: str, adapter: object) -> None:
        """Register only adapters that explicitly declare observational semantics."""

        if (
            not isinstance(provider_id, str)
            or not provider_id
            or provider_id in self._adapters
            or getattr(adapter, "verification_read_only", None) is not True
            or not callable(getattr(adapter, "verify", None))
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "invalid_device_management_enrollment_verification_adapter_registration"
            )
        self._adapters[provider_id] = adapter  # type: ignore[assignment]

    def _state(self) -> tuple[object, tuple[ActorBinding, ...]]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementEnrollmentVerificationRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc

    @staticmethod
    def _actor(actor: str, bindings: tuple[ActorBinding, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise DeviceManagementEnrollmentVerificationRuntimeError("household_actor_not_bound")
        return member_id

    def _execution(self, plan_id: object) -> tuple[dict[str, Any], object, dict[str, object]]:
        try:
            key = execution_key(plan_id)
        except Exception as exc:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_execution_plan_not_found"
            ) from exc
        envelope = self.store.get_meta(key)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != EXECUTION_STATE_SCHEMA
            or envelope.get("status") != "provider-accepted"
            or isinstance(envelope.get("cancel_receipt"), dict)
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_execution_not_verifiable"
            )
        try:
            plan = execution_plan_from_dict(envelope.get("plan"))
        except DeviceManagementEnrollmentExecutionError as exc:
            raise DeviceManagementEnrollmentVerificationRuntimeError(exc.code) from exc
        receipt = envelope.get("receipt")
        if not isinstance(receipt, dict):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_execution_receipt_invalid"
            )
        return envelope, plan, dict(receipt)

    def _adapter(self, provider_id: str) -> DeviceManagementEnrollmentVerificationAdapter:
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_adapter_unavailable"
            )
        return adapter

    @staticmethod
    def _parse_plan(value: object) -> DeviceManagementEnrollmentVerificationPlan:
        if not isinstance(value, dict):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        required = {
            "schema", "verification_id", "execution_plan_id", "execution_job_id",
            "provider_id", "provider_operation_id", "household_id", "snapshot_id",
            "resource_version", "generation", "device_id", "member_id",
            "confirmation_required", "post_condition_verified",
            "managed_state_change_authorized", "policy_application_authorized",
            "infrastructure_mutation_authorized", "external_publication_authorized",
        }
        if set(value) != required:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        if (
            value.get("schema") != "home-center.device-management-enrollment-verification-plan.v1"
            or value.get("confirmation_required") is not True
            or value.get("post_condition_verified") is not False
            or value.get("managed_state_change_authorized") is not False
            or value.get("policy_application_authorized") is not False
            or value.get("infrastructure_mutation_authorized") is not False
            or value.get("external_publication_authorized") is not False
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        scalar_names = (
            "verification_id", "execution_plan_id", "execution_job_id", "provider_id",
            "provider_operation_id", "household_id", "snapshot_id", "resource_version",
            "device_id", "member_id",
        )
        if any(not isinstance(value.get(name), str) or not value[name] for name in scalar_names):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        generation = value.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        return DeviceManagementEnrollmentVerificationPlan(
            verification_id=value["verification_id"],
            execution_plan_id=value["execution_plan_id"],
            execution_job_id=value["execution_job_id"],
            provider_id=value["provider_id"],
            provider_operation_id=value["provider_operation_id"],
            household_id=value["household_id"],
            snapshot_id=value["snapshot_id"],
            resource_version=value["resource_version"],
            generation=generation,
            device_id=value["device_id"],
            member_id=value["member_id"],
        )

    def _load(self, verification_id: object) -> tuple[str, dict[str, Any], DeviceManagementEnrollmentVerificationPlan]:
        key = _key(verification_id)
        envelope = self.store.get_meta(key)
        if not isinstance(envelope, dict) or envelope.get("schema") != STATE_SCHEMA:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_plan_not_found"
            )
        plan = self._parse_plan(envelope.get("plan"))
        if plan.verification_id != verification_id:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        return key, envelope, plan

    def _jobs(self, verification_id: str) -> list[dict[str, Any]]:
        connection = getattr(self.store, "_connection", None)
        lock = getattr(self.store, "_lock", None)
        decoder = getattr(self.store, "_decode_job", None)
        if connection is not None and lock is not None and callable(decoder):
            with lock:
                rows = connection.execute(
                    """SELECT j.*,m.idempotency_key,m.request_hash,m.steps_json
                    FROM jobs AS j LEFT JOIN action_job_metadata AS m ON m.job_id=j.job_id
                    WHERE j.job_type=? ORDER BY j.created_at DESC,j.rowid DESC""",
                    (VERIFY_ACTION,),
                ).fetchall()
            jobs = [decoder(row) for row in rows]
        else:
            jobs = self.store.jobs(500)
        return [
            job
            for job in jobs
            if job.get("job_type") == VERIFY_ACTION
            and isinstance(job.get("preflight"), dict)
            and job["preflight"].get("verification_id") == verification_id
        ]

    def _revalidate(
        self,
        *,
        actor: str,
        envelope: dict[str, Any],
        plan: DeviceManagementEnrollmentVerificationPlan,
    ) -> tuple[object, tuple[ActorBinding, ...]]:
        snapshot, bindings = self._state()
        actor_member_id = self._actor(actor, bindings)
        execution_envelope, execution_plan, execution_receipt = self._execution(plan.execution_plan_id)
        if (
            actor_member_id != execution_plan.actor_member_id
            or execution_plan.provider_id != plan.provider_id
            or execution_plan.device_id != plan.device_id
            or execution_plan.member_id != plan.member_id
            or execution_receipt.get("job_id") != plan.execution_job_id
            or execution_receipt.get("provider_operation_id") != plan.provider_operation_id
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_binding_mismatch"
            )
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
            rebuilt = build_enrollment_verification_plan(
                snapshot=base,
                execution_plan=execution_envelope.get("plan"),
                execution_receipt=execution_receipt,
            )
        except Exception as exc:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                getattr(exc, "code", "device_management_enrollment_verification_state_invalid")
            ) from exc
        if rebuilt != plan:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        if (
            snapshot.snapshot_id != base.snapshot_id
            or snapshot.resource_version != base.resource_version
            or snapshot.generation != base.generation
            or snapshot.household != base.household
        ):
            expected_raw = envelope.get("expected_snapshot")
            if expected_raw is None:
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_stale"
                )
            try:
                expected = _snapshot_from_dict(expected_raw)
            except Exception as exc:
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_state_invalid"
                ) from exc
            if snapshot != expected:
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_stale"
                )
        return snapshot, bindings

    def plan(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "execution_plan_id"}
            or request.get("schema") != PLAN_REQUEST_SCHEMA
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "invalid_device_management_enrollment_verification_plan_request"
            )
        with self._lock:
            snapshot, bindings = self._state()
            actor_member_id = self._actor(actor, bindings)
            execution_envelope, execution_plan, execution_receipt = self._execution(
                request.get("execution_plan_id")
            )
            if actor_member_id != execution_plan.actor_member_id:
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_actor_mismatch"
                )
            try:
                plan = build_enrollment_verification_plan(
                    snapshot=snapshot,
                    execution_plan=execution_envelope.get("plan"),
                    execution_receipt=execution_receipt,
                )
            except DeviceManagementEnrollmentVerificationError as exc:
                raise DeviceManagementEnrollmentVerificationRuntimeError(exc.code) from exc
            key = _key(plan.verification_id)
            old = self.store.get_meta(key)
            envelope = {
                "schema": STATE_SCHEMA,
                "status": "planned",
                "plan": plan.to_dict(),
                "base_snapshot": snapshot.to_dict(),
                "execution_receipt": execution_receipt,
                "pre_audit_event_id": None,
                "adapter_result": None,
                "expected_snapshot": None,
                "commit": None,
                "receipt": None,
            }
            if old is None:
                self.store.set_meta(key, envelope)
            elif (
                not isinstance(old, dict)
                or old.get("schema") != STATE_SCHEMA
                or old.get("plan") != plan.to_dict()
                or old.get("base_snapshot") != snapshot.to_dict()
                or old.get("execution_receipt") != execution_receipt
            ):
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_state_invalid"
                )
            self.store.audit(
                actor=actor,
                action="household.device.management.enrollment-verification.plan",
                target=plan.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "verification_id": plan.verification_id,
                    "execution_plan_id": plan.execution_plan_id,
                    "execution_job_id": plan.execution_job_id,
                    "provider_id": plan.provider_id,
                    "post_condition_verified": False,
                    "managed_state_change_authorized": False,
                },
            )
            return plan.to_dict()

    def _validated_job_result(
        self,
        job: dict[str, Any],
        request: DeviceManagementEnrollmentAdapterVerifyRequest,
    ):
        result = job.get("result")
        try:
            return adapter_verification_result_from_dict(result, expected=request)
        except DeviceManagementEnrollmentVerificationError as exc:
            raise DeviceManagementEnrollmentVerificationRuntimeError(exc.code) from exc

    def _prepare_apply(
        self,
        *,
        actor: str,
        correlation_id: str,
        key: str,
        envelope: dict[str, Any],
        plan: DeviceManagementEnrollmentVerificationPlan,
        job: dict[str, Any],
    ) -> dict[str, Any]:
        request = adapter_request_for_plan(plan)
        adapter_result = self._validated_job_result(job, request)
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
            expected_snapshot, commit, receipt = apply_verified_managed_state(
                snapshot=base,
                plan=plan,
                adapter_result=adapter_result,
            )
        except Exception as exc:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                getattr(exc, "code", "device_management_enrollment_verification_state_invalid")
            ) from exc

        pre_audit_event_id = envelope.get("pre_audit_event_id")
        if not isinstance(pre_audit_event_id, str) or not pre_audit_event_id:
            pre_audit_event_id = self.store.audit(
                actor=actor,
                action="household.device.management.enrollment-verification.requested",
                target=plan.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "verification_id": plan.verification_id,
                    "job_id": job["job_id"],
                    "provider_id": plan.provider_id,
                    "provider_operation_id": plan.provider_operation_id,
                    "post_condition_verified": True,
                    "managed_state_change_authorized": False,
                },
            )
        updated = dict(envelope)
        updated.update(
            status="applying",
            pre_audit_event_id=pre_audit_event_id,
            adapter_result=adapter_result.to_dict(),
            expected_snapshot=expected_snapshot.to_dict(),
            commit=commit.to_dict(),
            receipt=receipt,
        )
        self.store.set_meta(key, updated)
        return updated

    def _finish_apply(
        self,
        *,
        actor: str,
        correlation_id: str,
        key: str,
        envelope: dict[str, Any],
        plan: DeviceManagementEnrollmentVerificationPlan,
        job: dict[str, Any],
    ) -> dict[str, object]:
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
            expected = _snapshot_from_dict(envelope.get("expected_snapshot"))
        except Exception as exc:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            ) from exc
        receipt = envelope.get("receipt")
        commit = envelope.get("commit")
        if (
            not isinstance(receipt, dict)
            or receipt.get("verification_id") != plan.verification_id
            or receipt.get("snapshot_id") != expected.snapshot_id
            or receipt.get("resource_version") != expected.resource_version
            or receipt.get("managed_state_change_authorized") is not True
            or receipt.get("policy_application_authorized") is not False
            or receipt.get("infrastructure_mutation_authorized") is not False
            or receipt.get("external_publication_authorized") is not False
            or not isinstance(commit, dict)
            or commit.get("snapshot_id") != expected.snapshot_id
            or commit.get("resource_version") != expected.resource_version
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )

        current, bindings = self._state()
        self._actor(actor, bindings)
        if current == base:
            self.store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(expected, bindings))
            current = expected
        elif current != expected:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_stale"
            )

        completion_audit_event_id = self.store.audit(
            actor=actor,
            action="household.device.management.enrollment-verification.apply",
            target=plan.device_id,
            outcome="succeeded",
            correlation_id=correlation_id,
            details={
                "verification_id": plan.verification_id,
                "job_id": job["job_id"],
                "provider_id": plan.provider_id,
                "provider_operation_id": plan.provider_operation_id,
                "previous_snapshot_id": base.snapshot_id,
                "snapshot_id": current.snapshot_id,
                "resource_version": current.resource_version,
                "commit_id": commit.get("commit_id"),
                "post_condition_verified": True,
                "managed_state_change_authorized": True,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
        )

        refreshed = self.store.job(job["job_id"])
        if refreshed is None:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        if refreshed.get("state") == "verifying":
            refreshed = self.store.transition_action_job(
                refreshed["job_id"],
                expected_state="verifying",
                new_state="succeeded",
                evidence={
                    "schema": "home-center.device-management-enrollment-verification-evidence.v1",
                    "scope": "provider-post-condition-and-household-managed-state",
                    "verification_id": plan.verification_id,
                    "provider_operation_id": plan.provider_operation_id,
                    "snapshot_id": current.snapshot_id,
                    "resource_version": current.resource_version,
                    "post_condition_verified": True,
                    "managed_state_change_authorized": True,
                    "policy_application_authorized": False,
                    "infrastructure_mutation_authorized": False,
                    "external_publication_authorized": False,
                },
            )
        elif refreshed.get("state") != "succeeded":
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )

        final = dict(envelope)
        final.update(
            status="applied",
            completion_audit_event_id=completion_audit_event_id,
            receipt=receipt,
        )
        self.store.set_meta(key, final)
        return dict(receipt)

    def confirm(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "verification_id", "confirmed", "idempotency_key"}
            or request.get("schema") != CONFIRM_REQUEST_SCHEMA
            or request.get("confirmed") is not True
            or not isinstance(request.get("idempotency_key"), str)
            or not request["idempotency_key"]
            or len(request["idempotency_key"]) > 128
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "invalid_device_management_enrollment_verification_confirm_request"
            )

        with self._lock:
            key, envelope, plan = self._load(request.get("verification_id"))
            status = envelope.get("status")
            if status not in {"planned", "applying", "applied"}:
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_state_invalid"
                )
            self._revalidate(actor=actor, envelope=envelope, plan=plan)

            if status == "applied":
                receipt = envelope.get("receipt")
                if not isinstance(receipt, dict):
                    raise DeviceManagementEnrollmentVerificationRuntimeError(
                        "device_management_enrollment_verification_state_invalid"
                    )
                return dict(receipt)

            jobs = self._jobs(plan.verification_id)
            if status == "applying":
                if not jobs:
                    raise DeviceManagementEnrollmentVerificationRuntimeError(
                        "device_management_enrollment_verification_state_invalid"
                    )
                latest = jobs[0]
                if latest.get("state") not in {"verifying", "succeeded"}:
                    raise DeviceManagementEnrollmentVerificationRuntimeError(
                        "device_management_enrollment_verification_state_invalid"
                    )
                return self._finish_apply(
                    actor=actor,
                    correlation_id=correlation_id,
                    key=key,
                    envelope=envelope,
                    plan=plan,
                    job=latest,
                )

            idempotency_key = request["idempotency_key"]
            active = [
                item for item in jobs
                if item.get("state") in {"preflight", "running", "verifying"}
            ]
            if active and not (
                active[0].get("initiator") == actor
                and active[0].get("idempotency_key") == idempotency_key
            ):
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_in_progress"
                )
            request_hash = _hash(
                {
                    "verification_id": plan.verification_id,
                    "execution_plan_id": plan.execution_plan_id,
                    "execution_job_id": plan.execution_job_id,
                    "idempotency_key": idempotency_key,
                }
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=VERIFY_ACTION,
                    actor=actor,
                    reason="explicit provider enrollment post-condition confirmation",
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.device-management-enrollment-verification-preflight.v1",
                        "verification_id": plan.verification_id,
                        "execution_plan_id": plan.execution_plan_id,
                        "execution_job_id": plan.execution_job_id,
                        "provider_id": plan.provider_id,
                        "provider_operation_id": plan.provider_operation_id,
                        "device_id": plan.device_id,
                        "managed_state_change_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate", "state": "succeeded"},
                        {"step": "provider-verify", "state": "pending"},
                        {"step": "apply-managed-state", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_idempotency_conflict"
                ) from exc

            if not created:
                if job.get("state") == "succeeded":
                    refreshed = self.store.get_meta(key)
                    if isinstance(refreshed, dict) and refreshed.get("status") == "applied":
                        receipt = refreshed.get("receipt")
                        if isinstance(receipt, dict):
                            return dict(receipt)
                    raise DeviceManagementEnrollmentVerificationRuntimeError(
                        "device_management_enrollment_verification_state_invalid"
                    )
                if job.get("state") == "failed":
                    raise DeviceManagementEnrollmentVerificationRuntimeError(
                        "device_management_enrollment_verification_previous_attempt_failed"
                    )
                if job.get("initiator") != actor or job.get("idempotency_key") != idempotency_key:
                    raise DeviceManagementEnrollmentVerificationRuntimeError(
                        "device_management_enrollment_verification_in_progress"
                    )

            adapter_request = adapter_request_for_plan(plan)
            adapter = self._adapter(plan.provider_id)

            if job.get("state") == "preflight":
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="preflight",
                    new_state="running",
                )
            elif job.get("state") == "verifying":
                applying = self._prepare_apply(
                    actor=actor,
                    correlation_id=correlation_id,
                    key=key,
                    envelope=envelope,
                    plan=plan,
                    job=job,
                )
                return self._finish_apply(
                    actor=actor,
                    correlation_id=correlation_id,
                    key=key,
                    envelope=applying,
                    plan=plan,
                    job=job,
                )
            elif job.get("state") != "running":
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_in_progress"
                )

            try:
                raw_result = adapter.verify(adapter_request)
                adapter_result = adapter_verification_result_from_dict(
                    raw_result,
                    expected=adapter_request,
                )
            except DeviceManagementEnrollmentVerificationError as exc:
                self.store.transition_action_job(
                    job["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-enrollment-verification-failure.v1",
                        "state": "failed",
                        "code": exc.code,
                        "post_condition_verified": False,
                        "managed_state_change_authorized": False,
                    },
                )
                raise DeviceManagementEnrollmentVerificationRuntimeError(exc.code) from exc
            except Exception as exc:
                self.store.transition_action_job(
                    job["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-enrollment-verification-failure.v1",
                        "state": "failed",
                        "code": "device_management_enrollment_verification_provider_error",
                        "post_condition_verified": False,
                        "managed_state_change_authorized": False,
                    },
                )
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_provider_error"
                ) from exc

            job = self.store.transition_action_job(
                job["job_id"],
                expected_state="running",
                new_state="verifying",
                result=adapter_result.to_dict(),
            )
            applying = self._prepare_apply(
                actor=actor,
                correlation_id=correlation_id,
                key=key,
                envelope=envelope,
                plan=plan,
                job=job,
            )
            return self._finish_apply(
                actor=actor,
                correlation_id=correlation_id,
                key=key,
                envelope=applying,
                plan=plan,
                job=job,
            )
