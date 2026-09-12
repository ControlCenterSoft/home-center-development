"""Durable fail-closed NR2 de-enrollment execution and reconciliation runtime.

A confirmed de-enrollment plan can invoke a qualified provider mutation exactly once.
The provider response is never treated as proof of success: a fresh exact-bound read-back
must verify `unmanaged`/`absent` before local Household managed state may be cleared.
Ambiguous provider outcomes are persisted as reconciliation-required and are never
retried automatically; reconciliation is read-only.
"""
from __future__ import annotations

import hashlib
import threading
from typing import Any, Protocol

from .device_management_deenrollment import (
    DeviceManagementDeenrollmentError,
    DeviceManagementDeenrollmentPlan,
    confirm_deenrollment,
    readback_from_dict,
    verify_deenrollment,
)
from .device_management_deenrollment_runtime import (
    DeviceManagementDeenrollmentRuntimeError,
    DeviceManagementDeenrollmentRuntimeService,
)
from .home_services import HomeServiceCatalogError
from .household import Household, ManagedDevice
from .household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted, _snapshot_from_dict
from .household_store import HouseholdSnapshot, build_household_replacement
from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now

EXECUTE_REQUEST_SCHEMA = "home-center.device-management-deenrollment-execute-request.v1"
RECONCILE_REQUEST_SCHEMA = "home-center.device-management-deenrollment-reconcile-request.v1"
MUTATION_REQUEST_SCHEMA = "home-center.device-management-deenrollment-provider-mutation-request.v1"
MUTATION_RESULT_SCHEMA = "home-center.device-management-deenrollment-provider-mutation-result.v1"
APPLY_RECEIPT_SCHEMA = "home-center.device-management-deenrollment-managed-state-apply-receipt.v1"
COMPLETION_SCHEMA = "home-center.device-management-deenrollment-completion.v1"
EXECUTE_ACTION = "household.device.management.deenrollment.execute"
RECONCILE_ACTION = "household.device.management.deenrollment.reconcile"
_MUTATION_STATES = frozenset({"accepted", "rejected", "ambiguous"})


class DeviceManagementDeenrollmentExecutionRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DeviceManagementDeenrollmentProviderAdapter(Protocol):
    mutation_capable: bool

    def deenroll(self, request: dict[str, object]) -> object: ...

    def read_back(self, request: dict[str, object]) -> object: ...


def _digest(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class DeviceManagementDeenrollmentExecutionRuntimeService:
    """Execute one provider mutation, verify by read-back, then apply local state."""

    def __init__(
        self,
        store: StateStore,
        planning: DeviceManagementDeenrollmentRuntimeService,
        *,
        now=utc_now,
    ) -> None:
        self.store = store
        self.planning = planning
        self._now = now
        self._lock = threading.RLock()
        self._adapters: dict[str, DeviceManagementDeenrollmentProviderAdapter] = {}

    def register_adapter(self, provider_id: str, adapter: object) -> None:
        if (
            not isinstance(provider_id, str)
            or not provider_id
            or len(provider_id) > 128
            or provider_id in self._adapters
            or getattr(adapter, "mutation_capable", None) is not True
            or not callable(getattr(adapter, "deenroll", None))
            or not callable(getattr(adapter, "read_back", None))
        ):
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "invalid_device_management_deenrollment_execution_adapter_registration"
            )
        self._adapters[provider_id] = adapter  # type: ignore[assignment]

    def _adapter(self, provider_id: str) -> DeviceManagementDeenrollmentProviderAdapter:
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_execution_adapter_unavailable"
            )
        return adapter

    @staticmethod
    def _confirmation(envelope: dict[str, Any], plan: DeviceManagementDeenrollmentPlan):
        raw = envelope.get("confirmation")
        if not isinstance(raw, dict):
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_confirmation_required"
            )
        try:
            value = confirm_deenrollment(
                plan=plan,
                actor_member_id=raw.get("actor_member_id"),
                confirmed_at=raw.get("confirmed_at"),
            )
        except DeviceManagementDeenrollmentError as exc:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(exc.code) from exc
        if value.to_dict() != raw:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_confirmation_invalid"
            )
        return value

    @staticmethod
    def _mutation_result(raw: object, request: dict[str, object]) -> dict[str, object]:
        expected = {
            "schema",
            "plan_id",
            "provider_id",
            "provider_operation_id",
            "device_id",
            "member_id",
            "execution_job_id",
            "state",
        }
        if not isinstance(raw, dict) or set(raw) != expected:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_provider_outcome_ambiguous"
            )
        state = raw.get("state")
        if (
            raw.get("schema") != MUTATION_RESULT_SCHEMA
            or state not in _MUTATION_STATES
            or raw.get("plan_id") != request["plan_id"]
            or raw.get("provider_id") != request["provider_id"]
            or raw.get("provider_operation_id") != request["provider_operation_id"]
            or raw.get("device_id") != request["device_id"]
            or raw.get("member_id") != request["member_id"]
            or raw.get("execution_job_id") != request["execution_job_id"]
        ):
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_provider_outcome_ambiguous"
            )
        return dict(raw)

    @staticmethod
    def _read_request(plan: DeviceManagementDeenrollmentPlan) -> dict[str, object]:
        return {
            "schema": "home-center.device-management-deenrollment-readback-request.v1",
            "plan_id": plan.plan_id,
            "provider_id": plan.binding.provider_id,
            "provider_operation_id": plan.binding.provider_operation_id,
            "device_id": plan.binding.device_id,
            "member_id": plan.binding.member_id,
        }

    @staticmethod
    def _expected_snapshot(
        base: HouseholdSnapshot,
        plan: DeviceManagementDeenrollmentPlan,
    ) -> tuple[HouseholdSnapshot, dict[str, object]]:
        devices: list[ManagedDevice] = []
        matched = False
        for device in base.household.devices:
            if device.device_id != plan.binding.device_id:
                devices.append(device)
                continue
            matched = True
            if device.member_id != plan.binding.member_id:
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_binding_mismatch"
                )
            if not device.managed:
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_device_not_managed"
                )
            devices.append(
                ManagedDevice(
                    device_id=device.device_id,
                    member_id=device.member_id,
                    display_name=device.display_name,
                    managed=False,
                )
            )
        if not matched:
            raise DeviceManagementDeenrollmentExecutionRuntimeError("household_device_not_found")
        try:
            household = Household(
                household_id=base.household.household_id,
                members=base.household.members,
                devices=tuple(devices),
            )
            expected, commit = build_household_replacement(
                base,
                household,
                expected_resource_version=base.resource_version,
            )
        except HomeServiceCatalogError as exc:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(exc.code) from exc
        return expected, {
            "schema": APPLY_RECEIPT_SCHEMA,
            "state": "planned",
            "plan_id": plan.plan_id,
            "device_id": plan.binding.device_id,
            "member_id": plan.binding.member_id,
            "previous_snapshot_id": base.snapshot_id,
            "previous_resource_version": base.resource_version,
            "snapshot_id": expected.snapshot_id,
            "resource_version": expected.resource_version,
            "generation": expected.generation,
            "commit_id": commit.commit_id,
            "provider_readback_verified": True,
            "managed_state_change_authorized": True,
            "managed_state_applied": False,
            "policy_mutation_authorized": False,
            "device_record_removal_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    def _apply_verified(
        self,
        *,
        actor: str,
        correlation_id: str,
        key: str,
        envelope: dict[str, Any],
        plan: DeviceManagementDeenrollmentPlan,
        job_id: str,
        bindings: tuple[ActorBinding, ...],
    ) -> dict[str, object]:
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
        except Exception as exc:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_state_invalid"
            ) from exc
        expected_raw = envelope.get("expected_snapshot")
        apply_receipt = envelope.get("apply_receipt")
        if expected_raw is None:
            expected, apply_receipt = self._expected_snapshot(base, plan)
            pending = dict(envelope)
            pending.update(
                status="verified-pending-apply",
                expected_snapshot=expected.to_dict(),
                apply_receipt=apply_receipt,
            )
            self.store.set_meta(key, pending)
            envelope = pending
        else:
            try:
                expected = _snapshot_from_dict(expected_raw)
            except Exception as exc:
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_state_invalid"
                ) from exc
            if not isinstance(apply_receipt, dict) or apply_receipt.get("schema") != APPLY_RECEIPT_SCHEMA:
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_state_invalid"
                )

        current, current_bindings = self.planning._state()
        if current_bindings != bindings:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_stale"
            )
        if current == base:
            self.store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(expected, bindings))
        elif current != expected:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_stale"
            )

        readback, readback_bindings = self.planning._state()
        if readback != expected or readback_bindings != bindings:
            self.store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(base, bindings))
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_managed_state_readback_failed"
            )

        completed_apply = dict(apply_receipt)
        completed_apply.update(state="applied", managed_state_applied=True)
        job = self.store.job(job_id)
        if job is None:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_state_invalid"
            )
        if job.get("state") == "verifying":
            self.store.transition_action_job(
                job_id,
                expected_state="verifying",
                new_state="succeeded",
                evidence={
                    "schema": "home-center.device-management-deenrollment-completion-evidence.v1",
                    "plan_id": plan.plan_id,
                    "provider_mutation_result": envelope.get("mutation_result"),
                    "provider_readback": envelope.get("readback_result"),
                    "verification_receipt": envelope.get("verification_receipt"),
                    "managed_state_apply": completed_apply,
                    "provider_reinvoked": False,
                },
            )
        elif job.get("state") != "succeeded":
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "device_management_deenrollment_state_invalid"
            )

        completed = dict(envelope)
        completed.update(status="applied", apply_receipt=completed_apply)
        self.store.set_meta(key, completed)
        self.store.audit(
            actor=actor,
            action="household.device.management.deenrollment.complete",
            target=plan.binding.device_id,
            outcome="succeeded",
            correlation_id=correlation_id,
            details={
                "plan_id": plan.plan_id,
                "job_id": job_id,
                "snapshot_id": expected.snapshot_id,
                "resource_version": expected.resource_version,
                "generation": expected.generation,
                "provider_reinvoked": False,
                "managed_state_applied": True,
            },
        )
        return {
            "schema": COMPLETION_SCHEMA,
            "state": "applied",
            "verification": completed.get("verification_receipt"),
            "managed_state_apply": completed_apply,
        }

    def _mark_reconcile_required(
        self,
        *,
        key: str,
        envelope: dict[str, Any],
        job_id: str,
        from_state: str,
        code: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        self.store.transition_action_job(
            job_id,
            expected_state=from_state,
            new_state="failed",
            result=result
            or {
                "schema": "home-center.device-management-deenrollment-uncertain-result.v1",
                "state": "reconciliation-required",
                "code": code,
                "automatic_provider_retry_authorized": False,
            },
        )
        changed = dict(envelope)
        changed.update(status="reconcile-required", execution_job_id=job_id)
        if result is not None:
            changed["last_execution_result"] = result
        self.store.set_meta(key, changed)

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
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "invalid_device_management_deenrollment_execute_request"
            )
        idem = request.get("idempotency_key")
        if not isinstance(idem, str) or not 8 <= len(idem) <= 128:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "invalid_device_management_deenrollment_idempotency_key"
            )
        with self._lock:
            key, envelope, raw_plan = self.planning._load(request.get("plan_id"))
            if envelope.get("status") == "applied":
                verification = envelope.get("verification_receipt")
                apply_receipt = envelope.get("apply_receipt")
                if isinstance(verification, dict) and isinstance(apply_receipt, dict):
                    return {
                        "schema": COMPLETION_SCHEMA,
                        "state": "applied",
                        "verification": verification,
                        "managed_state_apply": apply_receipt,
                    }
            if envelope.get("status") == "reconcile-required":
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_reconciliation_required"
                )
            if envelope.get("status") != "confirmed":
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_confirmation_required"
                )
            plan = self.planning._rebuild(envelope, raw_plan)
            self.planning._revalidate(actor, envelope, plan)
            confirmation = self._confirmation(envelope, plan)
            adapter = self._adapter(plan.binding.provider_id)
            request_hash = _digest(
                {"plan_id": plan.plan_id, "confirmed": True, "idempotency_key": idem}
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=EXECUTE_ACTION,
                    actor=actor,
                    reason="explicit confirmed device de-enrollment",
                    idempotency_key=idem,
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.device-management-deenrollment-execution-preflight.v1",
                        "plan_id": plan.plan_id,
                        "provider_id": plan.binding.provider_id,
                        "device_id": plan.binding.device_id,
                        "provider_mutation_authorized": True,
                        "automatic_provider_retry_authorized": False,
                        "managed_state_change_authorized": False,
                    },
                    steps=[
                        {"step": "provider-deenroll", "state": "pending"},
                        {"step": "provider-read-back", "state": "pending"},
                        {"step": "verify-deenrollment", "state": "pending"},
                        {"step": "apply-managed-state", "state": "pending"},
                        {"step": "read-back-household", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_idempotency_conflict"
                ) from exc
            if not created:
                if job.get("state") == "succeeded" and envelope.get("status") == "applied":
                    return {
                        "schema": COMPLETION_SCHEMA,
                        "state": "applied",
                        "verification": envelope.get("verification_receipt"),
                        "managed_state_apply": envelope.get("apply_receipt"),
                    }
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_reconciliation_required"
                )

            running = self.store.transition_action_job(
                job["job_id"], expected_state="preflight", new_state="running"
            )
            mutation_request = {
                "schema": MUTATION_REQUEST_SCHEMA,
                "plan_id": plan.plan_id,
                "provider_id": plan.binding.provider_id,
                "provider_operation_id": plan.binding.provider_operation_id,
                "device_id": plan.binding.device_id,
                "member_id": plan.binding.member_id,
                "execution_job_id": running["job_id"],
                "idempotency_key": idem,
                "automatic_retry_authorized": False,
            }
            updated = dict(envelope)
            updated.update(status="provider-running", execution_job_id=running["job_id"])
            self.store.set_meta(key, updated)
            try:
                raw_mutation = adapter.deenroll(dict(mutation_request))
                mutation_result = self._mutation_result(raw_mutation, mutation_request)
            except DeviceManagementDeenrollmentExecutionRuntimeError as exc:
                self._mark_reconcile_required(
                    key=key,
                    envelope=updated,
                    job_id=running["job_id"],
                    from_state="running",
                    code=exc.code,
                )
                raise
            except Exception as exc:
                self._mark_reconcile_required(
                    key=key,
                    envelope=updated,
                    job_id=running["job_id"],
                    from_state="running",
                    code="device_management_deenrollment_provider_outcome_ambiguous",
                )
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_provider_outcome_ambiguous"
                ) from exc

            if mutation_result["state"] != "accepted":
                code = (
                    "device_management_deenrollment_provider_rejected"
                    if mutation_result["state"] == "rejected"
                    else "device_management_deenrollment_provider_outcome_ambiguous"
                )
                result = {
                    **mutation_result,
                    "automatic_provider_retry_authorized": False,
                    "managed_state_changed": False,
                }
                self.store.transition_action_job(
                    running["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result=result,
                )
                changed = dict(updated)
                changed.update(
                    status="provider-rejected" if mutation_result["state"] == "rejected" else "reconcile-required",
                    mutation_result=mutation_result,
                )
                self.store.set_meta(key, changed)
                raise DeviceManagementDeenrollmentExecutionRuntimeError(code)

            verifying = self.store.transition_action_job(
                running["job_id"],
                expected_state="running",
                new_state="verifying",
                result=mutation_result,
                steps=[
                    {"step": "provider-deenroll", "state": "succeeded"},
                    {"step": "provider-read-back", "state": "running"},
                    {"step": "verify-deenrollment", "state": "pending"},
                    {"step": "apply-managed-state", "state": "pending"},
                    {"step": "read-back-household", "state": "pending"},
                ],
            )
            changed = dict(updated)
            changed.update(status="verifying", mutation_result=mutation_result)
            self.store.set_meta(key, changed)
            try:
                result = readback_from_dict(adapter.read_back(self._read_request(plan)))
                receipt = verify_deenrollment(
                    plan=plan,
                    confirmation=confirmation,
                    readback=result.to_dict(),
                    now=self._now(),
                    job_id=verifying["job_id"],
                )
            except DeviceManagementDeenrollmentError as exc:
                self._mark_reconcile_required(
                    key=key,
                    envelope=changed,
                    job_id=verifying["job_id"],
                    from_state="verifying",
                    code=exc.code,
                )
                raise DeviceManagementDeenrollmentExecutionRuntimeError(exc.code) from exc
            except Exception as exc:
                self._mark_reconcile_required(
                    key=key,
                    envelope=changed,
                    job_id=verifying["job_id"],
                    from_state="verifying",
                    code="device_management_deenrollment_readback_unavailable",
                )
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_readback_unavailable"
                ) from exc

            verification = receipt.to_dict()
            changed.update(readback_result=result.to_dict(), verification_receipt=verification)
            if not receipt.verified:
                self.store.transition_action_job(
                    verifying["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    result=verification,
                )
                changed.update(status="reconcile-required")
                self.store.set_meta(key, changed)
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_verification_rejected"
                )

            snapshot, bindings = self.planning._state()
            try:
                base = _snapshot_from_dict(envelope.get("base_snapshot"))
            except Exception as exc:
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_state_invalid"
                ) from exc
            if snapshot != base:
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_stale"
                )
            self.store.set_meta(key, changed)
            return self._apply_verified(
                actor=actor,
                correlation_id=correlation_id,
                key=key,
                envelope=changed,
                plan=plan,
                job_id=verifying["job_id"],
                bindings=bindings,
            )

    def reconcile(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        required = {"schema", "plan_id", "idempotency_key"}
        if set(request) != required or request.get("schema") != RECONCILE_REQUEST_SCHEMA:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "invalid_device_management_deenrollment_reconcile_request"
            )
        idem = request.get("idempotency_key")
        if not isinstance(idem, str) or not 8 <= len(idem) <= 128:
            raise DeviceManagementDeenrollmentExecutionRuntimeError(
                "invalid_device_management_deenrollment_idempotency_key"
            )
        with self._lock:
            key, envelope, raw_plan = self.planning._load(request.get("plan_id"))
            if envelope.get("status") == "applied":
                return {
                    "schema": COMPLETION_SCHEMA,
                    "state": "applied",
                    "verification": envelope.get("verification_receipt"),
                    "managed_state_apply": envelope.get("apply_receipt"),
                }
            plan = self.planning._rebuild(envelope, raw_plan)
            confirmation = self._confirmation(envelope, plan)
            if envelope.get("status") == "verified-pending-apply":
                snapshot, bindings = self.planning._state()
                try:
                    base = _snapshot_from_dict(envelope.get("base_snapshot"))
                    expected = _snapshot_from_dict(envelope.get("expected_snapshot"))
                except Exception as exc:
                    raise DeviceManagementDeenrollmentExecutionRuntimeError(
                        "device_management_deenrollment_state_invalid"
                    ) from exc
                if snapshot not in {base, expected}:
                    raise DeviceManagementDeenrollmentExecutionRuntimeError(
                        "device_management_deenrollment_stale"
                    )
                job_id = envelope.get("execution_job_id")
                if not isinstance(job_id, str):
                    raise DeviceManagementDeenrollmentExecutionRuntimeError(
                        "device_management_deenrollment_state_invalid"
                    )
                return self._apply_verified(
                    actor=actor,
                    correlation_id=correlation_id,
                    key=key,
                    envelope=envelope,
                    plan=plan,
                    job_id=job_id,
                    bindings=bindings,
                )
            if envelope.get("status") != "reconcile-required":
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_reconciliation_not_required"
                )
            self.planning._revalidate(actor, envelope, plan)
            adapter = self._adapter(plan.binding.provider_id)
            request_hash = _digest({"plan_id": plan.plan_id, "idempotency_key": idem})
            try:
                job, created = self.store.create_action_job(
                    action_id=RECONCILE_ACTION,
                    actor=actor,
                    reason="read-only de-enrollment reconciliation",
                    idempotency_key=idem,
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.device-management-deenrollment-reconcile-preflight.v1",
                        "plan_id": plan.plan_id,
                        "provider_id": plan.binding.provider_id,
                        "provider_mutation_authorized": False,
                        "managed_state_change_authorized": False,
                        "automatic_provider_retry_authorized": False,
                    },
                    steps=[
                        {"step": "provider-read-back", "state": "pending"},
                        {"step": "verify-deenrollment", "state": "pending"},
                        {"step": "apply-managed-state", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_idempotency_conflict"
                ) from exc
            if not created:
                latest = self.planning._load(plan.plan_id)[1]
                if latest.get("status") == "applied":
                    return {
                        "schema": COMPLETION_SCHEMA,
                        "state": "applied",
                        "verification": latest.get("verification_receipt"),
                        "managed_state_apply": latest.get("apply_receipt"),
                    }
                receipt = latest.get("verification_receipt")
                if job.get("state") == "succeeded" and isinstance(receipt, dict):
                    return dict(receipt)
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_reconciliation_in_progress"
                )

            running = self.store.transition_action_job(
                job["job_id"], expected_state="preflight", new_state="running"
            )
            try:
                result = readback_from_dict(adapter.read_back(self._read_request(plan)))
                receipt = verify_deenrollment(
                    plan=plan,
                    confirmation=confirmation,
                    readback=result.to_dict(),
                    now=self._now(),
                    job_id=running["job_id"],
                )
            except DeviceManagementDeenrollmentError as exc:
                self.store.transition_action_job(
                    running["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-deenrollment-reconcile-failure.v1",
                        "state": "failed",
                        "code": exc.code,
                        "provider_mutation_performed": False,
                    },
                )
                raise DeviceManagementDeenrollmentExecutionRuntimeError(exc.code) from exc
            except Exception as exc:
                self.store.transition_action_job(
                    running["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-deenrollment-reconcile-failure.v1",
                        "state": "failed",
                        "code": "device_management_deenrollment_readback_unavailable",
                        "provider_mutation_performed": False,
                    },
                )
                raise DeviceManagementDeenrollmentExecutionRuntimeError(
                    "device_management_deenrollment_readback_unavailable"
                ) from exc

            verifying = self.store.transition_action_job(
                running["job_id"],
                expected_state="running",
                new_state="verifying",
                result=result.to_dict(),
            )
            verification = receipt.to_dict()
            changed = dict(envelope)
            changed.update(
                readback_result=result.to_dict(),
                verification_receipt=verification,
            )
            if not receipt.verified:
                self.store.transition_action_job(
                    verifying["job_id"],
                    expected_state="verifying",
                    new_state="succeeded",
                    evidence={
                        "schema": "home-center.device-management-deenrollment-reconcile-evidence.v1",
                        "plan_id": plan.plan_id,
                        "provider_readback": result.to_dict(),
                        "verification_receipt": verification,
                        "provider_mutation_performed": False,
                        "managed_state_changed": False,
                    },
                )
                changed.update(status="reconcile-required")
                self.store.set_meta(key, changed)
                self.store.audit(
                    actor=actor,
                    action="household.device.management.deenrollment.reconcile",
                    target=plan.binding.device_id,
                    outcome="blocked",
                    correlation_id=correlation_id,
                    details={
                        "plan_id": plan.plan_id,
                        "job_id": verifying["job_id"],
                        "observed_state": receipt.observed_state,
                        "provider_reinvoked": False,
                        "managed_state_changed": False,
                    },
                )
                return verification

            changed.update(status="verified-pending-apply", execution_job_id=verifying["job_id"])
            self.store.set_meta(key, changed)
            _snapshot, bindings = self.planning._state()
            return self._apply_verified(
                actor=actor,
                correlation_id=correlation_id,
                key=key,
                envelope=changed,
                plan=plan,
                job_id=verifying["job_id"],
                bindings=bindings,
            )
