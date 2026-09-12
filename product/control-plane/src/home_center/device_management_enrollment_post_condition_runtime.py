"""Durable 0.58 post-condition verification and managed-state apply boundary.

This layer consumes the pure 0.58 post-condition contracts and wires them to
authenticated Household state, durable Jobs, one-time re-auth grants and an
observational provider read-back adapter. Provider read-back never receives
authority to mutate Household state.
"""
from __future__ import annotations

import hashlib
import threading
from typing import Any, Protocol

from .device_management_enrollment_execution import (
    DeviceManagementEnrollmentExecutionError,
    execution_plan_from_dict,
)
from .device_management_enrollment_execution_runtime import (
    STATE_SCHEMA as EXECUTION_STATE_SCHEMA,
    _key as execution_key,
)
from .device_management_enrollment_verification import (
    DeviceManagementEnrollmentPostConditionRequest,
    DeviceManagementEnrollmentVerificationError,
    PostConditionBinding,
    request_from_dict,
    result_from_dict,
    verify_post_condition,
)
from .home_services import HomeServiceCatalogError
from .household import Household, ManagedDevice, effective_policy
from .household_runtime import (
    ActorBinding,
    HOUSEHOLD_STATE_KEY,
    _persisted,
    _snapshot_from_dict,
    _state_from_dict,
)
from .household_store import HouseholdSnapshot, build_household_replacement
from .step_up import StepUpError, StepUpGrantManager
from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now


PLAN_REQUEST_SCHEMA = "home-center.device-management-enrollment-post-condition-plan-request.v1"
PLAN_SCHEMA = "home-center.device-management-enrollment-post-condition-plan.v1"
CONFIRM_REQUEST_SCHEMA = "home-center.device-management-enrollment-post-condition-confirm-request.v1"
STATE_SCHEMA = "home-center.device-management-enrollment-post-condition-runtime-state.v1"
APPLY_RECEIPT_SCHEMA = "home-center.device-management-enrollment-managed-state-apply-receipt.v1"
ACTION = "household.device.management.enrollment.post-condition.verify"
KEY_PREFIX = "cozy.household.device-enrollment-post-condition."
EXECUTION_RECEIPT_SCHEMA = "home-center.device-management-enrollment-execution-receipt.v1"
SIGNAL_NAMES = ("certificate", "profile", "agent")


class DeviceManagementEnrollmentPostConditionRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DeviceManagementEnrollmentReadBackAdapter(Protocol):
    verification_read_only: bool

    def read_back(self, request: dict[str, object]) -> object: ...


def _digest(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _verification_id(value: dict[str, object]) -> str:
    return "dmpverify-" + _digest(value)[:24]


def _key(verification_id: object) -> str:
    if (
        not isinstance(verification_id, str)
        or not verification_id.startswith("dmpverify-")
        or len(verification_id) != 34
        or any(char not in "0123456789abcdef" for char in verification_id.removeprefix("dmpverify-"))
    ):
        raise DeviceManagementEnrollmentPostConditionRuntimeError(
            "invalid_device_management_enrollment_verification_id"
        )
    return KEY_PREFIX + verification_id


class DeviceManagementEnrollmentPostConditionRuntimeService:
    """Plan/confirm boundary for 0.58 post-condition verification."""

    def __init__(
        self,
        store: StateStore,
        step_up: StepUpGrantManager,
        *,
        now=utc_now,
    ) -> None:
        self.store = store
        self.step_up = step_up
        self._now = now
        self._lock = threading.RLock()
        self._adapters: dict[str, DeviceManagementEnrollmentReadBackAdapter] = {}

    def register_adapter(self, provider_id: str, adapter: object) -> None:
        if (
            not isinstance(provider_id, str)
            or not provider_id
            or len(provider_id) > 128
            or provider_id in self._adapters
            or getattr(adapter, "verification_read_only", None) is not True
            or not callable(getattr(adapter, "read_back", None))
        ):
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "invalid_device_management_enrollment_verification_adapter_registration"
            )
        self._adapters[provider_id] = adapter  # type: ignore[assignment]

    @staticmethod
    def step_up_scope(verification_id: str) -> str:
        _key(verification_id)
        return f"household.device.management.enrollment.verify:{verification_id}"

    def _state(self) -> tuple[HouseholdSnapshot, tuple[ActorBinding, ...]]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementEnrollmentPostConditionRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc

    @staticmethod
    def _actor_member(
        actor: str,
        snapshot: HouseholdSnapshot,
        bindings: tuple[ActorBinding, ...],
    ) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise DeviceManagementEnrollmentPostConditionRuntimeError("household_actor_not_bound")
        try:
            policy = effective_policy(snapshot.household, member_id)
        except HomeServiceCatalogError as exc:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(exc.code) from exc
        if not policy.administration_allowed:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_not_authorized"
            )
        return member_id

    def _execution(self, execution_plan_id: object) -> tuple[object, dict[str, Any], dict[str, object]]:
        try:
            key = execution_key(execution_plan_id)
        except Exception as exc:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_execution_plan_not_found"
            ) from exc
        envelope = self.store.get_meta(key)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != EXECUTION_STATE_SCHEMA
            or envelope.get("status") != "provider-accepted"
            or isinstance(envelope.get("cancel_receipt"), dict)
        ):
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_execution_not_verifiable"
            )
        try:
            plan = execution_plan_from_dict(envelope.get("plan"))
        except DeviceManagementEnrollmentExecutionError as exc:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(exc.code) from exc
        receipt = envelope.get("receipt")
        expected = {
            "schema", "state", "job_id", "retry_of_job_id", "plan_id",
            "selection_proposal_id", "provider_id", "provider_operation_id",
            "device_id", "member_id", "one_time_artifact", "enrollment_completed",
            "post_condition_verified", "managed_state_change_authorized",
            "policy_application_authorized", "infrastructure_mutation_authorized",
            "external_publication_authorized",
        }
        if (
            not isinstance(receipt, dict)
            or set(receipt) != expected
            or receipt.get("schema") != EXECUTION_RECEIPT_SCHEMA
            or receipt.get("state") != "provider-accepted"
            or receipt.get("plan_id") != plan.plan_id
            or receipt.get("selection_proposal_id") != plan.selection_proposal_id
            or receipt.get("provider_id") != plan.provider_id
            or receipt.get("device_id") != plan.device_id
            or receipt.get("member_id") != plan.member_id
            or not isinstance(receipt.get("job_id"), str)
            or not receipt.get("job_id")
            or not isinstance(receipt.get("provider_operation_id"), str)
            or not receipt.get("provider_operation_id")
            or receipt.get("enrollment_completed") is not False
            or receipt.get("post_condition_verified") is not False
            or receipt.get("managed_state_change_authorized") is not False
            or receipt.get("policy_application_authorized") is not False
            or receipt.get("infrastructure_mutation_authorized") is not False
            or receipt.get("external_publication_authorized") is not False
        ):
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_execution_receipt_invalid"
            )
        return plan, envelope, dict(receipt)

    @staticmethod
    def _device(snapshot: HouseholdSnapshot, device_id: str, member_id: str) -> ManagedDevice:
        device = next((item for item in snapshot.household.devices if item.device_id == device_id), None)
        if device is None:
            raise DeviceManagementEnrollmentPostConditionRuntimeError("household_device_not_found")
        if device.member_id != member_id:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_binding_mismatch"
            )
        return device

    def plan(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        required = {
            "schema",
            "execution_plan_id",
            "max_observed_age_seconds",
            "expected_signals",
        }
        if set(request) != required or request.get("schema") != PLAN_REQUEST_SCHEMA:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "invalid_device_management_enrollment_verification_plan_request"
            )
        with self._lock:
            snapshot, bindings = self._state()
            actor_member_id = self._actor_member(actor, snapshot, bindings)
            execution_plan, _execution_envelope, execution_receipt = self._execution(
                request.get("execution_plan_id")
            )
            if actor_member_id != execution_plan.actor_member_id:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_actor_mismatch"
                )
            if (
                snapshot.household_id != execution_plan.household_id
                or snapshot.snapshot_id != execution_plan.snapshot_id
                or snapshot.resource_version != execution_plan.resource_version
                or snapshot.generation != execution_plan.generation
            ):
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_stale"
                )
            device = self._device(snapshot, execution_plan.device_id, execution_plan.member_id)
            if device.managed:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_device_already_managed"
                )
            signals = request.get("expected_signals")
            if not isinstance(signals, dict) or set(signals) != set(SIGNAL_NAMES):
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "invalid_device_management_enrollment_verification_plan_request"
                )
            max_age = request.get("max_observed_age_seconds")
            binding = PostConditionBinding(
                plan_id=execution_plan.plan_id,
                provider_id=execution_plan.provider_id,
                provider_operation_id=execution_receipt["provider_operation_id"],
                device_id=execution_plan.device_id,
                member_id=execution_plan.member_id,
                execution_generation=execution_plan.generation,
            )
            try:
                post_request = DeviceManagementEnrollmentPostConditionRequest(
                    binding=binding,
                    requested_at=self._now(),
                    max_observed_age_seconds=max_age,
                    expected_signals=tuple((name, signals[name]) for name in SIGNAL_NAMES),
                )
                post_request = request_from_dict(post_request.to_dict())
            except (DeviceManagementEnrollmentVerificationError, KeyError, TypeError, ValueError) as exc:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    getattr(exc, "code", "invalid_device_management_enrollment_verification_plan_request")
                ) from exc
            identity = {
                "execution_job_id": execution_receipt["job_id"],
                "request": post_request.to_dict(),
                "actor_member_id": actor_member_id,
            }
            verification_id = _verification_id(identity)
            plan = {
                "schema": PLAN_SCHEMA,
                "verification_id": verification_id,
                "execution_plan_id": execution_plan.plan_id,
                "execution_job_id": execution_receipt["job_id"],
                "provider_id": execution_plan.provider_id,
                "provider_operation_id": execution_receipt["provider_operation_id"],
                "household_id": snapshot.household_id,
                "snapshot_id": snapshot.snapshot_id,
                "resource_version": snapshot.resource_version,
                "generation": snapshot.generation,
                "device_id": execution_plan.device_id,
                "member_id": execution_plan.member_id,
                "actor_member_id": actor_member_id,
                "post_condition_request": post_request.to_dict(),
                "confirmation_required": True,
                "reauth_required": True,
                "provider_read_required": True,
                "provider_mutation_authorized": False,
                "managed_state_change_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            }
            key = _key(verification_id)
            old = self.store.get_meta(key)
            envelope = {
                "schema": STATE_SCHEMA,
                "status": "planned",
                "plan": plan,
                "base_snapshot": snapshot.to_dict(),
                "bindings": [item.to_dict() for item in bindings],
                "execution_receipt": execution_receipt,
                "job_id": None,
                "readback_result": None,
                "evidence": None,
                "receipt": None,
                "expected_snapshot": None,
                "apply_receipt": None,
            }
            if old is None:
                self.store.set_meta(key, envelope)
            elif (
                not isinstance(old, dict)
                or old.get("schema") != STATE_SCHEMA
                or old.get("plan") != plan
                or old.get("base_snapshot") != snapshot.to_dict()
                or old.get("execution_receipt") != execution_receipt
            ):
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_state_invalid"
                )
            self.store.audit(
                actor=actor,
                action="household.device.management.enrollment.post-condition.plan",
                target=execution_plan.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "verification_id": verification_id,
                    "execution_plan_id": execution_plan.plan_id,
                    "provider_id": execution_plan.provider_id,
                    "confirmation_required": True,
                    "reauth_required": True,
                    "managed_state_change_authorized": False,
                },
            )
            return plan

    def _load(
        self,
        verification_id: object,
    ) -> tuple[str, dict[str, Any], dict[str, object]]:
        key = _key(verification_id)
        envelope = self.store.get_meta(key)
        if not isinstance(envelope, dict) or envelope.get("schema") != STATE_SCHEMA:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_plan_not_found"
            )
        plan = envelope.get("plan")
        if (
            not isinstance(plan, dict)
            or plan.get("schema") != PLAN_SCHEMA
            or plan.get("verification_id") != verification_id
        ):
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        return key, envelope, dict(plan)

    def _revalidate(
        self,
        *,
        actor: str,
        envelope: dict[str, Any],
        plan: dict[str, object],
    ) -> tuple[HouseholdSnapshot, tuple[ActorBinding, ...]]:
        snapshot, bindings = self._state()
        actor_member_id = self._actor_member(actor, snapshot, bindings)
        if actor_member_id != plan.get("actor_member_id"):
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_actor_mismatch"
            )
        execution_plan, _execution_envelope, execution_receipt = self._execution(
            plan.get("execution_plan_id")
        )
        if (
            execution_plan.actor_member_id != actor_member_id
            or execution_plan.provider_id != plan.get("provider_id")
            or execution_plan.device_id != plan.get("device_id")
            or execution_plan.member_id != plan.get("member_id")
            or execution_receipt.get("job_id") != plan.get("execution_job_id")
            or execution_receipt.get("provider_operation_id") != plan.get("provider_operation_id")
        ):
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_binding_mismatch"
            )
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
        except Exception as exc:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            ) from exc
        if snapshot != base:
            expected_raw = envelope.get("expected_snapshot")
            if expected_raw is None:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_stale"
                )
            try:
                expected = _snapshot_from_dict(expected_raw)
            except Exception as exc:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_state_invalid"
                ) from exc
            if snapshot != expected:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_stale"
                )
        return snapshot, bindings

    def _adapter(self, provider_id: object) -> DeviceManagementEnrollmentReadBackAdapter:
        if not isinstance(provider_id, str):
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_adapter_unavailable"
            )
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_adapter_unavailable"
            )
        return adapter

    @staticmethod
    def _build_expected_snapshot(
        base: HouseholdSnapshot,
        plan: dict[str, object],
    ) -> tuple[HouseholdSnapshot, dict[str, object]]:
        device_id = plan.get("device_id")
        member_id = plan.get("member_id")
        devices: list[ManagedDevice] = []
        matched = False
        for device in base.household.devices:
            if device.device_id != device_id:
                devices.append(device)
                continue
            matched = True
            if device.member_id != member_id:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_binding_mismatch"
                )
            if device.managed:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_device_already_managed"
                )
            devices.append(
                ManagedDevice(
                    device_id=device.device_id,
                    member_id=device.member_id,
                    display_name=device.display_name,
                    managed=True,
                )
            )
        if not matched:
            raise DeviceManagementEnrollmentPostConditionRuntimeError("household_device_not_found")
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
            raise DeviceManagementEnrollmentPostConditionRuntimeError(exc.code) from exc
        apply_receipt = {
            "schema": APPLY_RECEIPT_SCHEMA,
            "state": "planned",
            "verification_id": plan["verification_id"],
            "device_id": plan["device_id"],
            "member_id": plan["member_id"],
            "previous_snapshot_id": base.snapshot_id,
            "previous_resource_version": base.resource_version,
            "snapshot_id": expected.snapshot_id,
            "resource_version": expected.resource_version,
            "generation": expected.generation,
            "commit_id": commit.commit_id,
            "post_condition_verified": True,
            "managed_state_change_authorized": True,
            "managed_state_applied": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }
        return expected, apply_receipt

    def _apply_verified(
        self,
        *,
        actor: str,
        correlation_id: str,
        key: str,
        envelope: dict[str, Any],
        plan: dict[str, object],
        job_id: str,
        bindings: tuple[ActorBinding, ...],
    ) -> dict[str, object]:
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
        except Exception as exc:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            ) from exc
        expected_raw = envelope.get("expected_snapshot")
        apply_receipt = envelope.get("apply_receipt")
        if expected_raw is None:
            expected, apply_receipt = self._build_expected_snapshot(base, plan)
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
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_state_invalid"
                ) from exc
            if not isinstance(apply_receipt, dict) or apply_receipt.get("schema") != APPLY_RECEIPT_SCHEMA:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_state_invalid"
                )

        current, current_bindings = self._state()
        if current_bindings != bindings:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_stale"
            )
        if current == base:
            self.store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(expected, bindings))
        elif current != expected:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_stale"
            )

        readback, readback_bindings = self._state()
        if readback != expected or readback_bindings != bindings:
            self.store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(base, bindings))
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_managed_state_readback_failed"
            )

        completed_apply = dict(apply_receipt)
        completed_apply.update(state="applied", managed_state_applied=True)
        job = self.store.job(job_id)
        if job is None:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        if job.get("state") == "verifying":
            self.store.transition_action_job(
                job_id,
                expected_state="verifying",
                new_state="succeeded",
                evidence={
                    "schema": "home-center.device-management-enrollment-verification-completion-evidence.v1",
                    "verification_id": plan["verification_id"],
                    "post_condition": envelope.get("evidence"),
                    "verification_receipt": envelope.get("receipt"),
                    "managed_state_apply": completed_apply,
                    "provider_reinvoked": False,
                },
            )
        elif job.get("state") != "succeeded":
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )

        completed = dict(envelope)
        completed.update(status="applied", apply_receipt=completed_apply)
        self.store.set_meta(key, completed)
        self.store.audit(
            actor=actor,
            action="household.device.management.enrollment.post-condition.complete",
            target=str(plan["device_id"]),
            outcome="succeeded",
            correlation_id=correlation_id,
            details={
                "verification_id": plan["verification_id"],
                "job_id": job_id,
                "snapshot_id": expected.snapshot_id,
                "resource_version": expected.resource_version,
                "generation": expected.generation,
                "provider_reinvoked": False,
                "managed_state_applied": True,
            },
        )
        return {
            "schema": "home-center.device-management-enrollment-post-condition-completion.v1",
            "state": "applied",
            "verification": completed.get("receipt"),
            "managed_state_apply": completed_apply,
        }

    def confirm(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        step_up_token: object,
        correlation_id: str,
    ) -> dict[str, object]:
        required = {"schema", "verification_id", "idempotency_key", "confirmed"}
        if (
            set(request) != required
            or request.get("schema") != CONFIRM_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "invalid_device_management_enrollment_verification_confirm_request"
            )
        idempotency_key = request.get("idempotency_key")
        if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 128:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "invalid_device_management_enrollment_idempotency_key"
            )
        verification_id = request.get("verification_id")
        with self._lock:
            key, envelope, plan = self._load(verification_id)
            if envelope.get("status") == "applied":
                apply_receipt = envelope.get("apply_receipt")
                receipt = envelope.get("receipt")
                if isinstance(apply_receipt, dict) and isinstance(receipt, dict):
                    return {
                        "schema": "home-center.device-management-enrollment-post-condition-completion.v1",
                        "state": "applied",
                        "verification": receipt,
                        "managed_state_apply": apply_receipt,
                    }
            _snapshot, bindings = self._revalidate(actor=actor, envelope=envelope, plan=plan)
            scope = self.step_up_scope(str(verification_id))
            try:
                self.step_up.consume(actor=actor, scope=scope, token=step_up_token)
            except StepUpError as exc:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(exc.code) from exc

            request_hash = _digest(
                {
                    "verification_id": str(verification_id),
                    "confirmed": True,
                    "idempotency_key": idempotency_key,
                }
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=ACTION,
                    actor=actor,
                    reason="explicit post-condition verification confirmation",
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.device-management-enrollment-post-condition-preflight.v1",
                        "verification_id": verification_id,
                        "provider_id": plan["provider_id"],
                        "device_id": plan["device_id"],
                        "provider_mutation_authorized": False,
                        "managed_state_change_authorized": False,
                    },
                    steps=[
                        {"step": "provider-read-back", "state": "pending"},
                        {"step": "verify-post-condition", "state": "pending"},
                        {"step": "apply-managed-state", "state": "pending"},
                        {"step": "read-back-household", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_idempotency_conflict"
                ) from exc

            if not created:
                if job.get("state") == "succeeded" and envelope.get("status") == "applied":
                    return {
                        "schema": "home-center.device-management-enrollment-post-condition-completion.v1",
                        "state": "applied",
                        "verification": envelope.get("receipt"),
                        "managed_state_apply": envelope.get("apply_receipt"),
                    }
                if job.get("state") in {"preflight", "running", "verifying"}:
                    raise DeviceManagementEnrollmentPostConditionRuntimeError(
                        "device_management_enrollment_verification_in_progress"
                    )
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_previous_attempt_failed"
                )

            updated = dict(envelope)
            updated.update(status="running", job_id=job["job_id"])
            self.store.set_meta(key, updated)
            running = self.store.transition_action_job(
                job["job_id"], expected_state="preflight", new_state="running"
            )
            adapter = self._adapter(plan.get("provider_id"))
            post_request = plan.get("post_condition_request")
            try:
                parsed_request = request_from_dict(post_request)
                raw_result = adapter.read_back(parsed_request.to_dict())
                result = result_from_dict(raw_result)
            except DeviceManagementEnrollmentVerificationError as exc:
                self.store.transition_action_job(
                    running["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-enrollment-post-condition-provider-read-failure.v1",
                        "state": "failed",
                        "code": exc.code,
                        "provider_mutation_performed": False,
                    },
                )
                failed = dict(updated)
                failed.update(status="readback-failed")
                self.store.set_meta(key, failed)
                raise DeviceManagementEnrollmentPostConditionRuntimeError(exc.code) from exc
            except Exception as exc:
                self.store.transition_action_job(
                    running["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-enrollment-post-condition-provider-read-failure.v1",
                        "state": "failed",
                        "code": "device_management_enrollment_verification_provider_error",
                        "provider_mutation_performed": False,
                    },
                )
                failed = dict(updated)
                failed.update(status="readback-failed")
                self.store.set_meta(key, failed)
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_provider_error"
                ) from exc

            verifying = self.store.transition_action_job(
                running["job_id"],
                expected_state="running",
                new_state="verifying",
                result=result.to_dict(),
                steps=[
                    {"step": "provider-read-back", "state": "succeeded"},
                    {"step": "verify-post-condition", "state": "running"},
                    {"step": "apply-managed-state", "state": "pending"},
                    {"step": "read-back-household", "state": "pending"},
                ],
            )
            try:
                evidence, receipt = verify_post_condition(
                    request=parsed_request.to_dict(),
                    result=result.to_dict(),
                    now=self._now(),
                    job_id=verifying["job_id"],
                )
            except DeviceManagementEnrollmentVerificationError as exc:
                self.store.transition_action_job(
                    verifying["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    evidence={
                        "schema": "home-center.device-management-enrollment-post-condition-evaluation-failure.v1",
                        "code": exc.code,
                    },
                )
                failed = dict(updated)
                failed.update(status="verification-failed", readback_result=result.to_dict())
                self.store.set_meta(key, failed)
                raise DeviceManagementEnrollmentPostConditionRuntimeError(exc.code) from exc

            verified_envelope = dict(updated)
            verified_envelope.update(
                status="verified" if receipt.verified else "rejected",
                readback_result=result.to_dict(),
                evidence=evidence.to_dict(),
                receipt=receipt.to_dict(),
            )
            self.store.set_meta(key, verified_envelope)
            if not receipt.verified:
                self.store.transition_action_job(
                    verifying["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    evidence={
                        "schema": "home-center.device-management-enrollment-post-condition-rejection-evidence.v1",
                        "post_condition": evidence.to_dict(),
                        "verification_receipt": receipt.to_dict(),
                        "managed_state_applied": False,
                    },
                )
                self.store.audit(
                    actor=actor,
                    action="household.device.management.enrollment.post-condition.complete",
                    target=str(plan["device_id"]),
                    outcome="denied",
                    correlation_id=correlation_id,
                    details={
                        "verification_id": verification_id,
                        "job_id": verifying["job_id"],
                        "failure_reason": evidence.failure_reason,
                        "managed_state_applied": False,
                    },
                )
                return {
                    "schema": "home-center.device-management-enrollment-post-condition-completion.v1",
                    "state": "rejected",
                    "verification": receipt.to_dict(),
                    "managed_state_apply": None,
                }

            expected, apply_receipt = self._build_expected_snapshot(
                _snapshot_from_dict(verified_envelope["base_snapshot"]),
                plan,
            )
            verified_envelope.update(
                status="verified-pending-apply",
                expected_snapshot=expected.to_dict(),
                apply_receipt=apply_receipt,
            )
            self.store.set_meta(key, verified_envelope)
            return self._apply_verified(
                actor=actor,
                correlation_id=correlation_id,
                key=key,
                envelope=verified_envelope,
                plan=plan,
                job_id=verifying["job_id"],
                bindings=bindings,
            )

    def recover_incomplete(self) -> int:
        """Finalize durable verified evidence without repeating provider read-back."""
        connection = getattr(self.store, "_connection", None)
        lock = getattr(self.store, "_lock", None)
        if connection is None or lock is None:
            return 0
        with lock:
            rows = connection.execute(
                "SELECT key,value_json FROM cluster_meta WHERE key LIKE ? ORDER BY key",
                (KEY_PREFIX + "%",),
            ).fetchall()
        recovered = 0
        for row in rows:
            envelope = self.store.get_meta(row["key"])
            if not isinstance(envelope, dict) or envelope.get("status") != "verified-pending-apply":
                continue
            plan = envelope.get("plan")
            job_id = envelope.get("job_id")
            if not isinstance(plan, dict) or not isinstance(job_id, str):
                continue
            try:
                bindings_raw = envelope.get("bindings")
                if not isinstance(bindings_raw, list):
                    continue
                bindings = tuple(
                    ActorBinding(actor=item["actor"], member_id=item["member_id"])
                    for item in bindings_raw
                    if isinstance(item, dict) and set(item) == {"actor", "member_id"}
                )
                if len(bindings) != len(bindings_raw):
                    continue
                self._apply_verified(
                    actor="system:recovery",
                    correlation_id=f"recovery-{plan.get('verification_id')}",
                    key=row["key"],
                    envelope=envelope,
                    plan=plan,
                    job_id=job_id,
                    bindings=bindings,
                )
                recovered += 1
            except DeviceManagementEnrollmentPostConditionRuntimeError:
                job = self.store.job(job_id)
                if job is not None and job.get("state") == "verifying":
                    self.store.transition_action_job(
                        job_id,
                        expected_state="verifying",
                        new_state="failed",
                        evidence={
                            "schema": "home-center.device-management-enrollment-post-condition-recovery-blocked.v1",
                            "provider_reinvoked": False,
                            "managed_state_applied": False,
                        },
                    )
        return recovered
