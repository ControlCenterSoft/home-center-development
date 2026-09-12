"""Durable, fail-closed provider de-enrollment runtime for Home Center 0.58.

A failed enrollment may leave provider-side certificate/profile/agent state that
must be removed before a new enrollment can even be planned.  The pure 0.58
boundary in :mod:`device_management_enrollment_deenrollment` defines the typed
plan/confirm/adapter contracts; this module gives that boundary a durable Job and
Audit lifecycle.

Crash recovery is deliberately conservative.  An exact preflight can be resumed
because no provider mutation has started.  A ``verifying`` job can be finalized
from the already persisted typed provider acceptance without calling the provider
again.  A ``running`` job is ambiguous after restart and is failed closed: the
provider command is never replayed automatically.
"""
from __future__ import annotations

import hashlib
import re
import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from .device_management_enrollment_cleanup import (
    DeviceManagementEnrollmentCleanupError,
    build_failed_enrollment_cleanup_plan,
)
from .device_management_enrollment_deenrollment import (
    DEENROLLMENT_ADAPTER_RESULT_SCHEMA,
    DEENROLLMENT_RECEIPT_SCHEMA,
    DeviceManagementEnrollmentDeenrollmentAdapter,
    DeviceManagementEnrollmentDeenrollmentError,
    DeviceManagementEnrollmentDeenrollmentReceipt,
    build_deenrollment_adapter_request,
    build_deenrollment_plan,
    confirm_deenrollment,
    deenrollment_adapter_result_from_dict,
)
from .device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationError,
)
from .device_management_enrollment_verification_persistence import (
    verification_evidence_from_dict,
)
from .device_management_enrollment_verification_runtime import (
    VERIFY_ACTION,
    VERIFY_KEY_PREFIX,
    VERIFY_STATE_SCHEMA,
)
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now


DEENROLLMENT_RUNTIME_REQUEST_SCHEMA = (
    "home-center.device-management-enrollment-deenrollment-runtime-request.v1"
)
DEENROLLMENT_RUNTIME_STATE_SCHEMA = (
    "home-center.device-management-enrollment-deenrollment-runtime-state.v1"
)
DEENROLLMENT_ACTION = "household.device.management.enrollment.de-enroll"
DEENROLLMENT_KEY_PREFIX = "cozy.household.device-enrollment-deenrollment."
VERIFICATION_ID = re.compile(r"^dmpverify-[0-9a-f]{24}$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
PROVIDER_TIMEOUT_SECONDS = 300


class DeviceManagementEnrollmentDeenrollmentRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _hash(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _state_key(de_enrollment_id: object) -> str:
    if (
        not isinstance(de_enrollment_id, str)
        or not de_enrollment_id.startswith("dmpdeenroll-")
        or len(de_enrollment_id) != len("dmpdeenroll-") + 24
        or any(character not in "0123456789abcdef" for character in de_enrollment_id[12:])
    ):
        raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
            "device_management_enrollment_deenrollment_id_invalid"
        )
    return DEENROLLMENT_KEY_PREFIX + de_enrollment_id


class DeviceManagementEnrollmentDeenrollmentRuntimeService:
    """Persist one explicitly confirmed provider cleanup without false success."""

    def __init__(
        self,
        store: StateStore,
        *,
        now: Callable[[], str] = utc_now,
    ) -> None:
        self.store = store
        self._now = now
        self._lock = threading.RLock()
        self._adapters: dict[str, DeviceManagementEnrollmentDeenrollmentAdapter] = {}

    def register_adapter(
        self,
        provider_id: str,
        adapter: DeviceManagementEnrollmentDeenrollmentAdapter,
    ) -> None:
        if (
            not isinstance(provider_id, str)
            or not provider_id
            or len(provider_id) > 128
            or provider_id in self._adapters
            or not callable(getattr(adapter, "de_enroll", None))
        ):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "invalid_device_management_enrollment_deenrollment_adapter_registration"
            )
        self._adapters[provider_id] = adapter

    def _adapter(self, provider_id: str) -> DeviceManagementEnrollmentDeenrollmentAdapter:
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_adapter_unavailable"
            )
        return adapter

    def _negative_verification(self, verification_id: str, *, actor: str):
        envelope = self.store.get_meta(VERIFY_KEY_PREFIX + verification_id)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != VERIFY_STATE_SCHEMA
            or envelope.get("status") != "complete"
            or not isinstance(envelope.get("job_id"), str)
            or not isinstance(envelope.get("evidence"), dict)
        ):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_verification_evidence_not_found"
            )
        verification_job = self.store.job(envelope["job_id"])
        if (
            not isinstance(verification_job, dict)
            or verification_job.get("job_type") != VERIFY_ACTION
            or verification_job.get("state") != "succeeded"
            or verification_job.get("initiator") != actor
        ):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_actor_or_verification_mismatch"
            )
        try:
            evidence = verification_evidence_from_dict(envelope["evidence"])
        except DeviceManagementEnrollmentVerificationError as exc:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(exc.code) from exc
        if evidence.verification_id != verification_id:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_verification_evidence_mismatch"
            )
        if evidence.verified or evidence.managed_state_change_authorized:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_not_required"
            )
        try:
            cleanup = build_failed_enrollment_cleanup_plan(evidence)
        except DeviceManagementEnrollmentCleanupError as exc:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(exc.code) from exc
        if cleanup.action != "de-enroll-required":
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_not_required"
            )
        return evidence, cleanup

    def _snapshot_and_actor_member(self, actor: str):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "household_not_configured"
            )
        try:
            snapshot, bindings = _state_from_dict(raw)
        except Exception as exc:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc
        actor_member_id = next(
            (binding.member_id for binding in bindings if binding.actor == actor),
            None,
        )
        if not isinstance(actor_member_id, str) or not actor_member_id:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "household_actor_not_bound"
            )
        return snapshot, actor_member_id

    def _trusted_now(self) -> str:
        value = self._now()
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except (TypeError, ValueError) as exc:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "trusted_time_invalid"
            ) from exc
        if parsed.year < 2020:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "trusted_time_invalid"
            )
        return value

    @staticmethod
    def _deadline(confirmed_at: str) -> str:
        parsed = datetime.strptime(confirmed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        return (parsed + timedelta(seconds=PROVIDER_TIMEOUT_SECONDS)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    def _fresh_preflight(
        self,
        *,
        actor: str,
        verification_id: str,
        idempotency_key: str,
        confirmed_at: str | None = None,
    ):
        evidence, cleanup = self._negative_verification(verification_id, actor=actor)
        snapshot, actor_member_id = self._snapshot_and_actor_member(actor)
        try:
            plan = build_deenrollment_plan(
                cleanup,
                current=snapshot,
                actor_member_id=actor_member_id,
            )
            confirmation = confirm_deenrollment(
                plan,
                actor_member_id=actor_member_id,
                confirmed=True,
                idempotency_key=idempotency_key,
                confirmed_at=confirmed_at or self._trusted_now(),
            )
        except DeviceManagementEnrollmentDeenrollmentError as exc:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(exc.code) from exc
        return evidence, cleanup, plan, confirmation

    @staticmethod
    def _preflight(job: dict[str, Any]) -> dict[str, Any]:
        preflight = job.get("preflight")
        if (
            not isinstance(preflight, dict)
            or preflight.get("schema")
            != "home-center.device-management-enrollment-deenrollment-preflight.v1"
            or preflight.get("confirmed") is not True
            or not isinstance(preflight.get("cleanup_plan"), dict)
            or not isinstance(preflight.get("de_enrollment_plan"), dict)
            or not isinstance(preflight.get("confirmation"), dict)
        ):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_state_invalid"
            )
        return preflight

    def _validate_preflight(
        self,
        *,
        actor: str,
        verification_id: str,
        idempotency_key: str,
        job: dict[str, Any],
    ):
        preflight = self._preflight(job)
        confirmation_raw = preflight["confirmation"]
        confirmed_at = confirmation_raw.get("confirmed_at")
        if not isinstance(confirmed_at, str):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_state_invalid"
            )
        evidence, cleanup, plan, confirmation = self._fresh_preflight(
            actor=actor,
            verification_id=verification_id,
            idempotency_key=idempotency_key,
            confirmed_at=confirmed_at,
        )
        if (
            preflight.get("verification_id") != verification_id
            or preflight.get("cleanup_plan") != cleanup.to_dict()
            or preflight.get("de_enrollment_plan") != plan.to_dict()
            or confirmation_raw != confirmation.to_dict()
            or confirmation.idempotency_key != idempotency_key
        ):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_state_invalid"
            )
        return evidence, cleanup, plan, confirmation

    @staticmethod
    def _stored_bindings(job: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        preflight = DeviceManagementEnrollmentDeenrollmentRuntimeService._preflight(job)
        plan = preflight["de_enrollment_plan"]
        confirmation = preflight["confirmation"]
        required_plan = {
            "schema",
            "de_enrollment_id",
            "cleanup_id",
            "verification_id",
            "execution_job_id",
            "enrollment_plan_id",
            "provider_id",
            "provider_operation_id",
            "household_id",
            "snapshot_id",
            "resource_version",
            "generation",
            "actor_member_id",
            "device_id",
            "member_id",
            "failure_reasons",
            "confirmation_required",
            "durable_job_required",
            "audit_required",
            "provider_mutation_authorized",
            "retry_planning_allowed",
            "retry_execution_authorized",
            "managed_state_change_authorized",
            "credential_value_access_authorized",
            "policy_application_authorized",
            "infrastructure_mutation_authorized",
            "external_publication_authorized",
        }
        required_confirmation = {
            "schema",
            "confirmation_id",
            "de_enrollment_id",
            "cleanup_id",
            "actor_member_id",
            "idempotency_key",
            "confirmed_at",
            "confirmed",
            "provider_mutation_authorized",
            "credential_value_access_authorized",
            "retry_execution_authorized",
            "managed_state_change_authorized",
            "policy_application_authorized",
            "infrastructure_mutation_authorized",
            "external_publication_authorized",
        }
        if (
            set(plan) != required_plan
            or set(confirmation) != required_confirmation
            or plan.get("schema")
            != "home-center.device-management-enrollment-deenrollment-plan.v1"
            or confirmation.get("schema")
            != "home-center.device-management-enrollment-deenrollment-confirmation.v1"
            or confirmation.get("de_enrollment_id") != plan.get("de_enrollment_id")
            or confirmation.get("cleanup_id") != plan.get("cleanup_id")
            or confirmation.get("actor_member_id") != plan.get("actor_member_id")
            or plan.get("confirmation_required") is not True
            or plan.get("durable_job_required") is not True
            or plan.get("audit_required") is not True
            or plan.get("provider_mutation_authorized") is not False
            or plan.get("retry_planning_allowed") is not False
            or plan.get("retry_execution_authorized") is not False
            or plan.get("managed_state_change_authorized") is not False
            or plan.get("credential_value_access_authorized") is not False
            or plan.get("policy_application_authorized") is not False
            or plan.get("infrastructure_mutation_authorized") is not False
            or plan.get("external_publication_authorized") is not False
            or confirmation.get("confirmed") is not True
            or confirmation.get("provider_mutation_authorized") is not True
            or confirmation.get("credential_value_access_authorized") is not False
            or confirmation.get("retry_execution_authorized") is not False
            or confirmation.get("managed_state_change_authorized") is not False
            or confirmation.get("policy_application_authorized") is not False
            or confirmation.get("infrastructure_mutation_authorized") is not False
            or confirmation.get("external_publication_authorized") is not False
        ):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_state_invalid"
            )
        return plan, confirmation

    def _fail_running_unknown(self, job: dict[str, Any], *, actor: str, correlation_id: str) -> None:
        if job.get("state") != "running":
            return
        failed = self.store.transition_action_job(
            job["job_id"],
            expected_state="running",
            new_state="failed",
            result={
                "schema": "home-center.device-management-enrollment-deenrollment-failure.v1",
                "state": "failed",
                "code": "device_management_enrollment_deenrollment_provider_acceptance_unknown",
                "provider_acceptance_unknown": True,
                "post_cleanup_verified": False,
                "retry_planning_allowed": False,
                "retry_execution_authorized": False,
                "managed_state_change_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
            steps=[
                {"step": "revalidate-negative-evidence", "state": "succeeded"},
                {"step": "provider-de-enroll", "state": "unknown"},
                {"step": "persist-provider-acceptance", "state": "blocked"},
            ],
        )
        plan, _confirmation = self._stored_bindings(failed)
        self.store.audit(
            actor=actor,
            action=DEENROLLMENT_ACTION,
            target=str(plan.get("device_id")),
            outcome="indeterminate",
            correlation_id=correlation_id,
            details={
                "job_id": failed["job_id"],
                "de_enrollment_id": plan.get("de_enrollment_id"),
                "provider_id": plan.get("provider_id"),
                "provider_acceptance_unknown": True,
                "provider_reinvoked": False,
                "post_cleanup_verified": False,
                "retry_execution_authorized": False,
            },
        )

    def _provider_failure(
        self,
        job: dict[str, Any],
        *,
        actor: str,
        correlation_id: str,
        code: str,
    ) -> None:
        if job.get("state") != "running":
            return
        failed = self.store.transition_action_job(
            job["job_id"],
            expected_state="running",
            new_state="failed",
            result={
                "schema": "home-center.device-management-enrollment-deenrollment-failure.v1",
                "state": "failed",
                "code": code,
                "provider_acceptance_unknown": True,
                "post_cleanup_verified": False,
                "retry_planning_allowed": False,
                "retry_execution_authorized": False,
                "managed_state_change_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
            steps=[
                {"step": "revalidate-negative-evidence", "state": "succeeded"},
                {"step": "provider-de-enroll", "state": "failed"},
                {"step": "persist-provider-acceptance", "state": "blocked"},
            ],
        )
        plan, _confirmation = self._stored_bindings(failed)
        self.store.audit(
            actor=actor,
            action=DEENROLLMENT_ACTION,
            target=str(plan.get("device_id")),
            outcome="indeterminate",
            correlation_id=correlation_id,
            details={
                "job_id": failed["job_id"],
                "de_enrollment_id": plan.get("de_enrollment_id"),
                "provider_id": plan.get("provider_id"),
                "code": code,
                "provider_acceptance_unknown": True,
                "post_cleanup_verified": False,
                "retry_execution_authorized": False,
            },
        )

    def _persist_complete(
        self,
        *,
        job: dict[str, Any],
        receipt: dict[str, object],
        adapter_result: dict[str, object],
    ) -> None:
        plan, confirmation = self._stored_bindings(job)
        envelope = {
            "schema": DEENROLLMENT_RUNTIME_STATE_SCHEMA,
            "status": "provider-cleanup-accepted",
            "job_id": job["job_id"],
            "de_enrollment_id": plan["de_enrollment_id"],
            "verification_id": plan["verification_id"],
            "cleanup_id": plan["cleanup_id"],
            "plan": plan,
            "confirmation": confirmation,
            "adapter_result": adapter_result,
            "receipt": receipt,
        }
        self.store.set_meta(_state_key(plan["de_enrollment_id"]), envelope)

    def _finalize_verifying(
        self,
        *,
        actor: str,
        correlation_id: str,
        job: dict[str, Any],
        recovered_after_restart: bool,
    ) -> dict[str, object]:
        if job.get("state") != "verifying":
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_state_invalid"
            )
        plan, confirmation = self._stored_bindings(job)
        raw_result = job.get("result")
        try:
            adapter_result = deenrollment_adapter_result_from_dict(raw_result)
        except DeviceManagementEnrollmentDeenrollmentError as exc:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(exc.code) from exc
        receipt = DeviceManagementEnrollmentDeenrollmentReceipt(
            job_id=job["job_id"],
            de_enrollment_id=str(plan["de_enrollment_id"]),
            cleanup_id=str(plan["cleanup_id"]),
            confirmation_id=str(confirmation["confirmation_id"]),
            provider_id=str(plan["provider_id"]),
            provider_operation_id=str(plan["provider_operation_id"]),
            cleanup_operation_id=adapter_result.cleanup_operation_id,
            device_id=str(plan["device_id"]),
        ).to_dict()
        audit_event_id = self.store.audit(
            actor=actor,
            action=DEENROLLMENT_ACTION,
            target=str(plan["device_id"]),
            outcome="accepted",
            correlation_id=correlation_id,
            details={
                "job_id": job["job_id"],
                "de_enrollment_id": plan["de_enrollment_id"],
                "verification_id": plan["verification_id"],
                "cleanup_id": plan["cleanup_id"],
                "provider_id": plan["provider_id"],
                "provider_operation_id": plan["provider_operation_id"],
                "cleanup_operation_id": adapter_result.cleanup_operation_id,
                "scope": "provider-cleanup-command-accepted-only",
                "recovered_after_restart": recovered_after_restart,
                "provider_reinvoked": False if recovered_after_restart else True,
                "post_cleanup_verified": False,
                "retry_planning_allowed": False,
                "retry_execution_authorized": False,
                "managed_state_change_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
        )
        done = self.store.transition_action_job(
            job["job_id"],
            expected_state="verifying",
            new_state="succeeded",
            result=receipt,
            evidence={
                "schema": "home-center.device-management-enrollment-deenrollment-evidence.v1",
                "audit_event_id": audit_event_id,
                "de_enrollment_id": plan["de_enrollment_id"],
                "verification_id": plan["verification_id"],
                "cleanup_id": plan["cleanup_id"],
                "provider_id": plan["provider_id"],
                "provider_operation_id": plan["provider_operation_id"],
                "cleanup_operation_id": adapter_result.cleanup_operation_id,
                "provider_cleanup_command_accepted": True,
                "post_cleanup_verified": False,
                "retry_planning_allowed": False,
                "retry_execution_authorized": False,
                "managed_state_change_authorized": False,
                "recovered_after_restart": recovered_after_restart,
            },
            steps=[
                {"step": "revalidate-negative-evidence", "state": "succeeded"},
                {"step": "provider-de-enroll", "state": "succeeded"},
                {"step": "persist-provider-acceptance", "state": "succeeded"},
            ],
        )
        self._persist_complete(
            job=done,
            receipt=receipt,
            adapter_result=adapter_result.to_dict(),
        )
        return receipt

    def _resume_succeeded(self, job: dict[str, Any]) -> dict[str, object]:
        result = job.get("result")
        evidence = job.get("evidence")
        if (
            not isinstance(result, dict)
            or result.get("schema") != DEENROLLMENT_RECEIPT_SCHEMA
            or result.get("state") != "provider-cleanup-accepted"
            or not isinstance(evidence, dict)
            or evidence.get("schema")
            != "home-center.device-management-enrollment-deenrollment-evidence.v1"
            or not isinstance(evidence.get("audit_event_id"), str)
            or not evidence.get("audit_event_id")
            or evidence.get("provider_cleanup_command_accepted") is not True
            or evidence.get("post_cleanup_verified") is not False
            or evidence.get("retry_execution_authorized") is not False
            or evidence.get("managed_state_change_authorized") is not False
        ):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_state_invalid"
            )
        adapter_result = {
            "schema": DEENROLLMENT_ADAPTER_RESULT_SCHEMA,
            "state": "accepted",
            "cleanup_operation_id": result.get("cleanup_operation_id"),
            "post_cleanup_verified": False,
            "retry_planning_allowed": False,
            "retry_execution_authorized": False,
            "managed_state_change_authorized": False,
        }
        try:
            deenrollment_adapter_result_from_dict(adapter_result)
        except DeviceManagementEnrollmentDeenrollmentError as exc:
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(exc.code) from exc
        self._persist_complete(
            job=job,
            receipt=dict(result),
            adapter_result=adapter_result,
        )
        return dict(result)

    def de_enroll(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        expected = {"schema", "verification_id", "confirmed", "idempotency_key"}
        if (
            not isinstance(request, dict)
            or set(request) != expected
            or request.get("schema") != DEENROLLMENT_RUNTIME_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "invalid_device_management_enrollment_deenrollment_runtime_request"
            )
        verification_id = request.get("verification_id")
        idempotency_key = request.get("idempotency_key")
        if (
            not isinstance(verification_id, str)
            or VERIFICATION_ID.fullmatch(verification_id) is None
            or not isinstance(idempotency_key, str)
            or IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
        ):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "invalid_device_management_enrollment_deenrollment_runtime_request"
            )

        with self._lock:
            evidence, cleanup, plan, confirmation = self._fresh_preflight(
                actor=actor,
                verification_id=verification_id,
                idempotency_key=idempotency_key,
            )
            request_hash = _hash(
                {
                    "verification_id": verification_id,
                    "confirmed": True,
                    "idempotency_key": idempotency_key,
                }
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=DEENROLLMENT_ACTION,
                    actor=actor,
                    reason="explicit cleanup of residual provider enrollment state",
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.device-management-enrollment-deenrollment-preflight.v1",
                        "verification_id": verification_id,
                        "confirmed": True,
                        "cleanup_plan": cleanup.to_dict(),
                        "de_enrollment_plan": plan.to_dict(),
                        "confirmation": confirmation.to_dict(),
                        "provider_mutation_authorized": True,
                        "credential_value_access_authorized": False,
                        "retry_planning_allowed": False,
                        "retry_execution_authorized": False,
                        "managed_state_change_authorized": False,
                        "policy_application_authorized": False,
                        "infrastructure_mutation_authorized": False,
                        "external_publication_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate-negative-evidence", "state": "succeeded"},
                        {"step": "provider-de-enroll", "state": "pending"},
                        {"step": "persist-provider-acceptance", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                    "device_management_enrollment_deenrollment_idempotency_conflict"
                ) from exc

            if not created:
                if (
                    job.get("job_type") != DEENROLLMENT_ACTION
                    or job.get("initiator") != actor
                    or job.get("idempotency_key") != idempotency_key
                ):
                    raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                        "device_management_enrollment_deenrollment_state_invalid"
                    )
                if job.get("state") == "succeeded":
                    return self._resume_succeeded(job)
                if job.get("state") == "failed":
                    result = job.get("result")
                    if (
                        isinstance(result, dict)
                        and result.get("provider_acceptance_unknown") is True
                    ):
                        raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                            "device_management_enrollment_deenrollment_provider_acceptance_unknown"
                        )
                    raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                        "device_management_enrollment_deenrollment_retry_required"
                    )
                if job.get("state") == "running":
                    self._fail_running_unknown(
                        job,
                        actor=actor,
                        correlation_id=correlation_id,
                    )
                    raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                        "device_management_enrollment_deenrollment_provider_acceptance_unknown"
                    )
                if job.get("state") == "verifying":
                    return self._finalize_verifying(
                        actor=actor,
                        correlation_id=correlation_id,
                        job=job,
                        recovered_after_restart=True,
                    )
                if job.get("state") != "preflight":
                    raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                        "device_management_enrollment_deenrollment_state_invalid"
                    )
                _evidence, _cleanup, plan, confirmation = self._validate_preflight(
                    actor=actor,
                    verification_id=verification_id,
                    idempotency_key=idempotency_key,
                    job=job,
                )

            adapter = self._adapter(plan.provider_id)
            adapter_request = build_deenrollment_adapter_request(
                plan,
                confirmation,
                job_id=job["job_id"],
                deadline_at=self._deadline(confirmation.confirmed_at),
            )
            running = self.store.transition_action_job(
                job["job_id"],
                expected_state="preflight",
                new_state="running",
                result={
                    "schema": "home-center.device-management-enrollment-deenrollment-dispatch.v1",
                    "adapter_request": adapter_request.to_dict(),
                    "provider_acceptance_unknown": True,
                    "post_cleanup_verified": False,
                    "retry_execution_authorized": False,
                    "managed_state_change_authorized": False,
                },
                steps=[
                    {"step": "revalidate-negative-evidence", "state": "succeeded"},
                    {"step": "provider-de-enroll", "state": "running"},
                    {"step": "persist-provider-acceptance", "state": "pending"},
                ],
            )
            try:
                raw_result = adapter.de_enroll(adapter_request)
                result = deenrollment_adapter_result_from_dict(raw_result)
            except TimeoutError as exc:
                self._provider_failure(
                    running,
                    actor=actor,
                    correlation_id=correlation_id,
                    code="device_management_enrollment_deenrollment_provider_timeout",
                )
                raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                    "device_management_enrollment_deenrollment_provider_timeout"
                ) from exc
            except DeviceManagementEnrollmentDeenrollmentError as exc:
                self._provider_failure(
                    running,
                    actor=actor,
                    correlation_id=correlation_id,
                    code=exc.code,
                )
                raise DeviceManagementEnrollmentDeenrollmentRuntimeError(exc.code) from exc
            except Exception as exc:
                self._provider_failure(
                    running,
                    actor=actor,
                    correlation_id=correlation_id,
                    code="device_management_enrollment_deenrollment_provider_error",
                )
                raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                    "device_management_enrollment_deenrollment_provider_error"
                ) from exc

            verifying = self.store.transition_action_job(
                running["job_id"],
                expected_state="running",
                new_state="verifying",
                result=result.to_dict(),
                steps=[
                    {"step": "revalidate-negative-evidence", "state": "succeeded"},
                    {"step": "provider-de-enroll", "state": "succeeded"},
                    {"step": "persist-provider-acceptance", "state": "running"},
                ],
            )
            return self._finalize_verifying(
                actor=actor,
                correlation_id=correlation_id,
                job=verifying,
                recovered_after_restart=False,
            )

    def receipt(self, job_id: str) -> dict[str, object]:
        job = self.store.job(job_id)
        if (
            not isinstance(job, dict)
            or job.get("job_type") != DEENROLLMENT_ACTION
            or job.get("state") != "succeeded"
            or not isinstance(job.get("result"), dict)
            or job["result"].get("schema") != DEENROLLMENT_RECEIPT_SCHEMA
        ):
            raise DeviceManagementEnrollmentDeenrollmentRuntimeError(
                "device_management_enrollment_deenrollment_receipt_not_found"
            )
        return dict(job["result"])
