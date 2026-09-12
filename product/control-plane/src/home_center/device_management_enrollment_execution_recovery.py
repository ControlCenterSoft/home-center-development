"""Crash-safe recovery layer for the 0.57 enrollment execution boundary.

Recovery never replays an ambiguous provider command. A preflight job may resume
because provider execution has not started yet. A verifying job may be finalized
without contacting the provider because validated provider acceptance is already
durable. A running job remains fail-closed because provider acceptance is unknown.
"""
from __future__ import annotations

from typing import Any

from .device_management_enrollment_execution import (
    DeviceManagementEnrollmentExecutionError,
    adapter_result_from_dict,
)
from .device_management_enrollment_execution_runtime import (
    CANCEL_ACTION,
    CANCEL_RECEIPT_SCHEMA,
    RETRY_ACTION,
    START_ACTION,
    DeviceManagementEnrollmentExecutionRuntimeError,
    DeviceManagementEnrollmentExecutionRuntimeService,
    RECEIPT_SCHEMA,
)
from .device_management_enrollment_execution_runtime_safe import (
    SafeDeviceManagementEnrollmentExecutionRuntimeService,
)


class RecoverableDeviceManagementEnrollmentExecutionRuntimeService(
    SafeDeviceManagementEnrollmentExecutionRuntimeService
):
    @staticmethod
    def _same_request(job: dict[str, Any], *, actor: str, action: str, idempotency_key: object) -> bool:
        return (
            job.get("job_type") == action
            and job.get("initiator") == actor
            and isinstance(idempotency_key, str)
            and job.get("idempotency_key") == idempotency_key
        )

    @staticmethod
    def _retry_parent_matches(job: dict[str, Any], failed_job_id: object) -> bool:
        preflight = job.get("preflight")
        return isinstance(preflight, dict) and preflight.get("retry_of_job_id") == failed_job_id

    def _recover_provider_acceptance(
        self,
        *,
        actor: str,
        correlation_id: str,
        key: str,
        envelope: dict[str, Any],
        plan: object,
        job: dict[str, Any],
    ) -> dict[str, object]:
        result = job.get("result")
        if (
            not isinstance(result, dict)
            or set(result)
            != {
                "schema",
                "state",
                "provider_operation_id",
                "one_time_artifact",
                "enrollment_completed",
                "post_condition_verified",
                "managed_state_change_authorized",
            }
            or result.get("schema") != "home-center.device-management-enrollment-provider-acceptance.v1"
            or result.get("state") != "provider-accepted"
            or result.get("enrollment_completed") is not False
            or result.get("post_condition_verified") is not False
            or result.get("managed_state_change_authorized") is not False
        ):
            raise DeviceManagementEnrollmentExecutionRuntimeError(
                "device_management_enrollment_execution_state_invalid"
            )
        try:
            accepted = adapter_result_from_dict(
                {
                    "schema": "home-center.device-management-enrollment-adapter-start-result.v1",
                    "state": "accepted",
                    "provider_operation_id": result.get("provider_operation_id"),
                    "one_time_artifact": result.get("one_time_artifact"),
                    "post_condition_verified": False,
                    "managed_state_change_authorized": False,
                },
                requested_artifact=plan.one_time_artifact,
            )
        except DeviceManagementEnrollmentExecutionError as exc:
            raise DeviceManagementEnrollmentExecutionRuntimeError(exc.code) from exc

        done = self.store.transition_action_job(
            job["job_id"],
            expected_state="verifying",
            new_state="succeeded",
            evidence={
                "schema": "home-center.device-management-enrollment-provider-acceptance-evidence.v1",
                "scope": "provider-command-accepted-only",
                "plan_id": plan.plan_id,
                "provider_operation_id": accepted.provider_operation_id,
                "enrollment_completed": False,
                "post_condition_verified": False,
                "managed_state_change_authorized": False,
                "next_required_boundary": "post-condition-verification",
                "recovered_after_restart": True,
            },
        )
        preflight = job.get("preflight") if isinstance(job.get("preflight"), dict) else {}
        retry_of = preflight.get("retry_of_job_id")
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "state": "provider-accepted",
            "job_id": done["job_id"],
            "retry_of_job_id": retry_of,
            "plan_id": plan.plan_id,
            "selection_proposal_id": plan.selection_proposal_id,
            "provider_id": plan.provider_id,
            "provider_operation_id": accepted.provider_operation_id,
            "device_id": plan.device_id,
            "member_id": plan.member_id,
            "one_time_artifact": accepted.to_dict()["one_time_artifact"],
            "enrollment_completed": False,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }
        updated = dict(envelope)
        updated.update(status="provider-accepted", receipt=receipt)
        self.store.set_meta(key, updated)
        self.store.audit(
            actor=actor,
            action="household.device.management.enrollment-execution.recover",
            target=plan.device_id,
            outcome="accepted",
            correlation_id=correlation_id,
            details={
                "job_id": done["job_id"],
                "provider_id": plan.provider_id,
                "provider_operation_id": accepted.provider_operation_id,
                "recovery": "finalized-durable-provider-acceptance",
                "provider_reinvoked": False,
                "post_condition_verified": False,
            },
        )
        return receipt

    def start(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        with self._lock:
            key, envelope, plan = self._load(request.get("plan_id"))
            if not isinstance(envelope.get("receipt"), dict):
                previous = self._jobs_for_plan(plan.plan_id, {START_ACTION, RETRY_ACTION})
                if previous:
                    latest = previous[0]
                    same = self._same_request(
                        latest,
                        actor=actor,
                        action=START_ACTION,
                        idempotency_key=request.get("idempotency_key"),
                    )
                    if latest.get("state") == "preflight" and same and len(previous) == 1:
                        # Provider has not been called yet; the durable idempotency row
                        # makes resuming this exact request safe.
                        return DeviceManagementEnrollmentExecutionRuntimeService.start(
                            self, actor=actor, request=request, correlation_id=correlation_id
                        )
                    if latest.get("state") == "verifying" and same and len(previous) == 1:
                        return self._recover_provider_acceptance(
                            actor=actor,
                            correlation_id=correlation_id,
                            key=key,
                            envelope=envelope,
                            plan=plan,
                            job=latest,
                        )
            return super().start(actor=actor, request=request, correlation_id=correlation_id)

    def retry(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        with self._lock:
            key, envelope, plan = self._load(request.get("plan_id"))
            if not isinstance(envelope.get("receipt"), dict):
                previous = self._jobs_for_plan(plan.plan_id, {START_ACTION, RETRY_ACTION})
                if previous:
                    latest = previous[0]
                    same = self._same_request(
                        latest,
                        actor=actor,
                        action=RETRY_ACTION,
                        idempotency_key=request.get("idempotency_key"),
                    ) and self._retry_parent_matches(latest, request.get("failed_job_id"))
                    parent_is_previous = (
                        len(previous) >= 2
                        and previous[1].get("job_id") == request.get("failed_job_id")
                        and previous[1].get("state") == "failed"
                        and isinstance(previous[1].get("result"), dict)
                        and previous[1]["result"].get("retry_safe") is True
                    )
                    if latest.get("state") == "preflight" and same and parent_is_previous:
                        return DeviceManagementEnrollmentExecutionRuntimeService.retry(
                            self, actor=actor, request=request, correlation_id=correlation_id
                        )
                    if latest.get("state") == "verifying" and same and parent_is_previous:
                        return self._recover_provider_acceptance(
                            actor=actor,
                            correlation_id=correlation_id,
                            key=key,
                            envelope=envelope,
                            plan=plan,
                            job=latest,
                        )
            return super().retry(actor=actor, request=request, correlation_id=correlation_id)

    def _complete_cancel(
        self,
        *,
        actor: str,
        correlation_id: str,
        key: str,
        envelope: dict[str, Any],
        plan: object,
        request: dict[str, Any],
        job: dict[str, Any],
        invoke_provider: bool,
    ) -> dict[str, object]:
        receipt = envelope.get("receipt")
        if (
            not isinstance(receipt, dict)
            or receipt.get("state") != "provider-accepted"
            or receipt.get("job_id") != request.get("start_job_id")
        ):
            raise DeviceManagementEnrollmentExecutionRuntimeError(
                "device_management_enrollment_execution_cancel_not_allowed"
            )
        op = receipt.get("provider_operation_id")
        preflight = job.get("preflight")
        if not isinstance(preflight, dict) or preflight.get("provider_operation_id") != op:
            raise DeviceManagementEnrollmentExecutionRuntimeError(
                "device_management_enrollment_execution_state_invalid"
            )

        if invoke_provider:
            self._revalidate(actor, plan)
            adapter = self._adapter(plan.provider_id)
            running = self.store.transition_action_job(
                job["job_id"], expected_state="preflight", new_state="running"
            )
            try:
                adapter.cancel(provider_operation_id=op, job_id=request["start_job_id"])
            except Exception as exc:
                self.store.transition_action_job(
                    running["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={"state": "failed", "provider_acceptance_unknown": True},
                )
                raise DeviceManagementEnrollmentExecutionRuntimeError(
                    "device_management_enrollment_cancel_provider_error"
                ) from exc
            job = self.store.transition_action_job(
                running["job_id"],
                expected_state="running",
                new_state="verifying",
                result={"state": "cancel-requested", "post_condition_verified": False},
            )
        else:
            result = job.get("result")
            if result != {"state": "cancel-requested", "post_condition_verified": False}:
                raise DeviceManagementEnrollmentExecutionRuntimeError(
                    "device_management_enrollment_execution_state_invalid"
                )

        done = self.store.transition_action_job(
            job["job_id"],
            expected_state="verifying",
            new_state="succeeded",
            evidence={
                "scope": "provider-cancel-command-accepted-only",
                "post_condition_verified": False,
                "recovered_after_restart": not invoke_provider,
            },
        )
        cancel_receipt = {
            "schema": CANCEL_RECEIPT_SCHEMA,
            "state": "cancel-requested",
            "job_id": done["job_id"],
            "start_job_id": request["start_job_id"],
            "plan_id": plan.plan_id,
            "provider_id": plan.provider_id,
            "provider_operation_id": op,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        }
        updated = dict(envelope)
        updated.update(status="cancel-requested", cancel_receipt=cancel_receipt)
        self.store.set_meta(key, updated)
        self.store.audit(
            actor=actor,
            action=(
                "household.device.management.enrollment-execution.cancel"
                if invoke_provider
                else "household.device.management.enrollment-execution.cancel-recover"
            ),
            target=plan.device_id,
            outcome="accepted",
            correlation_id=correlation_id,
            details={
                "job_id": done["job_id"],
                "start_job_id": request["start_job_id"],
                "scope": "provider-cancel-command-accepted-only",
                "provider_reinvoked": invoke_provider,
            },
        )
        return cancel_receipt

    def cancel(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        with self._lock:
            key, envelope, plan = self._load(request.get("plan_id"))
            if not isinstance(envelope.get("cancel_receipt"), dict):
                previous = self._jobs_for_plan(plan.plan_id, {CANCEL_ACTION})
                if previous:
                    latest = previous[0]
                    same = self._same_request(
                        latest,
                        actor=actor,
                        action=CANCEL_ACTION,
                        idempotency_key=request.get("idempotency_key"),
                    )
                    if latest.get("state") == "preflight" and same and len(previous) == 1:
                        return self._complete_cancel(
                            actor=actor,
                            correlation_id=correlation_id,
                            key=key,
                            envelope=envelope,
                            plan=plan,
                            request=request,
                            job=latest,
                            invoke_provider=True,
                        )
                    if latest.get("state") == "verifying" and same and len(previous) == 1:
                        return self._complete_cancel(
                            actor=actor,
                            correlation_id=correlation_id,
                            key=key,
                            envelope=envelope,
                            plan=plan,
                            request=request,
                            job=latest,
                            invoke_provider=False,
                        )
            return super().cancel(actor=actor, request=request, correlation_id=correlation_id)
