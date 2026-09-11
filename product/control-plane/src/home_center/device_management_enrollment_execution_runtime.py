"""Durable 0.57 provider-enrollment execution boundary.

A successful job in this module means only that a typed provider adapter accepted
an enrollment/cancel command. It never means that enrollment was verified and it
never changes ManagedDevice.managed. Verification belongs to 0.58.
"""
from __future__ import annotations

import hashlib
import re
import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from .device_management_enrollment_execution import (
    DeviceManagementEnrollmentAdapterStartRequest,
    DeviceManagementEnrollmentExecutionError,
    DeviceManagementEnrollmentExecutionPlan,
    DeviceManagementEnrollmentProviderAdapter,
    adapter_result_from_dict,
    build_enrollment_execution_plan,
    execution_plan_from_dict,
)
from .device_management_provider import DeviceManagementProviderError, empty_provider_catalog, normalize_provider_catalog
from .device_management_provider_runtime import PROVIDER_CATALOG_STATE_KEY
from .device_management_provider_selection import (
    DeviceManagementProviderSelectionConfirmation,
    DeviceManagementProviderSelectionError,
    provider_selection_proposal_from_dict,
    revalidate_provider_selection_proposal,
)
from .device_management_provider_selection_runtime import PROVIDER_SELECTION_STATE_SCHEMA, _selection_key
from .household_device_enrollment import device_enrollment_proposal_from_dict
from .household_device_enrollment_runtime import DEVICE_ENROLLMENT_STATE_SCHEMA, _proposal_key as enrollment_key
from .household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore
from .util import canonical_json, utc_now

PLAN_REQUEST_SCHEMA = "home-center.device-management-enrollment-execution-plan-request.v1"
START_REQUEST_SCHEMA = "home-center.device-management-enrollment-execution-start-request.v1"
CANCEL_REQUEST_SCHEMA = "home-center.device-management-enrollment-execution-cancel-request.v1"
RETRY_REQUEST_SCHEMA = "home-center.device-management-enrollment-execution-retry-request.v1"
STATE_SCHEMA = "home-center.device-management-enrollment-execution-state.v1"
RECEIPT_SCHEMA = "home-center.device-management-enrollment-execution-receipt.v1"
CANCEL_RECEIPT_SCHEMA = "home-center.device-management-enrollment-cancel-receipt.v1"
KEY_PREFIX = "cozy.household.device-enrollment-execution."
PLAN_ID = re.compile(r"^dmpexec-[0-9a-f]{24}$")
IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
START_ACTION = "household.device.management.enrollment.start"
RETRY_ACTION = "household.device.management.enrollment.retry"
CANCEL_ACTION = "household.device.management.enrollment.cancel"


class DeviceManagementEnrollmentExecutionRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code); self.code = code


class DeviceManagementEnrollmentAdapterFailure(RuntimeError):
    """Adapter-declared failure; retry_safe=True requires proof no command was accepted."""
    def __init__(self, code: str, *, retry_safe: bool = False) -> None:
        if not isinstance(code, str) or not code or not isinstance(retry_safe, bool):
            raise ValueError("invalid_device_management_enrollment_adapter_failure")
        super().__init__(code); self.code = code; self.retry_safe = retry_safe


def _key(plan_id: object) -> str:
    if not isinstance(plan_id, str) or PLAN_ID.fullmatch(plan_id) is None:
        raise DeviceManagementEnrollmentExecutionRuntimeError("invalid_device_management_enrollment_execution_plan_id")
    return KEY_PREFIX + plan_id


def _hash(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


class DeviceManagementEnrollmentExecutionRuntimeService:
    def __init__(self, store: StateStore, *, now: Callable[[], str] = utc_now) -> None:
        self.store = store; self._now = now; self._lock = threading.RLock()
        self._adapters: dict[str, DeviceManagementEnrollmentProviderAdapter] = {}

    def register_adapter(self, provider_id: str, adapter: DeviceManagementEnrollmentProviderAdapter) -> None:
        if not isinstance(provider_id, str) or not provider_id or provider_id in self._adapters:
            raise DeviceManagementEnrollmentExecutionRuntimeError("invalid_device_management_enrollment_adapter_registration")
        if not callable(getattr(adapter, "start", None)) or not callable(getattr(adapter, "cancel", None)):
            raise DeviceManagementEnrollmentExecutionRuntimeError("invalid_device_management_enrollment_adapter_registration")
        self._adapters[provider_id] = adapter

    def _state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None: raise DeviceManagementEnrollmentExecutionRuntimeError("household_not_configured")
        try: return _state_from_dict(raw)
        except Exception as exc: raise DeviceManagementEnrollmentExecutionRuntimeError(getattr(exc,"code","household_state_invalid")) from exc

    @staticmethod
    def _actor(actor: str, bindings: tuple[ActorBinding, ...]) -> str:
        member = next((x.member_id for x in bindings if x.actor == actor), None)
        if member is None: raise DeviceManagementEnrollmentExecutionRuntimeError("household_actor_not_bound")
        return member

    def _catalog(self):
        raw = self.store.get_meta(PROVIDER_CATALOG_STATE_KEY)
        try: return empty_provider_catalog() if raw is None else normalize_provider_catalog(raw)
        except DeviceManagementProviderError as exc: raise DeviceManagementEnrollmentExecutionRuntimeError(exc.code) from exc

    def _enrollment(self, proposal_id: object):
        envelope = self.store.get_meta(enrollment_key(proposal_id))
        if not isinstance(envelope, dict) or envelope.get("schema") != DEVICE_ENROLLMENT_STATE_SCHEMA or envelope.get("status") != "confirmed":
            raise DeviceManagementEnrollmentExecutionRuntimeError("household_device_enrollment_not_confirmed")
        try: proposal = device_enrollment_proposal_from_dict(envelope.get("proposal"))
        except Exception as exc: raise DeviceManagementEnrollmentExecutionRuntimeError(getattr(exc,"code","household_device_enrollment_state_invalid")) from exc
        receipt = envelope.get("receipt")
        if not isinstance(receipt, dict) or receipt.get("proposal_id") != proposal.proposal_id or receipt.get("provider_selected") is not False:
            raise DeviceManagementEnrollmentExecutionRuntimeError("household_device_enrollment_receipt_invalid")
        return proposal

    def _selection(self, proposal_id: object):
        envelope = self.store.get_meta(_selection_key(proposal_id))
        if not isinstance(envelope, dict) or envelope.get("schema") != PROVIDER_SELECTION_STATE_SCHEMA or envelope.get("status") != "confirmed":
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_provider_selection_not_confirmed")
        try: proposal = provider_selection_proposal_from_dict(envelope.get("proposal"))
        except DeviceManagementProviderSelectionError as exc: raise DeviceManagementEnrollmentExecutionRuntimeError(exc.code) from exc
        receipt = envelope.get("receipt")
        audit_id = receipt.get("audit_event_id") if isinstance(receipt, dict) else None
        if not isinstance(audit_id, str) or not audit_id:
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_provider_selection_receipt_invalid")
        expected = DeviceManagementProviderSelectionConfirmation(
            proposal_id=proposal.proposal_id, resolution_plan_id=proposal.resolution_plan_id,
            enrollment_proposal_id=proposal.enrollment_proposal_id, device_id=proposal.device_id,
            member_id=proposal.member_id, selected_provider_id=proposal.proposed_provider_id,
            snapshot_id=proposal.snapshot_id, resource_version=proposal.resource_version,
            generation=proposal.generation, catalog_id=proposal.catalog_id, audit_event_id=audit_id,
            outcome="provider-selected",
        ).to_dict()
        if receipt != expected: raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_provider_selection_receipt_invalid")
        return proposal, expected

    def _inputs(self, actor: str, selection_id: object):
        snapshot, bindings = self._state(); actor_member = self._actor(actor, bindings)
        selection, receipt = self._selection(selection_id); catalog = self._catalog()
        if selection.actor_member_id != actor_member:
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_actor_mismatch")
        enrollment = self._enrollment(selection.enrollment_proposal_id)
        try: revalidate_provider_selection_proposal(snapshot, enrollment, catalog, selection, actor_member_id=actor_member)
        except DeviceManagementProviderSelectionError as exc: raise DeviceManagementEnrollmentExecutionRuntimeError(exc.code) from exc
        snapshot2, bindings2 = self._state(); selection2, receipt2 = self._selection(selection_id); catalog2 = self._catalog()
        if (self._actor(actor,bindings2) != actor_member or snapshot2 != snapshot or selection2 != selection
                or receipt2 != receipt or catalog2.catalog_id != catalog.catalog_id):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_stale")
        return snapshot, actor_member, catalog, receipt

    def _load(self, plan_id: object):
        key = _key(plan_id); envelope = self.store.get_meta(key)
        if not isinstance(envelope, dict) or envelope.get("schema") != STATE_SCHEMA:
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_plan_not_found")
        try: plan = execution_plan_from_dict(envelope.get("plan"))
        except DeviceManagementEnrollmentExecutionError as exc: raise DeviceManagementEnrollmentExecutionRuntimeError(exc.code) from exc
        return key, envelope, plan

    def _revalidate(self, actor: str, plan: DeviceManagementEnrollmentExecutionPlan) -> None:
        snapshot, actor_member, catalog, receipt = self._inputs(actor, plan.selection_proposal_id)
        try:
            fresh = build_enrollment_execution_plan(
                selection_confirmation=receipt, catalog=catalog, household_id=snapshot.household_id,
                snapshot_id=snapshot.snapshot_id, resource_version=snapshot.resource_version, generation=snapshot.generation,
                actor_member_id=actor_member, enrollment_mode=plan.enrollment_mode,
                credential_references=[x.to_dict() for x in plan.credential_references],
                timeout_seconds=plan.timeout_seconds, one_time_artifact=plan.one_time_artifact,
            )
        except DeviceManagementEnrollmentExecutionError as exc: raise DeviceManagementEnrollmentExecutionRuntimeError(exc.code) from exc
        if fresh != plan: raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_stale")

    def plan(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        fields={"schema","selection_proposal_id","enrollment_mode","credential_references","timeout_seconds","one_time_artifact"}
        if set(request)!=fields or request.get("schema")!=PLAN_REQUEST_SCHEMA:
            raise DeviceManagementEnrollmentExecutionRuntimeError("invalid_device_management_enrollment_execution_plan_request")
        with self._lock:
            snapshot, actor_member, catalog, receipt = self._inputs(actor, request.get("selection_proposal_id"))
            try:
                plan=build_enrollment_execution_plan(
                    selection_confirmation=receipt,catalog=catalog,household_id=snapshot.household_id,
                    snapshot_id=snapshot.snapshot_id,resource_version=snapshot.resource_version,generation=snapshot.generation,
                    actor_member_id=actor_member,enrollment_mode=request.get("enrollment_mode"),
                    credential_references=request.get("credential_references"),timeout_seconds=request.get("timeout_seconds"),
                    one_time_artifact=request.get("one_time_artifact"))
            except DeviceManagementEnrollmentExecutionError as exc: raise DeviceManagementEnrollmentExecutionRuntimeError(exc.code) from exc
            key=_key(plan.plan_id); old=self.store.get_meta(key)
            if old is None:
                self.store.set_meta(key,{"schema":STATE_SCHEMA,"status":"planned","plan":plan.to_dict(),"receipt":None,"cancel_receipt":None})
            elif not isinstance(old,dict) or old.get("plan")!=plan.to_dict():
                raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_state_invalid")
            self.store.audit(actor=actor,action="household.device.management.enrollment-execution.plan",target=plan.device_id,
                outcome="accepted",correlation_id=correlation_id,details={"plan_id":plan.plan_id,"provider_id":plan.provider_id,
                "credential_reference_count":len(plan.credential_references),"provider_execution_authorized":False,
                "managed_state_change_authorized":False})
            return plan.to_dict()

    def _adapter(self, provider_id: str):
        adapter=self._adapters.get(provider_id)
        if adapter is None: raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_adapter_unavailable")
        return adapter

    def _deadline(self, seconds: int):
        try: now=datetime.strptime(self._now(),"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except (TypeError,ValueError) as exc: raise DeviceManagementEnrollmentExecutionRuntimeError("trusted_time_invalid") from exc
        return now,(now+timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _fail(self, job_id: str, *, code: str, retry_safe: bool) -> None:
        if (job:=self.store.job(job_id)) and job["state"]=="running":
            self.store.transition_action_job(job_id,expected_state="running",new_state="failed",result={
                "schema":"home-center.device-management-enrollment-provider-start-failure.v1","state":"failed","code":code,
                "retry_safe":retry_safe,"provider_acceptance_unknown":not retry_safe,"post_condition_verified":False,
                "managed_state_change_authorized":False})

    def _start(self, *, actor: str, plan_id: object, idempotency_key: object, correlation_id: str, retry_of: str|None):
        if not isinstance(idempotency_key,str) or IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise DeviceManagementEnrollmentExecutionRuntimeError("invalid_device_management_enrollment_idempotency_key")
        key,envelope,plan=self._load(plan_id); self._revalidate(actor,plan); adapter=self._adapter(plan.provider_id)
        action=RETRY_ACTION if retry_of else START_ACTION
        job,created=self.store.create_action_job(action_id=action,actor=actor,reason="explicit provider enrollment confirmation",
            idempotency_key=idempotency_key,request_hash=_hash({"plan_id":plan.plan_id,"retry_of":retry_of,"key":idempotency_key}),
            preflight={"schema":"home-center.device-management-enrollment-execution-preflight.v1","plan_id":plan.plan_id,
                "provider_id":plan.provider_id,"device_id":plan.device_id,"retry_of_job_id":retry_of,
                "provider_execution_authorized":False,"post_condition_verified":False,"managed_state_change_authorized":False},
            steps=[{"step":"revalidate","state":"succeeded"},{"step":"provider-start","state":"pending"}])
        if not created:
            receipt=envelope.get("receipt")
            if job["state"]=="succeeded" and isinstance(receipt,dict) and receipt.get("job_id")==job["job_id"]: return receipt
            if job["state"] in {"running","verifying"}: raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_in_progress")
            if job["state"]=="failed": raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_retry_required")
        running=self.store.transition_action_job(job["job_id"],expected_state="preflight",new_state="running")
        now,deadline=self._deadline(plan.timeout_seconds)
        req=DeviceManagementEnrollmentAdapterStartRequest(job_id=running["job_id"],plan_id=plan.plan_id,provider_id=plan.provider_id,
            device_id=plan.device_id,member_id=plan.member_id,enrollment_mode=plan.enrollment_mode,
            credential_references=plan.credential_references,timeout_seconds=plan.timeout_seconds,deadline_at=deadline,
            one_time_artifact=plan.one_time_artifact)
        try:
            result=adapter_result_from_dict(adapter.start(req),requested_artifact=plan.one_time_artifact)
            if result.one_time_artifact_expires_at:
                expires=datetime.strptime(result.one_time_artifact_expires_at,"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
                limit=datetime.strptime(deadline,"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
                if not now < expires <= limit: raise DeviceManagementEnrollmentExecutionError("device_management_enrollment_adapter_result_rejected")
        except DeviceManagementEnrollmentAdapterFailure as exc:
            self._fail(running["job_id"],code=exc.code,retry_safe=exc.retry_safe); raise DeviceManagementEnrollmentExecutionRuntimeError(exc.code) from exc
        except TimeoutError as exc:
            self._fail(running["job_id"],code="device_management_enrollment_provider_timeout",retry_safe=False); raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_provider_timeout") from exc
        except DeviceManagementEnrollmentExecutionError as exc:
            self._fail(running["job_id"],code=exc.code,retry_safe=False); raise DeviceManagementEnrollmentExecutionRuntimeError(exc.code) from exc
        except Exception as exc:
            self._fail(running["job_id"],code="device_management_enrollment_provider_error",retry_safe=False); raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_provider_error") from exc
        verifying=self.store.transition_action_job(running["job_id"],expected_state="running",new_state="verifying",result={
            "schema":"home-center.device-management-enrollment-provider-acceptance.v1","state":"provider-accepted",
            "provider_operation_id":result.provider_operation_id,"one_time_artifact":result.to_dict()["one_time_artifact"],
            "enrollment_completed":False,"post_condition_verified":False,"managed_state_change_authorized":False})
        done=self.store.transition_action_job(verifying["job_id"],expected_state="verifying",new_state="succeeded",evidence={
            "schema":"home-center.device-management-enrollment-provider-acceptance-evidence.v1","scope":"provider-command-accepted-only",
            "plan_id":plan.plan_id,"provider_operation_id":result.provider_operation_id,"enrollment_completed":False,
            "post_condition_verified":False,"managed_state_change_authorized":False,"next_required_boundary":"post-condition-verification"})
        receipt={"schema":RECEIPT_SCHEMA,"state":"provider-accepted","job_id":done["job_id"],"retry_of_job_id":retry_of,
            "plan_id":plan.plan_id,"selection_proposal_id":plan.selection_proposal_id,"provider_id":plan.provider_id,
            "provider_operation_id":result.provider_operation_id,"device_id":plan.device_id,"member_id":plan.member_id,
            "one_time_artifact":result.to_dict()["one_time_artifact"],"enrollment_completed":False,"post_condition_verified":False,
            "managed_state_change_authorized":False,"policy_application_authorized":False,"infrastructure_mutation_authorized":False,
            "external_publication_authorized":False}
        new=dict(envelope); new.update(status="provider-accepted",receipt=receipt); self.store.set_meta(key,new)
        self.store.audit(actor=actor,action="household.device.management.enrollment-execution.start",target=plan.device_id,
            outcome="accepted",correlation_id=correlation_id,details={"job_id":done["job_id"],"provider_id":plan.provider_id,
            "provider_operation_id":result.provider_operation_id,"scope":"provider-command-accepted-only","post_condition_verified":False})
        return receipt

    def start(self, *, actor: str, request: dict[str,Any], correlation_id: str):
        if set(request)!={"schema","plan_id","confirmed","idempotency_key"} or request.get("schema")!=START_REQUEST_SCHEMA or request.get("confirmed") is not True:
            raise DeviceManagementEnrollmentExecutionRuntimeError("invalid_device_management_enrollment_execution_start_request")
        with self._lock: return self._start(actor=actor,plan_id=request.get("plan_id"),idempotency_key=request.get("idempotency_key"),correlation_id=correlation_id,retry_of=None)

    def retry(self, *, actor: str, request: dict[str,Any], correlation_id: str):
        if set(request)!={"schema","plan_id","failed_job_id","confirmed","idempotency_key"} or request.get("schema")!=RETRY_REQUEST_SCHEMA or request.get("confirmed") is not True:
            raise DeviceManagementEnrollmentExecutionRuntimeError("invalid_device_management_enrollment_execution_retry_request")
        failed=self.store.job(request.get("failed_job_id")) if isinstance(request.get("failed_job_id"),str) else None
        if not failed or failed["job_type"] not in {START_ACTION,RETRY_ACTION} or failed["state"]!="failed" or failed["preflight"].get("plan_id")!=request.get("plan_id"):
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_retry_not_allowed")
        if not isinstance(failed.get("result"),dict) or failed["result"].get("retry_safe") is not True:
            raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_retry_not_safe")
        with self._lock: return self._start(actor=actor,plan_id=request.get("plan_id"),idempotency_key=request.get("idempotency_key"),correlation_id=correlation_id,retry_of=failed["job_id"])

    def cancel(self, *, actor: str, request: dict[str,Any], correlation_id: str):
        if set(request)!={"schema","plan_id","start_job_id","confirmed","idempotency_key"} or request.get("schema")!=CANCEL_REQUEST_SCHEMA or request.get("confirmed") is not True:
            raise DeviceManagementEnrollmentExecutionRuntimeError("invalid_device_management_enrollment_execution_cancel_request")
        idem=request.get("idempotency_key")
        if not isinstance(idem,str) or IDEMPOTENCY.fullmatch(idem) is None: raise DeviceManagementEnrollmentExecutionRuntimeError("invalid_device_management_enrollment_idempotency_key")
        with self._lock:
            key,envelope,plan=self._load(request.get("plan_id")); self._revalidate(actor,plan); receipt=envelope.get("receipt")
            if not isinstance(receipt,dict) or receipt.get("state")!="provider-accepted" or receipt.get("job_id")!=request.get("start_job_id"):
                raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_cancel_not_allowed")
            adapter=self._adapter(plan.provider_id); op=receipt.get("provider_operation_id")
            job,created=self.store.create_action_job(action_id=CANCEL_ACTION,actor=actor,reason="explicit enrollment cancellation confirmation",
                idempotency_key=idem,request_hash=_hash({"plan_id":plan.plan_id,"start_job_id":request.get("start_job_id"),"key":idem}),
                preflight={"schema":"home-center.device-management-enrollment-cancel-preflight.v1","plan_id":plan.plan_id,
                    "provider_operation_id":op,"managed_state_change_authorized":False},steps=[{"step":"provider-cancel","state":"pending"}])
            if not created and job["state"]=="succeeded" and isinstance(envelope.get("cancel_receipt"),dict): return envelope["cancel_receipt"]
            if not created: raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_execution_cancel_in_progress")
            running=self.store.transition_action_job(job["job_id"],expected_state="preflight",new_state="running")
            try: adapter.cancel(provider_operation_id=op,job_id=request["start_job_id"])
            except Exception as exc:
                self.store.transition_action_job(running["job_id"],expected_state="running",new_state="failed",result={"state":"failed","provider_acceptance_unknown":True})
                raise DeviceManagementEnrollmentExecutionRuntimeError("device_management_enrollment_cancel_provider_error") from exc
            verifying=self.store.transition_action_job(running["job_id"],expected_state="running",new_state="verifying",result={"state":"cancel-requested","post_condition_verified":False})
            done=self.store.transition_action_job(verifying["job_id"],expected_state="verifying",new_state="succeeded",evidence={"scope":"provider-cancel-command-accepted-only","post_condition_verified":False})
            cancel={"schema":CANCEL_RECEIPT_SCHEMA,"state":"cancel-requested","job_id":done["job_id"],"start_job_id":request["start_job_id"],
                "plan_id":plan.plan_id,"provider_id":plan.provider_id,"provider_operation_id":op,"post_condition_verified":False,"managed_state_change_authorized":False}
            new=dict(envelope); new.update(status="cancel-requested",cancel_receipt=cancel); self.store.set_meta(key,new)
            self.store.audit(actor=actor,action="household.device.management.enrollment-execution.cancel",target=plan.device_id,outcome="accepted",
                correlation_id=correlation_id,details={"job_id":done["job_id"],"start_job_id":request["start_job_id"],"scope":"provider-cancel-command-accepted-only"})
            return cancel
