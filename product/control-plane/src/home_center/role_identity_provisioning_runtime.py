"""Durable fail-closed role identity provisioning runtime for Home Center 0.62.

The runtime persists a Job before the first provider side effect, binds execution
to exact planning/preflight evidence, invokes a deliberately registered typed
provider adapter at most once per durable attempt, and requires separate read-
back verification before reporting success. It never mutates Household state,
the emergency administrator, privileges or external-publication state.
"""
from __future__ import annotations

import hashlib
import re
import threading
from typing import Protocol

from .role_identity_provisioning import IdentityProviderCapability, RoleIdentityProvisioningPlan
from .role_identity_provisioning_execution import (
    IdentityProvisioningExecutionError,
    RoleIdentityProvisioningExecutionRequest,
    adapter_result_from_dict,
    build_identity_execution_request,
    normalize_secret_references,
)
from .role_identity_provisioning_preflight import IdentityProvisioningPreflightDecision
from .role_identity_provisioning_verification import (
    IdentityProvisioningVerificationError,
    observation_from_dict,
    verify_identity_provisioning,
)
from .store import IdempotencyConflict, StateStore
from .util import canonical_json

ACTION = "household.identity.provisioning.execute"
RECEIPT_SCHEMA = "home-center.role-identity-provisioning-execution-receipt.v1"
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class IdentityProvisioningRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RoleIdentityProvisioningRuntimeAdapter(Protocol):
    """Provider adapter with one mutation call and a separate read-only observation."""

    def start(self, request: RoleIdentityProvisioningExecutionRequest) -> object: ...

    def observe(self, *, provider_operation_id: str, account_name: str) -> object: ...


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _receipt(
    *,
    job_id: str,
    plan: RoleIdentityProvisioningPlan,
    provider_operation_id: str,
    account_identity_sha256: str,
    observation_evidence_sha256: str,
) -> dict[str, object]:
    return {
        "schema": RECEIPT_SCHEMA,
        "state": "verified",
        "job_id": job_id,
        "plan_id": plan.plan_id,
        "household_id": plan.household_id,
        "member_id": plan.member_id,
        "provider_id": plan.provider_id,
        "provider_version": plan.provider_version,
        "provider_kind": plan.provider_kind.value,
        "provider_operation_id": provider_operation_id,
        "account_name": plan.account_name,
        "account_identity_sha256": account_identity_sha256,
        "observation_evidence_sha256": observation_evidence_sha256,
        "account_created_verified": True,
        "home_directory_verified": True,
        "profile_verified": True,
        "post_condition_verified": True,
        "durable_state_change_authorized": False,
        "emergency_admin_mutation_authorized": False,
        "privilege_grant_authorized": False,
        "external_publication_authorized": False,
    }


class RoleIdentityProvisioningRuntimeService:
    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()
        self._adapters: dict[str, RoleIdentityProvisioningRuntimeAdapter] = {}

    def register_adapter(self, provider_id: str, adapter: RoleIdentityProvisioningRuntimeAdapter) -> None:
        if (
            not isinstance(provider_id, str)
            or not provider_id
            or provider_id in self._adapters
            or not callable(getattr(adapter, "start", None))
            or not callable(getattr(adapter, "observe", None))
        ):
            raise IdentityProvisioningRuntimeError("identity_runtime_adapter_registration_invalid")
        self._adapters[provider_id] = adapter

    @staticmethod
    def _validate_binding(
        plan: RoleIdentityProvisioningPlan,
        provider: IdentityProviderCapability,
        preflight: IdentityProvisioningPreflightDecision,
    ) -> None:
        if not isinstance(plan, RoleIdentityProvisioningPlan):
            raise IdentityProvisioningRuntimeError("identity_runtime_plan_invalid")
        if not isinstance(provider, IdentityProviderCapability):
            raise IdentityProvisioningRuntimeError("identity_runtime_provider_invalid")
        if not isinstance(preflight, IdentityProvisioningPreflightDecision):
            raise IdentityProvisioningRuntimeError("identity_runtime_preflight_invalid")
        if (
            provider.provider_id != plan.provider_id
            or provider.provider_version != plan.provider_version
            or provider.provider_kind is not plan.provider_kind
            or provider.evidence_sha256 != plan.provider_evidence_sha256
        ):
            raise IdentityProvisioningRuntimeError("identity_runtime_provider_binding_mismatch")
        if (
            preflight.plan_id != plan.plan_id
            or preflight.account_name != plan.account_name
            or preflight.provider_id != plan.provider_id
            or preflight.provider_version != plan.provider_version
            or preflight.provider_evidence_sha256 != plan.provider_evidence_sha256
            or preflight.ready is not True
            or preflight.blockers
            or preflight.execution_authorized is not False
            or preflight.external_publication_authorized is not False
        ):
            raise IdentityProvisioningRuntimeError("identity_runtime_preflight_not_ready")

    def _adapter(self, provider_id: str) -> RoleIdentityProvisioningRuntimeAdapter:
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            raise IdentityProvisioningRuntimeError("identity_runtime_adapter_unavailable")
        return adapter

    def _audit(
        self,
        *,
        actor: str,
        plan: RoleIdentityProvisioningPlan,
        outcome: str,
        correlation_id: str,
        job_id: str,
        provider_operation_id: str | None = None,
        blockers: tuple[str, ...] = (),
    ) -> None:
        self.store.audit(
            actor=actor,
            action=ACTION,
            target=plan.member_id,
            outcome=outcome,
            correlation_id=correlation_id,
            details={
                "job_id": job_id,
                "plan_id": plan.plan_id,
                "provider_id": plan.provider_id,
                "provider_operation_id": provider_operation_id,
                "blockers": list(blockers),
                "credential_material_included": False,
                "emergency_admin_mutation_authorized": False,
                "privilege_grant_authorized": False,
                "external_publication_authorized": False,
            },
        )

    def execute(
        self,
        *,
        actor: str,
        plan: RoleIdentityProvisioningPlan,
        provider: IdentityProviderCapability,
        preflight: IdentityProvisioningPreflightDecision,
        credential_references: object,
        confirmed: bool,
        idempotency_key: str,
        correlation_id: str,
    ) -> dict[str, object]:
        if confirmed is not True:
            raise IdentityProvisioningRuntimeError("identity_runtime_confirmation_required")
        if not isinstance(actor, str) or not actor or not isinstance(correlation_id, str) or not correlation_id:
            raise IdentityProvisioningRuntimeError("identity_runtime_actor_or_correlation_invalid")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise IdentityProvisioningRuntimeError("identity_runtime_idempotency_key_invalid")
        self._validate_binding(plan, provider, preflight)
        adapter = self._adapter(plan.provider_id)
        try:
            refs = normalize_secret_references(credential_references)
        except IdentityProvisioningExecutionError as exc:
            raise IdentityProvisioningRuntimeError(exc.code) from exc
        ref_digest = _digest([item.to_dict() for item in refs])
        request_hash = _digest(
            {
                "plan_id": plan.plan_id,
                "provider_id": plan.provider_id,
                "provider_version": plan.provider_version,
                "provider_evidence_sha256": plan.provider_evidence_sha256,
                "preflight_observation_evidence_sha256": preflight.observation_evidence_sha256,
                "credential_reference_digest": ref_digest,
            }
        )

        with self._lock:
            try:
                job, created = self.store.create_action_job(
                    action_id=ACTION,
                    actor=actor,
                    reason="explicit identity provisioning confirmation",
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.role-identity-provisioning-runtime-preflight.v1",
                        "plan_id": plan.plan_id,
                        "household_id": plan.household_id,
                        "member_id": plan.member_id,
                        "provider_id": plan.provider_id,
                        "provider_version": plan.provider_version,
                        "provider_evidence_sha256": plan.provider_evidence_sha256,
                        "account_name": plan.account_name,
                        "preflight_observation_evidence_sha256": preflight.observation_evidence_sha256,
                        "credential_reference_count": len(refs),
                        "credential_reference_digest": ref_digest,
                        "provider_execution_authorized": False,
                        "post_condition_verification_required": True,
                        "durable_state_change_authorized": False,
                        "emergency_admin_mutation_authorized": False,
                        "privilege_grant_authorized": False,
                        "external_publication_authorized": False,
                    },
                    steps=[
                        {"step": "preflight-revalidate", "state": "succeeded"},
                        {"step": "provider-start", "state": "pending"},
                        {"step": "provider-readback", "state": "pending"},
                        {"step": "post-condition-verify", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise IdentityProvisioningRuntimeError("identity_runtime_idempotency_conflict") from exc

            if not created:
                if job["state"] == "succeeded" and isinstance(job.get("evidence"), dict):
                    receipt = job["evidence"].get("receipt")
                    if isinstance(receipt, dict) and receipt.get("schema") == RECEIPT_SCHEMA:
                        return dict(receipt)
                if job["state"] in {"preflight", "running", "verifying"}:
                    raise IdentityProvisioningRuntimeError("identity_runtime_execution_in_progress")
                if job["state"] == "failed":
                    raise IdentityProvisioningRuntimeError("identity_runtime_previous_attempt_failed")
                raise IdentityProvisioningRuntimeError("identity_runtime_job_state_invalid")

            running = self.store.transition_action_job(
                job["job_id"],
                expected_state="preflight",
                new_state="running",
                steps=[
                    {"step": "preflight-revalidate", "state": "succeeded"},
                    {"step": "provider-start", "state": "running"},
                    {"step": "provider-readback", "state": "pending"},
                    {"step": "post-condition-verify", "state": "pending"},
                ],
            )
            try:
                request = build_identity_execution_request(
                    plan=plan,
                    provider=provider,
                    job_id=running["job_id"],
                    credential_references=[item.to_dict() for item in refs],
                    confirmed=True,
                )
                accepted = adapter_result_from_dict(adapter.start(request))
            except TimeoutError as exc:
                self.store.transition_action_job(
                    running["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={
                        "schema": "home-center.role-identity-provider-start-failure.v1",
                        "state": "failed",
                        "code": "identity_runtime_provider_timeout",
                        "provider_acceptance_unknown": True,
                        "retry_safe": False,
                        "post_condition_verified": False,
                    },
                )
                self._audit(
                    actor=actor, plan=plan, outcome="failed", correlation_id=correlation_id, job_id=running["job_id"]
                )
                raise IdentityProvisioningRuntimeError("identity_runtime_provider_timeout") from exc
            except (IdentityProvisioningExecutionError, Exception) as exc:
                code = (
                    exc.code
                    if isinstance(exc, IdentityProvisioningExecutionError)
                    else "identity_runtime_provider_error"
                )
                self.store.transition_action_job(
                    running["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={
                        "schema": "home-center.role-identity-provider-start-failure.v1",
                        "state": "failed",
                        "code": code,
                        "provider_acceptance_unknown": True,
                        "retry_safe": False,
                        "post_condition_verified": False,
                    },
                )
                self._audit(
                    actor=actor, plan=plan, outcome="failed", correlation_id=correlation_id, job_id=running["job_id"]
                )
                raise IdentityProvisioningRuntimeError(code) from exc

            verifying = self.store.transition_action_job(
                running["job_id"],
                expected_state="running",
                new_state="verifying",
                result={
                    "schema": "home-center.role-identity-provider-acceptance.v1",
                    "state": "accepted",
                    "provider_operation_id": accepted.provider_operation_id,
                    "account_name": accepted.account_name,
                    "account_created_verified": False,
                    "home_directory_verified": False,
                    "profile_verified": False,
                    "post_condition_verified": False,
                },
                steps=[
                    {"step": "preflight-revalidate", "state": "succeeded"},
                    {"step": "provider-start", "state": "succeeded"},
                    {"step": "provider-readback", "state": "running"},
                    {"step": "post-condition-verify", "state": "pending"},
                ],
            )
            try:
                observation = observation_from_dict(
                    adapter.observe(
                        provider_operation_id=accepted.provider_operation_id,
                        account_name=plan.account_name,
                    )
                )
                verification = verify_identity_provisioning(
                    plan=plan,
                    provider=provider,
                    accepted=accepted,
                    observation=observation,
                    now=observation.observed_at,
                )
            except (IdentityProvisioningVerificationError, TimeoutError, Exception) as exc:
                code = (
                    exc.code
                    if isinstance(exc, IdentityProvisioningVerificationError)
                    else "identity_runtime_verification_unavailable"
                )
                failed = self.store.transition_action_job(
                    verifying["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    evidence={
                        "schema": "home-center.role-identity-verification-failure-evidence.v1",
                        "provider_operation_id": accepted.provider_operation_id,
                        "code": code,
                        "provider_reinvocation_authorized": False,
                        "post_condition_verified": False,
                        "durable_state_change_authorized": False,
                    },
                )
                self._audit(
                    actor=actor,
                    plan=plan,
                    outcome="failed",
                    correlation_id=correlation_id,
                    job_id=failed["job_id"],
                    provider_operation_id=accepted.provider_operation_id,
                    blockers=(code,),
                )
                raise IdentityProvisioningRuntimeError(code) from exc

            if not verification.verified:
                failed = self.store.transition_action_job(
                    verifying["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    result=verification.to_dict(),
                    evidence={
                        "schema": "home-center.role-identity-verification-failure-evidence.v1",
                        "provider_operation_id": accepted.provider_operation_id,
                        "observation_evidence_sha256": observation.evidence_sha256,
                        "blockers": list(verification.blockers),
                        "provider_reinvocation_authorized": False,
                        "post_condition_verified": False,
                        "durable_state_change_authorized": False,
                    },
                )
                self._audit(
                    actor=actor,
                    plan=plan,
                    outcome="blocked",
                    correlation_id=correlation_id,
                    job_id=failed["job_id"],
                    provider_operation_id=accepted.provider_operation_id,
                    blockers=verification.blockers,
                )
                raise IdentityProvisioningRuntimeError("identity_runtime_post_condition_not_verified")

            if verification.account_identity_sha256 is None:
                raise IdentityProvisioningRuntimeError("identity_runtime_verification_state_invalid")
            receipt = _receipt(
                job_id=verifying["job_id"],
                plan=plan,
                provider_operation_id=accepted.provider_operation_id,
                account_identity_sha256=verification.account_identity_sha256,
                observation_evidence_sha256=observation.evidence_sha256,
            )
            done = self.store.transition_action_job(
                verifying["job_id"],
                expected_state="verifying",
                new_state="succeeded",
                result=verification.to_dict(),
                evidence={
                    "schema": "home-center.role-identity-provisioning-success-evidence.v1",
                    "receipt": receipt,
                    "provider_reinvocation_authorized": False,
                    "durable_state_change_authorized": False,
                },
                steps=[
                    {"step": "preflight-revalidate", "state": "succeeded"},
                    {"step": "provider-start", "state": "succeeded"},
                    {"step": "provider-readback", "state": "succeeded"},
                    {"step": "post-condition-verify", "state": "succeeded"},
                ],
            )
            self._audit(
                actor=actor,
                plan=plan,
                outcome="verified",
                correlation_id=correlation_id,
                job_id=done["job_id"],
                provider_operation_id=accepted.provider_operation_id,
            )
            return receipt
