"""Durable fail-closed runtime for Home Center 0.62 role identity provisioning.

The runtime binds the already-qualified 0.62 plan, account preflight, typed provider
execution and read-back verification contracts to the existing durable Job/Audit
store. Provider mutation is possible only through an explicitly registered exact
qualified adapter. Replays never implicitly invoke the provider again, and a lost or
ambiguous provider response is terminal for automatic mutation and requires explicit
operator reconciliation. Verified provider post-condition is still separate from any
future Home Center durable identity-state transition.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .home_services import HomeServiceCatalogError, _identifier
from .household import EffectivePolicy
from .household_policy_composer import ComposedPolicy
from .household_store import HouseholdSnapshot
from .role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProvisioningError,
    RoleIdentityProvisioningPlan,
    build_role_identity_provisioning_plan,
    plan_from_dict,
)
from .role_identity_provisioning_execution import (
    IdentityProvisioningExecutionError,
    RoleIdentityProvisioningProviderAdapter,
    adapter_result_from_dict,
    build_identity_execution_request,
    execution_request_from_dict,
    normalize_secret_references,
)
from .role_identity_provisioning_preflight import (
    AccountPreflightObservation,
    IdentityProvisioningPreflightError,
    evaluate_account_preflight,
)
from .role_identity_provisioning_verification import (
    IdentityProvisioningReadbackObservation,
    IdentityProvisioningVerificationError,
    observation_from_dict as verification_observation_from_dict,
    verify_identity_provisioning,
)
from .store import StateStore
from .util import canonical_json

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CORRELATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z")
ACTION_ID = "role-identity-provisioning"


class IdentityProvisioningRuntimeError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _sha(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise IdentityProvisioningRuntimeError(code)
    return value


def _actor(value: object) -> str:
    try:
        return _identifier(value, "identity_runtime_actor_invalid")
    except HomeServiceCatalogError as exc:
        raise IdentityProvisioningRuntimeError(exc.code) from exc


def _bounded_text(value: object, code: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise IdentityProvisioningRuntimeError(code)
    return value.strip()


def _idempotency(value: object) -> str:
    if not isinstance(value, str) or _IDEMPOTENCY.fullmatch(value) is None:
        raise IdentityProvisioningRuntimeError("identity_runtime_idempotency_key_invalid")
    return value


def _correlation(value: object) -> str:
    if not isinstance(value, str) or _CORRELATION.fullmatch(value) is None:
        raise IdentityProvisioningRuntimeError("identity_runtime_correlation_id_invalid")
    return value


def _request_hash(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _strict_plan(value: RoleIdentityProvisioningPlan | dict[str, object]) -> RoleIdentityProvisioningPlan:
    try:
        return plan_from_dict(value.to_dict() if isinstance(value, RoleIdentityProvisioningPlan) else value)
    except IdentityProvisioningError as exc:
        raise IdentityProvisioningRuntimeError("identity_runtime_plan_rejected") from exc


def _revalidate_current_plan(
    *,
    snapshot: HouseholdSnapshot,
    policy: EffectivePolicy | ComposedPolicy,
    provider: IdentityProviderCapability,
    plan: RoleIdentityProvisioningPlan | dict[str, object],
) -> RoleIdentityProvisioningPlan:
    if not isinstance(snapshot, HouseholdSnapshot):
        raise IdentityProvisioningRuntimeError("identity_runtime_household_snapshot_invalid")
    if not isinstance(provider, IdentityProviderCapability):
        raise IdentityProvisioningRuntimeError("identity_runtime_provider_invalid")
    parsed = _strict_plan(plan)
    try:
        rebuilt = build_role_identity_provisioning_plan(
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            member_id=parsed.member_id,
            account_name=parsed.account_name,
            home_directory_mode=parsed.home_directory_mode,
            profile_mode=parsed.profile_mode,
        )
    except IdentityProvisioningError as exc:
        raise IdentityProvisioningRuntimeError(
            getattr(exc, "code", "identity_runtime_plan_stale")
        ) from exc
    if rebuilt.to_dict() != parsed.to_dict():
        raise IdentityProvisioningRuntimeError("identity_runtime_plan_stale")
    return parsed


@dataclass(frozen=True, slots=True)
class QualifiedIdentityAdapterRegistration:
    provider_id: str
    provider_version: str
    provider_evidence_sha256: str
    qualification_evidence_sha256: str
    adapter: RoleIdentityProvisioningProviderAdapter


class QualifiedIdentityAdapterRegistry:
    """Exact provider/evidence registry. Nothing is registered implicitly."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str, str], QualifiedIdentityAdapterRegistration] = {}

    def register(
        self,
        *,
        provider: IdentityProviderCapability,
        adapter: RoleIdentityProvisioningProviderAdapter,
        qualification_evidence_sha256: str,
    ) -> QualifiedIdentityAdapterRegistration:
        if not isinstance(provider, IdentityProviderCapability):
            raise IdentityProvisioningRuntimeError("identity_runtime_provider_invalid")
        if adapter is None or not callable(getattr(adapter, "start", None)):
            raise IdentityProvisioningRuntimeError("identity_runtime_adapter_invalid")
        evidence = _sha(
            qualification_evidence_sha256,
            "identity_runtime_adapter_qualification_evidence_invalid",
        )
        key = (provider.provider_id, provider.provider_version, provider.evidence_sha256)
        registration = QualifiedIdentityAdapterRegistration(
            provider_id=provider.provider_id,
            provider_version=provider.provider_version,
            provider_evidence_sha256=provider.evidence_sha256,
            qualification_evidence_sha256=evidence,
            adapter=adapter,
        )
        existing = self._items.get(key)
        if existing is not None and existing != registration:
            raise IdentityProvisioningRuntimeError("identity_runtime_adapter_registration_conflict")
        self._items[key] = registration
        return registration

    def resolve(self, provider: IdentityProviderCapability) -> QualifiedIdentityAdapterRegistration:
        if not isinstance(provider, IdentityProviderCapability):
            raise IdentityProvisioningRuntimeError("identity_runtime_provider_invalid")
        key = (provider.provider_id, provider.provider_version, provider.evidence_sha256)
        registration = self._items.get(key)
        if registration is None:
            raise IdentityProvisioningRuntimeError("identity_runtime_qualified_adapter_unavailable")
        return registration


class RoleIdentityProvisioningRuntimeService:
    def __init__(self, *, store: StateStore, registry: QualifiedIdentityAdapterRegistry) -> None:
        if not isinstance(store, StateStore):
            raise TypeError("store must be StateStore")
        if not isinstance(registry, QualifiedIdentityAdapterRegistry):
            raise TypeError("registry must be QualifiedIdentityAdapterRegistry")
        self.store = store
        self.registry = registry

    def start(
        self,
        *,
        snapshot: HouseholdSnapshot,
        policy: EffectivePolicy | ComposedPolicy,
        plan: RoleIdentityProvisioningPlan | dict[str, object],
        provider: IdentityProviderCapability,
        preflight_observation: AccountPreflightObservation,
        credential_references: object,
        actor: str,
        reason: str,
        idempotency_key: str,
        correlation_id: str,
        now: str,
        confirmed: bool,
    ) -> dict[str, Any]:
        """Create a durable Job and invoke the exact qualified adapter at most once here.

        The plan is reconstructed and rebuilt against the exact current Household and
        policy immediately before durable admission. Replaying the same durable request
        returns the existing Job without any provider call, regardless of its state.
        """

        actor_id = _actor(actor)
        reason_text = _bounded_text(reason, "identity_runtime_reason_invalid", 512)
        idem = _idempotency(idempotency_key)
        correlation = _correlation(correlation_id)
        if confirmed is not True:
            raise IdentityProvisioningRuntimeError("identity_runtime_confirmation_required")
        current_plan = _revalidate_current_plan(
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            plan=plan,
        )
        if not isinstance(preflight_observation, AccountPreflightObservation):
            raise IdentityProvisioningRuntimeError("identity_runtime_preflight_observation_invalid")

        try:
            preflight = evaluate_account_preflight(
                plan=current_plan,
                provider=provider,
                observation=preflight_observation,
                now=now,
            )
        except IdentityProvisioningPreflightError as exc:
            raise IdentityProvisioningRuntimeError(exc.code) from exc
        if not preflight.ready:
            raise IdentityProvisioningRuntimeError("identity_runtime_preflight_not_ready")

        registration = self.registry.resolve(provider)
        try:
            normalized_refs = normalize_secret_references(credential_references)
        except IdentityProvisioningExecutionError as exc:
            raise IdentityProvisioningRuntimeError(exc.code) from exc

        intent = {
            "schema": "home-center.role-identity-runtime-intent.v1",
            "plan": current_plan.to_dict(),
            "provider": provider.to_dict(),
            "preflight": preflight.to_dict(),
            "preflight_observation": preflight_observation.to_dict(),
            "credential_references": [item.to_dict() for item in normalized_refs],
            "adapter_qualification_evidence_sha256": registration.qualification_evidence_sha256,
            "confirmed": True,
        }
        digest = _request_hash(intent)
        steps = [
            {"step": "durable-admission", "state": "completed"},
            {"step": "provider-create-account", "state": "pending"},
            {"step": "post-condition-readback", "state": "pending"},
            {"step": "durable-identity-state-transition", "state": "not-authorized"},
        ]
        job, created = self.store.create_action_job(
            action_id=ACTION_ID,
            actor=actor_id,
            reason=reason_text,
            idempotency_key=idem,
            request_hash=digest,
            preflight={
                "schema": "home-center.role-identity-runtime-preflight.v1",
                "plan_id": current_plan.plan_id,
                "household_snapshot_id": current_plan.household_snapshot_id,
                "household_resource_version": current_plan.household_resource_version,
                "household_generation": current_plan.household_generation,
                "policy_id": current_plan.policy_id,
                "provider_id": provider.provider_id,
                "provider_version": provider.provider_version,
                "provider_evidence_sha256": provider.evidence_sha256,
                "account_name": current_plan.account_name,
                "preflight": preflight.to_dict(),
                "adapter_qualification_evidence_sha256": registration.qualification_evidence_sha256,
                "provider_execution_authorized": False,
                "durable_identity_state_change_authorized": False,
                "external_publication_authorized": False,
            },
            steps=steps,
        )
        if not created:
            return job

        try:
            request = build_identity_execution_request(
                plan=current_plan,
                provider=provider,
                job_id=job["job_id"],
                credential_references=[item.to_dict() for item in normalized_refs],
                confirmed=True,
            )
        except IdentityProvisioningExecutionError as exc:
            failed = self.store.transition_action_job(
                job["job_id"],
                expected_state="preflight",
                new_state="failed",
                result={
                    "schema": "home-center.role-identity-runtime-result.v1",
                    "state": "admission-failed",
                    "code": exc.code,
                    "provider_invoked": False,
                    "automatic_retry_authorized": False,
                },
            )
            self.store.audit(
                actor=actor_id,
                action="role-identity-provisioning-admission",
                target=current_plan.plan_id,
                outcome="failed",
                correlation_id=correlation,
                details={"job_id": job["job_id"], "code": exc.code, "provider_invoked": False},
            )
            return failed

        running_steps = [
            {"step": "durable-admission", "state": "completed"},
            {"step": "provider-create-account", "state": "running"},
            {"step": "post-condition-readback", "state": "pending"},
            {"step": "durable-identity-state-transition", "state": "not-authorized"},
        ]
        job = self.store.transition_action_job(
            job["job_id"],
            expected_state="preflight",
            new_state="running",
            evidence={
                "schema": "home-center.role-identity-runtime-execution-evidence.v1",
                "execution_request": request.to_dict(),
                "adapter_qualification_evidence_sha256": registration.qualification_evidence_sha256,
                "provider_invocation_may_have_started": True,
                "automatic_provider_retry_authorized": False,
                "durable_identity_state_change_authorized": False,
            },
            steps=running_steps,
        )
        self.store.audit(
            actor=actor_id,
            action="role-identity-provisioning-provider-start",
            target=current_plan.plan_id,
            outcome="started",
            correlation_id=correlation,
            details={
                "job_id": job["job_id"],
                "provider_id": provider.provider_id,
                "account_name": current_plan.account_name,
                "automatic_retry_authorized": False,
            },
        )

        try:
            raw_result = registration.adapter.start(request)
            accepted = adapter_result_from_dict(raw_result)
            if accepted.account_name != current_plan.account_name:
                raise IdentityProvisioningExecutionError("identity_adapter_result_account_mismatch")
        except Exception as exc:
            code = (
                exc.code
                if isinstance(exc, IdentityProvisioningExecutionError)
                else "identity_provider_outcome_ambiguous"
            )
            failed_steps = [
                {"step": "durable-admission", "state": "completed"},
                {"step": "provider-create-account", "state": "ambiguous"},
                {"step": "post-condition-readback", "state": "required"},
                {"step": "durable-identity-state-transition", "state": "not-authorized"},
            ]
            failed = self.store.transition_action_job(
                job["job_id"],
                expected_state="running",
                new_state="failed",
                result={
                    "schema": "home-center.role-identity-runtime-result.v1",
                    "state": "provider-outcome-ambiguous",
                    "code": code,
                    "provider_invoked": True,
                    "automatic_retry_authorized": False,
                    "reconciliation_required": True,
                },
                steps=failed_steps,
            )
            self.store.audit(
                actor=actor_id,
                action="role-identity-provisioning-provider-start",
                target=current_plan.plan_id,
                outcome="ambiguous",
                correlation_id=correlation,
                details={
                    "job_id": job["job_id"],
                    "code": code,
                    "automatic_retry_authorized": False,
                    "reconciliation_required": True,
                },
            )
            return failed

        verifying_steps = [
            {"step": "durable-admission", "state": "completed"},
            {"step": "provider-create-account", "state": "accepted-unverified"},
            {"step": "post-condition-readback", "state": "required"},
            {"step": "durable-identity-state-transition", "state": "not-authorized"},
        ]
        job = self.store.transition_action_job(
            job["job_id"],
            expected_state="running",
            new_state="verifying",
            result={
                "schema": "home-center.role-identity-runtime-result.v1",
                "state": "provider-accepted-unverified",
                "adapter_result": accepted.to_dict(),
                "post_condition_verified": False,
                "durable_identity_state_change_authorized": False,
            },
            steps=verifying_steps,
        )
        self.store.audit(
            actor=actor_id,
            action="role-identity-provisioning-provider-start",
            target=current_plan.plan_id,
            outcome="accepted-unverified",
            correlation_id=correlation,
            details={
                "job_id": job["job_id"],
                "provider_operation_id": accepted.provider_operation_id,
                "post_condition_verified": False,
            },
        )
        return job

    def verify(
        self,
        *,
        job_id: str,
        plan: RoleIdentityProvisioningPlan | dict[str, object],
        provider: IdentityProviderCapability,
        observation: IdentityProvisioningReadbackObservation | dict[str, object],
        actor: str,
        correlation_id: str,
        now: str,
    ) -> dict[str, Any]:
        actor_id = _actor(actor)
        correlation = _correlation(correlation_id)
        parsed_plan = _strict_plan(plan)
        job = self.store.job(job_id)
        if job is None:
            raise IdentityProvisioningRuntimeError("identity_runtime_job_not_found")
        if job["job_type"] != ACTION_ID:
            raise IdentityProvisioningRuntimeError("identity_runtime_job_type_mismatch")
        if job["state"] != "verifying":
            raise IdentityProvisioningRuntimeError("identity_runtime_job_not_verifying")
        result = job.get("result")
        evidence = job.get("evidence")
        if not isinstance(result, dict) or not isinstance(evidence, dict):
            raise IdentityProvisioningRuntimeError("identity_runtime_job_evidence_missing")
        raw_request = evidence.get("execution_request")
        raw_accepted = result.get("adapter_result")
        try:
            request = execution_request_from_dict(raw_request)
            accepted = adapter_result_from_dict(raw_accepted)
            parsed_observation = (
                observation
                if isinstance(observation, IdentityProvisioningReadbackObservation)
                else verification_observation_from_dict(observation)
            )
        except (IdentityProvisioningExecutionError, IdentityProvisioningVerificationError) as exc:
            raise IdentityProvisioningRuntimeError(
                getattr(exc, "code", "identity_runtime_verification_evidence_rejected")
            ) from exc
        if (
            request.job_id != job_id
            or request.plan_id != parsed_plan.plan_id
            or request.provider_id != provider.provider_id
            or request.provider_version != provider.provider_version
            or request.provider_evidence_sha256 != provider.evidence_sha256
            or request.account_name != parsed_plan.account_name
        ):
            raise IdentityProvisioningRuntimeError("identity_runtime_execution_binding_mismatch")

        try:
            verification = verify_identity_provisioning(
                plan=parsed_plan,
                provider=provider,
                accepted=accepted,
                observation=parsed_observation,
                now=now,
            )
        except IdentityProvisioningVerificationError as exc:
            raise IdentityProvisioningRuntimeError(exc.code) from exc

        if not verification.verified:
            self.store.audit(
                actor=actor_id,
                action="role-identity-provisioning-post-condition",
                target=parsed_plan.plan_id,
                outcome="blocked",
                correlation_id=correlation,
                details={
                    "job_id": job_id,
                    "blockers": list(verification.blockers),
                    "provider_reinvocation_authorized": False,
                },
            )
            return job

        final_evidence = dict(evidence)
        final_evidence["verification"] = verification.to_dict()
        final_evidence["durable_identity_state_change_authorized"] = False
        succeeded_steps = [
            {"step": "durable-admission", "state": "completed"},
            {"step": "provider-create-account", "state": "verified"},
            {"step": "post-condition-readback", "state": "verified"},
            {"step": "durable-identity-state-transition", "state": "required-separate-boundary"},
        ]
        succeeded = self.store.transition_action_job(
            job_id,
            expected_state="verifying",
            new_state="succeeded",
            result={
                "schema": "home-center.role-identity-runtime-result.v1",
                "state": "provider-post-condition-verified",
                "adapter_result": accepted.to_dict(),
                "verification": verification.to_dict(),
                "post_condition_verified": True,
                "durable_identity_state_change_authorized": False,
            },
            evidence=final_evidence,
            steps=succeeded_steps,
        )
        self.store.audit(
            actor=actor_id,
            action="role-identity-provisioning-post-condition",
            target=parsed_plan.plan_id,
            outcome="verified",
            correlation_id=correlation,
            details={
                "job_id": job_id,
                "provider_operation_id": accepted.provider_operation_id,
                "account_identity_sha256": verification.account_identity_sha256,
                "durable_identity_state_change_authorized": False,
            },
        )
        return succeeded

    def recovery_view(self, job_id: str) -> dict[str, object]:
        job = self.store.job(job_id)
        if job is None:
            raise IdentityProvisioningRuntimeError("identity_runtime_job_not_found")
        if job["job_type"] != ACTION_ID:
            raise IdentityProvisioningRuntimeError("identity_runtime_job_type_mismatch")
        state = job["state"]
        if state == "preflight":
            next_action = "explicit-resume-required"
            reconciliation_required = False
        elif state == "running":
            next_action = "read-only-provider-reconciliation-required"
            reconciliation_required = True
        elif state == "verifying":
            next_action = "fresh-readback-verification"
            reconciliation_required = False
        elif state == "succeeded":
            next_action = "separate-durable-identity-state-transition"
            reconciliation_required = False
        else:
            next_action = "operator-review"
            result = job.get("result")
            reconciliation_required = bool(
                isinstance(result, dict) and result.get("reconciliation_required") is True
            )
        return {
            "schema": "home-center.role-identity-runtime-recovery-view.v1",
            "job_id": job_id,
            "state": state,
            "next_action": next_action,
            "automatic_provider_retry_authorized": False,
            "provider_reinvocation_authorized": False,
            "reconciliation_required": reconciliation_required,
            "durable_identity_state_change_authorized": False,
            "external_publication_authorized": False,
        }
