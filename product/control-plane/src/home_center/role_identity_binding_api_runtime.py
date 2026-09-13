"""Server-authoritative verified identity-binding API runtime for Home Center 0.62.

The HTTP client names only the exact provisioning plan and execution Job. The
verified execution receipt is resolved from durable server-side Job evidence and
is never accepted from the client. The existing binding transition then revalidates
current Household parent/admin authority and exact Household state before the one
local binding mutation. This boundary never invokes the identity provider.
"""
from __future__ import annotations

import re

from .role_identity_binding_transition import (
    RoleIdentityBindingTransitionError,
    RoleIdentityBindingTransitionService,
)
from .role_identity_provisioning import IdentityProvisioningError, RoleIdentityProvisioningPlan, plan_from_dict
from .role_identity_provisioning_api_runtime import PLAN_KEY_PREFIX, PLAN_STATE_SCHEMA
from .role_identity_provisioning_runtime import ACTION as EXECUTION_ACTION, RECEIPT_SCHEMA as EXECUTION_RECEIPT_SCHEMA
from .store import StateStore

_IDEMPOTENCY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PLAN_ID = re.compile(r"hcidp-[0-9a-f]{24}\Z")
_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class IdentityBindingApiRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RoleIdentityBindingApiRuntimeService:
    """Bind only persisted verified provisioning evidence to current Household state."""

    def __init__(self, store: StateStore, binding: RoleIdentityBindingTransitionService) -> None:
        if not isinstance(binding, RoleIdentityBindingTransitionService):
            raise IdentityBindingApiRuntimeError("identity_binding_api_transition_service_required")
        self.store = store
        self.binding = binding

    @staticmethod
    def _plan_key(plan_id: object) -> str:
        if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None:
            raise IdentityBindingApiRuntimeError("identity_binding_api_plan_id_invalid")
        return PLAN_KEY_PREFIX + plan_id

    def _load_plan(self, *, actor: str, plan_id: str) -> RoleIdentityProvisioningPlan:
        state = self.store.get_meta(self._plan_key(plan_id))
        if (
            not isinstance(state, dict)
            or set(state) != {"schema", "actor", "plan"}
            or state.get("schema") != PLAN_STATE_SCHEMA
            or state.get("actor") != actor
        ):
            raise IdentityBindingApiRuntimeError("identity_binding_api_plan_not_found")
        try:
            plan = plan_from_dict(state.get("plan"))
        except IdentityProvisioningError as exc:
            raise IdentityBindingApiRuntimeError("identity_binding_api_plan_state_invalid") from exc
        if plan.plan_id != plan_id:
            raise IdentityBindingApiRuntimeError("identity_binding_api_plan_state_invalid")
        return plan

    def _verified_execution_receipt(
        self,
        *,
        actor: str,
        plan: RoleIdentityProvisioningPlan,
        execution_job_id: object,
    ) -> dict[str, object]:
        if not isinstance(execution_job_id, str) or _JOB_ID.fullmatch(execution_job_id) is None:
            raise IdentityBindingApiRuntimeError("identity_binding_api_execution_job_id_invalid")
        job = self.store.job(execution_job_id)
        if job is None:
            raise IdentityBindingApiRuntimeError("identity_binding_api_execution_job_not_found")
        evidence = job.get("evidence")
        receipt = evidence.get("receipt") if isinstance(evidence, dict) else None
        if (
            job.get("job_type") != EXECUTION_ACTION
            or job.get("state") != "succeeded"
            or job.get("initiator") != actor
            or not isinstance(receipt, dict)
            or receipt.get("schema") != EXECUTION_RECEIPT_SCHEMA
            or receipt.get("state") != "verified"
            or receipt.get("job_id") != execution_job_id
            or receipt.get("plan_id") != plan.plan_id
            or receipt.get("household_id") != plan.household_id
            or receipt.get("member_id") != plan.member_id
            or receipt.get("provider_id") != plan.provider_id
            or receipt.get("provider_version") != plan.provider_version
            or receipt.get("provider_kind") != plan.provider_kind.value
            or receipt.get("account_name") != plan.account_name
            or receipt.get("post_condition_verified") is not True
            or receipt.get("durable_state_change_authorized") is not False
            or receipt.get("emergency_admin_mutation_authorized") is not False
            or receipt.get("privilege_grant_authorized") is not False
            or receipt.get("external_publication_authorized") is not False
        ):
            raise IdentityBindingApiRuntimeError("identity_binding_api_verified_execution_required")
        return dict(receipt)

    def bind(
        self,
        *,
        actor: str,
        plan_id: str,
        execution_job_id: str,
        confirmed: bool,
        idempotency_key: str,
        correlation_id: str,
    ) -> dict[str, object]:
        if confirmed is not True:
            raise IdentityBindingApiRuntimeError("identity_binding_api_confirmation_required")
        if not isinstance(actor, str) or not actor or not isinstance(correlation_id, str) or not correlation_id:
            raise IdentityBindingApiRuntimeError("identity_binding_api_actor_or_correlation_invalid")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise IdentityBindingApiRuntimeError("identity_binding_api_idempotency_key_invalid")

        plan = self._load_plan(actor=actor, plan_id=plan_id)
        receipt = self._verified_execution_receipt(
            actor=actor,
            plan=plan,
            execution_job_id=execution_job_id,
        )
        try:
            return self.binding.transition(
                actor=actor,
                plan=plan,
                execution_receipt=receipt,
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
            )
        except RoleIdentityBindingTransitionError as exc:
            raise IdentityBindingApiRuntimeError(exc.code) from exc
