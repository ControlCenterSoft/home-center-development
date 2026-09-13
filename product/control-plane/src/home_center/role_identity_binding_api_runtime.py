"""Server-authoritative API boundary for the final Home Center 0.62 identity binding step.

The client supplies only exact identifiers plus explicit confirmation. The service
loads the persisted provisioning plan and the verified execution receipt from the
Home Center store, then delegates to the already-qualified binding transition.
Provider execution is never repeated by this boundary.
"""
from __future__ import annotations

import re

from .role_identity_binding_transition import (
    RoleIdentityBindingTransitionError,
    RoleIdentityBindingTransitionService,
)
from .role_identity_provisioning import IdentityProvisioningError, plan_from_dict
from .role_identity_provisioning_api_runtime import PLAN_KEY_PREFIX, PLAN_STATE_SCHEMA
from .store import StateStore

BIND_REQUEST_SCHEMA = "home-center.role-identity-provisioning-api-bind-request.v1"
_PLAN_ID = re.compile(r"hcidp-[0-9a-f]{24}\Z")
_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class IdentityBindingApiRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RoleIdentityBindingApiRuntimeService:
    """Bind one verified provider-created account to the exact Household member."""

    def __init__(
        self,
        store: StateStore,
        binding: RoleIdentityBindingTransitionService,
    ) -> None:
        if not isinstance(binding, RoleIdentityBindingTransitionService):
            raise IdentityBindingApiRuntimeError("identity_binding_api_runtime_required")
        self.store = store
        self.binding = binding

    @staticmethod
    def _plan_key(plan_id: str) -> str:
        if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None:
            raise IdentityBindingApiRuntimeError("identity_binding_api_plan_id_invalid")
        return PLAN_KEY_PREFIX + plan_id

    def _load_plan(self, *, actor: str, plan_id: str):
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
        if not isinstance(execution_job_id, str) or _JOB_ID.fullmatch(execution_job_id) is None:
            raise IdentityBindingApiRuntimeError("identity_binding_api_execution_job_id_invalid")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise IdentityBindingApiRuntimeError("identity_binding_api_idempotency_key_invalid")

        plan = self._load_plan(actor=actor, plan_id=plan_id)
        job = self.store.job(execution_job_id)
        if not isinstance(job, dict):
            raise IdentityBindingApiRuntimeError("identity_binding_api_execution_job_not_found")
        evidence = job.get("evidence")
        receipt = evidence.get("receipt") if isinstance(evidence, dict) else None
        if not isinstance(receipt, dict):
            raise IdentityBindingApiRuntimeError("identity_binding_api_verified_execution_required")

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
