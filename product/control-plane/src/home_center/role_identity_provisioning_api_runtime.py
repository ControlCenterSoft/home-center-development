"""Authenticated qualification-bound API runtime for Home Center 0.62 identity provisioning.

The service persists exact plans, revalidates current Household/RBAC and provider
qualification before execution, never persists credential values, and keeps the
provider mutation and the later Home Center binding transition as separate explicit
steps. Provider acceptance is not success: the existing provisioning runtime must
complete read-back/post-condition verification before a binding transition is allowed.
"""
from __future__ import annotations

import re
import threading
from typing import Any

from .home_services import HomeServiceCatalogError
from .household import HouseholdRole, effective_policy
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .role_identity_binding_transition import (
    RoleIdentityBindingTransitionError,
    RoleIdentityBindingTransitionService,
)
from .role_identity_provisioning import (
    IdentityProvisioningError,
    RoleIdentityProvisioningPlan,
    StorageMode,
    build_role_identity_provisioning_plan,
    plan_from_dict,
)
from .role_identity_provisioning_preflight import (
    IdentityProvisioningPreflightError,
    observation_from_dict,
)
from .role_identity_provisioning_runtime import IdentityProvisioningRuntimeError
from .role_identity_provisioning_runtime_safe import SafeRoleIdentityProvisioningRuntimeService
from .store import StateStore

STATE_SCHEMA = "home-center.role-identity-provisioning-api-state.v1"
PLAN_REQUEST_SCHEMA = "home-center.role-identity-provisioning-api-plan-request.v1"
EXECUTE_REQUEST_SCHEMA = "home-center.role-identity-provisioning-api-execute-request.v1"
BIND_REQUEST_SCHEMA = "home-center.role-identity-provisioning-api-bind-request.v1"
PLAN_KEY_PREFIX = "cozy.household.identity-provisioning-api."
_PLAN_ID = re.compile(r"hcidp-[0-9a-f]{24}\Z")


class RoleIdentityProvisioningApiError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _key(plan_id: object) -> str:
    if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None:
        raise RoleIdentityProvisioningApiError("identity_provisioning_api_plan_id_invalid")
    return PLAN_KEY_PREFIX + plan_id


class RoleIdentityProvisioningApiService:
    """Server-side lifecycle wrapper over the qualified identity runtime."""

    def __init__(
        self,
        store: StateStore,
        provisioning: SafeRoleIdentityProvisioningRuntimeService,
        binding: RoleIdentityBindingTransitionService,
    ) -> None:
        if not isinstance(provisioning, SafeRoleIdentityProvisioningRuntimeService):
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_safe_runtime_required")
        self.store = store
        self.provisioning = provisioning
        self.binding = binding
        self._lock = threading.RLock()

    def _context(self, *, actor: str, member_id: str):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if not isinstance(raw, dict):
            raise RoleIdentityProvisioningApiError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
            actor_member_id = next((item.member_id for item in bindings if item.actor == actor), None)
            if actor_member_id is None:
                raise RoleIdentityProvisioningApiError("household_actor_not_bound")
            actor_member = snapshot.household.member(actor_member_id)
            target_member = snapshot.household.member(member_id)
            actor_policy = effective_policy(snapshot.household, actor_member_id)
            target_policy = effective_policy(snapshot.household, member_id)
        except RoleIdentityProvisioningApiError:
            raise
        except HomeServiceCatalogError as exc:
            raise RoleIdentityProvisioningApiError(exc.code) from exc
        except Exception as exc:
            raise RoleIdentityProvisioningApiError(getattr(exc, "code", "household_state_invalid")) from exc
        if not actor_member.enabled or not target_member.enabled:
            raise RoleIdentityProvisioningApiError("household_member_disabled")
        if actor_policy.role is not HouseholdRole.PARENT or not actor_policy.administration_allowed:
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_not_authorized")
        return snapshot, target_policy

    @staticmethod
    def _request(value: object, *, schema: str, fields: set[str]) -> dict[str, object]:
        required = {"schema", *fields}
        if not isinstance(value, dict) or set(value) != required or value.get("schema") != schema:
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_request_invalid")
        return dict(value)

    def plan(self, *, actor: str, request: object, correlation_id: str) -> dict[str, object]:
        body = self._request(
            request,
            schema=PLAN_REQUEST_SCHEMA,
            fields={"member_id", "provider_id", "account_name", "home_directory_mode", "profile_mode"},
        )
        member_id = body.get("member_id")
        provider_id = body.get("provider_id")
        account_name = body.get("account_name")
        if not all(isinstance(value, str) for value in (member_id, provider_id, account_name)):
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_request_invalid")
        try:
            home_mode = StorageMode(body.get("home_directory_mode"))
            profile_mode = StorageMode(body.get("profile_mode"))
        except (TypeError, ValueError) as exc:
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_request_invalid") from exc

        with self._lock:
            snapshot, target_policy = self._context(actor=actor, member_id=member_id)
            try:
                provider = self.provisioning.qualified_provider(provider_id)
                qualification_sha256 = self.provisioning.qualification_evidence_sha256(provider_id)
                plan = build_role_identity_provisioning_plan(
                    snapshot=snapshot,
                    policy=target_policy,
                    provider=provider,
                    member_id=member_id,
                    account_name=account_name,
                    home_directory_mode=home_mode,
                    profile_mode=profile_mode,
                )
            except (IdentityProvisioningRuntimeError, IdentityProvisioningError) as exc:
                raise RoleIdentityProvisioningApiError(exc.code) from exc

            key = _key(plan.plan_id)
            envelope = {
                "schema": STATE_SCHEMA,
                "actor": actor,
                "plan": plan.to_dict(),
                "qualification_evidence_sha256": qualification_sha256,
                "execution_receipt": None,
                "binding_receipt": None,
            }
            existing = self.store.get_meta(key)
            if existing is None:
                self.store.set_meta(key, envelope)
                self.store.audit(
                    actor=actor,
                    action="household.identity.provisioning.api.plan",
                    target=member_id,
                    outcome="planned",
                    correlation_id=correlation_id,
                    details={
                        "plan_id": plan.plan_id,
                        "provider_id": provider.provider_id,
                        "qualification_evidence_sha256": qualification_sha256,
                        "credential_material_included": False,
                        "provider_execution_authorized": False,
                        "external_publication_authorized": False,
                    },
                )
            elif existing != envelope:
                raise RoleIdentityProvisioningApiError("identity_provisioning_api_plan_conflict")
            return plan.to_dict()

    def _load(self, *, actor: str, plan_id: str) -> tuple[str, dict[str, Any], RoleIdentityProvisioningPlan]:
        key = _key(plan_id)
        state = self.store.get_meta(key)
        if (
            not isinstance(state, dict)
            or state.get("schema") != STATE_SCHEMA
            or state.get("actor") != actor
            or not isinstance(state.get("plan"), dict)
        ):
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_plan_not_found")
        try:
            plan = plan_from_dict(state["plan"])
        except IdentityProvisioningError as exc:
            raise RoleIdentityProvisioningApiError(exc.code) from exc
        if plan.plan_id != plan_id:
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_plan_invalid")
        return key, state, plan

    def _revalidate(self, *, actor: str, state: dict[str, Any], plan: RoleIdentityProvisioningPlan):
        snapshot, target_policy = self._context(actor=actor, member_id=plan.member_id)
        if (
            snapshot.household_id != plan.household_id
            or snapshot.snapshot_id != plan.household_snapshot_id
            or snapshot.resource_version != plan.household_resource_version
            or snapshot.generation != plan.household_generation
            or target_policy.policy_id != plan.policy_id
            or target_policy.role is not plan.role
        ):
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_plan_stale")
        try:
            provider = self.provisioning.qualified_provider(plan.provider_id)
            qualification_sha256 = self.provisioning.qualification_evidence_sha256(plan.provider_id)
        except IdentityProvisioningRuntimeError as exc:
            raise RoleIdentityProvisioningApiError(exc.code) from exc
        if (
            provider.provider_version != plan.provider_version
            or provider.provider_kind is not plan.provider_kind
            or provider.evidence_sha256 != plan.provider_evidence_sha256
            or state.get("qualification_evidence_sha256") != qualification_sha256
        ):
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_provider_stale")
        return provider

    def execute(
        self,
        *,
        actor: str,
        request: object,
        idempotency_key: str,
        correlation_id: str,
    ) -> dict[str, object]:
        body = self._request(
            request,
            schema=EXECUTE_REQUEST_SCHEMA,
            fields={"plan_id", "preflight_observation", "credential_references", "confirmed"},
        )
        plan_id = body.get("plan_id")
        if not isinstance(plan_id, str) or body.get("confirmed") is not True:
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_confirmation_required")
        with self._lock:
            key, state, plan = self._load(actor=actor, plan_id=plan_id)
            provider = self._revalidate(actor=actor, state=state, plan=plan)
            try:
                observation = observation_from_dict(body.get("preflight_observation"))
                receipt = self.provisioning.execute(
                    actor=actor,
                    plan=plan,
                    provider=provider,
                    preflight_observation=observation,
                    credential_references=body.get("credential_references"),
                    confirmed=True,
                    idempotency_key=idempotency_key,
                    correlation_id=correlation_id,
                )
            except (IdentityProvisioningPreflightError, IdentityProvisioningRuntimeError) as exc:
                raise RoleIdentityProvisioningApiError(exc.code) from exc
            updated = dict(state)
            previous = updated.get("execution_receipt")
            if previous is not None and previous != receipt:
                raise RoleIdentityProvisioningApiError("identity_provisioning_api_execution_conflict")
            updated["execution_receipt"] = receipt
            self.store.set_meta(key, updated)
            return dict(receipt)

    def bind(
        self,
        *,
        actor: str,
        request: object,
        idempotency_key: str,
        correlation_id: str,
    ) -> dict[str, object]:
        body = self._request(
            request,
            schema=BIND_REQUEST_SCHEMA,
            fields={"plan_id", "confirmed"},
        )
        plan_id = body.get("plan_id")
        if not isinstance(plan_id, str) or body.get("confirmed") is not True:
            raise RoleIdentityProvisioningApiError("identity_provisioning_api_confirmation_required")
        with self._lock:
            key, state, plan = self._load(actor=actor, plan_id=plan_id)
            self._revalidate(actor=actor, state=state, plan=plan)
            execution_receipt = state.get("execution_receipt")
            if not isinstance(execution_receipt, dict):
                raise RoleIdentityProvisioningApiError("identity_provisioning_api_verified_execution_required")
            try:
                receipt = self.binding.transition(
                    actor=actor,
                    plan=plan,
                    execution_receipt=execution_receipt,
                    idempotency_key=idempotency_key,
                    correlation_id=correlation_id,
                )
            except RoleIdentityBindingTransitionError as exc:
                raise RoleIdentityProvisioningApiError(exc.code) from exc
            updated = dict(state)
            previous = updated.get("binding_receipt")
            if previous is not None and previous != receipt:
                raise RoleIdentityProvisioningApiError("identity_provisioning_api_binding_conflict")
            updated["binding_receipt"] = receipt
            self.store.set_meta(key, updated)
            return dict(receipt)
