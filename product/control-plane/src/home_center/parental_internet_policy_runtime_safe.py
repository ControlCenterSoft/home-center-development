"""Production-safe scoped re-auth wrapper for Home Center 0.60 parental policy changes.

The underlying parental runtime already revalidates the exact Household snapshot,
verified 0.59 child-policy base and current parental Desired State before committing.
This wrapper adds the missing production re-auth boundary without weakening those
checks: it performs a read-only preflight first, consumes one actor/plan-bound step-up
grant, then calls the base runtime which revalidates the exact state again before any
write. Idempotent reads of an already committed receipt require current parent
authority and exact durable receipt/plan binding but do not consume a new grant.
"""
from __future__ import annotations

import re
from typing import Any

from .home_services import HomeServiceCatalogError
from .household import HouseholdRole
from .household_runtime import _snapshot_from_dict
from .parental_internet_policy import ParentalInternetPolicyError
from .parental_internet_policy_change_api import (
    ParentalInternetPolicyChangeAPIError,
    parse_parental_internet_confirm_request,
)
from .parental_internet_policy_runtime import (
    COMMIT_RECEIPT_SCHEMA,
    ParentalInternetPolicyRuntimeError,
    ParentalInternetPolicyRuntimeService,
    _digest,
)
from .parental_internet_policy_validation import parental_internet_policy_from_dict
from .step_up import StepUpError, StepUpGrantManager
from .store import StateStore

_SCOPE_PREFIX = "household.parental-internet.policy:"
_PLAN_ID = re.compile(r"hpip-[0-9a-f]{24}\Z")


class SafeParentalInternetPolicyRuntimeService:
    """Require one short-lived actor/plan-bound grant for each new Desired State commit."""

    def __init__(self, store: StateStore, step_up: StepUpGrantManager) -> None:
        self.store = store
        self.step_up = step_up
        self.base = ParentalInternetPolicyRuntimeService(store)

    @staticmethod
    def step_up_scope(plan_id: object) -> str:
        if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None:
            raise ParentalInternetPolicyRuntimeError("invalid_parental_internet_plan_id")
        return _SCOPE_PREFIX + plan_id

    def plan(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        return self.base.plan(actor=actor, request=request, correlation_id=correlation_id)

    def desired_state(self, *, actor: str, member_id: str) -> dict[str, object] | None:
        return self.base.desired_state(actor=actor, member_id=member_id)

    @staticmethod
    def _committed_receipt_matches(
        *,
        receipt: object,
        plan: dict[str, Any],
        household_id: str,
        member_id: str,
    ) -> bool:
        return bool(
            isinstance(receipt, dict)
            and receipt.get("schema") == COMMIT_RECEIPT_SCHEMA
            and receipt.get("state") == "desired-state-committed"
            and receipt.get("plan_id") == plan.get("plan_id")
            and receipt.get("household_id") == household_id
            and receipt.get("member_id") == member_id
            and receipt.get("desired_generation") == plan.get("expected_desired_generation")
            and receipt.get("verified_base_state_sha256") == plan.get("verified_base_state_sha256")
            and receipt.get("policy_sha256") == plan.get("proposed_policy_sha256")
            and receipt.get("enforcement_verified") is False
            and receipt.get("reconciliation_required") is True
            and receipt.get("dns_policy_applied") is False
            and receipt.get("proxy_policy_applied") is False
            and receipt.get("infrastructure_mutation_performed") is False
            and receipt.get("external_publication_performed") is False
        )

    def confirmation_scope(self, *, actor: str, plan_id: object) -> str | None:
        """Revalidate immutable plan/authority before a credential grant is issued.

        ``None`` means the exact plan is already durably committed and only an
        idempotent receipt read remains. All other valid planned states return the
        exact scope that the re-auth endpoint may issue.
        """

        scope = self.step_up_scope(plan_id)
        with self.base._lock:
            _key, envelope, plan = self.base._load(plan_id)
            if envelope.get("actor") != actor:
                raise ParentalInternetPolicyRuntimeError("parental_internet_actor_mismatch")

            snapshot, bindings = self.base._state()
            actor_member_id = self.base._actor_parent(actor, snapshot, bindings)

            if envelope.get("status") == "committed":
                subject_member_id = plan.get("subject_member_id")
                try:
                    subject = snapshot.household.member(subject_member_id)
                except HomeServiceCatalogError as exc:
                    raise ParentalInternetPolicyRuntimeError(exc.code) from exc
                if not subject.enabled or subject.role is not HouseholdRole.CHILD:
                    raise ParentalInternetPolicyRuntimeError("parental_internet_subject_not_eligible")
                if not self._committed_receipt_matches(
                    receipt=envelope.get("commit"),
                    plan=plan,
                    household_id=snapshot.household_id,
                    member_id=subject.member_id,
                ):
                    raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid")
                return None

            if envelope.get("status") != "planned":
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid")

            try:
                base_snapshot = _snapshot_from_dict(envelope.get("base_snapshot"))
            except Exception as exc:
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid") from exc
            if (
                snapshot != base_snapshot
                or [item.to_dict() for item in bindings] != envelope.get("bindings")
                or actor_member_id != plan.get("actor_member_id")
                or snapshot.snapshot_id != plan.get("household_snapshot_id")
                or snapshot.resource_version != plan.get("household_resource_version")
                or snapshot.generation != plan.get("household_generation")
            ):
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_stale")

            subject_member_id = plan.get("subject_member_id")
            try:
                subject = snapshot.household.member(subject_member_id)
            except HomeServiceCatalogError as exc:
                raise ParentalInternetPolicyRuntimeError(exc.code) from exc
            if not subject.enabled or subject.role is not HouseholdRole.CHILD:
                raise ParentalInternetPolicyRuntimeError("parental_internet_subject_not_eligible")

            verified = self.base._verified_base(
                household_id=snapshot.household_id,
                member_id=subject.member_id,
            )
            self.base._require_current_role_base(snapshot, verified)
            if (
                verified.verified_state_sha256 != plan.get("verified_base_state_sha256")
                or verified.policy.policy_id != plan.get("base_policy_id")
                or verified.policy_sha256 != plan.get("base_policy_sha256")
                or verified.desired_generation != plan.get("base_desired_generation")
                or verified.evidence_sha256 != plan.get("base_evidence_sha256")
            ):
                raise ParentalInternetPolicyRuntimeError("parental_internet_verified_base_stale")

            try:
                proposed = parental_internet_policy_from_dict(
                    value=plan.get("proposed_policy"),
                    base=verified.policy,
                )
            except (ParentalInternetPolicyError, TypeError) as exc:
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid") from exc
            if _digest(proposed.to_dict()) != plan.get("proposed_policy_sha256"):
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid")

            expected_generation = plan.get("expected_desired_generation")
            if type(expected_generation) is not int or expected_generation < 1:
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid")
            return scope

    def confirm(
        self,
        *,
        actor: str,
        request: object,
        step_up_token: object,
        correlation_id: str,
    ) -> dict[str, object]:
        try:
            parsed = parse_parental_internet_confirm_request(request)
        except ParentalInternetPolicyChangeAPIError as exc:
            raise ParentalInternetPolicyRuntimeError(exc.code) from exc

        plan_id = parsed["plan_id"]
        scope = self.confirmation_scope(actor=actor, plan_id=plan_id)
        if scope is not None:
            try:
                self.step_up.consume(actor=actor, scope=scope, token=step_up_token)
            except StepUpError as exc:
                raise ParentalInternetPolicyRuntimeError(exc.code) from exc

        # The base runtime repeats all exact-state checks under its own lock before any
        # durable write. A state change between preflight and this call therefore fails
        # closed even though the one-time grant has already been consumed.
        return self.base.confirm(
            actor=actor,
            request=parsed,
            correlation_id=correlation_id,
        )
