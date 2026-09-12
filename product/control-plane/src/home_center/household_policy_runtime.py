"""Durable, fail-closed confirmation runtime for Home Center 0.59 Policy Composer.

This boundary persists policy proposals and explicit parental confirmation evidence.
It intentionally does not write policy Desired State and never calls providers or
mutates infrastructure. A later protected Desired State writer must consume the
exact confirmation receipt, repeat all state preconditions, and produce its own
Audit/recovery evidence before any policy becomes active.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any

from .household_policy_composer import (
    HouseholdPolicyComposerError,
    PolicyCompositionProposal,
    build_policy_composition_proposal,
    compose_policy_bundle,
    revalidate_policy_composition_proposal,
)
from .household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore


POLICY_PLAN_REQUEST_SCHEMA = "home-center.household-policy-plan-request.v1"
POLICY_CONFIRM_REQUEST_SCHEMA = "home-center.household-policy-confirm-request.v1"
POLICY_RECOVERY_REQUEST_SCHEMA = "home-center.household-policy-recovery-request.v1"
POLICY_PROPOSAL_STATE_SCHEMA = "home-center.household-policy-proposal-state.v1"
POLICY_CONFIRMATION_SCHEMA = "home-center.household-policy-confirmation.v1"
POLICY_RECOVERY_RESULT_SCHEMA = "home-center.household-policy-recovery-result.v1"
POLICY_PROPOSAL_KEY_PREFIX = "cozy.household.policy-proposal."
PROPOSAL_ID = re.compile(r"^hpc-[0-9a-f]{24}$")
BUNDLE_ID = re.compile(r"^hpb-[0-9a-f]{24}$")


class HouseholdPolicyRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def _proposal_key(proposal_id: object) -> str:
    if not isinstance(proposal_id, str) or PROPOSAL_ID.fullmatch(proposal_id) is None:
        raise HouseholdPolicyRuntimeError("invalid_household_policy_proposal_id")
    return POLICY_PROPOSAL_KEY_PREFIX + proposal_id


def _confirmation_id(proposal: PolicyCompositionProposal) -> str:
    material = {
        "proposal_id": proposal.proposal_id,
        "household_id": proposal.household_id,
        "snapshot_id": proposal.snapshot_id,
        "resource_version": proposal.resource_version,
        "generation": proposal.generation,
        "actor_member_id": proposal.actor_member_id,
        "member_id": proposal.member_id,
        "expected_desired_state_generation": proposal.expected_desired_state_generation,
        "expected_desired_state_bundle_id": proposal.expected_desired_state_bundle_id,
        "bundle_id": proposal.bundle.bundle_id,
        "desired_state_resource_key": proposal.bundle.desired_state_resource_key,
    }
    return "hpconfirm-" + hashlib.sha256(_canonical(material)).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class HouseholdPolicyConfirmation:
    confirmation_id: str
    proposal_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    member_id: str
    bundle_id: str
    desired_state_resource_key: str
    expected_desired_state_generation: int
    expected_desired_state_bundle_id: str | None
    audit_event_id: str
    schema: str = field(default=POLICY_CONFIRMATION_SCHEMA, init=False)
    outcome: str = field(default="confirmed-for-desired-state-write", init=False)
    desired_state_write_ready: bool = field(default=True, init=False)
    desired_state_write_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "confirmation_id": self.confirmation_id,
            "proposal_id": self.proposal_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "member_id": self.member_id,
            "bundle_id": self.bundle_id,
            "desired_state_resource_key": self.desired_state_resource_key,
            "expected_desired_state_generation": self.expected_desired_state_generation,
            "expected_desired_state_bundle_id": self.expected_desired_state_bundle_id,
            "audit_event_id": self.audit_event_id,
            "outcome": self.outcome,
            "desired_state_write_ready": True,
            "desired_state_write_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


class HouseholdPolicyRuntimeService:
    """Persist plan/confirm evidence without granting mutation authority."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _read_household_state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdPolicyRuntimeError(getattr(exc, "code", "household_state_invalid")) from exc

    @staticmethod
    def _actor_member(actor: str, bindings: tuple[ActorBinding, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise HouseholdPolicyRuntimeError("household_actor_not_bound")
        return member_id

    def _desired_state_revision(self, resource_key: str) -> tuple[int, str | None]:
        matches = [item for item in self.store.desired_state() if item.get("resource_key") == resource_key]
        if not matches:
            return 0, None
        if len(matches) != 1:
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")
        record = matches[0]
        generation = record.get("generation")
        value = record.get("value")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")
        if not isinstance(value, dict):
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")
        if value.get("schema") != "home-center.household-policy-bundle.v1":
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")
        if value.get("desired_state_resource_key") != resource_key:
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")
        bundle_id = value.get("bundle_id")
        if not isinstance(bundle_id, str) or BUNDLE_ID.fullmatch(bundle_id) is None:
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")
        if (
            value.get("desired_state_write_authorized") is not False
            or value.get("infrastructure_mutation_authorized") is not False
            or value.get("external_publication_authorized") is not False
        ):
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")
        return generation, bundle_id

    @staticmethod
    def _validate_envelope(value: object) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("schema") != POLICY_PROPOSAL_STATE_SCHEMA:
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")
        if value.get("status") not in {"pending", "confirming", "confirmed", "invalidated"}:
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")
        proposal = value.get("proposal")
        if not isinstance(proposal, dict) or not isinstance(proposal.get("proposal_id"), str):
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")
        confirmation = value.get("confirmation")
        if value.get("status") == "confirmed":
            if not isinstance(confirmation, dict) or confirmation.get("proposal_id") != proposal.get("proposal_id"):
                raise HouseholdPolicyRuntimeError("household_policy_confirmation_invalid")
        elif confirmation is not None:
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")
        if not isinstance(value.get("recovery_required"), bool):
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")
        if value.get("status") == "confirming" and value.get("recovery_required") is not True:
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")
        if value.get("status") != "confirming" and value.get("recovery_required") is not False:
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")
        return value

    def _rebuild_proposal(
        self,
        *,
        actor: str,
        envelope: dict[str, Any],
    ) -> tuple[PolicyCompositionProposal, object, tuple[ActorBinding, ...]]:
        snapshot, bindings = self._read_household_state()
        actor_member_id = self._actor_member(actor, bindings)
        raw = envelope.get("proposal")
        if not isinstance(raw, dict):
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")
        member_id = raw.get("member_id")
        expected_generation = raw.get("expected_desired_state_generation")
        expected_bundle_id = raw.get("expected_desired_state_bundle_id")
        if not isinstance(member_id, str):
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")
        try:
            proposal = build_policy_composition_proposal(
                snapshot,
                actor_member_id=actor_member_id,
                member_id=member_id,
                expected_desired_state_generation=expected_generation,
                expected_desired_state_bundle_id=expected_bundle_id,
            )
        except HouseholdPolicyComposerError as exc:
            raise HouseholdPolicyRuntimeError(exc.code) from exc
        if proposal.to_dict() != raw:
            raise HouseholdPolicyRuntimeError("household_policy_proposal_evidence_mismatch")
        return proposal, snapshot, bindings

    def plan(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "member_id"}
            or request.get("schema") != POLICY_PLAN_REQUEST_SCHEMA
            or not isinstance(request.get("member_id"), str)
        ):
            raise HouseholdPolicyRuntimeError("invalid_household_policy_plan_request")

        with self._lock:
            snapshot, bindings = self._read_household_state()
            actor_member_id = self._actor_member(actor, bindings)
            try:
                bundle = compose_policy_bundle(snapshot, member_id=request["member_id"])
                current_generation, current_bundle_id = self._desired_state_revision(bundle.desired_state_resource_key)
                proposal = build_policy_composition_proposal(
                    snapshot,
                    actor_member_id=actor_member_id,
                    member_id=request["member_id"],
                    expected_desired_state_generation=current_generation,
                    expected_desired_state_bundle_id=current_bundle_id,
                )
            except HouseholdPolicyComposerError as exc:
                raise HouseholdPolicyRuntimeError(exc.code) from exc

            key = _proposal_key(proposal.proposal_id)
            existing_raw = self.store.get_meta(key)
            if existing_raw is None:
                self.store.set_meta(
                    key,
                    {
                        "schema": POLICY_PROPOSAL_STATE_SCHEMA,
                        "status": "pending",
                        "proposal": proposal.to_dict(),
                        "confirmation": None,
                        "recovery_required": False,
                    },
                )
            else:
                existing = self._validate_envelope(existing_raw)
                if existing.get("proposal") != proposal.to_dict():
                    raise HouseholdPolicyRuntimeError("household_policy_proposal_collision")

            self.store.audit(
                actor=actor,
                action="household.policy.plan",
                target=proposal.bundle.desired_state_resource_key,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "snapshot_id": proposal.snapshot_id,
                    "resource_version": proposal.resource_version,
                    "bundle_id": proposal.bundle.bundle_id,
                    "expected_desired_state_generation": proposal.expected_desired_state_generation,
                    "expected_desired_state_bundle_id": proposal.expected_desired_state_bundle_id,
                    "desired_state_write_authorized": False,
                    "infrastructure_mutation_authorized": False,
                },
            )
            return proposal.to_dict()

    def confirm(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "proposal_id", "confirmed"}
            or request.get("schema") != POLICY_CONFIRM_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise HouseholdPolicyRuntimeError("invalid_household_policy_confirm_request")
        key = _proposal_key(request.get("proposal_id"))

        with self._lock:
            envelope = self._validate_envelope(self.store.get_meta(key))
            if envelope.get("status") == "invalidated":
                raise HouseholdPolicyRuntimeError("household_policy_proposal_invalidated")
            if envelope.get("status") == "confirming":
                raise HouseholdPolicyRuntimeError("household_policy_confirmation_recovery_required")
            if envelope.get("status") == "confirmed":
                confirmation = envelope.get("confirmation")
                if not isinstance(confirmation, dict):
                    raise HouseholdPolicyRuntimeError("household_policy_confirmation_invalid")
                replay = dict(confirmation)
                replay["outcome"] = "already-confirmed"
                return replay

            proposal, snapshot, _bindings = self._rebuild_proposal(actor=actor, envelope=envelope)
            current_generation, current_bundle_id = self._desired_state_revision(
                proposal.bundle.desired_state_resource_key
            )
            try:
                revalidate_policy_composition_proposal(
                    snapshot,
                    proposal,
                    actor_member_id=proposal.actor_member_id,
                    current_desired_state_generation=current_generation,
                    current_desired_state_bundle_id=current_bundle_id,
                )
            except HouseholdPolicyComposerError as exc:
                raise HouseholdPolicyRuntimeError(exc.code) from exc

            confirming = {
                "schema": POLICY_PROPOSAL_STATE_SCHEMA,
                "status": "confirming",
                "proposal": proposal.to_dict(),
                "confirmation": None,
                "recovery_required": True,
            }
            self.store.set_meta(key, confirming)

            audit_event_id = self.store.audit(
                actor=actor,
                action="household.policy.confirm",
                target=proposal.bundle.desired_state_resource_key,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "confirmation_id": _confirmation_id(proposal),
                    "snapshot_id": proposal.snapshot_id,
                    "resource_version": proposal.resource_version,
                    "bundle_id": proposal.bundle.bundle_id,
                    "expected_desired_state_generation": proposal.expected_desired_state_generation,
                    "expected_desired_state_bundle_id": proposal.expected_desired_state_bundle_id,
                    "desired_state_write_ready": True,
                    "desired_state_write_authorized": False,
                    "infrastructure_mutation_authorized": False,
                },
            )
            confirmation = HouseholdPolicyConfirmation(
                confirmation_id=_confirmation_id(proposal),
                proposal_id=proposal.proposal_id,
                household_id=proposal.household_id,
                snapshot_id=proposal.snapshot_id,
                resource_version=proposal.resource_version,
                generation=proposal.generation,
                actor_member_id=proposal.actor_member_id,
                member_id=proposal.member_id,
                bundle_id=proposal.bundle.bundle_id,
                desired_state_resource_key=proposal.bundle.desired_state_resource_key,
                expected_desired_state_generation=proposal.expected_desired_state_generation,
                expected_desired_state_bundle_id=proposal.expected_desired_state_bundle_id,
                audit_event_id=audit_event_id,
            ).to_dict()
            self.store.set_meta(
                key,
                {
                    "schema": POLICY_PROPOSAL_STATE_SCHEMA,
                    "status": "confirmed",
                    "proposal": proposal.to_dict(),
                    "confirmation": confirmation,
                    "recovery_required": False,
                },
            )
            return confirmation

    def recover(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "proposal_id"}
            or request.get("schema") != POLICY_RECOVERY_REQUEST_SCHEMA
        ):
            raise HouseholdPolicyRuntimeError("invalid_household_policy_recovery_request")
        key = _proposal_key(request.get("proposal_id"))

        with self._lock:
            envelope = self._validate_envelope(self.store.get_meta(key))
            status = envelope.get("status")
            if status == "confirmed":
                return {
                    "schema": POLICY_RECOVERY_RESULT_SCHEMA,
                    "proposal_id": request["proposal_id"],
                    "status": "confirmed",
                    "recovered": False,
                    "confirmation": envelope.get("confirmation"),
                    "desired_state_write_authorized": False,
                    "infrastructure_mutation_authorized": False,
                }
            if status == "pending":
                return {
                    "schema": POLICY_RECOVERY_RESULT_SCHEMA,
                    "proposal_id": request["proposal_id"],
                    "status": "pending",
                    "recovered": False,
                    "confirmation": None,
                    "desired_state_write_authorized": False,
                    "infrastructure_mutation_authorized": False,
                }
            if status == "invalidated":
                return {
                    "schema": POLICY_RECOVERY_RESULT_SCHEMA,
                    "proposal_id": request["proposal_id"],
                    "status": "invalidated",
                    "recovered": False,
                    "confirmation": None,
                    "desired_state_write_authorized": False,
                    "infrastructure_mutation_authorized": False,
                }

            try:
                proposal, snapshot, _bindings = self._rebuild_proposal(actor=actor, envelope=envelope)
                current_generation, current_bundle_id = self._desired_state_revision(
                    proposal.bundle.desired_state_resource_key
                )
                revalidate_policy_composition_proposal(
                    snapshot,
                    proposal,
                    actor_member_id=proposal.actor_member_id,
                    current_desired_state_generation=current_generation,
                    current_desired_state_bundle_id=current_bundle_id,
                )
            except (HouseholdPolicyRuntimeError, HouseholdPolicyComposerError) as exc:
                self.store.set_meta(
                    key,
                    {
                        "schema": POLICY_PROPOSAL_STATE_SCHEMA,
                        "status": "invalidated",
                        "proposal": envelope["proposal"],
                        "confirmation": None,
                        "recovery_required": False,
                    },
                )
                self.store.audit(
                    actor=actor,
                    action="household.policy.confirm.recover",
                    target=request["proposal_id"],
                    outcome="invalidated",
                    correlation_id=correlation_id,
                    details={
                        "reason": getattr(exc, "code", "household_policy_confirmation_recovery_failed"),
                        "desired_state_write_authorized": False,
                        "infrastructure_mutation_authorized": False,
                    },
                )
                return {
                    "schema": POLICY_RECOVERY_RESULT_SCHEMA,
                    "proposal_id": request["proposal_id"],
                    "status": "invalidated",
                    "recovered": True,
                    "confirmation": None,
                    "desired_state_write_authorized": False,
                    "infrastructure_mutation_authorized": False,
                }

            self.store.set_meta(
                key,
                {
                    "schema": POLICY_PROPOSAL_STATE_SCHEMA,
                    "status": "pending",
                    "proposal": proposal.to_dict(),
                    "confirmation": None,
                    "recovery_required": False,
                },
            )
            self.store.audit(
                actor=actor,
                action="household.policy.confirm.recover",
                target=proposal.bundle.desired_state_resource_key,
                outcome="reopened-for-confirmation",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "bundle_id": proposal.bundle.bundle_id,
                    "desired_state_write_authorized": False,
                    "infrastructure_mutation_authorized": False,
                },
            )
            return {
                "schema": POLICY_RECOVERY_RESULT_SCHEMA,
                "proposal_id": proposal.proposal_id,
                "status": "pending",
                "recovered": True,
                "confirmation": None,
                "desired_state_write_authorized": False,
                "infrastructure_mutation_authorized": False,
            }
