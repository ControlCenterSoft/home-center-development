"""Runtime integration for the Home Center Household/Cozy domain.

0.48 intentionally limits mutation to Home Center product state.  It does not
create operating-system accounts, change DNS/VPN/MDM, execute providers, mutate
external Desired State, or publish services.  Household state is persisted in
the existing SQLite-backed cluster metadata and every accepted mutation is
recorded in the audit chain.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass
from typing import Any

from .home_services import HomeServiceCatalogError
from .household import FamilyMember, Household, HouseholdRole, ManagedDevice
from .household_intent import HouseholdIntent, HouseholdIntentKind
from .household_intent_proposal import build_household_intent_proposal
from .household_store import HouseholdSnapshot, HouseholdStore
from .store import StateStore


HOUSEHOLD_STATE_KEY = "cozy.household.snapshot.v1"
HOUSEHOLD_BINDINGS_KEY = "cozy.household.actor-bindings.v1"
HOUSEHOLD_RUNTIME_SCHEMA = "home-center.household-runtime.v1"
HOUSEHOLD_BOOTSTRAP_SCHEMA = "home-center.household-bootstrap.v1"
HOUSEHOLD_BOOTSTRAP_RESULT_SCHEMA = "home-center.household-bootstrap-result.v1"
HOUSEHOLD_INTENT_REQUEST_SCHEMA = "home-center.household-intent-request.v1"


class HouseholdRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ActorBinding:
    actor: str
    member_id: str

    def to_dict(self) -> dict[str, str]:
        return {"actor": self.actor, "member_id": self.member_id}


def _household_from_dict(value: object) -> Household:
    if not isinstance(value, dict) or value.get("schema") != "home-center.household.v1":
        raise HouseholdRuntimeError("household_state_invalid")
    members_raw = value.get("members")
    devices_raw = value.get("devices")
    if not isinstance(members_raw, list) or not isinstance(devices_raw, list):
        raise HouseholdRuntimeError("household_state_invalid")
    try:
        members = tuple(
            FamilyMember(
                member_id=item["member_id"],
                display_name=item["display_name"],
                role=HouseholdRole(item["role"]),
                enabled=item["enabled"],
            )
            for item in members_raw
            if isinstance(item, dict)
        )
        devices = tuple(
            ManagedDevice(
                device_id=item["device_id"],
                member_id=item["member_id"],
                display_name=item["display_name"],
                managed=item["managed"],
            )
            for item in devices_raw
            if isinstance(item, dict)
        )
        if len(members) != len(members_raw) or len(devices) != len(devices_raw):
            raise HouseholdRuntimeError("household_state_invalid")
        return Household(
            household_id=value["household_id"],
            members=members,
            devices=devices,
        )
    except (KeyError, TypeError, ValueError, HomeServiceCatalogError) as exc:
        if isinstance(exc, HouseholdRuntimeError):
            raise
        raise HouseholdRuntimeError("household_state_invalid") from exc


def _snapshot_from_dict(value: object) -> HouseholdSnapshot:
    if not isinstance(value, dict) or value.get("schema") != "home-center.household-snapshot.v1":
        raise HouseholdRuntimeError("household_state_invalid")
    household = _household_from_dict(value.get("household"))
    try:
        snapshot = HouseholdSnapshot(
            snapshot_id=value["snapshot_id"],
            resource_version=value["resource_version"],
            household_id=value["household_id"],
            generation=value["generation"],
            previous_snapshot_id=value.get("previous_snapshot_id"),
            household=household,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise HouseholdRuntimeError("household_state_invalid") from exc
    if snapshot.household_id != household.household_id:
        raise HouseholdRuntimeError("household_state_invalid")

    # 0.48 persists only the initial generation.  Reconstruct it through the
    # authoritative HouseholdStore so tampered ids/resource versions fail closed.
    if snapshot.generation != 1 or snapshot.previous_snapshot_id is not None:
        raise HouseholdRuntimeError("household_state_generation_unsupported")
    verifier = HouseholdStore()
    verifier.create(household)
    expected = verifier.read(household.household_id)
    if expected != snapshot:
        raise HouseholdRuntimeError("household_state_evidence_mismatch")
    return snapshot


class HouseholdRuntimeService:
    """Authenticated, audited runtime facade for Household state and planning."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def status(self) -> dict[str, object]:
        with self._lock:
            raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
            if raw is None:
                return {
                    "schema": HOUSEHOLD_RUNTIME_SCHEMA,
                    "configured": False,
                    "snapshot": None,
                    "infrastructure_mutation_authorized": False,
                    "external_publication_authorized": False,
                }
            snapshot = _snapshot_from_dict(raw)
            return {
                "schema": HOUSEHOLD_RUNTIME_SCHEMA,
                "configured": True,
                "snapshot": snapshot.to_dict(),
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            }

    def bootstrap(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if set(request) != {"schema", "display_name"} or request.get("schema") != HOUSEHOLD_BOOTSTRAP_SCHEMA:
            raise HouseholdRuntimeError("invalid_household_bootstrap_request")
        display_name = request.get("display_name")
        if not isinstance(display_name, str):
            raise HouseholdRuntimeError("invalid_household_bootstrap_request")

        with self._lock:
            if self.store.get_meta(HOUSEHOLD_STATE_KEY) is not None:
                raise HouseholdRuntimeError("household_already_configured")
            member_id = "member-" + uuid.uuid4().hex[:16]
            household = Household(
                household_id="home",
                members=(
                    FamilyMember(
                        member_id=member_id,
                        display_name=display_name,
                        role=HouseholdRole.PARENT,
                    ),
                ),
                devices=(),
            )
            reference = HouseholdStore()
            commit = reference.create(household)
            snapshot = reference.read(household.household_id)
            bindings = {
                "schema": "home-center.household-actor-bindings.v1",
                "bindings": [{"actor": actor, "member_id": member_id}],
            }
            self.store.set_meta(HOUSEHOLD_STATE_KEY, snapshot.to_dict())
            self.store.set_meta(HOUSEHOLD_BINDINGS_KEY, bindings)
            audit_event_id = self.store.audit(
                actor=actor,
                action="household.bootstrap",
                target=household.household_id,
                outcome="succeeded",
                correlation_id=correlation_id,
                details={
                    "commit_id": commit.commit_id,
                    "snapshot_id": snapshot.snapshot_id,
                    "resource_version": snapshot.resource_version,
                    "generation": snapshot.generation,
                    "member_id": member_id,
                },
            )
            return {
                "schema": HOUSEHOLD_BOOTSTRAP_RESULT_SCHEMA,
                "snapshot": snapshot.to_dict(),
                "commit": commit.to_dict(),
                "actor_binding": ActorBinding(actor=actor, member_id=member_id).to_dict(),
                "audit_event_id": audit_event_id,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            }

    def actor_member_id(self, actor: str) -> str:
        with self._lock:
            value = self.store.get_meta(HOUSEHOLD_BINDINGS_KEY)
        if not isinstance(value, dict) or value.get("schema") != "home-center.household-actor-bindings.v1":
            raise HouseholdRuntimeError("household_actor_not_bound")
        bindings = value.get("bindings")
        if not isinstance(bindings, list):
            raise HouseholdRuntimeError("household_actor_not_bound")
        for binding in bindings:
            if isinstance(binding, dict) and binding.get("actor") == actor and isinstance(binding.get("member_id"), str):
                return binding["member_id"]
        raise HouseholdRuntimeError("household_actor_not_bound")

    def plan_intent(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        required = {"schema", "intent_id", "kind", "target_id", "requested_role", "subject_member_id"}
        if set(request) != required or request.get("schema") != HOUSEHOLD_INTENT_REQUEST_SCHEMA:
            raise HouseholdRuntimeError("invalid_household_intent_request")
        with self._lock:
            raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
            if raw is None:
                raise HouseholdRuntimeError("household_not_configured")
            snapshot = _snapshot_from_dict(raw)
            actor_member_id = self.actor_member_id(actor)
            try:
                kind = HouseholdIntentKind(request["kind"])
                role_raw = request.get("requested_role")
                role = HouseholdRole(role_raw) if role_raw is not None else None
                intent = HouseholdIntent(
                    intent_id=request["intent_id"],
                    actor_member_id=actor_member_id,
                    kind=kind,
                    target_id=request["target_id"],
                    requested_role=role,
                    subject_member_id=request.get("subject_member_id"),
                )
                proposal = build_household_intent_proposal(snapshot, intent)
            except (KeyError, TypeError, ValueError, HomeServiceCatalogError) as exc:
                code = exc.code if isinstance(exc, HomeServiceCatalogError) else "invalid_household_intent_request"
                raise HouseholdRuntimeError(code) from exc
            digest = hashlib.sha256(
                json.dumps(proposal.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            self.store.audit(
                actor=actor,
                action="household.intent.plan",
                target=proposal.proposal_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "proposal_sha256": digest,
                    "snapshot_id": proposal.snapshot_id,
                    "resource_version": proposal.resource_version,
                    "intent_kind": proposal.intent.kind.value,
                },
            )
            return proposal.to_dict()
