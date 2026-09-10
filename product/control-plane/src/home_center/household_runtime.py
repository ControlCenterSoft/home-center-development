"""Runtime integration for the Home Center Household/Cozy domain.

0.49 permits confirmation-gated mutation of Home Center Household product state
only. It still does not create operating-system accounts, change DNS/VPN/MDM,
execute providers, mutate external Desired State, or publish services.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from dataclasses import dataclass
from typing import Any

from .home_services import HomeServiceCatalogError
from .household import FamilyMember, Household, HouseholdRole, ManagedDevice
from .household_intent import HouseholdIntent, HouseholdIntentKind
from .household_intent_proposal import build_household_intent_proposal
from .household_member_change import (
    HouseholdMemberAddReceipt,
    HouseholdMemberChangeError,
    apply_member_add_proposal,
    build_member_add_proposal,
    member_add_proposal_from_dict,
)
from .household_store import HouseholdSnapshot, HouseholdStore, MAX_GENERATION
from .store import StateStore


HOUSEHOLD_STATE_KEY = "cozy.household.runtime-state.v1"
HOUSEHOLD_PERSISTED_SCHEMA = "home-center.household-persisted-state.v1"
HOUSEHOLD_RUNTIME_SCHEMA = "home-center.household-runtime.v1"
HOUSEHOLD_BOOTSTRAP_SCHEMA = "home-center.household-bootstrap.v1"
HOUSEHOLD_BOOTSTRAP_RESULT_SCHEMA = "home-center.household-bootstrap-result.v1"
HOUSEHOLD_INTENT_REQUEST_SCHEMA = "home-center.household-intent-request.v1"
HOUSEHOLD_MEMBER_PLAN_SCHEMA = "home-center.household-member-add-plan.v1"
HOUSEHOLD_MEMBER_CONFIRM_SCHEMA = "home-center.household-member-add-confirm.v1"
HOUSEHOLD_MEMBER_PROPOSAL_STATE_SCHEMA = "home-center.household-member-proposal-state.v1"
MEMBER_PROPOSAL_KEY_PREFIX = "cozy.household.member-proposal."
SNAPSHOT_ID = re.compile(r"^hsnap-[a-f0-9]{24}$")
RESOURCE_VERSION = re.compile(r"^hrv-[a-f0-9]{24}$")
MEMBER_PROPOSAL_ID = re.compile(r"^hmadd-[a-f0-9]{24}$")


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
    except HouseholdRuntimeError:
        raise
    except (KeyError, TypeError, ValueError, HomeServiceCatalogError) as exc:
        raise HouseholdRuntimeError("household_state_invalid") from exc


def _snapshot_from_dict(value: object) -> HouseholdSnapshot:
    if not isinstance(value, dict) or value.get("schema") != "home-center.household-snapshot.v1":
        raise HouseholdRuntimeError("household_state_invalid")
    household = _household_from_dict(value.get("household"))
    try:
        generation = value["generation"]
        previous_snapshot_id = value.get("previous_snapshot_id")
        snapshot_id = value["snapshot_id"]
        resource_version = value["resource_version"]
        household_id = value["household_id"]
    except KeyError as exc:
        raise HouseholdRuntimeError("household_state_invalid") from exc
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= MAX_GENERATION
        or not isinstance(snapshot_id, str)
        or SNAPSHOT_ID.fullmatch(snapshot_id) is None
        or not isinstance(resource_version, str)
        or RESOURCE_VERSION.fullmatch(resource_version) is None
        or household_id != household.household_id
    ):
        raise HouseholdRuntimeError("household_state_invalid")
    if generation == 1:
        if previous_snapshot_id is not None:
            raise HouseholdRuntimeError("household_state_invalid")
    elif not isinstance(previous_snapshot_id, str) or SNAPSHOT_ID.fullmatch(previous_snapshot_id) is None:
        raise HouseholdRuntimeError("household_state_invalid")

    canonical = {
        "household": household.to_dict(),
        "generation": generation,
        "previous_snapshot_id": previous_snapshot_id,
    }
    digest = hashlib.sha256(
        json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    ).hexdigest()
    if snapshot_id != "hsnap-" + digest[:24] or resource_version != "hrv-" + digest[24:48]:
        raise HouseholdRuntimeError("household_state_evidence_mismatch")
    return HouseholdSnapshot(
        snapshot_id=snapshot_id,
        resource_version=resource_version,
        household_id=household_id,
        generation=generation,
        previous_snapshot_id=previous_snapshot_id,
        household=household,
    )


def _state_from_dict(value: object) -> tuple[HouseholdSnapshot, tuple[ActorBinding, ...]]:
    if not isinstance(value, dict) or value.get("schema") != HOUSEHOLD_PERSISTED_SCHEMA:
        raise HouseholdRuntimeError("household_state_invalid")
    snapshot = _snapshot_from_dict(value.get("snapshot"))
    raw_bindings = value.get("bindings")
    if not isinstance(raw_bindings, list) or not raw_bindings:
        raise HouseholdRuntimeError("household_state_invalid")
    bindings: list[ActorBinding] = []
    seen_actors: set[str] = set()
    seen_members: set[str] = set()
    known_members = {member.member_id for member in snapshot.household.members}
    for raw in raw_bindings:
        if not isinstance(raw, dict) or set(raw) != {"actor", "member_id"}:
            raise HouseholdRuntimeError("household_state_invalid")
        actor = raw.get("actor")
        member_id = raw.get("member_id")
        if (
            not isinstance(actor, str)
            or not actor
            or len(actor) > 320
            or not isinstance(member_id, str)
            or member_id not in known_members
            or actor in seen_actors
            or member_id in seen_members
        ):
            raise HouseholdRuntimeError("household_state_invalid")
        seen_actors.add(actor)
        seen_members.add(member_id)
        bindings.append(ActorBinding(actor=actor, member_id=member_id))
    return snapshot, tuple(bindings)


def _persisted(snapshot: HouseholdSnapshot, bindings: tuple[ActorBinding, ...]) -> dict[str, object]:
    return {
        "schema": HOUSEHOLD_PERSISTED_SCHEMA,
        "snapshot": snapshot.to_dict(),
        "bindings": [binding.to_dict() for binding in bindings],
    }


def _proposal_key(proposal_id: str) -> str:
    if not isinstance(proposal_id, str) or MEMBER_PROPOSAL_ID.fullmatch(proposal_id) is None:
        raise HouseholdRuntimeError("invalid_household_member_proposal_id")
    return MEMBER_PROPOSAL_KEY_PREFIX + proposal_id


class HouseholdRuntimeService:
    """Authenticated, audited runtime facade for Household state and planning."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _read_state(self) -> tuple[HouseholdSnapshot, tuple[ActorBinding, ...]]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdRuntimeError("household_not_configured")
        return _state_from_dict(raw)

    @staticmethod
    def _actor_member(actor: str, bindings: tuple[ActorBinding, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise HouseholdRuntimeError("household_actor_not_bound")
        return member_id

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
            snapshot, _bindings = _state_from_dict(raw)
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
            try:
                household = Household(
                    household_id="home",
                    members=(FamilyMember(member_id=member_id, display_name=display_name, role=HouseholdRole.PARENT),),
                    devices=(),
                )
            except HomeServiceCatalogError as exc:
                raise HouseholdRuntimeError(exc.code) from exc
            reference = HouseholdStore()
            commit = reference.create(household)
            snapshot = reference.read(household.household_id)
            binding = ActorBinding(actor=actor, member_id=member_id)
            self.store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(snapshot, (binding,)))
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
                "actor_binding": binding.to_dict(),
                "audit_event_id": audit_event_id,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            }

    def actor_member_id(self, actor: str) -> str:
        with self._lock:
            _snapshot, bindings = self._read_state()
            return self._actor_member(actor, bindings)

    def plan_intent(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        required = {"schema", "intent_id", "kind", "target_id", "requested_role", "subject_member_id"}
        if set(request) != required or request.get("schema") != HOUSEHOLD_INTENT_REQUEST_SCHEMA:
            raise HouseholdRuntimeError("invalid_household_intent_request")
        with self._lock:
            snapshot, bindings = self._read_state()
            actor_member_id = self._actor_member(actor, bindings)
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

    def plan_member_add(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if set(request) != {"schema", "display_name", "role"} or request.get("schema") != HOUSEHOLD_MEMBER_PLAN_SCHEMA:
            raise HouseholdRuntimeError("invalid_household_member_plan_request")
        with self._lock:
            snapshot, bindings = self._read_state()
            actor_member_id = self._actor_member(actor, bindings)
            try:
                role = HouseholdRole(request.get("role"))
            except (TypeError, ValueError) as exc:
                raise HouseholdRuntimeError("invalid_household_role") from exc
            display_name = request.get("display_name")
            if not isinstance(display_name, str):
                raise HouseholdRuntimeError("invalid_household_member_name")

            for _attempt in range(4):
                member_id = "member-" + uuid.uuid4().hex[:16]
                try:
                    proposal = build_member_add_proposal(
                        snapshot,
                        actor_member_id=actor_member_id,
                        member_id=member_id,
                        display_name=display_name,
                        role=role,
                    )
                except HouseholdMemberChangeError as exc:
                    raise HouseholdRuntimeError(exc.code) from exc
                key = _proposal_key(proposal.proposal_id)
                if self.store.get_meta(key) is None:
                    break
            else:
                raise HouseholdRuntimeError("household_member_proposal_collision")

            envelope = {
                "schema": HOUSEHOLD_MEMBER_PROPOSAL_STATE_SCHEMA,
                "status": "pending",
                "proposal": proposal.to_dict(),
                "base_snapshot": snapshot.to_dict(),
                "pre_audit_event_id": None,
                "receipt": None,
            }
            self.store.set_meta(key, envelope)
            self.store.audit(
                actor=actor,
                action="household.member.plan",
                target=proposal.proposal_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "snapshot_id": proposal.snapshot_id,
                    "resource_version": proposal.resource_version,
                    "member_id": proposal.member.member_id,
                    "role": proposal.member.role.value,
                },
            )
            return proposal.to_dict()

    def confirm_member_add(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "proposal_id", "confirmed"}
            or request.get("schema") != HOUSEHOLD_MEMBER_CONFIRM_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise HouseholdRuntimeError("invalid_household_member_confirm_request")
        proposal_id = request.get("proposal_id")
        key = _proposal_key(proposal_id)

        with self._lock:
            raw = self.store.get_meta(key)
            if not isinstance(raw, dict) or raw.get("schema") != HOUSEHOLD_MEMBER_PROPOSAL_STATE_SCHEMA:
                raise HouseholdRuntimeError("household_member_proposal_not_found")
            status = raw.get("status")
            if status not in {"pending", "applying", "applied"}:
                raise HouseholdRuntimeError("household_member_proposal_state_invalid")
            try:
                proposal = member_add_proposal_from_dict(raw.get("proposal"))
                base_snapshot = _snapshot_from_dict(raw.get("base_snapshot"))
            except (HouseholdMemberChangeError, HouseholdRuntimeError) as exc:
                code = getattr(exc, "code", "household_member_proposal_state_invalid")
                raise HouseholdRuntimeError(code) from exc
            if (
                base_snapshot.household_id != proposal.household_id
                or base_snapshot.snapshot_id != proposal.snapshot_id
                or base_snapshot.resource_version != proposal.resource_version
                or base_snapshot.generation != proposal.generation
            ):
                raise HouseholdRuntimeError("household_member_proposal_evidence_mismatch")
            try:
                rebuilt = build_member_add_proposal(
                    base_snapshot,
                    actor_member_id=proposal.actor_member_id,
                    member_id=proposal.member.member_id,
                    display_name=proposal.member.display_name,
                    role=proposal.member.role,
                )
            except HouseholdMemberChangeError as exc:
                raise HouseholdRuntimeError(exc.code) from exc
            if rebuilt != proposal:
                raise HouseholdRuntimeError("household_member_proposal_evidence_mismatch")

            current, bindings = self._read_state()
            actor_member_id = self._actor_member(actor, bindings)
            if actor_member_id != proposal.actor_member_id:
                raise HouseholdRuntimeError("household_member_change_actor_mismatch")

            if status == "applied":
                receipt = raw.get("receipt")
                if not isinstance(receipt, dict) or receipt.get("proposal_id") != proposal.proposal_id:
                    raise HouseholdRuntimeError("household_member_receipt_invalid")
                member = next(
                    (item for item in current.household.members if item.member_id == proposal.member.member_id),
                    None,
                )
                if member != proposal.member:
                    raise HouseholdRuntimeError("household_member_receipt_state_mismatch")
                result = dict(receipt)
                result["outcome"] = "already-applied"
                return result

            try:
                expected_snapshot, commit = apply_member_add_proposal(
                    base_snapshot,
                    proposal,
                    actor_member_id=actor_member_id,
                )
            except HouseholdMemberChangeError as exc:
                raise HouseholdRuntimeError(exc.code) from exc

            current_is_base = (
                current.snapshot_id == base_snapshot.snapshot_id
                and current.resource_version == base_snapshot.resource_version
                and current.generation == base_snapshot.generation
                and current.household == base_snapshot.household
            )
            current_is_expected = current == expected_snapshot
            if not current_is_base and not current_is_expected:
                raise HouseholdRuntimeError("household_member_change_stale")

            pre_audit_event_id = raw.get("pre_audit_event_id")
            if status == "pending" or not isinstance(pre_audit_event_id, str):
                pre_audit_event_id = self.store.audit(
                    actor=actor,
                    action="household.member.create.requested",
                    target=proposal.member.member_id,
                    outcome="accepted",
                    correlation_id=correlation_id,
                    details={
                        "proposal_id": proposal.proposal_id,
                        "snapshot_id": proposal.snapshot_id,
                        "resource_version": proposal.resource_version,
                        "role": proposal.member.role.value,
                    },
                )
                raw = {
                    "schema": HOUSEHOLD_MEMBER_PROPOSAL_STATE_SCHEMA,
                    "status": "applying",
                    "proposal": proposal.to_dict(),
                    "base_snapshot": base_snapshot.to_dict(),
                    "pre_audit_event_id": pre_audit_event_id,
                    "receipt": None,
                }
                self.store.set_meta(key, raw)

            if current_is_base:
                self.store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(expected_snapshot, bindings))

            completion_audit_event_id = self.store.audit(
                actor=actor,
                action="household.member.create",
                target=proposal.member.member_id,
                outcome="succeeded" if current_is_base else "recovered",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "pre_audit_event_id": pre_audit_event_id,
                    "commit_id": commit.commit_id,
                    "previous_snapshot_id": base_snapshot.snapshot_id,
                    "snapshot_id": expected_snapshot.snapshot_id,
                    "resource_version": expected_snapshot.resource_version,
                    "role": proposal.member.role.value,
                },
            )
            receipt = HouseholdMemberAddReceipt(
                proposal_id=proposal.proposal_id,
                outcome="applied" if current_is_base else "already-applied",
                member=proposal.member,
                previous_snapshot_id=base_snapshot.snapshot_id,
                previous_resource_version=base_snapshot.resource_version,
                snapshot_id=expected_snapshot.snapshot_id,
                resource_version=expected_snapshot.resource_version,
                generation=expected_snapshot.generation,
                commit_id=commit.commit_id,
                audit_event_id=completion_audit_event_id,
            )
            result = receipt.to_dict()
            self.store.set_meta(
                key,
                {
                    "schema": HOUSEHOLD_MEMBER_PROPOSAL_STATE_SCHEMA,
                    "status": "applied",
                    "proposal": proposal.to_dict(),
                    "base_snapshot": base_snapshot.to_dict(),
                    "pre_audit_event_id": pre_audit_event_id,
                    "receipt": result,
                },
            )
            return result
