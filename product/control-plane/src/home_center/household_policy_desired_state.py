"""Protected Desired State materialization for Home Center 0.59 Policy Composer.

The service consumes an exact durable confirmation produced by
``HouseholdPolicyRuntimeService`` and performs a local SQLite compare-and-set of
one policy Desired State resource. It never executes a provider, changes device
state, alters networking, or grants infrastructure authority.

The write protocol is crash-aware:
1. persist an ``applying`` marker;
2. append pre-write Audit evidence;
3. compare-and-set the exact Desired State revision;
4. append completion Audit evidence;
5. persist an idempotent application receipt.

If a process dies after step 3, a replay recognizes the exact target bundle and
finalizes evidence instead of applying the mutation a second time.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .household_policy_composer import (
    HouseholdPolicyComposerError,
    PolicyCompositionProposal,
    build_policy_composition_proposal,
    revalidate_policy_composition_proposal,
)
from .household_policy_runtime import (
    POLICY_CONFIRMATION_SCHEMA,
    POLICY_PROPOSAL_KEY_PREFIX,
    POLICY_PROPOSAL_STATE_SCHEMA,
)
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore
from .util import canonical_json, utc_now


POLICY_APPLY_REQUEST_SCHEMA = "home-center.household-policy-apply-request.v1"
POLICY_APPLY_STATE_SCHEMA = "home-center.household-policy-apply-state.v1"
POLICY_APPLY_RECEIPT_SCHEMA = "home-center.household-policy-apply-receipt.v1"
POLICY_APPLY_KEY_PREFIX = "cozy.household.policy-apply."
PROPOSAL_ID = re.compile(r"^hpc-[0-9a-f]{24}$")
CONFIRMATION_ID = re.compile(r"^hpconfirm-[0-9a-f]{24}$")
BUNDLE_ID = re.compile(r"^hpb-[0-9a-f]{24}$")


class HouseholdPolicyDesiredStateError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _proposal_key(proposal_id: object) -> str:
    if not isinstance(proposal_id, str) or PROPOSAL_ID.fullmatch(proposal_id) is None:
        raise HouseholdPolicyDesiredStateError("invalid_household_policy_proposal_id")
    return POLICY_PROPOSAL_KEY_PREFIX + proposal_id


def _apply_key(confirmation_id: object) -> str:
    if not isinstance(confirmation_id, str) or CONFIRMATION_ID.fullmatch(confirmation_id) is None:
        raise HouseholdPolicyDesiredStateError("invalid_household_policy_confirmation_id")
    return POLICY_APPLY_KEY_PREFIX + confirmation_id


def _bundle_from_record(record: dict[str, object]) -> tuple[str, dict[str, object]]:
    value = record.get("value")
    if not isinstance(value, dict) or value.get("schema") != "home-center.household-policy-bundle.v1":
        raise HouseholdPolicyDesiredStateError("household_policy_desired_state_invalid")
    bundle_id = value.get("bundle_id")
    if not isinstance(bundle_id, str) or BUNDLE_ID.fullmatch(bundle_id) is None:
        raise HouseholdPolicyDesiredStateError("household_policy_desired_state_invalid")
    if value.get("desired_state_resource_key") != record.get("resource_key"):
        raise HouseholdPolicyDesiredStateError("household_policy_desired_state_invalid")
    if (
        value.get("desired_state_write_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyDesiredStateError("household_policy_desired_state_invalid")
    return bundle_id, value


class HouseholdPolicyDesiredStateRepository:
    """Small SQLite CAS boundary over the existing ``desired_state`` table."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    @staticmethod
    def _decode(row: sqlite3.Row | None) -> dict[str, object] | None:
        if row is None:
            return None
        try:
            value = json.loads(row["value_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise HouseholdPolicyDesiredStateError("household_policy_desired_state_invalid") from exc
        record: dict[str, object] = {
            "resource_key": row["resource_key"],
            "generation": row["generation"],
            "value": value,
            "updated_at": row["updated_at"],
        }
        generation = record["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise HouseholdPolicyDesiredStateError("household_policy_desired_state_invalid")
        _bundle_from_record(record)
        return record

    def read(self, resource_key: str) -> dict[str, object] | None:
        with self._lock:
            connection = sqlite3.connect(self.path, timeout=5)
            connection.row_factory = sqlite3.Row
            try:
                row = connection.execute(
                    "SELECT resource_key,generation,value_json,updated_at FROM desired_state WHERE resource_key=?",
                    (resource_key,),
                ).fetchone()
            finally:
                connection.close()
        return self._decode(row)

    @staticmethod
    def revision(record: dict[str, object] | None) -> tuple[int, str | None]:
        if record is None:
            return 0, None
        bundle_id, _value = _bundle_from_record(record)
        generation = record.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise HouseholdPolicyDesiredStateError("household_policy_desired_state_invalid")
        return generation, bundle_id

    def compare_and_set(self, proposal: PolicyCompositionProposal) -> tuple[dict[str, object], bool]:
        resource_key = proposal.bundle.desired_state_resource_key
        target = proposal.bundle.to_dict()
        expected_generation = proposal.expected_desired_state_generation
        expected_bundle_id = proposal.expected_desired_state_bundle_id
        target_bundle_id = proposal.bundle.bundle_id
        now = utc_now()

        with self._lock:
            connection = sqlite3.connect(self.path, timeout=5)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT resource_key,generation,value_json,updated_at FROM desired_state WHERE resource_key=?",
                    (resource_key,),
                ).fetchone()
                current = self._decode(row)
                current_generation, current_bundle_id = self.revision(current)

                # Exact replay after a committed write: do not mutate a second time.
                if current is not None and current.get("value") == target:
                    if current_generation == expected_generation and current_bundle_id == target_bundle_id:
                        connection.commit()
                        return current, False
                    if current_generation == expected_generation + 1 and current_bundle_id == target_bundle_id:
                        connection.commit()
                        return current, False

                if current_generation != expected_generation or current_bundle_id != expected_bundle_id:
                    raise HouseholdPolicyDesiredStateError("household_policy_desired_state_precondition_failed")

                # A plan whose target already equals the exact observed revision is an honest no-op.
                if current is not None and current_bundle_id == target_bundle_id:
                    if current.get("value") != target:
                        raise HouseholdPolicyDesiredStateError("household_policy_desired_state_evidence_mismatch")
                    connection.commit()
                    return current, False

                next_generation = expected_generation + 1
                if current is None:
                    connection.execute(
                        "INSERT INTO desired_state(resource_key,generation,value_json,updated_at) VALUES(?,?,?,?)",
                        (resource_key, next_generation, canonical_json(target), now),
                    )
                else:
                    cursor = connection.execute(
                        """UPDATE desired_state SET generation=?,value_json=?,updated_at=?
                        WHERE resource_key=? AND generation=?""",
                        (
                            next_generation,
                            canonical_json(target),
                            now,
                            resource_key,
                            expected_generation,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise HouseholdPolicyDesiredStateError("household_policy_desired_state_precondition_failed")
                row = connection.execute(
                    "SELECT resource_key,generation,value_json,updated_at FROM desired_state WHERE resource_key=?",
                    (resource_key,),
                ).fetchone()
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

        result = self._decode(row)
        if result is None:
            raise HouseholdPolicyDesiredStateError("household_policy_desired_state_write_failed")
        return result, True


class HouseholdPolicyDesiredStateService:
    """Consume confirmed policy evidence and materialize local protected Desired State."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self.repository = HouseholdPolicyDesiredStateRepository(store.path)
        self._lock = threading.RLock()

    def _actor_member(self, actor: str) -> tuple[object, str]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyDesiredStateError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdPolicyDesiredStateError(getattr(exc, "code", "household_state_invalid")) from exc
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise HouseholdPolicyDesiredStateError("household_actor_not_bound")
        return snapshot, member_id

    @staticmethod
    def _confirmed_envelope(value: object) -> tuple[dict[str, Any], dict[str, Any]]:
        if (
            not isinstance(value, dict)
            or value.get("schema") != POLICY_PROPOSAL_STATE_SCHEMA
            or value.get("status") != "confirmed"
            or value.get("recovery_required") is not False
        ):
            raise HouseholdPolicyDesiredStateError("household_policy_confirmation_required")
        proposal = value.get("proposal")
        confirmation = value.get("confirmation")
        if not isinstance(proposal, dict) or not isinstance(confirmation, dict):
            raise HouseholdPolicyDesiredStateError("household_policy_confirmation_invalid")
        if confirmation.get("schema") != POLICY_CONFIRMATION_SCHEMA:
            raise HouseholdPolicyDesiredStateError("household_policy_confirmation_invalid")
        if confirmation.get("proposal_id") != proposal.get("proposal_id"):
            raise HouseholdPolicyDesiredStateError("household_policy_confirmation_invalid")
        if confirmation.get("desired_state_write_ready") is not True:
            raise HouseholdPolicyDesiredStateError("household_policy_confirmation_invalid")
        if (
            confirmation.get("desired_state_write_authorized") is not False
            or confirmation.get("infrastructure_mutation_authorized") is not False
            or confirmation.get("external_publication_authorized") is not False
        ):
            raise HouseholdPolicyDesiredStateError("household_policy_confirmation_invalid")
        return proposal, confirmation

    def _proposal_for_actor(
        self,
        *,
        actor: str,
        raw: dict[str, Any],
        require_expected_revision: bool,
    ) -> PolicyCompositionProposal:
        snapshot, actor_member_id = self._actor_member(actor)
        try:
            proposal = build_policy_composition_proposal(
                snapshot,
                actor_member_id=actor_member_id,
                member_id=raw.get("member_id"),
                expected_desired_state_generation=raw.get("expected_desired_state_generation"),
                expected_desired_state_bundle_id=raw.get("expected_desired_state_bundle_id"),
            )
        except (HouseholdPolicyComposerError, TypeError) as exc:
            raise HouseholdPolicyDesiredStateError(
                getattr(exc, "code", "household_policy_proposal_invalid")
            ) from exc
        if proposal.to_dict() != raw:
            raise HouseholdPolicyDesiredStateError("household_policy_proposal_evidence_mismatch")
        if require_expected_revision:
            current = self.repository.read(proposal.bundle.desired_state_resource_key)
            current_generation, current_bundle_id = self.repository.revision(current)
            try:
                revalidate_policy_composition_proposal(
                    snapshot,
                    proposal,
                    actor_member_id=actor_member_id,
                    current_desired_state_generation=current_generation,
                    current_desired_state_bundle_id=current_bundle_id,
                )
            except HouseholdPolicyComposerError as exc:
                raise HouseholdPolicyDesiredStateError(exc.code) from exc
        return proposal

    @staticmethod
    def _confirmation_matches(proposal: PolicyCompositionProposal, confirmation: dict[str, Any]) -> None:
        expected = {
            "proposal_id": proposal.proposal_id,
            "household_id": proposal.household_id,
            "snapshot_id": proposal.snapshot_id,
            "resource_version": proposal.resource_version,
            "generation": proposal.generation,
            "actor_member_id": proposal.actor_member_id,
            "member_id": proposal.member_id,
            "bundle_id": proposal.bundle.bundle_id,
            "desired_state_resource_key": proposal.bundle.desired_state_resource_key,
            "expected_desired_state_generation": proposal.expected_desired_state_generation,
            "expected_desired_state_bundle_id": proposal.expected_desired_state_bundle_id,
        }
        if any(confirmation.get(key) != value for key, value in expected.items()):
            raise HouseholdPolicyDesiredStateError("household_policy_confirmation_evidence_mismatch")

    @staticmethod
    def _receipt(
        *,
        proposal: PolicyCompositionProposal,
        confirmation: dict[str, Any],
        record: dict[str, object],
        changed: bool,
        pre_audit_event_id: str | None,
        post_audit_event_id: str,
        recovered: bool,
    ) -> dict[str, object]:
        generation, bundle_id = HouseholdPolicyDesiredStateRepository.revision(record)
        return {
            "schema": POLICY_APPLY_RECEIPT_SCHEMA,
            "proposal_id": proposal.proposal_id,
            "confirmation_id": confirmation["confirmation_id"],
            "resource_key": proposal.bundle.desired_state_resource_key,
            "generation": generation,
            "bundle_id": bundle_id,
            "changed": changed,
            "recovered": recovered,
            "outcome": "applied" if changed else "already-current",
            "pre_audit_event_id": pre_audit_event_id,
            "post_audit_event_id": post_audit_event_id,
            "desired_state_materialized": True,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    def apply(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "proposal_id", "confirmation_id"}
            or request.get("schema") != POLICY_APPLY_REQUEST_SCHEMA
        ):
            raise HouseholdPolicyDesiredStateError("invalid_household_policy_apply_request")
        proposal_key = _proposal_key(request.get("proposal_id"))
        apply_key = _apply_key(request.get("confirmation_id"))

        with self._lock:
            raw_proposal, confirmation = self._confirmed_envelope(self.store.get_meta(proposal_key))
            if confirmation.get("confirmation_id") != request.get("confirmation_id"):
                raise HouseholdPolicyDesiredStateError("household_policy_confirmation_evidence_mismatch")

            existing_apply = self.store.get_meta(apply_key)
            if isinstance(existing_apply, dict) and existing_apply.get("schema") == POLICY_APPLY_STATE_SCHEMA:
                status = existing_apply.get("status")
                if existing_apply.get("proposal") != raw_proposal or existing_apply.get("confirmation") != confirmation:
                    raise HouseholdPolicyDesiredStateError("household_policy_apply_state_invalid")
                if status == "applied":
                    receipt = existing_apply.get("receipt")
                    if not isinstance(receipt, dict):
                        raise HouseholdPolicyDesiredStateError("household_policy_apply_state_invalid")
                    record = self.repository.read(receipt.get("resource_key"))
                    if record is None:
                        raise HouseholdPolicyDesiredStateError("household_policy_desired_state_missing")
                    generation, bundle_id = self.repository.revision(record)
                    if generation != receipt.get("generation") or bundle_id != receipt.get("bundle_id"):
                        raise HouseholdPolicyDesiredStateError("household_policy_desired_state_evidence_mismatch")
                    replay = dict(receipt)
                    replay["outcome"] = "already-applied"
                    return replay
                if status not in {"applying", "invalidated"}:
                    raise HouseholdPolicyDesiredStateError("household_policy_apply_state_invalid")
                if status == "invalidated":
                    raise HouseholdPolicyDesiredStateError("household_policy_apply_invalidated")

                # Recovery after an ambiguous interruption. If the exact target bundle is already
                # present at the only valid next generation, finalize evidence without reapplying.
                recovery_proposal = self._proposal_for_actor(
                    actor=actor,
                    raw=raw_proposal,
                    require_expected_revision=False,
                )
                self._confirmation_matches(recovery_proposal, confirmation)
                record = self.repository.read(recovery_proposal.bundle.desired_state_resource_key)
                generation, bundle_id = self.repository.revision(record)
                expected_generation = recovery_proposal.expected_desired_state_generation
                target_bundle_id = recovery_proposal.bundle.bundle_id
                target_value = recovery_proposal.bundle.to_dict()
                if (
                    record is not None
                    and bundle_id == target_bundle_id
                    and record.get("value") == target_value
                    and generation in {expected_generation, expected_generation + 1}
                ):
                    recovery_audit_id = self.store.audit(
                        actor=actor,
                        action="household.policy.desired-state.recover",
                        target=recovery_proposal.bundle.desired_state_resource_key,
                        outcome="finalized-existing-write",
                        correlation_id=correlation_id,
                        details={
                            "proposal_id": recovery_proposal.proposal_id,
                            "confirmation_id": confirmation["confirmation_id"],
                            "generation": generation,
                            "bundle_id": bundle_id,
                            "provider_execution_authorized": False,
                            "infrastructure_mutation_authorized": False,
                        },
                    )
                    receipt = self._receipt(
                        proposal=recovery_proposal,
                        confirmation=confirmation,
                        record=record,
                        changed=generation == expected_generation + 1,
                        pre_audit_event_id=None,
                        post_audit_event_id=recovery_audit_id,
                        recovered=True,
                    )
                    self.store.set_meta(
                        apply_key,
                        {
                            "schema": POLICY_APPLY_STATE_SCHEMA,
                            "status": "applied",
                            "proposal": raw_proposal,
                            "confirmation": confirmation,
                            "receipt": receipt,
                        },
                    )
                    return receipt

                # No write can be inferred. Revalidate all current preconditions before retrying.
                try:
                    proposal = self._proposal_for_actor(
                        actor=actor,
                        raw=raw_proposal,
                        require_expected_revision=True,
                    )
                except HouseholdPolicyDesiredStateError:
                    self.store.set_meta(
                        apply_key,
                        {
                            "schema": POLICY_APPLY_STATE_SCHEMA,
                            "status": "invalidated",
                            "proposal": raw_proposal,
                            "confirmation": confirmation,
                            "receipt": None,
                        },
                    )
                    raise
            else:
                if existing_apply is not None:
                    raise HouseholdPolicyDesiredStateError("household_policy_apply_state_invalid")
                proposal = self._proposal_for_actor(
                    actor=actor,
                    raw=raw_proposal,
                    require_expected_revision=True,
                )
                self._confirmation_matches(proposal, confirmation)
                self.store.set_meta(
                    apply_key,
                    {
                        "schema": POLICY_APPLY_STATE_SCHEMA,
                        "status": "applying",
                        "proposal": raw_proposal,
                        "confirmation": confirmation,
                        "receipt": None,
                    },
                )

            pre_audit_event_id = self.store.audit(
                actor=actor,
                action="household.policy.desired-state.apply.begin",
                target=proposal.bundle.desired_state_resource_key,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "confirmation_id": confirmation["confirmation_id"],
                    "expected_generation": proposal.expected_desired_state_generation,
                    "expected_bundle_id": proposal.expected_desired_state_bundle_id,
                    "target_bundle_id": proposal.bundle.bundle_id,
                    "provider_execution_authorized": False,
                    "infrastructure_mutation_authorized": False,
                },
            )
            try:
                record, changed = self.repository.compare_and_set(proposal)
            except HouseholdPolicyDesiredStateError as exc:
                self.store.audit(
                    actor=actor,
                    action="household.policy.desired-state.apply.complete",
                    target=proposal.bundle.desired_state_resource_key,
                    outcome="failed",
                    correlation_id=correlation_id,
                    details={
                        "proposal_id": proposal.proposal_id,
                        "confirmation_id": confirmation["confirmation_id"],
                        "reason": exc.code,
                        "infrastructure_mutation_authorized": False,
                    },
                )
                self.store.set_meta(
                    apply_key,
                    {
                        "schema": POLICY_APPLY_STATE_SCHEMA,
                        "status": "invalidated",
                        "proposal": raw_proposal,
                        "confirmation": confirmation,
                        "receipt": None,
                    },
                )
                raise

            generation, bundle_id = self.repository.revision(record)
            post_audit_event_id = self.store.audit(
                actor=actor,
                action="household.policy.desired-state.apply.complete",
                target=proposal.bundle.desired_state_resource_key,
                outcome="succeeded" if changed else "already-current",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "confirmation_id": confirmation["confirmation_id"],
                    "generation": generation,
                    "bundle_id": bundle_id,
                    "changed": changed,
                    "desired_state_materialized": True,
                    "provider_execution_authorized": False,
                    "infrastructure_mutation_authorized": False,
                },
            )
            receipt = self._receipt(
                proposal=proposal,
                confirmation=confirmation,
                record=record,
                changed=changed,
                pre_audit_event_id=pre_audit_event_id,
                post_audit_event_id=post_audit_event_id,
                recovered=False,
            )
            self.store.set_meta(
                apply_key,
                {
                    "schema": POLICY_APPLY_STATE_SCHEMA,
                    "status": "applied",
                    "proposal": raw_proposal,
                    "confirmation": confirmation,
                    "receipt": receipt,
                },
            )
            return receipt
