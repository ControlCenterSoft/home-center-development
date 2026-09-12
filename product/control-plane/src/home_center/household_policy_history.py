"""Revision evidence and fail-closed rollback for Home Center 0.59 Policy Desired State.

History is stored under generation-addressed StateStore keys and bound to the
keyed append-only Audit chain. Rollback never rewinds the generation counter:
when a previous bundle is restored it becomes a new forward revision. This module
never executes providers, changes devices/networking, or grants infrastructure
authority.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from typing import Any

from .household import effective_policy
from .household_policy_desired_state import (
    POLICY_APPLY_REQUEST_SCHEMA,
    HouseholdPolicyDesiredStateError,
    HouseholdPolicyDesiredStateRepository,
    HouseholdPolicyDesiredStateService,
    _proposal_key,
)
from .household_policy_runtime import POLICY_PROPOSAL_STATE_SCHEMA
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore
from .util import canonical_json, utc_now


POLICY_HISTORY_SCHEMA = "home-center.household-policy-history.v1"
POLICY_ROLLBACK_REQUEST_SCHEMA = "home-center.household-policy-rollback-request.v1"
POLICY_ROLLBACK_STATE_SCHEMA = "home-center.household-policy-rollback-state.v1"
POLICY_ROLLBACK_RECEIPT_SCHEMA = "home-center.household-policy-rollback-receipt.v1"
POLICY_HISTORY_KEY_PREFIX = "cozy.household.policy-history."
POLICY_ROLLBACK_KEY_PREFIX = "cozy.household.policy-rollback."


class HouseholdPolicyHistoryError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _history_key(resource_key: str, generation: int) -> str:
    digest = hashlib.sha256(resource_key.encode("utf-8")).hexdigest()[:24]
    return f"{POLICY_HISTORY_KEY_PREFIX}{digest}.{generation}"


def _rollback_id(actor: str, request: dict[str, Any]) -> str:
    material = {
        "actor": actor,
        "resource_key": request["resource_key"],
        "expected_generation": request["expected_generation"],
        "expected_bundle_id": request["expected_bundle_id"],
        "target_generation": request["target_generation"],
    }
    return "hprb-" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:24]


class HouseholdPolicyHistoryService:
    """Archive every production policy revision and restore old bundles as new revisions."""

    def __init__(
        self,
        store: StateStore,
        *,
        desired_state: HouseholdPolicyDesiredStateService,
    ) -> None:
        self.store = store
        self.desired_state = desired_state
        self.repository = desired_state.repository
        self._lock = threading.RLock()

    @staticmethod
    def _history_core(record: dict[str, object]) -> dict[str, object]:
        generation, bundle_id = HouseholdPolicyDesiredStateRepository.revision(record)
        resource_key = record.get("resource_key")
        value = record.get("value")
        if not isinstance(resource_key, str) or not isinstance(value, dict):
            raise HouseholdPolicyHistoryError("household_policy_history_record_invalid")
        return {
            "schema": POLICY_HISTORY_SCHEMA,
            "resource_key": resource_key,
            "generation": generation,
            "bundle_id": bundle_id,
            "value": value,
        }

    @staticmethod
    def _evidence_hash(core: dict[str, object]) -> str:
        return hashlib.sha256(canonical_json(core).encode("utf-8")).hexdigest()

    def _validate_history_audit(self, value: dict[str, object]) -> None:
        audit_event_id = value.get("audit_event_id")
        if not isinstance(audit_event_id, str) or not audit_event_id:
            raise HouseholdPolicyHistoryError("household_policy_history_audit_invalid")
        try:
            self.store.verify_audit_chain()
        except RuntimeError as exc:
            raise HouseholdPolicyHistoryError("household_policy_history_audit_invalid") from exc
        connection = sqlite3.connect(self.store.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT action,target,outcome,details_json FROM audit WHERE event_id=?",
                (audit_event_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise HouseholdPolicyHistoryError("household_policy_history_audit_missing")
        try:
            details = json.loads(row["details_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise HouseholdPolicyHistoryError("household_policy_history_audit_invalid") from exc
        if (
            row["action"] != "household.policy.history.record"
            or row["target"] != value.get("resource_key")
            or row["outcome"] != "recorded"
            or details.get("generation") != value.get("generation")
            or details.get("bundle_id") != value.get("bundle_id")
            or details.get("evidence_sha256") != value.get("evidence_sha256")
            or details.get("provider_execution_authorized") is not False
            or details.get("infrastructure_mutation_authorized") is not False
        ):
            raise HouseholdPolicyHistoryError("household_policy_history_audit_mismatch")

    def archive(self, record: dict[str, object]) -> dict[str, object]:
        """Persist a generation-addressed copy once and bind it to keyed Audit evidence."""

        core = self._history_core(record)
        resource_key = core["resource_key"]
        generation = core["generation"]
        assert isinstance(resource_key, str)
        assert isinstance(generation, int)
        key = _history_key(resource_key, generation)
        evidence_sha256 = self._evidence_hash(core)
        with self._lock:
            existing = self.store.get_meta(key)
            if existing is not None:
                validated = self._validate_history(existing, resource_key=resource_key, generation=generation)
                if validated.get("evidence_sha256") != evidence_sha256:
                    raise HouseholdPolicyHistoryError("household_policy_history_conflict")
                return validated

            audit_event_id = self.store.audit(
                actor="system:household-policy-history",
                action="household.policy.history.record",
                target=resource_key,
                outcome="recorded",
                correlation_id=f"policy-history-{generation}",
                details={
                    "generation": generation,
                    "bundle_id": core["bundle_id"],
                    "evidence_sha256": evidence_sha256,
                    "provider_execution_authorized": False,
                    "infrastructure_mutation_authorized": False,
                },
            )
            payload = {
                **core,
                "evidence_sha256": evidence_sha256,
                "audit_event_id": audit_event_id,
                "recorded_at": utc_now(),
                "provider_execution_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            }
            self.store.set_meta(key, payload)
            persisted = self.store.get_meta(key)
            return self._validate_history(persisted, resource_key=resource_key, generation=generation)

    def _validate_history(
        self,
        value: object,
        *,
        resource_key: str,
        generation: int,
    ) -> dict[str, object]:
        if not isinstance(value, dict) or value.get("schema") != POLICY_HISTORY_SCHEMA:
            raise HouseholdPolicyHistoryError("household_policy_history_invalid")
        if value.get("resource_key") != resource_key or value.get("generation") != generation:
            raise HouseholdPolicyHistoryError("household_policy_history_invalid")
        if (
            value.get("provider_execution_authorized") is not False
            or value.get("infrastructure_mutation_authorized") is not False
            or value.get("external_publication_authorized") is not False
        ):
            raise HouseholdPolicyHistoryError("household_policy_history_invalid")
        core = {
            "schema": POLICY_HISTORY_SCHEMA,
            "resource_key": value.get("resource_key"),
            "generation": value.get("generation"),
            "bundle_id": value.get("bundle_id"),
            "value": value.get("value"),
        }
        if value.get("evidence_sha256") != self._evidence_hash(core):
            raise HouseholdPolicyHistoryError("household_policy_history_evidence_mismatch")
        record = {
            "resource_key": resource_key,
            "generation": generation,
            "value": value.get("value"),
            "updated_at": value.get("recorded_at"),
        }
        _, bundle_id = HouseholdPolicyDesiredStateRepository.revision(record)
        if bundle_id != value.get("bundle_id"):
            raise HouseholdPolicyHistoryError("household_policy_history_evidence_mismatch")
        self._validate_history_audit(value)
        return value

    def read(self, *, resource_key: str, generation: int) -> dict[str, object]:
        if not isinstance(resource_key, str) or not resource_key:
            raise HouseholdPolicyHistoryError("invalid_household_policy_resource_key")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise HouseholdPolicyHistoryError("invalid_household_policy_history_generation")
        value = self.store.get_meta(_history_key(resource_key, generation))
        if value is None:
            raise HouseholdPolicyHistoryError("household_policy_history_not_found")
        return self._validate_history(value, resource_key=resource_key, generation=generation)

    def materialize(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        """Wrap exact apply so every observed revision is archived without changing its receipt contract."""

        if request.get("schema") != POLICY_APPLY_REQUEST_SCHEMA:
            raise HouseholdPolicyDesiredStateError("invalid_household_policy_apply_request")
        key = _proposal_key(request.get("proposal_id"))
        envelope = self.store.get_meta(key)
        if not isinstance(envelope, dict) or envelope.get("schema") != POLICY_PROPOSAL_STATE_SCHEMA:
            raise HouseholdPolicyDesiredStateError("household_policy_proposal_state_invalid")
        raw_proposal = envelope.get("proposal")
        bundle = raw_proposal.get("bundle") if isinstance(raw_proposal, dict) else None
        resource_key = bundle.get("desired_state_resource_key") if isinstance(bundle, dict) else None
        if not isinstance(resource_key, str):
            raise HouseholdPolicyDesiredStateError("household_policy_proposal_state_invalid")

        with self._lock:
            before = self.repository.read(resource_key)
            if before is not None:
                self.archive(before)
            receipt = self.desired_state.apply(
                actor=actor,
                request=request,
                correlation_id=correlation_id,
            )
            after = self.repository.read(resource_key)
            if after is None:
                raise HouseholdPolicyHistoryError("household_policy_desired_state_missing_after_apply")
            self.archive(after)
            return receipt

    def _authorized_actor(self, actor: str, resource_key: str) -> None:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyHistoryError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdPolicyHistoryError(getattr(exc, "code", "household_state_invalid")) from exc
        actor_member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if actor_member_id is None:
            raise HouseholdPolicyHistoryError("household_actor_not_bound")
        try:
            actor_policy = effective_policy(snapshot.household, actor_member_id)
        except Exception as exc:
            raise HouseholdPolicyHistoryError(getattr(exc, "code", "household_policy_rollback_not_authorized")) from exc
        if not actor_policy.administration_allowed:
            raise HouseholdPolicyHistoryError("household_policy_rollback_not_authorized")
        if not resource_key.startswith(f"household-policy:{snapshot.household_id}:"):
            raise HouseholdPolicyHistoryError("household_policy_rollback_resource_mismatch")

    @staticmethod
    def _validate_rollback_request(request: dict[str, Any]) -> None:
        required = {
            "schema",
            "resource_key",
            "expected_generation",
            "expected_bundle_id",
            "target_generation",
            "confirmed",
        }
        if set(request) != required or request.get("schema") != POLICY_ROLLBACK_REQUEST_SCHEMA:
            raise HouseholdPolicyHistoryError("invalid_household_policy_rollback_request")
        if request.get("confirmed") is not True:
            raise HouseholdPolicyHistoryError("invalid_household_policy_rollback_request")
        resource_key = request.get("resource_key")
        expected_generation = request.get("expected_generation")
        expected_bundle_id = request.get("expected_bundle_id")
        target_generation = request.get("target_generation")
        if not isinstance(resource_key, str) or not resource_key:
            raise HouseholdPolicyHistoryError("invalid_household_policy_rollback_request")
        if (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation < 1
            or not isinstance(expected_bundle_id, str)
            or not expected_bundle_id
            or isinstance(target_generation, bool)
            or not isinstance(target_generation, int)
            or target_generation < 1
            or target_generation >= expected_generation
        ):
            raise HouseholdPolicyHistoryError("invalid_household_policy_rollback_request")

    def _current_record(self, resource_key: str) -> dict[str, object]:
        current = self.repository.read(resource_key)
        if current is None:
            raise HouseholdPolicyHistoryError("household_policy_desired_state_missing")
        return current

    @staticmethod
    def _rollback_receipt(
        *,
        rollback_id: str,
        resource_key: str,
        target_generation: int,
        target_bundle_id: str,
        result: dict[str, object],
        changed: bool,
        audit_event_id: str,
        recovered: bool,
    ) -> dict[str, object]:
        generation, bundle_id = HouseholdPolicyDesiredStateRepository.revision(result)
        return {
            "schema": POLICY_ROLLBACK_RECEIPT_SCHEMA,
            "rollback_id": rollback_id,
            "resource_key": resource_key,
            "target_history_generation": target_generation,
            "target_history_bundle_id": target_bundle_id,
            "generation": generation,
            "bundle_id": bundle_id,
            "changed": changed,
            "recovered": recovered,
            "outcome": "rolled-back" if changed else "already-current",
            "audit_event_id": audit_event_id,
            "desired_state_materialized": True,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    def rollback(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        """Restore a historical bundle as a new monotonic Desired State generation."""

        self._validate_rollback_request(request)
        resource_key = request["resource_key"]
        expected_generation = request["expected_generation"]
        expected_bundle_id = request["expected_bundle_id"]
        target_generation = request["target_generation"]
        assert isinstance(resource_key, str)
        assert isinstance(expected_generation, int)
        assert isinstance(expected_bundle_id, str)
        assert isinstance(target_generation, int)
        self._authorized_actor(actor, resource_key)
        target_history = self.read(resource_key=resource_key, generation=target_generation)
        target_bundle_id = target_history.get("bundle_id")
        target_value = target_history.get("value")
        if not isinstance(target_bundle_id, str) or not isinstance(target_value, dict):
            raise HouseholdPolicyHistoryError("household_policy_history_invalid")

        rollback_id = _rollback_id(actor, request)
        rollback_key = POLICY_ROLLBACK_KEY_PREFIX + rollback_id

        with self._lock:
            existing = self.store.get_meta(rollback_key)
            if isinstance(existing, dict) and existing.get("schema") == POLICY_ROLLBACK_STATE_SCHEMA:
                if existing.get("request") != request or existing.get("target_history") != target_history:
                    raise HouseholdPolicyHistoryError("household_policy_rollback_state_invalid")
                status = existing.get("status")
                if status == "applied":
                    receipt = existing.get("receipt")
                    if not isinstance(receipt, dict):
                        raise HouseholdPolicyHistoryError("household_policy_rollback_state_invalid")
                    current = self._current_record(resource_key)
                    generation, bundle_id = HouseholdPolicyDesiredStateRepository.revision(current)
                    if generation != receipt.get("generation") or bundle_id != receipt.get("bundle_id"):
                        raise HouseholdPolicyHistoryError("household_policy_rollback_evidence_mismatch")
                    replay = dict(receipt)
                    replay["outcome"] = "already-rolled-back"
                    return replay
                if status == "invalidated":
                    raise HouseholdPolicyHistoryError("household_policy_rollback_invalidated")
                if status != "applying":
                    raise HouseholdPolicyHistoryError("household_policy_rollback_state_invalid")

                current = self._current_record(resource_key)
                current_generation, current_bundle_id = HouseholdPolicyDesiredStateRepository.revision(current)
                if (
                    current_generation == expected_generation + 1
                    and current_bundle_id == target_bundle_id
                    and current.get("value") == target_value
                ):
                    history = self.archive(current)
                    audit_event_id = self.store.audit(
                        actor=actor,
                        action="household.policy.desired-state.rollback.recover",
                        target=resource_key,
                        outcome="finalized-existing-write",
                        correlation_id=correlation_id,
                        details={
                            "rollback_id": rollback_id,
                            "generation": current_generation,
                            "bundle_id": current_bundle_id,
                            "history_evidence_sha256": history["evidence_sha256"],
                            "provider_execution_authorized": False,
                            "infrastructure_mutation_authorized": False,
                        },
                    )
                    receipt = self._rollback_receipt(
                        rollback_id=rollback_id,
                        resource_key=resource_key,
                        target_generation=target_generation,
                        target_bundle_id=target_bundle_id,
                        result=current,
                        changed=True,
                        audit_event_id=audit_event_id,
                        recovered=True,
                    )
                    self.store.set_meta(
                        rollback_key,
                        {
                            "schema": POLICY_ROLLBACK_STATE_SCHEMA,
                            "status": "applied",
                            "request": request,
                            "target_history": target_history,
                            "receipt": receipt,
                        },
                    )
                    return receipt
                if current_generation != expected_generation or current_bundle_id != expected_bundle_id:
                    self.store.set_meta(
                        rollback_key,
                        {
                            "schema": POLICY_ROLLBACK_STATE_SCHEMA,
                            "status": "invalidated",
                            "request": request,
                            "target_history": target_history,
                            "receipt": None,
                        },
                    )
                    raise HouseholdPolicyHistoryError("household_policy_rollback_precondition_failed")
            elif existing is not None:
                raise HouseholdPolicyHistoryError("household_policy_rollback_state_invalid")
            else:
                current = self._current_record(resource_key)
                current_generation, current_bundle_id = HouseholdPolicyDesiredStateRepository.revision(current)
                if current_generation != expected_generation or current_bundle_id != expected_bundle_id:
                    raise HouseholdPolicyHistoryError("household_policy_rollback_precondition_failed")
                self.archive(current)
                self.store.set_meta(
                    rollback_key,
                    {
                        "schema": POLICY_ROLLBACK_STATE_SCHEMA,
                        "status": "applying",
                        "request": request,
                        "target_history": target_history,
                        "receipt": None,
                    },
                )

            current = self._current_record(resource_key)
            current_generation, current_bundle_id = HouseholdPolicyDesiredStateRepository.revision(current)
            if current_generation != expected_generation or current_bundle_id != expected_bundle_id:
                raise HouseholdPolicyHistoryError("household_policy_rollback_precondition_failed")

            begin_audit_id = self.store.audit(
                actor=actor,
                action="household.policy.desired-state.rollback.begin",
                target=resource_key,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "rollback_id": rollback_id,
                    "expected_generation": expected_generation,
                    "expected_bundle_id": expected_bundle_id,
                    "target_history_generation": target_generation,
                    "target_history_bundle_id": target_bundle_id,
                    "provider_execution_authorized": False,
                    "infrastructure_mutation_authorized": False,
                },
            )

            changed = current.get("value") != target_value
            if changed:
                connection = sqlite3.connect(self.store.path, timeout=5)
                connection.row_factory = sqlite3.Row
                try:
                    connection.execute("PRAGMA foreign_keys=ON")
                    connection.execute("BEGIN IMMEDIATE")
                    row = connection.execute(
                        "SELECT resource_key,generation,value_json,updated_at FROM desired_state WHERE resource_key=?",
                        (resource_key,),
                    ).fetchone()
                    locked_current = HouseholdPolicyDesiredStateRepository._decode(row)
                    if locked_current is None:
                        raise HouseholdPolicyHistoryError("household_policy_desired_state_missing")
                    locked_generation, locked_bundle_id = HouseholdPolicyDesiredStateRepository.revision(locked_current)
                    if locked_generation != expected_generation or locked_bundle_id != expected_bundle_id:
                        raise HouseholdPolicyHistoryError("household_policy_rollback_precondition_failed")
                    next_generation = expected_generation + 1
                    now = utc_now()
                    cursor = connection.execute(
                        """UPDATE desired_state SET generation=?,value_json=?,updated_at=?
                        WHERE resource_key=? AND generation=?""",
                        (
                            next_generation,
                            canonical_json(target_value),
                            now,
                            resource_key,
                            expected_generation,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise HouseholdPolicyHistoryError("household_policy_rollback_precondition_failed")
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
                result = HouseholdPolicyDesiredStateRepository._decode(row)
                if result is None:
                    raise HouseholdPolicyHistoryError("household_policy_rollback_write_failed")
            else:
                result = current

            history = self.archive(result)
            generation, bundle_id = HouseholdPolicyDesiredStateRepository.revision(result)
            complete_audit_id = self.store.audit(
                actor=actor,
                action="household.policy.desired-state.rollback.complete",
                target=resource_key,
                outcome="succeeded" if changed else "already-current",
                correlation_id=correlation_id,
                details={
                    "rollback_id": rollback_id,
                    "begin_audit_event_id": begin_audit_id,
                    "generation": generation,
                    "bundle_id": bundle_id,
                    "target_history_generation": target_generation,
                    "history_evidence_sha256": history["evidence_sha256"],
                    "provider_execution_authorized": False,
                    "infrastructure_mutation_authorized": False,
                },
            )
            receipt = self._rollback_receipt(
                rollback_id=rollback_id,
                resource_key=resource_key,
                target_generation=target_generation,
                target_bundle_id=target_bundle_id,
                result=result,
                changed=changed,
                audit_event_id=complete_audit_id,
                recovered=False,
            )
            self.store.set_meta(
                rollback_key,
                {
                    "schema": POLICY_ROLLBACK_STATE_SCHEMA,
                    "status": "applied",
                    "request": request,
                    "target_history": target_history,
                    "receipt": receipt,
                },
            )
            return receipt
