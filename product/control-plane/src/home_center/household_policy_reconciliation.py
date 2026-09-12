"""Typed, fail-closed reconciliation boundary for Home Center 0.59 policy Desired State.

This module is deliberately side-effect free.  It validates that an adapter observation is
cryptographically bound by hashes and identifiers to the exact protected Desired State.
A successful decision is only a *candidate* for a later durable writer.  It never flips
``enforcement_verified`` and never authorizes infrastructure or external publication.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

DESIRED_STATE_SCHEMA = "home-center.household-policy-desired-state.v1"
REQUEST_SCHEMA = "home-center.household-policy-reconciliation-request.v1"
OBSERVATION_SCHEMA = "home-center.household-policy-reconciliation-observation.v1"
DECISION_SCHEMA = "home-center.household-policy-reconciliation-decision.v1"

SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
PLAN_ID = re.compile(r"^hpcp-[0-9a-f]{24}$")


class HouseholdPolicyReconciliationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise HouseholdPolicyReconciliationError(code)
    return value


def _id(value: object, code: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise HouseholdPolicyReconciliationError(code)
    return value


def _generation(value: object, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise HouseholdPolicyReconciliationError(code)
    return value


def _validate_desired(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HouseholdPolicyReconciliationError("household_policy_desired_state_invalid")
    required = {
        "schema",
        "household_id",
        "member_id",
        "generation",
        "plan_id",
        "policy",
        "policy_sha256",
        "reason",
        "enforcement_verified",
        "reconciliation_required",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if set(value) != required or value.get("schema") != DESIRED_STATE_SCHEMA:
        raise HouseholdPolicyReconciliationError("household_policy_desired_state_invalid")
    _id(value.get("household_id"), "household_policy_desired_state_invalid")
    _id(value.get("member_id"), "household_policy_desired_state_invalid")
    _generation(value.get("generation"), "household_policy_desired_state_invalid")
    plan_id = value.get("plan_id")
    if not isinstance(plan_id, str) or PLAN_ID.fullmatch(plan_id) is None:
        raise HouseholdPolicyReconciliationError("household_policy_desired_state_invalid")
    policy = value.get("policy")
    if not isinstance(policy, dict) or _digest(policy) != _sha(
        value.get("policy_sha256"), "household_policy_desired_state_invalid"
    ):
        raise HouseholdPolicyReconciliationError("household_policy_desired_state_digest_mismatch")
    if (
        value.get("enforcement_verified") is not False
        or value.get("reconciliation_required") is not True
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyReconciliationError("household_policy_desired_state_not_reconcilable")
    return dict(value)


def build_reconciliation_request(
    *,
    desired_state: dict[str, Any],
    adapter_id: str,
    adapter_revision: str,
    target_id: str,
    correlation_id: str,
) -> dict[str, object]:
    desired = _validate_desired(desired_state)
    request = {
        "schema": REQUEST_SCHEMA,
        "household_id": desired["household_id"],
        "member_id": desired["member_id"],
        "desired_generation": desired["generation"],
        "plan_id": desired["plan_id"],
        "policy_sha256": desired["policy_sha256"],
        "adapter_id": _id(adapter_id, "household_policy_reconciliation_adapter_invalid"),
        "adapter_revision": _id(
            adapter_revision, "household_policy_reconciliation_adapter_revision_invalid"
        ),
        "target_id": _id(target_id, "household_policy_reconciliation_target_invalid"),
        "correlation_id": _id(
            correlation_id, "household_policy_reconciliation_correlation_invalid"
        ),
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    request["request_sha256"] = _digest(request)
    return request


def evaluate_reconciliation(
    *,
    desired_state: dict[str, Any],
    request: dict[str, Any],
    observation: dict[str, Any],
) -> dict[str, object]:
    desired = _validate_desired(desired_state)
    request_required = {
        "schema",
        "household_id",
        "member_id",
        "desired_generation",
        "plan_id",
        "policy_sha256",
        "adapter_id",
        "adapter_revision",
        "target_id",
        "correlation_id",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
        "request_sha256",
    }
    if not isinstance(request, dict) or set(request) != request_required:
        raise HouseholdPolicyReconciliationError("household_policy_reconciliation_request_invalid")
    request_hash = request.get("request_sha256")
    unsigned_request = dict(request)
    unsigned_request.pop("request_sha256", None)
    if (
        request.get("schema") != REQUEST_SCHEMA
        or request.get("infrastructure_mutation_authorized") is not False
        or request.get("external_publication_authorized") is not False
        or _digest(unsigned_request)
        != _sha(request_hash, "household_policy_reconciliation_request_invalid")
    ):
        raise HouseholdPolicyReconciliationError("household_policy_reconciliation_request_invalid")

    binding = {
        "household_id": desired["household_id"],
        "member_id": desired["member_id"],
        "desired_generation": desired["generation"],
        "plan_id": desired["plan_id"],
        "policy_sha256": desired["policy_sha256"],
    }
    if any(request.get(key) != expected for key, expected in binding.items()):
        raise HouseholdPolicyReconciliationError("household_policy_reconciliation_request_stale")
    for key in ("adapter_id", "adapter_revision", "target_id", "correlation_id"):
        _id(request.get(key), "household_policy_reconciliation_request_invalid")

    observation_required = {
        "schema",
        "request_sha256",
        "adapter_id",
        "adapter_revision",
        "target_id",
        "household_id",
        "member_id",
        "desired_generation",
        "plan_id",
        "policy_sha256",
        "outcome",
        "actual_state_revision",
        "observed_policy_sha256",
        "evidence_sha256",
        "provider_receipt_id",
    }
    if not isinstance(observation, dict) or set(observation) != observation_required:
        raise HouseholdPolicyReconciliationError(
            "household_policy_reconciliation_observation_invalid"
        )
    if observation.get("schema") != OBSERVATION_SCHEMA:
        raise HouseholdPolicyReconciliationError(
            "household_policy_reconciliation_observation_invalid"
        )
    for key in (
        "request_sha256",
        "policy_sha256",
        "observed_policy_sha256",
        "evidence_sha256",
    ):
        _sha(observation.get(key), "household_policy_reconciliation_observation_invalid")
    for key in (
        "adapter_id",
        "adapter_revision",
        "target_id",
        "household_id",
        "member_id",
        "actual_state_revision",
    ):
        _id(observation.get(key), "household_policy_reconciliation_observation_invalid")
    _generation(
        observation.get("desired_generation"),
        "household_policy_reconciliation_observation_invalid",
    )
    provider_receipt_id = observation.get("provider_receipt_id")
    if provider_receipt_id is not None:
        _id(
            provider_receipt_id,
            "household_policy_reconciliation_observation_invalid",
        )
    outcome = observation.get("outcome")
    if outcome not in {"verified", "mismatch", "unavailable"}:
        raise HouseholdPolicyReconciliationError(
            "household_policy_reconciliation_observation_invalid"
        )

    exact_bindings = {
        "request_sha256": request["request_sha256"],
        "adapter_id": request["adapter_id"],
        "adapter_revision": request["adapter_revision"],
        "target_id": request["target_id"],
        "household_id": request["household_id"],
        "member_id": request["member_id"],
        "desired_generation": request["desired_generation"],
        "plan_id": request["plan_id"],
        "policy_sha256": request["policy_sha256"],
    }
    if any(observation.get(key) != expected for key, expected in exact_bindings.items()):
        raise HouseholdPolicyReconciliationError(
            "household_policy_reconciliation_observation_stale"
        )

    verified_candidate = (
        outcome == "verified"
        and observation["observed_policy_sha256"] == desired["policy_sha256"]
        and provider_receipt_id is not None
    )
    if outcome == "verified" and not verified_candidate:
        raise HouseholdPolicyReconciliationError(
            "household_policy_reconciliation_verified_evidence_incomplete"
        )

    status = "verified_candidate" if verified_candidate else outcome
    decision = {
        "schema": DECISION_SCHEMA,
        "status": status,
        "household_id": desired["household_id"],
        "member_id": desired["member_id"],
        "desired_generation": desired["generation"],
        "plan_id": desired["plan_id"],
        "policy_sha256": desired["policy_sha256"],
        "request_sha256": request["request_sha256"],
        "adapter_id": request["adapter_id"],
        "adapter_revision": request["adapter_revision"],
        "target_id": request["target_id"],
        "actual_state_revision": observation["actual_state_revision"],
        "observed_policy_sha256": observation["observed_policy_sha256"],
        "evidence_sha256": observation["evidence_sha256"],
        "provider_receipt_id": provider_receipt_id,
        "eligible_for_enforcement_verification": verified_candidate,
        "enforcement_verified": False,
        "reconciliation_required": True,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    decision["decision_id"] = "hcpr-" + _digest(decision)[:24]
    return decision
