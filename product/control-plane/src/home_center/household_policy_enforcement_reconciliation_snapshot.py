"""Crash-safe exact reconciliation snapshot for Home Center 0.59 policy enforcement.

This adapter wrapper persists the exact sanitized backend mutation request and the
qualified adapter identity before delegating the one permitted mutation attempt.
The snapshot is immutable for the plan and is deliberately sufficient for a later
read-only reconciliation even if protected Desired State subsequently changes.

Persisting the snapshot does not mean that the backend command ran or succeeded.
An ``invoking`` or ``in-doubt`` snapshot must therefore be treated as uncertain,
must never authorize automatic retry, and requires read-only reconciliation.
"""

from __future__ import annotations

import hashlib
import re
import threading
from typing import Any, Protocol

from .store import StateStore
from .util import canonical_json

SNAPSHOT_SCHEMA = "home-center.household-policy-enforcement-reconciliation-snapshot.v1"
BACKEND_REQUEST_SCHEMA = "home-center.household-policy-backend-apply-request.v1"
SNAPSHOT_KEY_PREFIX = "cozy.household.policy.enforcement-reconciliation."

IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
PLAN_ID = re.compile(r"^hpep-[0-9a-f]{24}$")
DESIRED_PLAN_ID = re.compile(r"^hpcp-[0-9a-f]{24}$")
POLICY_ID = re.compile(r"^hcpol-[0-9a-f]{24}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

REQUEST_KEYS = {
    "schema",
    "plan_id",
    "household_id",
    "member_id",
    "backend_id",
    "desired_generation",
    "desired_plan_id",
    "policy_id",
    "policy_sha256",
    "desired_state_sha256",
    "policy",
    "adapter_id",
    "adapter_version",
    "adapter_artifact_sha256",
    "qualification_evidence_sha256",
    "secret_values_present",
    "backend_mutation_authorized",
    "automatic_retry_authorized",
    "infrastructure_mutation_authorized",
    "external_publication_authorized",
}


class HouseholdPolicyEnforcementReconciliationSnapshotError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class QualifiedPolicyMutationAdapter(Protocol):
    policy_mutation_capable: bool
    policy_backend_qualified: bool
    adapter_id: str
    adapter_version: str
    adapter_artifact_sha256: str
    qualification_evidence_sha256: str

    def apply_policy(self, request: dict[str, object]) -> object: ...


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _snapshot_key(plan_id: object) -> str:
    if not isinstance(plan_id, str) or PLAN_ID.fullmatch(plan_id) is None:
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "invalid_household_policy_enforcement_plan_id"
        )
    return SNAPSHOT_KEY_PREFIX + plan_id


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(code)
    return value


def _sha(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(code)
    return value


def _adapter_metadata(backend_id: str, adapter: object) -> dict[str, str]:
    adapter_id = getattr(adapter, "adapter_id", None)
    adapter_version = getattr(adapter, "adapter_version", None)
    artifact_sha256 = getattr(adapter, "adapter_artifact_sha256", None)
    evidence_sha256 = getattr(adapter, "qualification_evidence_sha256", None)
    if (
        getattr(adapter, "policy_mutation_capable", None) is not True
        or getattr(adapter, "policy_backend_qualified", None) is not True
        or adapter_id != backend_id
        or not isinstance(adapter_version, str)
        or not adapter_version
        or len(adapter_version) > 128
        or not isinstance(artifact_sha256, str)
        or SHA256.fullmatch(artifact_sha256) is None
        or not isinstance(evidence_sha256, str)
        or SHA256.fullmatch(evidence_sha256) is None
        or not callable(getattr(adapter, "apply_policy", None))
    ):
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "invalid_household_policy_enforcement_snapshot_adapter_registration"
        )
    return {
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "adapter_artifact_sha256": artifact_sha256,
        "qualification_evidence_sha256": evidence_sha256,
    }


def _validated_request(
    request: object,
    *,
    backend_id: str,
    adapter_metadata: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(request, dict) or set(request) != REQUEST_KEYS:
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "household_policy_enforcement_snapshot_request_invalid"
        )
    value = dict(request)
    policy = value.get("policy")
    if (
        value.get("schema") != BACKEND_REQUEST_SCHEMA
        or not isinstance(value.get("plan_id"), str)
        or PLAN_ID.fullmatch(value["plan_id"]) is None
        or not isinstance(value.get("household_id"), str)
        or not value["household_id"]
        or len(value["household_id"]) > 128
        or not isinstance(value.get("member_id"), str)
        or not value["member_id"]
        or len(value["member_id"]) > 128
        or value.get("backend_id") != backend_id
        or isinstance(value.get("desired_generation"), bool)
        or not isinstance(value.get("desired_generation"), int)
        or value["desired_generation"] < 1
        or not isinstance(value.get("desired_plan_id"), str)
        or DESIRED_PLAN_ID.fullmatch(value["desired_plan_id"]) is None
        or not isinstance(value.get("policy_id"), str)
        or POLICY_ID.fullmatch(value["policy_id"]) is None
        or not isinstance(value.get("policy_sha256"), str)
        or SHA256.fullmatch(value["policy_sha256"]) is None
        or not isinstance(value.get("desired_state_sha256"), str)
        or SHA256.fullmatch(value["desired_state_sha256"]) is None
        or not isinstance(policy, dict)
        or _digest(policy) != value["policy_sha256"]
        or value.get("adapter_id") != adapter_metadata["adapter_id"]
        or value.get("adapter_version") != adapter_metadata["adapter_version"]
        or value.get("adapter_artifact_sha256")
        != adapter_metadata["adapter_artifact_sha256"]
        or value.get("qualification_evidence_sha256")
        != adapter_metadata["qualification_evidence_sha256"]
        or value.get("secret_values_present") is not False
        or value.get("backend_mutation_authorized") is not True
        or value.get("automatic_retry_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "household_policy_enforcement_snapshot_request_invalid"
        )
    return value


def _snapshot(
    *,
    request: dict[str, Any],
    request_sha256: str,
    adapter_metadata: dict[str, str],
    state: str,
    backend_outcome: str,
    backend_command_accepted: bool | None,
) -> dict[str, object]:
    return {
        "schema": SNAPSHOT_SCHEMA,
        "state": state,
        "plan_id": request["plan_id"],
        "household_id": request["household_id"],
        "member_id": request["member_id"],
        "backend_id": request["backend_id"],
        "desired_generation": request["desired_generation"],
        "desired_plan_id": request["desired_plan_id"],
        "policy_id": request["policy_id"],
        "policy_sha256": request["policy_sha256"],
        "desired_state_sha256": request["desired_state_sha256"],
        "adapter_id": adapter_metadata["adapter_id"],
        "adapter_version": adapter_metadata["adapter_version"],
        "adapter_artifact_sha256": adapter_metadata["adapter_artifact_sha256"],
        "qualification_evidence_sha256": adapter_metadata["qualification_evidence_sha256"],
        "backend_request_sha256": request_sha256,
        "backend_request": request,
        "backend_outcome": backend_outcome,
        "backend_command_accepted": backend_command_accepted,
        "enforcement_verified": False,
        "reconciliation_required": True,
        "automatic_retry_authorized": False,
        "backend_reinvocation_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _validate_snapshot(value: object, plan_id: str) -> dict[str, object]:
    required = {
        "schema",
        "state",
        "plan_id",
        "household_id",
        "member_id",
        "backend_id",
        "desired_generation",
        "desired_plan_id",
        "policy_id",
        "policy_sha256",
        "desired_state_sha256",
        "adapter_id",
        "adapter_version",
        "adapter_artifact_sha256",
        "qualification_evidence_sha256",
        "backend_request_sha256",
        "backend_request",
        "backend_outcome",
        "backend_command_accepted",
        "enforcement_verified",
        "reconciliation_required",
        "automatic_retry_authorized",
        "backend_reinvocation_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "household_policy_enforcement_snapshot_invalid"
        )
    state = value.get("state")
    outcome = value.get("backend_outcome")
    accepted = value.get("backend_command_accepted")
    if (
        value.get("schema") != SNAPSHOT_SCHEMA
        or value.get("plan_id") != plan_id
        or state not in {"invoking", "completed", "in-doubt"}
        or outcome not in {"pending", "accepted", "rejected", "ambiguous"}
        or value.get("enforcement_verified") is not False
        or value.get("reconciliation_required") is not True
        or value.get("automatic_retry_authorized") is not False
        or value.get("backend_reinvocation_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "household_policy_enforcement_snapshot_invalid"
        )
    if state == "invoking" and (outcome != "pending" or accepted is not None):
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "household_policy_enforcement_snapshot_invalid"
        )
    if state == "in-doubt" and (outcome != "ambiguous" or accepted is not None):
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "household_policy_enforcement_snapshot_invalid"
        )
    if state == "completed":
        if outcome not in {"accepted", "rejected"} or not isinstance(accepted, bool):
            raise HouseholdPolicyEnforcementReconciliationSnapshotError(
                "household_policy_enforcement_snapshot_invalid"
            )
        if accepted != (outcome == "accepted"):
            raise HouseholdPolicyEnforcementReconciliationSnapshotError(
                "household_policy_enforcement_snapshot_invalid"
            )

    backend_id = _identifier(
        value.get("backend_id"), "household_policy_enforcement_snapshot_invalid"
    )
    adapter_metadata = {
        "adapter_id": _identifier(
            value.get("adapter_id"), "household_policy_enforcement_snapshot_invalid"
        ),
        "adapter_version": value.get("adapter_version"),
        "adapter_artifact_sha256": _sha(
            value.get("adapter_artifact_sha256"),
            "household_policy_enforcement_snapshot_invalid",
        ),
        "qualification_evidence_sha256": _sha(
            value.get("qualification_evidence_sha256"),
            "household_policy_enforcement_snapshot_invalid",
        ),
    }
    if (
        adapter_metadata["adapter_id"] != backend_id
        or not isinstance(adapter_metadata["adapter_version"], str)
        or not adapter_metadata["adapter_version"]
        or len(adapter_metadata["adapter_version"]) > 128
    ):
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "household_policy_enforcement_snapshot_invalid"
        )
    request = _validated_request(
        value.get("backend_request"),
        backend_id=backend_id,
        adapter_metadata=adapter_metadata,  # type: ignore[arg-type]
    )
    request_sha256 = _sha(
        value.get("backend_request_sha256"),
        "household_policy_enforcement_snapshot_invalid",
    )
    if request_sha256 != _digest(request):
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "household_policy_enforcement_snapshot_invalid"
        )
    if (
        request["plan_id"] != value["plan_id"]
        or request["household_id"] != value["household_id"]
        or request["member_id"] != value["member_id"]
        or request["desired_generation"] != value["desired_generation"]
        or request["desired_plan_id"] != value["desired_plan_id"]
        or request["policy_id"] != value["policy_id"]
        or request["policy_sha256"] != value["policy_sha256"]
        or request["desired_state_sha256"] != value["desired_state_sha256"]
    ):
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "household_policy_enforcement_snapshot_invalid"
        )
    return dict(value)


def load_enforcement_reconciliation_snapshot(
    store: StateStore,
    plan_id: str,
) -> dict[str, object]:
    key = _snapshot_key(plan_id)
    value = store.get_meta(key)
    if value is None:
        raise HouseholdPolicyEnforcementReconciliationSnapshotError(
            "household_policy_enforcement_snapshot_not_found"
        )
    return _validate_snapshot(value, plan_id)


class ReconciliationSnapshotPolicyAdapter:
    """Wrap exactly one qualified policy mutation adapter without widening authority."""

    policy_mutation_capable = True
    policy_backend_qualified = True

    def __init__(
        self,
        store: StateStore,
        backend_id: str,
        delegate: QualifiedPolicyMutationAdapter,
    ) -> None:
        self.store = store
        self._lock = threading.RLock()
        self._delegate = delegate
        self._metadata = _adapter_metadata(
            _identifier(
                backend_id,
                "invalid_household_policy_enforcement_snapshot_adapter_registration",
            ),
            delegate,
        )
        self.adapter_id = self._metadata["adapter_id"]
        self.adapter_version = self._metadata["adapter_version"]
        self.adapter_artifact_sha256 = self._metadata["adapter_artifact_sha256"]
        self.qualification_evidence_sha256 = self._metadata[
            "qualification_evidence_sha256"
        ]

    def apply_policy(self, request: dict[str, object]) -> object:
        with self._lock:
            validated = _validated_request(
                request,
                backend_id=self.adapter_id,
                adapter_metadata=self._metadata,
            )
            plan_id = str(validated["plan_id"])
            key = _snapshot_key(plan_id)
            if self.store.get_meta(key) is not None:
                raise HouseholdPolicyEnforcementReconciliationSnapshotError(
                    "household_policy_enforcement_backend_reinvocation_forbidden"
                )

            request_sha256 = _digest(validated)
            invoking = _snapshot(
                request=validated,
                request_sha256=request_sha256,
                adapter_metadata=self._metadata,
                state="invoking",
                backend_outcome="pending",
                backend_command_accepted=None,
            )
            self.store.set_meta(key, invoking)
            if self.store.get_meta(key) != invoking:
                raise HouseholdPolicyEnforcementReconciliationSnapshotError(
                    "household_policy_enforcement_snapshot_persist_readback_failed"
                )

            try:
                raw_result = self._delegate.apply_policy(dict(validated))
            except Exception:
                indoubt = _snapshot(
                    request=validated,
                    request_sha256=request_sha256,
                    adapter_metadata=self._metadata,
                    state="in-doubt",
                    backend_outcome="ambiguous",
                    backend_command_accepted=None,
                )
                self.store.set_meta(key, indoubt)
                if self.store.get_meta(key) != indoubt:
                    raise HouseholdPolicyEnforcementReconciliationSnapshotError(
                        "household_policy_enforcement_snapshot_persist_readback_failed"
                    )
                raise

            accepted = isinstance(raw_result, dict) and raw_result.get("accepted") is True
            completed = _snapshot(
                request=validated,
                request_sha256=request_sha256,
                adapter_metadata=self._metadata,
                state="completed",
                backend_outcome="accepted" if accepted else "rejected",
                backend_command_accepted=accepted,
            )
            self.store.set_meta(key, completed)
            if self.store.get_meta(key) != completed:
                raise HouseholdPolicyEnforcementReconciliationSnapshotError(
                    "household_policy_enforcement_snapshot_persist_readback_failed"
                )
            return raw_result
