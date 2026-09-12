"""Read-only effective policy status projection for Home Center 0.59.

The projection is deliberately non-authoritative for mutation.  It combines the
current Household role policy, the protected Policy Composer Desired State and, when
present, the exact verified-state projection produced from durable reconciliation
evidence.  It never invokes a backend and never turns stale verification material
into a successful state.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .home_services import HomeServiceCatalogError
from .household import HouseholdRole, effective_policy
from .household_policy_reconciliation import EVIDENCE_SCHEMA, HouseholdPolicyReconciliationError, request_from_dict
from .household_policy_reconciliation_runtime import COMPLETION_SCHEMA, STATE_KEY_PREFIX, STATE_SCHEMA
from .household_policy_runtime import DESIRED_KEY_PREFIX, DESIRED_STATE_SCHEMA
from .household_policy_verification_state import VERIFIED_KEY_PREFIX, VERIFIED_STATE_SCHEMA
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore
from .util import canonical_json

STATUS_SCHEMA = "home-center.household-policy-effective-state.v1"
COMPOSED_POLICY_SCHEMA = "home-center.household-composed-policy.v1"
POLICY_ID = re.compile(r"^(?:hpol|hcpol)-[0-9a-f]{24}$")
PLAN_ID = re.compile(r"^hpcp-[0-9a-f]{24}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_ID = re.compile(r"^hpev-[0-9a-f]{24}$")
REQUEST_ID = re.compile(r"^hprq-[0-9a-f]{24}$")
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")


class HouseholdPolicyEffectiveStateError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _explanation(policy: dict[str, object]) -> str:
    internet = {
        "full": "интернет без дополнительного семейного фильтра",
        "filtered": "интернет с семейной фильтрацией",
        "guest": "гостевой режим интернета",
    }.get(policy["internet_policy"])
    if internet is None:
        raise HouseholdPolicyEffectiveStateError("household_policy_effective_state_policy_invalid")
    parts = [internet]
    parts.append("VPN разрешён" if policy["vpn_allowed"] else "VPN запрещён")
    if policy["managed_device_required"]:
        parts.append("нужно управляемое устройство")
    if policy["home_files_allowed"]:
        parts.append("домашние файлы доступны")
    if policy["smart_home_control_allowed"]:
        parts.append("управление умным домом разрешено")
    if policy["administration_allowed"]:
        parts.append("администрирование разрешено")
    parts.append("внешняя публикация запрещена")
    return "; ".join(parts) + "."


def _technical_policy(
    value: object,
    *,
    household_id: str,
    member_id: str,
    composed: bool,
) -> tuple[dict[str, object], str]:
    if not isinstance(value, dict):
        raise HouseholdPolicyEffectiveStateError("household_policy_effective_state_policy_invalid")

    common = {
        "policy_id",
        "household_id",
        "member_id",
        "role",
        "internet_policy",
        "vpn_allowed",
        "managed_device_required",
        "home_files_allowed",
        "smart_home_control_allowed",
        "administration_allowed",
        "external_publication_allowed",
    }
    if composed:
        expected = common | {
            "schema",
            "base_policy_id",
            "bundle_id",
            "enforcement_verified",
            "production_mutation_enabled",
            "explanation_ru",
        }
        if (
            set(value) != expected
            or value.get("schema") != COMPOSED_POLICY_SCHEMA
            or value.get("enforcement_verified") is not False
            or value.get("production_mutation_enabled") is not False
            or not isinstance(value.get("base_policy_id"), str)
            or not value["base_policy_id"]
            or not isinstance(value.get("bundle_id"), str)
            or not value["bundle_id"]
            or not isinstance(value.get("explanation_ru"), str)
            or not value["explanation_ru"]
        ):
            raise HouseholdPolicyEffectiveStateError("household_policy_effective_state_policy_invalid")
        explanation = value["explanation_ru"]
    else:
        expected = common | {"schema", "production_mutation_enabled"}
        if (
            set(value) != expected
            or value.get("schema") != "home-center.household-effective-policy.v1"
            or value.get("production_mutation_enabled") is not False
        ):
            raise HouseholdPolicyEffectiveStateError("household_policy_effective_state_policy_invalid")
        explanation = ""

    if (
        value.get("household_id") != household_id
        or value.get("member_id") != member_id
        or not isinstance(value.get("policy_id"), str)
        or POLICY_ID.fullmatch(value["policy_id"]) is None
        or value.get("role") not in {"parent", "child", "guest"}
        or value.get("internet_policy") not in {"full", "filtered", "guest"}
        or type(value.get("vpn_allowed")) is not bool
        or type(value.get("managed_device_required")) is not bool
        or type(value.get("home_files_allowed")) is not bool
        or type(value.get("smart_home_control_allowed")) is not bool
        or type(value.get("administration_allowed")) is not bool
        or value.get("external_publication_allowed") is not False
    ):
        raise HouseholdPolicyEffectiveStateError("household_policy_effective_state_policy_invalid")

    technical = {key: value[key] for key in (
        "policy_id",
        "role",
        "internet_policy",
        "vpn_allowed",
        "managed_device_required",
        "home_files_allowed",
        "smart_home_control_allowed",
        "administration_allowed",
        "external_publication_allowed",
    )}
    return technical, explanation or _explanation(technical)


def _desired(value: object, *, household_id: str, member_id: str) -> dict[str, Any] | None:
    if value is None:
        return None
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
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != DESIRED_STATE_SCHEMA
        or value.get("household_id") != household_id
        or value.get("member_id") != member_id
        or isinstance(value.get("generation"), bool)
        or not isinstance(value.get("generation"), int)
        or value["generation"] < 1
        or not isinstance(value.get("plan_id"), str)
        or PLAN_ID.fullmatch(value["plan_id"]) is None
        or not isinstance(value.get("policy_sha256"), str)
        or SHA256.fullmatch(value["policy_sha256"]) is None
        or not isinstance(value.get("reason"), str)
        or not value["reason"].strip()
        or len(value["reason"]) > 512
        or value.get("enforcement_verified") is not False
        or value.get("reconciliation_required") is not True
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyEffectiveStateError("household_policy_effective_state_desired_invalid")
    technical, _ = _technical_policy(
        value.get("policy"),
        household_id=household_id,
        member_id=member_id,
        composed=True,
    )
    if (
        _digest(value["policy"]) != value["policy_sha256"]
        or technical["policy_id"] != value["policy"]["policy_id"]
    ):
        raise HouseholdPolicyEffectiveStateError("household_policy_effective_state_desired_invalid")
    return dict(value)


def _verified(
    value: object,
    *,
    household_id: str,
    member_id: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    required = {
        "schema",
        "household_id",
        "member_id",
        "desired_generation",
        "desired_plan_id",
        "policy_id",
        "policy_sha256",
        "source_desired_state_sha256",
        "request_id",
        "backend_id",
        "evidence_id",
        "evidence_sha256",
        "observed_at",
        "enforcement_verified",
        "reconciliation_required",
        "backend_mutation_performed",
        "infrastructure_mutation_performed",
        "external_publication_performed",
        "desired_state",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != VERIFIED_STATE_SCHEMA
        or value.get("household_id") != household_id
        or value.get("member_id") != member_id
        or isinstance(value.get("desired_generation"), bool)
        or not isinstance(value.get("desired_generation"), int)
        or value["desired_generation"] < 1
        or not isinstance(value.get("desired_plan_id"), str)
        or PLAN_ID.fullmatch(value["desired_plan_id"]) is None
        or not isinstance(value.get("policy_id"), str)
        or POLICY_ID.fullmatch(value["policy_id"]) is None
        or not isinstance(value.get("policy_sha256"), str)
        or SHA256.fullmatch(value["policy_sha256"]) is None
        or not isinstance(value.get("source_desired_state_sha256"), str)
        or SHA256.fullmatch(value["source_desired_state_sha256"]) is None
        or not isinstance(value.get("request_id"), str)
        or REQUEST_ID.fullmatch(value["request_id"]) is None
        or not isinstance(value.get("backend_id"), str)
        or IDENTIFIER.fullmatch(value["backend_id"]) is None
        or not isinstance(value.get("evidence_id"), str)
        or EVIDENCE_ID.fullmatch(value["evidence_id"]) is None
        or not isinstance(value.get("evidence_sha256"), str)
        or SHA256.fullmatch(value["evidence_sha256"]) is None
        or not isinstance(value.get("observed_at"), str)
        or not value["observed_at"].endswith("Z")
        or value.get("enforcement_verified") is not True
        or value.get("reconciliation_required") is not False
        or value.get("backend_mutation_performed") is not False
        or value.get("infrastructure_mutation_performed") is not False
        or value.get("external_publication_performed") is not False
    ):
        raise HouseholdPolicyEffectiveStateError("household_policy_effective_state_verified_invalid")
    embedded = _desired(value.get("desired_state"), household_id=household_id, member_id=member_id)
    assert embedded is not None
    if (
        embedded["generation"] != value["desired_generation"]
        or embedded["plan_id"] != value["desired_plan_id"]
        or embedded["policy"]["policy_id"] != value["policy_id"]
        or embedded["policy_sha256"] != value["policy_sha256"]
        or _digest(embedded) != value["source_desired_state_sha256"]
    ):
        raise HouseholdPolicyEffectiveStateError("household_policy_effective_state_verified_invalid")
    return dict(value)


class HouseholdPolicyEffectiveStateService:
    """Build a safe read-only view for Cozy/Full interfaces."""

    def __init__(self, store: StateStore) -> None:
        self.store = store

    def _state(self) -> tuple[object, tuple[object, ...]]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyEffectiveStateError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdPolicyEffectiveStateError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc

    @staticmethod
    def _authorize(
        *,
        actor: str,
        member_id: str,
        snapshot: object,
        bindings: tuple[object, ...],
    ) -> None:
        actor_member_id = next(
            (item.member_id for item in bindings if getattr(item, "actor", None) == actor),
            None,
        )
        if actor_member_id is None:
            raise HouseholdPolicyEffectiveStateError("household_actor_not_bound")
        try:
            actor_member = snapshot.household.member(actor_member_id)  # type: ignore[attr-defined]
            target_member = snapshot.household.member(member_id)  # type: ignore[attr-defined]
            actor_policy = effective_policy(snapshot.household, actor_member_id)  # type: ignore[attr-defined]
        except HomeServiceCatalogError as exc:
            raise HouseholdPolicyEffectiveStateError(exc.code) from exc
        if not actor_member.enabled or not target_member.enabled:
            raise HouseholdPolicyEffectiveStateError("household_member_disabled")
        if actor_member_id != member_id and (
            actor_policy.role is not HouseholdRole.PARENT
            or not actor_policy.administration_allowed
        ):
            raise HouseholdPolicyEffectiveStateError(
                "household_policy_effective_state_not_authorized"
            )

    def _validate_verified_evidence(self, verified: dict[str, Any]) -> None:
        envelope = self.store.get_meta(STATE_KEY_PREFIX + verified["request_id"])
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != STATE_SCHEMA
            or envelope.get("status") != "completed"
        ):
            raise HouseholdPolicyEffectiveStateError(
                "household_policy_effective_state_verification_evidence_missing"
            )
        try:
            request = request_from_dict(envelope.get("request"))
        except HouseholdPolicyReconciliationError as exc:
            raise HouseholdPolicyEffectiveStateError(
                "household_policy_effective_state_verification_evidence_invalid"
            ) from exc
        completion = envelope.get("completion")
        if (
            request.request_id != verified["request_id"]
            or request.backend_id != verified["backend_id"]
            or request.binding.household_id != verified["household_id"]
            or request.binding.member_id != verified["member_id"]
            or request.binding.desired_generation != verified["desired_generation"]
            or request.binding.desired_plan_id != verified["desired_plan_id"]
            or request.binding.policy_id != verified["policy_id"]
            or request.binding.policy_sha256 != verified["policy_sha256"]
            or not isinstance(completion, dict)
            or completion.get("schema") != COMPLETION_SCHEMA
            or completion.get("state") != "verified"
            or completion.get("request_id") != verified["request_id"]
            or completion.get("backend_id") != verified["backend_id"]
            or completion.get("member_id") != verified["member_id"]
            or completion.get("desired_state_transition_performed") is not False
            or completion.get("backend_mutation_performed") is not False
            or completion.get("infrastructure_mutation_performed") is not False
            or completion.get("external_publication_performed") is not False
        ):
            raise HouseholdPolicyEffectiveStateError(
                "household_policy_effective_state_verification_evidence_invalid"
            )
        evidence = completion.get("evidence")
        if (
            not isinstance(evidence, dict)
            or evidence.get("schema") != EVIDENCE_SCHEMA
            or evidence.get("evidence_id") != verified["evidence_id"]
            or evidence.get("request_id") != verified["request_id"]
            or evidence.get("backend_id") != verified["backend_id"]
            or evidence.get("binding") != request.binding.to_dict()
            or evidence.get("status") != "verified"
            or evidence.get("blocker") is not None
            or evidence.get("observed_state") != "enforced"
            or evidence.get("actual_policy_sha256") != verified["policy_sha256"]
            or evidence.get("observed_at") != verified["observed_at"]
            or evidence.get("enforcement_verified") is not True
            or evidence.get("reconciliation_required") is not False
            or evidence.get("backend_mutation_performed") is not False
            or evidence.get("infrastructure_mutation_performed") is not False
            or evidence.get("external_publication_performed") is not False
            or _digest(evidence) != verified["evidence_sha256"]
        ):
            raise HouseholdPolicyEffectiveStateError(
                "household_policy_effective_state_verification_evidence_invalid"
            )

    def read(self, *, actor: str, member_id: str) -> dict[str, object]:
        if not isinstance(actor, str) or not actor:
            raise HouseholdPolicyEffectiveStateError("invalid_household_actor")
        if not isinstance(member_id, str) or not IDENTIFIER.fullmatch(member_id):
            raise HouseholdPolicyEffectiveStateError("invalid_household_member_id")

        snapshot, bindings = self._state()
        self._authorize(
            actor=actor,
            member_id=member_id,
            snapshot=snapshot,
            bindings=bindings,
        )
        household_id = snapshot.household_id  # type: ignore[attr-defined]
        default = effective_policy(snapshot.household, member_id)  # type: ignore[attr-defined]

        desired = _desired(
            self.store.get_meta(DESIRED_KEY_PREFIX + household_id + "." + member_id),
            household_id=household_id,
            member_id=member_id,
        )
        verified = _verified(
            self.store.get_meta(VERIFIED_KEY_PREFIX + household_id + "." + member_id),
            household_id=household_id,
            member_id=member_id,
        )

        if verified is not None:
            self._validate_verified_evidence(verified)

        if desired is None:
            if verified is not None:
                raise HouseholdPolicyEffectiveStateError(
                    "household_policy_effective_state_orphan_verified"
                )
            technical, explanation = _technical_policy(
                default.to_dict(),
                household_id=household_id,
                member_id=member_id,
                composed=False,
            )
            return {
                "schema": STATUS_SCHEMA,
                "household_id": household_id,
                "member_id": member_id,
                "source": "role-preset",
                "desired_generation": 0,
                "state": "role-default",
                "technical_policy": technical,
                "explanation_ru": explanation,
                "enforcement_verified": False,
                "reconciliation_required": False,
                "verified_evidence": None,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
                "production_mutation_enabled": False,
            }

        technical, explanation = _technical_policy(
            desired["policy"],
            household_id=household_id,
            member_id=member_id,
            composed=True,
        )

        current_verified = False
        evidence: dict[str, object] | None = None
        if verified is not None:
            if verified["desired_generation"] > desired["generation"]:
                raise HouseholdPolicyEffectiveStateError(
                    "household_policy_effective_state_verified_generation_invalid"
                )
            if verified["desired_generation"] == desired["generation"]:
                if (
                    verified["desired_state"] != desired
                    or verified["source_desired_state_sha256"] != _digest(desired)
                    or verified["desired_plan_id"] != desired["plan_id"]
                    or verified["policy_id"] != desired["policy"]["policy_id"]
                    or verified["policy_sha256"] != desired["policy_sha256"]
                ):
                    raise HouseholdPolicyEffectiveStateError(
                        "household_policy_effective_state_verified_mismatch"
                    )
                current_verified = True
                evidence = {
                    "request_id": verified["request_id"],
                    "backend_id": verified["backend_id"],
                    "evidence_id": verified["evidence_id"],
                    "evidence_sha256": verified["evidence_sha256"],
                    "observed_at": verified["observed_at"],
                }

        return {
            "schema": STATUS_SCHEMA,
            "household_id": household_id,
            "member_id": member_id,
            "source": "composed-desired",
            "desired_generation": desired["generation"],
            "state": "verified" if current_verified else "pending-reconciliation",
            "technical_policy": technical,
            "explanation_ru": explanation,
            "enforcement_verified": current_verified,
            "reconciliation_required": not current_verified,
            "verified_evidence": evidence,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
            "production_mutation_enabled": False,
        }
