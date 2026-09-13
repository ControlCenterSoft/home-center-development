"""Bounded internal product-state adapter for Home Center 0.63 QR effects.

The adapter implements only Home Center product-state evidence for the exact typed
QR effect jobs. It does not create operating-system/directory accounts, execute a
provider, change managed-device state, mutate infrastructure or publish anything.

The generic execution service revalidates the exact Household/handoff before this
adapter is called and persists the execution receipt before authoritative readback.
This adapter makes the local product-state mutation deterministic and idempotent so
its own replay cannot broaden the requested effect.
"""
from __future__ import annotations

import hashlib
from typing import Final

from .qr_onboarding_effect_execution import (
    QrOnboardingEffectExecutionRequest,
    QrOnboardingEffectExecutionReceipt,
    QrOnboardingEffectObservation,
)
from .qr_onboarding_effect_verification import QrOnboardingPostCondition
from .store import StateStore
from .util import canonical_json

QR_PRODUCT_STATE_SCHEMA: Final = "home-center.qr-onboarding-product-effect-state.v1"
QR_PRODUCT_STATE_KEY_PREFIX: Final = "qr.onboarding.product-effect."

GUEST_ACCESS_JOB: Final = "typed-guest-access-change-job"
DEVICE_BINDING_JOB: Final = "typed-device-binding-change-job"
ACCESS_REVOCATION_JOB: Final = "typed-access-revocation-change-job"
SUPPORTED_JOB_TYPES: Final = (GUEST_ACCESS_JOB, DEVICE_BINDING_JOB, ACCESS_REVOCATION_JOB)


class QrOnboardingProductStateError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _operation_id(request: QrOnboardingEffectExecutionRequest) -> str:
    digest = hashlib.sha256(canonical_json(request.to_dict()).encode("utf-8")).hexdigest()
    return "hcqop-" + digest[:24]


def _key(request: QrOnboardingEffectExecutionRequest) -> str:
    return QR_PRODUCT_STATE_KEY_PREFIX + request.handoff_id


def _validate_request(request: object) -> QrOnboardingEffectExecutionRequest:
    if not isinstance(request, QrOnboardingEffectExecutionRequest):
        raise QrOnboardingProductStateError("qr_product_effect_request_invalid")
    if (
        request.typed_effect_execution_authorized is not True
        or request.provider_execution_authorized is not False
        or request.infrastructure_mutation_authorized is not False
        or request.external_publication_authorized is not False
    ):
        raise QrOnboardingProductStateError("qr_product_effect_authority_invalid")

    if request.expected_post_condition is QrOnboardingPostCondition.GUEST_ACCESS_EFFECTIVE:
        if request.required_job_type != GUEST_ACCESS_JOB or request.device_id is not None:
            raise QrOnboardingProductStateError("qr_product_effect_binding_invalid")
    elif request.expected_post_condition is QrOnboardingPostCondition.DEVICE_BINDING_EFFECTIVE:
        if request.required_job_type != DEVICE_BINDING_JOB or not request.device_id:
            raise QrOnboardingProductStateError("qr_product_effect_binding_invalid")
    elif request.expected_post_condition is QrOnboardingPostCondition.ACCESS_REVOKED:
        if request.required_job_type != ACCESS_REVOCATION_JOB:
            raise QrOnboardingProductStateError("qr_product_effect_binding_invalid")
    else:
        raise QrOnboardingProductStateError("qr_product_effect_post_condition_invalid")
    return request


def _record(request: QrOnboardingEffectExecutionRequest) -> dict[str, object]:
    request = _validate_request(request)
    if request.expected_post_condition is QrOnboardingPostCondition.GUEST_ACCESS_EFFECTIVE:
        effect = "guest-access"
        state = "effective"
        guest_scope: list[str] = ["internet.guest"]
    elif request.expected_post_condition is QrOnboardingPostCondition.DEVICE_BINDING_EFFECTIVE:
        effect = "device-binding"
        state = "effective"
        guest_scope = []
    else:
        effect = "access-revocation"
        state = "revoked"
        guest_scope = []

    return {
        "schema": QR_PRODUCT_STATE_SCHEMA,
        "request_id": request.request_id,
        "handoff_id": request.handoff_id,
        "handoff_sha256": request.handoff_sha256,
        "job_id": request.job_id,
        "required_job_type": request.required_job_type,
        "household_id": request.household_id,
        "household_snapshot_id": request.household_snapshot_id,
        "household_resource_version": request.household_resource_version,
        "household_generation": request.household_generation,
        "target_member_id": request.target_member_id,
        "device_id": request.device_id,
        "guest_scope": guest_scope,
        "effect": effect,
        "state": state,
        "expected_post_condition": request.expected_post_condition.value,
        "product_state_only": True,
        "account_creation_authorized": False,
        "device_registration_authorized": False,
        "managed_state_change_authorized": False,
        "provider_execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


class QrOnboardingProductStateAdapter:
    """Concrete internal adapter backed by canonical StateStore product metadata."""

    def __init__(self, store: StateStore) -> None:
        if not isinstance(store, StateStore):
            raise QrOnboardingProductStateError("qr_product_effect_store_invalid")
        self.store = store

    def execute(self, request: QrOnboardingEffectExecutionRequest) -> QrOnboardingEffectExecutionReceipt:
        desired = _record(request)
        key = _key(request)
        # The canonical StateStore RLock makes get/compare/set atomic within the
        # single-node-core server process. A different durable value is never
        # overwritten or broadened by replay.
        with self.store._lock:  # noqa: SLF001 - canonical same-package state boundary
            existing = self.store.get_meta(key)
            if existing is None:
                self.store.set_meta(key, desired)
            elif existing != desired:
                raise QrOnboardingProductStateError("qr_product_effect_state_conflict")
        return QrOnboardingEffectExecutionReceipt(
            request_id=request.request_id,
            operation_id=_operation_id(request),
            accepted=True,
        )

    def observe(self, request: QrOnboardingEffectExecutionRequest) -> QrOnboardingEffectObservation:
        desired = _record(request)
        existing = self.store.get_meta(_key(request))
        verified = existing == desired
        evidence_material = {
            "request_id": request.request_id,
            "handoff_id": request.handoff_id,
            "expected": desired,
            "observed": existing if isinstance(existing, dict) else None,
            "verified": verified,
        }
        evidence_sha256 = hashlib.sha256(
            canonical_json(evidence_material).encode("utf-8")
        ).hexdigest()
        return QrOnboardingEffectObservation(
            request_id=request.request_id,
            operation_id=_operation_id(request),
            observed_post_condition=request.expected_post_condition,
            post_condition_verified=verified,
            evidence_sha256=evidence_sha256,
        )

    def state(self, handoff_id: str) -> dict[str, object] | None:
        """Read bounded product-state evidence for diagnostics/tests only."""
        if not isinstance(handoff_id, str) or not handoff_id.startswith("hcqeh-"):
            raise QrOnboardingProductStateError("qr_product_effect_handoff_id_invalid")
        value = self.store.get_meta(QR_PRODUCT_STATE_KEY_PREFIX + handoff_id)
        if value is None:
            return None
        if not isinstance(value, dict) or value.get("schema") != QR_PRODUCT_STATE_SCHEMA:
            raise QrOnboardingProductStateError("qr_product_effect_state_invalid")
        return value
