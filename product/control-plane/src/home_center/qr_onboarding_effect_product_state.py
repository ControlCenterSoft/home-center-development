"""Authoritative local QR onboarding effect product-state adapter for Home Center 0.63.

The adapter realizes only Home Center's bounded local guest/device access state in
the existing durable ``desired_state`` store. It does not call a provider, create
OS/directory accounts, change managed-device state, mutate network infrastructure
or publish anything externally.

Each durable product-state record is keyed by the exact effect handoff identity,
so one invitation cannot revoke or overwrite another invitation's effect evidence.
The operation identity is deterministic and replay-safe. Authoritative read-back
is performed from durable product state and is the only source for a positive
post-condition observation used by the effect execution service.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path

from .qr_onboarding_effect_execution import (
    QrOnboardingEffectExecutionError,
    QrOnboardingEffectExecutionReceipt,
    QrOnboardingEffectExecutionRequest,
    QrOnboardingEffectObservation,
)
from .qr_onboarding_effect_verification import QrOnboardingPostCondition
from .util import canonical_json, utc_now

STATE_SCHEMA = "home-center.qr-onboarding-effect-product-state.v1"
KEY_PREFIX = "household.qr-onboarding.effect:"


class QrOnboardingEffectProductStateError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _operation_id(request: QrOnboardingEffectExecutionRequest) -> str:
    digest = hashlib.sha256(canonical_json(request.to_dict()).encode("utf-8")).hexdigest()
    return "hcqop-" + digest[:24]


def _shape(request: QrOnboardingEffectExecutionRequest) -> tuple[str, str, list[str], str]:
    resource_key = f"{KEY_PREFIX}{request.handoff_id}"
    expected = request.expected_post_condition
    if expected is QrOnboardingPostCondition.GUEST_ACCESS_EFFECTIVE:
        if request.required_job_type != "typed-guest-access-change-job" or request.device_id is not None:
            raise QrOnboardingEffectProductStateError("qr_effect_product_state_guest_shape_invalid")
        return resource_key, "guest", ["internet.guest"], "active"
    if expected is QrOnboardingPostCondition.DEVICE_BINDING_EFFECTIVE:
        if request.required_job_type != "typed-device-binding-change-job" or not isinstance(request.device_id, str):
            raise QrOnboardingEffectProductStateError("qr_effect_product_state_device_shape_invalid")
        return resource_key, "device", [], "active"
    if expected is QrOnboardingPostCondition.ACCESS_REVOKED:
        if request.required_job_type != "typed-access-revocation-change-job":
            raise QrOnboardingEffectProductStateError("qr_effect_product_state_revoke_shape_invalid")
        return resource_key, "device" if request.device_id is not None else "guest", [], "revoked"
    raise QrOnboardingEffectProductStateError("qr_effect_product_state_post_condition_invalid")


def _state_value(
    request: QrOnboardingEffectExecutionRequest,
    *,
    resource_key: str,
    subject: str,
    guest_scope: list[str],
    state: str,
) -> dict[str, object]:
    return {
        "schema": STATE_SCHEMA,
        "resource_key": resource_key,
        "household_id": request.household_id,
        "household_snapshot_id": request.household_snapshot_id,
        "household_resource_version": request.household_resource_version,
        "household_generation": request.household_generation,
        "target_member_id": request.target_member_id,
        "subject": subject,
        "device_id": request.device_id,
        "guest_scope": guest_scope,
        "state": state,
        "post_condition": request.expected_post_condition.value,
        "request_id": request.request_id,
        "operation_id": _operation_id(request),
        "handoff_id": request.handoff_id,
        "handoff_sha256": request.handoff_sha256,
        "provider_execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _evidence_sha256(generation: int, value: dict[str, object]) -> str:
    material = {"generation": generation, "value": value}
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


class QrOnboardingLocalProductStateAdapter:
    """Typed QR effect adapter over existing durable Home Center product state."""

    def __init__(self, state_path: Path) -> None:
        self.state_path = Path(state_path)
        self._lock = threading.RLock()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.state_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def execute(self, request: QrOnboardingEffectExecutionRequest) -> QrOnboardingEffectExecutionReceipt:
        if not isinstance(request, QrOnboardingEffectExecutionRequest):
            raise QrOnboardingEffectProductStateError("qr_effect_product_state_request_invalid")
        resource_key, subject, guest_scope, state = _shape(request)
        value = _state_value(
            request,
            resource_key=resource_key,
            subject=subject,
            guest_scope=guest_scope,
            state=state,
        )
        operation_id = _operation_id(request)

        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT generation,value_json FROM desired_state WHERE resource_key=?",
                    (resource_key,),
                ).fetchone()
                if row is not None:
                    existing = json.loads(row["value_json"])
                    if existing.get("request_id") == request.request_id:
                        if existing != value:
                            raise QrOnboardingEffectProductStateError(
                                "qr_effect_product_state_replay_mismatch"
                            )
                        connection.commit()
                        return QrOnboardingEffectExecutionReceipt(
                            request_id=request.request_id,
                            operation_id=operation_id,
                            accepted=True,
                        )
                    generation = int(row["generation"]) + 1
                else:
                    generation = 1
                connection.execute(
                    """INSERT INTO desired_state(resource_key,generation,value_json,updated_at)
                    VALUES(?,?,?,?)
                    ON CONFLICT(resource_key) DO UPDATE SET
                      generation=excluded.generation,
                      value_json=excluded.value_json,
                      updated_at=excluded.updated_at""",
                    (resource_key, generation, canonical_json(value), utc_now()),
                )
                persisted = connection.execute(
                    "SELECT generation,value_json FROM desired_state WHERE resource_key=?",
                    (resource_key,),
                ).fetchone()
                if persisted is None or json.loads(persisted["value_json"]) != value:
                    raise QrOnboardingEffectProductStateError(
                        "qr_effect_product_state_write_readback_mismatch"
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

        return QrOnboardingEffectExecutionReceipt(
            request_id=request.request_id,
            operation_id=operation_id,
            accepted=True,
        )

    def observe(self, request: QrOnboardingEffectExecutionRequest) -> QrOnboardingEffectObservation:
        if not isinstance(request, QrOnboardingEffectExecutionRequest):
            raise QrOnboardingEffectProductStateError("qr_effect_product_state_request_invalid")
        resource_key, subject, guest_scope, state = _shape(request)
        expected_value = _state_value(
            request,
            resource_key=resource_key,
            subject=subject,
            guest_scope=guest_scope,
            state=state,
        )
        with self._lock:
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT generation,value_json FROM desired_state WHERE resource_key=?",
                    (resource_key,),
                ).fetchone()
            finally:
                connection.close()

        if row is None:
            missing = {
                "resource_key": resource_key,
                "request_id": request.request_id,
                "missing": True,
            }
            return QrOnboardingEffectObservation(
                request_id=request.request_id,
                operation_id=_operation_id(request),
                observed_post_condition=request.expected_post_condition,
                post_condition_verified=False,
                evidence_sha256=hashlib.sha256(canonical_json(missing).encode("utf-8")).hexdigest(),
            )

        try:
            persisted = json.loads(row["value_json"])
            generation = int(row["generation"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise QrOnboardingEffectProductStateError("qr_effect_product_state_readback_invalid") from exc
        verified = persisted == expected_value
        return QrOnboardingEffectObservation(
            request_id=request.request_id,
            operation_id=_operation_id(request),
            observed_post_condition=request.expected_post_condition,
            post_condition_verified=verified,
            evidence_sha256=_evidence_sha256(generation, persisted),
        )


def register_local_qr_effect_adapters(
    service: object,
    state_path: Path,
) -> QrOnboardingLocalProductStateAdapter:
    """Register the same bounded local adapter for the three closed 0.63 Job types."""
    register = getattr(service, "register", None)
    if not callable(register):
        raise QrOnboardingEffectExecutionError("qr_effect_execution_service_invalid")
    adapter = QrOnboardingLocalProductStateAdapter(state_path)
    for job_type in (
        "typed-guest-access-change-job",
        "typed-device-binding-change-job",
        "typed-access-revocation-change-job",
    ):
        register(job_type, adapter)
    return adapter
