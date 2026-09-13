"""Transport-neutral API contract for Home Center 0.63 QR onboarding.

This module deliberately does not register HTTP routes. It gives the future HTTP
layer strict request parsing and server-authoritative actor/time semantics without
creating a new execution path. Same-origin/CSRF checks and bounded body reads remain
requirements of the HTTP handler that invokes this adapter.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .household_store import HouseholdSnapshot
from .qr_onboarding import GuestScope, OnboardingSubject
from .qr_onboarding_runtime import (
    QrOnboardingIssueResult,
    QrOnboardingOperationReceipt,
    QrOnboardingRuntimeError,
    QrOnboardingRuntimeRecord,
    QrOnboardingRuntimeService,
)
from .qr_onboarding_validation import redemption_plan_from_dict

ISSUE_REQUEST_SCHEMA = "home-center.qr-onboarding-api-issue-request.v1"
PLAN_REQUEST_SCHEMA = "home-center.qr-onboarding-api-plan-request.v1"
CONSUME_REQUEST_SCHEMA = "home-center.qr-onboarding-api-consume-request.v1"
REVOKE_REQUEST_SCHEMA = "home-center.qr-onboarding-api-revoke-request.v1"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_INVITATION_ID = re.compile(r"hcqri-[0-9a-f]{24}\Z")
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9._:-]{8,128}\Z")
_CODE = re.compile(r"[A-Za-z0-9_-]{22,128}\Z")
_MIN_TTL_SECONDS = 60
_MAX_TTL_SECONDS = 1800


class QrOnboardingApiError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _exact_object(value: object, keys: set[str], schema: str, code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys or value.get("schema") != schema:
        raise QrOnboardingApiError(code)
    return value


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise QrOnboardingApiError(code)
    return value


def _invitation_id(value: object) -> str:
    if not isinstance(value, str) or not _INVITATION_ID.fullmatch(value):
        raise QrOnboardingApiError("qr_api_invitation_id_invalid")
    return value


def _code(value: object) -> str:
    if not isinstance(value, str) or not _CODE.fullmatch(value):
        raise QrOnboardingApiError("qr_api_onboarding_code_invalid")
    return value


def _expected_version(value: object) -> int:
    if type(value) is not int or value < 1:
        raise QrOnboardingApiError("qr_api_expected_version_invalid")
    return value


def _idempotency(value: object) -> str:
    if not isinstance(value, str) or not _IDEMPOTENCY.fullmatch(value):
        raise QrOnboardingApiError("qr_api_idempotency_key_invalid")
    return value


@dataclass(frozen=True, slots=True)
class IssueRequest:
    target_member_id: str
    subject: OnboardingSubject
    device_id: str | None
    guest_scope: tuple[GuestScope, ...]
    ttl_seconds: int


@dataclass(frozen=True, slots=True)
class PlanRequest:
    invitation_id: str
    onboarding_code: str


@dataclass(frozen=True, slots=True)
class ConsumeRequest:
    plan: dict[str, object]
    onboarding_code: str
    expected_version: int
    confirmed: bool
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class RevokeRequest:
    invitation_id: str
    expected_version: int
    idempotency_key: str


def parse_issue_request(value: object) -> IssueRequest:
    raw = _exact_object(
        value,
        {"schema", "target_member_id", "subject", "device_id", "guest_scope", "ttl_seconds"},
        ISSUE_REQUEST_SCHEMA,
        "qr_api_issue_request_rejected",
    )
    target_member_id = _identifier(raw["target_member_id"], "qr_api_target_member_id_invalid")
    try:
        subject = OnboardingSubject(raw["subject"])
    except (TypeError, ValueError) as exc:
        raise QrOnboardingApiError("qr_api_subject_invalid") from exc
    device_raw = raw["device_id"]
    if device_raw is None:
        device_id = None
    else:
        device_id = _identifier(device_raw, "qr_api_device_id_invalid")
    scope_raw = raw["guest_scope"]
    if not isinstance(scope_raw, list) or len(scope_raw) > len(GuestScope):
        raise QrOnboardingApiError("qr_api_guest_scope_invalid")
    try:
        guest_scope = tuple(GuestScope(item) for item in scope_raw)
    except (TypeError, ValueError) as exc:
        raise QrOnboardingApiError("qr_api_guest_scope_invalid") from exc
    if len(set(guest_scope)) != len(guest_scope):
        raise QrOnboardingApiError("qr_api_guest_scope_invalid")
    ttl = raw["ttl_seconds"]
    if type(ttl) is not int or not _MIN_TTL_SECONDS <= ttl <= _MAX_TTL_SECONDS:
        raise QrOnboardingApiError("qr_api_ttl_invalid")
    if subject is OnboardingSubject.GUEST and device_id is not None:
        raise QrOnboardingApiError("qr_api_guest_device_invalid")
    if subject is OnboardingSubject.DEVICE and (device_id is None or guest_scope):
        raise QrOnboardingApiError("qr_api_device_binding_invalid")
    return IssueRequest(
        target_member_id=target_member_id,
        subject=subject,
        device_id=device_id,
        guest_scope=guest_scope,
        ttl_seconds=ttl,
    )


def parse_plan_request(value: object) -> PlanRequest:
    raw = _exact_object(
        value,
        {"schema", "invitation_id", "onboarding_code"},
        PLAN_REQUEST_SCHEMA,
        "qr_api_plan_request_rejected",
    )
    return PlanRequest(
        invitation_id=_invitation_id(raw["invitation_id"]),
        onboarding_code=_code(raw["onboarding_code"]),
    )


def parse_consume_request(value: object) -> ConsumeRequest:
    raw = _exact_object(
        value,
        {"schema", "plan", "onboarding_code", "expected_version", "confirmed", "idempotency_key"},
        CONSUME_REQUEST_SCHEMA,
        "qr_api_consume_request_rejected",
    )
    plan = raw["plan"]
    if not isinstance(plan, dict) or len(plan) > 24:
        raise QrOnboardingApiError("qr_api_plan_invalid")
    if raw["confirmed"] is not True:
        raise QrOnboardingApiError("qr_api_confirmation_required")
    return ConsumeRequest(
        plan=dict(plan),
        onboarding_code=_code(raw["onboarding_code"]),
        expected_version=_expected_version(raw["expected_version"]),
        confirmed=True,
        idempotency_key=_idempotency(raw["idempotency_key"]),
    )


def parse_revoke_request(value: object) -> RevokeRequest:
    raw = _exact_object(
        value,
        {"schema", "invitation_id", "expected_version", "idempotency_key"},
        REVOKE_REQUEST_SCHEMA,
        "qr_api_revoke_request_rejected",
    )
    return RevokeRequest(
        invitation_id=_invitation_id(raw["invitation_id"]),
        expected_version=_expected_version(raw["expected_version"]),
        idempotency_key=_idempotency(raw["idempotency_key"]),
    )


class QrOnboardingApiService:
    """Server-authoritative adapter over the durable runtime service."""

    def __init__(self, runtime: QrOnboardingRuntimeService) -> None:
        self.runtime = runtime

    @staticmethod
    def _server_epoch(now_epoch: object) -> int:
        if type(now_epoch) is not int or now_epoch < 0:
            raise QrOnboardingApiError("qr_api_server_time_invalid")
        return now_epoch

    def issue(
        self,
        *,
        snapshot: HouseholdSnapshot,
        actor_member_id: str,
        body: object,
        now_epoch: int,
    ) -> QrOnboardingIssueResult:
        request = parse_issue_request(body)
        now = self._server_epoch(now_epoch)
        try:
            return self.runtime.issue(
                snapshot=snapshot,
                issuer_member_id=actor_member_id,
                target_member_id=request.target_member_id,
                subject=request.subject,
                created_at_epoch=now,
                expires_at_epoch=now + request.ttl_seconds,
                device_id=request.device_id,
                guest_scope=request.guest_scope,
            )
        except QrOnboardingRuntimeError as exc:
            raise QrOnboardingApiError(exc.code) from exc

    def plan(
        self,
        *,
        snapshot: HouseholdSnapshot,
        body: object,
        now_epoch: int,
    ):
        request = parse_plan_request(body)
        now = self._server_epoch(now_epoch)
        try:
            return self.runtime.plan_redemption(
                snapshot=snapshot,
                invitation_id=request.invitation_id,
                onboarding_code=request.onboarding_code,
                now_epoch=now,
            )
        except QrOnboardingRuntimeError as exc:
            raise QrOnboardingApiError(exc.code) from exc

    def consume(
        self,
        *,
        snapshot: HouseholdSnapshot,
        actor: str,
        body: object,
        now_epoch: int,
    ) -> tuple[QrOnboardingRuntimeRecord, QrOnboardingOperationReceipt]:
        request = parse_consume_request(body)
        now = self._server_epoch(now_epoch)
        invitation_id = _invitation_id(request.plan.get("invitation_id"))
        record = self.runtime.repository.get(invitation_id, now_epoch=now)
        if record is None:
            raise QrOnboardingApiError("qr_runtime_invitation_not_found")
        try:
            plan = redemption_plan_from_dict(request.plan, invitation=record.invitation)
            return self.runtime.consume(
                snapshot=snapshot,
                plan=plan,
                onboarding_code=request.onboarding_code,
                actor=actor,
                idempotency_key=request.idempotency_key,
                confirmed=request.confirmed,
                expected_version=request.expected_version,
                now_epoch=now,
            )
        except (ValueError, QrOnboardingRuntimeError) as exc:
            code = getattr(exc, "code", "qr_api_plan_rejected")
            raise QrOnboardingApiError(code) from exc

    def revoke(
        self,
        *,
        snapshot: HouseholdSnapshot,
        actor_member_id: str,
        body: object,
        now_epoch: int,
    ) -> tuple[QrOnboardingRuntimeRecord, QrOnboardingOperationReceipt]:
        request = parse_revoke_request(body)
        now = self._server_epoch(now_epoch)
        try:
            return self.runtime.revoke(
                snapshot=snapshot,
                invitation_id=request.invitation_id,
                actor_member_id=actor_member_id,
                idempotency_key=request.idempotency_key,
                expected_version=request.expected_version,
                now_epoch=now,
            )
        except QrOnboardingRuntimeError as exc:
            raise QrOnboardingApiError(exc.code) from exc
