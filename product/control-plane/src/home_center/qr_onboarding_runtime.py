"""Durable, fail-closed Home Center 0.63 QR onboarding runtime boundary.

This module is deliberately narrower than account/device provisioning. It persists
only bounded invitation evidence and one-time state. Consuming an invitation never
creates an account, registers a device, changes managed state, calls a provider, or
mutates infrastructure. Those remain separate typed Change/Job boundaries.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from .household import HouseholdRole
from .household_store import HouseholdSnapshot
from .qr_onboarding import (
    GuestScope,
    InvitationState,
    OnboardingSubject,
    QrOnboardingError,
    QrOnboardingInvitation,
    QrOnboardingPayload,
    QrOnboardingRedemptionPlan,
    build_qr_onboarding_invitation,
    build_qr_payload,
    hash_onboarding_code,
    plan_qr_redemption,
)
from .util import canonical_json

QR_RUNTIME_RECORD_SCHEMA = "home-center.qr-onboarding-runtime-record.v1"
QR_OPERATION_RECEIPT_SCHEMA = "home-center.qr-onboarding-operation-receipt.v1"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9._:-]{8,128}\Z")
_RUNTIME_DDL = """
CREATE TABLE IF NOT EXISTS qr_onboarding_runtime (
    runtime_record_id TEXT PRIMARY KEY,
    invitation_id TEXT NOT NULL UNIQUE,
    household_id TEXT NOT NULL,
    household_snapshot_id TEXT NOT NULL,
    household_resource_version TEXT NOT NULL,
    household_generation INTEGER NOT NULL CHECK(household_generation >= 1),
    target_member_id TEXT NOT NULL,
    invitation_json TEXT NOT NULL,
    invitation_evidence_sha256 TEXT NOT NULL,
    token_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','consumed','revoked','expired')),
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at_epoch INTEGER NOT NULL,
    expires_at_epoch INTEGER NOT NULL,
    consumed_at_epoch INTEGER,
    revoked_at_epoch INTEGER,
    updated_at_epoch INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS qr_onboarding_runtime_operations (
    operation_key_sha256 TEXT PRIMARY KEY,
    runtime_record_id TEXT NOT NULL REFERENCES qr_onboarding_runtime(runtime_record_id) ON DELETE CASCADE,
    request_sha256 TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at_epoch INTEGER NOT NULL
);
"""


class QrOnboardingRuntimeError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RuntimeOperation(StrEnum):
    ISSUE = "issue"
    CONSUME = "consume"
    REVOKE = "revoke"


@dataclass(frozen=True, slots=True)
class QrOnboardingRuntimeRecord:
    runtime_record_id: str
    invitation: QrOnboardingInvitation
    household_snapshot_id: str
    household_resource_version: str
    household_generation: int
    target_member_id: str
    invitation_evidence_sha256: str
    state: InvitationState
    version: int
    updated_at_epoch: int
    consumed_at_epoch: int | None = None
    revoked_at_epoch: int | None = None
    schema: str = field(default=QR_RUNTIME_RECORD_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.invitation, QrOnboardingInvitation):
            raise QrOnboardingRuntimeError("qr_runtime_invitation_invalid")
        if not isinstance(self.state, InvitationState):
            raise QrOnboardingRuntimeError("qr_runtime_state_invalid")
        if type(self.household_generation) is not int or self.household_generation < 1:
            raise QrOnboardingRuntimeError("qr_runtime_household_generation_invalid")
        if type(self.version) is not int or self.version < 1:
            raise QrOnboardingRuntimeError("qr_runtime_version_invalid")
        if type(self.updated_at_epoch) is not int or self.updated_at_epoch < self.invitation.created_at_epoch:
            raise QrOnboardingRuntimeError("qr_runtime_updated_at_invalid")
        if not isinstance(self.invitation_evidence_sha256, str) or not _SHA256.fullmatch(
            self.invitation_evidence_sha256
        ):
            raise QrOnboardingRuntimeError("qr_runtime_invitation_digest_invalid")
        expected_evidence = hashlib.sha256(
            canonical_json(self.invitation.to_dict()).encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(expected_evidence, self.invitation_evidence_sha256):
            raise QrOnboardingRuntimeError("qr_runtime_invitation_digest_mismatch")
        material = {
            "invitation_id": self.invitation.invitation_id,
            "household_id": self.invitation.household_id,
            "household_snapshot_id": self.household_snapshot_id,
            "household_resource_version": self.household_resource_version,
            "household_generation": self.household_generation,
            "target_member_id": self.target_member_id,
            "invitation_evidence_sha256": self.invitation_evidence_sha256,
        }
        expected_id = "hcqrr-" + hashlib.sha256(
            canonical_json(material).encode("utf-8")
        ).hexdigest()[:24]
        if self.runtime_record_id != expected_id:
            raise QrOnboardingRuntimeError("qr_runtime_identity_invalid")
        if self.state is InvitationState.CONSUMED:
            if type(self.consumed_at_epoch) is not int or self.revoked_at_epoch is not None:
                raise QrOnboardingRuntimeError("qr_runtime_consumed_evidence_invalid")
        elif self.state is InvitationState.REVOKED:
            if type(self.revoked_at_epoch) is not int or self.consumed_at_epoch is not None:
                raise QrOnboardingRuntimeError("qr_runtime_revoked_evidence_invalid")
        elif self.consumed_at_epoch is not None or self.revoked_at_epoch is not None:
            raise QrOnboardingRuntimeError("qr_runtime_terminal_evidence_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "runtime_record_id": self.runtime_record_id,
            "invitation": self.invitation.to_dict(),
            "household_snapshot_id": self.household_snapshot_id,
            "household_resource_version": self.household_resource_version,
            "household_generation": self.household_generation,
            "target_member_id": self.target_member_id,
            "invitation_evidence_sha256": self.invitation_evidence_sha256,
            "state": self.state.value,
            "version": self.version,
            "updated_at_epoch": self.updated_at_epoch,
            "consumed_at_epoch": self.consumed_at_epoch,
            "revoked_at_epoch": self.revoked_at_epoch,
            "raw_onboarding_code_persisted": False,
            "account_creation_authorized": False,
            "device_registration_authorized": False,
            "managed_state_change_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class QrOnboardingOperationReceipt:
    receipt_id: str
    operation: RuntimeOperation
    runtime_record_id: str
    invitation_id: str
    household_id: str
    household_snapshot_id: str
    household_resource_version: str
    household_generation: int
    target_member_id: str
    before_state: InvitationState | None
    after_state: InvitationState
    record_version: int
    occurred_at_epoch: int
    invitation_evidence_sha256: str
    next_required_boundary: str
    schema: str = field(default=QR_OPERATION_RECEIPT_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.operation, RuntimeOperation):
            raise QrOnboardingRuntimeError("qr_runtime_operation_invalid")
        if self.before_state is not None and not isinstance(self.before_state, InvitationState):
            raise QrOnboardingRuntimeError("qr_runtime_before_state_invalid")
        if not isinstance(self.after_state, InvitationState):
            raise QrOnboardingRuntimeError("qr_runtime_after_state_invalid")
        if type(self.record_version) is not int or self.record_version < 1:
            raise QrOnboardingRuntimeError("qr_runtime_receipt_version_invalid")
        if type(self.occurred_at_epoch) is not int or self.occurred_at_epoch < 0:
            raise QrOnboardingRuntimeError("qr_runtime_receipt_time_invalid")
        if not _SHA256.fullmatch(self.invitation_evidence_sha256):
            raise QrOnboardingRuntimeError("qr_runtime_receipt_digest_invalid")
        material = {
            "operation": self.operation.value,
            "runtime_record_id": self.runtime_record_id,
            "invitation_id": self.invitation_id,
            "household_id": self.household_id,
            "household_snapshot_id": self.household_snapshot_id,
            "household_resource_version": self.household_resource_version,
            "household_generation": self.household_generation,
            "target_member_id": self.target_member_id,
            "before_state": self.before_state.value if self.before_state else None,
            "after_state": self.after_state.value,
            "record_version": self.record_version,
            "occurred_at_epoch": self.occurred_at_epoch,
            "invitation_evidence_sha256": self.invitation_evidence_sha256,
            "next_required_boundary": self.next_required_boundary,
        }
        expected = "hcqro-" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:24]
        if self.receipt_id != expected:
            raise QrOnboardingRuntimeError("qr_runtime_receipt_identity_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "operation": self.operation.value,
            "runtime_record_id": self.runtime_record_id,
            "invitation_id": self.invitation_id,
            "household_id": self.household_id,
            "household_snapshot_id": self.household_snapshot_id,
            "household_resource_version": self.household_resource_version,
            "household_generation": self.household_generation,
            "target_member_id": self.target_member_id,
            "before_state": self.before_state.value if self.before_state else None,
            "after_state": self.after_state.value,
            "record_version": self.record_version,
            "occurred_at_epoch": self.occurred_at_epoch,
            "invitation_evidence_sha256": self.invitation_evidence_sha256,
            "invitation_state_post_condition_verified": True,
            "onboarding_effect_verified": False,
            "next_required_boundary": self.next_required_boundary,
            "raw_onboarding_code_persisted": False,
            "account_creation_authorized": False,
            "device_registration_authorized": False,
            "managed_state_change_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class QrOnboardingIssueResult:
    """Ephemeral issue result; payload is render-only and must never be persisted."""

    record: QrOnboardingRuntimeRecord
    payload: QrOnboardingPayload
    receipt: QrOnboardingOperationReceipt


class ReceiptFactory(Protocol):
    def __call__(
        self,
        before: QrOnboardingRuntimeRecord,
        after: QrOnboardingRuntimeRecord,
    ) -> QrOnboardingOperationReceipt: ...


class QrOnboardingRuntimeRepository(Protocol):
    def create(self, record: QrOnboardingRuntimeRecord, receipt: QrOnboardingOperationReceipt) -> None: ...
    def get(self, invitation_id: str, *, now_epoch: int) -> QrOnboardingRuntimeRecord | None: ...
    def consume(
        self,
        invitation_id: str,
        *,
        expected_version: int,
        now_epoch: int,
        onboarding_code: str,
        operation_key_sha256: str,
        request_sha256: str,
        receipt_factory: ReceiptFactory,
    ) -> tuple[QrOnboardingRuntimeRecord, QrOnboardingOperationReceipt]: ...
    def revoke(
        self,
        invitation_id: str,
        *,
        expected_version: int,
        now_epoch: int,
        operation_key_sha256: str,
        request_sha256: str,
        receipt_factory: ReceiptFactory,
    ) -> tuple[QrOnboardingRuntimeRecord, QrOnboardingOperationReceipt]: ...


def _record_from_row(
    row: sqlite3.Row, *, state_override: InvitationState | None = None
) -> QrOnboardingRuntimeRecord:
    import json

    from .qr_onboarding_validation import invitation_from_dict

    invitation = invitation_from_dict(json.loads(row["invitation_json"]))
    return QrOnboardingRuntimeRecord(
        runtime_record_id=row["runtime_record_id"],
        invitation=invitation,
        household_snapshot_id=row["household_snapshot_id"],
        household_resource_version=row["household_resource_version"],
        household_generation=int(row["household_generation"]),
        target_member_id=row["target_member_id"],
        invitation_evidence_sha256=row["invitation_evidence_sha256"],
        state=state_override or InvitationState(row["state"]),
        version=int(row["version"]),
        updated_at_epoch=int(row["updated_at_epoch"]),
        consumed_at_epoch=row["consumed_at_epoch"],
        revoked_at_epoch=row["revoked_at_epoch"],
    )


def _receipt_from_json(raw: str) -> QrOnboardingOperationReceipt:
    import json

    value = json.loads(raw)
    before = value["before_state"]
    receipt = QrOnboardingOperationReceipt(
        receipt_id=value["receipt_id"],
        operation=RuntimeOperation(value["operation"]),
        runtime_record_id=value["runtime_record_id"],
        invitation_id=value["invitation_id"],
        household_id=value["household_id"],
        household_snapshot_id=value["household_snapshot_id"],
        household_resource_version=value["household_resource_version"],
        household_generation=value["household_generation"],
        target_member_id=value["target_member_id"],
        before_state=InvitationState(before) if before is not None else None,
        after_state=InvitationState(value["after_state"]),
        record_version=value["record_version"],
        occurred_at_epoch=value["occurred_at_epoch"],
        invitation_evidence_sha256=value["invitation_evidence_sha256"],
        next_required_boundary=value["next_required_boundary"],
    )
    if receipt.to_dict() != value:
        raise QrOnboardingRuntimeError("qr_runtime_receipt_storage_rejected")
    return receipt


class SQLiteQrOnboardingRuntimeRepository:
    """SQLite adapter with transactional one-time consume/revoke semantics.

    Integration must install `schema_sql()` through the canonical migration
    mechanism before constructing this adapter. The adapter does not create schema
    on its own in production.
    """

    def __init__(self, connection: sqlite3.Connection, lock: threading.RLock | None = None) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("qr_runtime_connection_invalid")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._lock = lock or threading.RLock()

    @staticmethod
    def schema_sql() -> str:
        return _RUNTIME_DDL

    def create(self, record: QrOnboardingRuntimeRecord, receipt: QrOnboardingOperationReceipt) -> None:
        if receipt.operation is not RuntimeOperation.ISSUE or receipt.runtime_record_id != record.runtime_record_id:
            raise QrOnboardingRuntimeError("qr_runtime_issue_receipt_invalid")
        with self._lock, self._connection:
            try:
                self._connection.execute(
                    """INSERT INTO qr_onboarding_runtime(
                        runtime_record_id, invitation_id, household_id, household_snapshot_id,
                        household_resource_version, household_generation, target_member_id,
                        invitation_json, invitation_evidence_sha256, token_sha256, state, version,
                        created_at_epoch, expires_at_epoch, consumed_at_epoch, revoked_at_epoch,
                        updated_at_epoch
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        record.runtime_record_id,
                        record.invitation.invitation_id,
                        record.invitation.household_id,
                        record.household_snapshot_id,
                        record.household_resource_version,
                        record.household_generation,
                        record.target_member_id,
                        canonical_json(record.invitation.to_dict()),
                        record.invitation_evidence_sha256,
                        record.invitation.token_sha256,
                        record.state.value,
                        record.version,
                        record.invitation.created_at_epoch,
                        record.invitation.expires_at_epoch,
                        record.consumed_at_epoch,
                        record.revoked_at_epoch,
                        record.updated_at_epoch,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise QrOnboardingRuntimeError("qr_runtime_invitation_already_exists") from exc

    @staticmethod
    def _effective_record(row: sqlite3.Row, now_epoch: int) -> QrOnboardingRuntimeRecord:
        state = InvitationState(row["state"])
        if state is InvitationState.ACTIVE and now_epoch >= int(row["expires_at_epoch"]):
            state = InvitationState.EXPIRED
        return _record_from_row(row, state_override=state)

    def get(self, invitation_id: str, *, now_epoch: int) -> QrOnboardingRuntimeRecord | None:
        if type(now_epoch) is not int or now_epoch < 0:
            raise QrOnboardingRuntimeError("qr_runtime_now_invalid")
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM qr_onboarding_runtime WHERE invitation_id=?", (invitation_id,)
            ).fetchone()
            if row is None:
                return None
            return self._effective_record(row, now_epoch)

    def _stored_replay(
        self,
        operation_key_sha256: str,
        request_sha256: str,
    ) -> QrOnboardingOperationReceipt | None:
        row = self._connection.execute(
            """SELECT request_sha256, receipt_json
               FROM qr_onboarding_runtime_operations WHERE operation_key_sha256=?""",
            (operation_key_sha256,),
        ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(row["request_sha256"], request_sha256):
            raise QrOnboardingRuntimeError("qr_runtime_idempotency_conflict")
        return _receipt_from_json(row["receipt_json"])

    def _transition(
        self,
        invitation_id: str,
        *,
        expected_version: int,
        now_epoch: int,
        operation_key_sha256: str,
        request_sha256: str,
        onboarding_code: str | None,
        target_state: InvitationState,
        receipt_factory: ReceiptFactory,
    ) -> tuple[QrOnboardingRuntimeRecord, QrOnboardingOperationReceipt]:
        if not _SHA256.fullmatch(operation_key_sha256) or not _SHA256.fullmatch(request_sha256):
            raise QrOnboardingRuntimeError("qr_runtime_operation_digest_invalid")
        if type(expected_version) is not int or expected_version < 1:
            raise QrOnboardingRuntimeError("qr_runtime_expected_version_invalid")
        if type(now_epoch) is not int or now_epoch < 0:
            raise QrOnboardingRuntimeError("qr_runtime_now_invalid")

        with self._lock, self._connection:
            replay = self._stored_replay(operation_key_sha256, request_sha256)
            if replay is not None:
                row = self._connection.execute(
                    "SELECT * FROM qr_onboarding_runtime WHERE runtime_record_id=?",
                    (replay.runtime_record_id,),
                ).fetchone()
                if row is None:
                    raise QrOnboardingRuntimeError("qr_runtime_replay_record_missing")
                return self._effective_record(row, now_epoch), replay

            row = self._connection.execute(
                "SELECT * FROM qr_onboarding_runtime WHERE invitation_id=?", (invitation_id,)
            ).fetchone()
            if row is None:
                raise QrOnboardingRuntimeError("qr_runtime_invitation_not_found")
            before = self._effective_record(row, now_epoch)
            if before.version != expected_version:
                raise QrOnboardingRuntimeError("qr_runtime_stale_version")
            if before.state is not InvitationState.ACTIVE:
                raise QrOnboardingRuntimeError(f"qr_runtime_invitation_{before.state.value}")
            if target_state is InvitationState.CONSUMED:
                if onboarding_code is None or not hmac.compare_digest(
                    hash_onboarding_code(onboarding_code), before.invitation.token_sha256
                ):
                    raise QrOnboardingRuntimeError("qr_runtime_onboarding_code_mismatch")
                consumed_at = now_epoch
                revoked_at = None
            elif target_state is InvitationState.REVOKED:
                consumed_at = None
                revoked_at = now_epoch
            else:
                raise QrOnboardingRuntimeError("qr_runtime_transition_invalid")

            cursor = self._connection.execute(
                """UPDATE qr_onboarding_runtime
                   SET state=?, version=version+1, consumed_at_epoch=?, revoked_at_epoch=?,
                       updated_at_epoch=?
                   WHERE invitation_id=? AND state='active' AND version=?""",
                (
                    target_state.value,
                    consumed_at,
                    revoked_at,
                    now_epoch,
                    invitation_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise QrOnboardingRuntimeError("qr_runtime_transition_race")
            after_row = self._connection.execute(
                "SELECT * FROM qr_onboarding_runtime WHERE invitation_id=?", (invitation_id,)
            ).fetchone()
            after = self._effective_record(after_row, now_epoch)
            receipt = receipt_factory(before, after)
            self._connection.execute(
                """INSERT INTO qr_onboarding_runtime_operations(
                    operation_key_sha256, runtime_record_id, request_sha256, receipt_json, created_at_epoch
                ) VALUES(?,?,?,?,?)""",
                (
                    operation_key_sha256,
                    after.runtime_record_id,
                    request_sha256,
                    canonical_json(receipt.to_dict()),
                    now_epoch,
                ),
            )
            return after, receipt

    def consume(
        self,
        invitation_id: str,
        *,
        expected_version: int,
        now_epoch: int,
        onboarding_code: str,
        operation_key_sha256: str,
        request_sha256: str,
        receipt_factory: ReceiptFactory,
    ) -> tuple[QrOnboardingRuntimeRecord, QrOnboardingOperationReceipt]:
        return self._transition(
            invitation_id,
            expected_version=expected_version,
            now_epoch=now_epoch,
            onboarding_code=onboarding_code,
            operation_key_sha256=operation_key_sha256,
            request_sha256=request_sha256,
            target_state=InvitationState.CONSUMED,
            receipt_factory=receipt_factory,
        )

    def revoke(
        self,
        invitation_id: str,
        *,
        expected_version: int,
        now_epoch: int,
        operation_key_sha256: str,
        request_sha256: str,
        receipt_factory: ReceiptFactory,
    ) -> tuple[QrOnboardingRuntimeRecord, QrOnboardingOperationReceipt]:
        return self._transition(
            invitation_id,
            expected_version=expected_version,
            now_epoch=now_epoch,
            onboarding_code=None,
            operation_key_sha256=operation_key_sha256,
            request_sha256=request_sha256,
            target_state=InvitationState.REVOKED,
            receipt_factory=receipt_factory,
        )


def _idempotency_digest(*, actor: str, operation: RuntimeOperation, idempotency_key: str) -> str:
    if not isinstance(actor, str) or not actor or len(actor) > 128:
        raise QrOnboardingRuntimeError("qr_runtime_actor_invalid")
    if not isinstance(idempotency_key, str) or not _IDEMPOTENCY.fullmatch(idempotency_key):
        raise QrOnboardingRuntimeError("qr_runtime_idempotency_key_invalid")
    return hashlib.sha256(
        canonical_json(
            {"actor": actor, "operation": operation.value, "idempotency_key": idempotency_key}
        ).encode("utf-8")
    ).hexdigest()


def _receipt(
    *,
    operation: RuntimeOperation,
    before: QrOnboardingRuntimeRecord | None,
    after: QrOnboardingRuntimeRecord,
    now_epoch: int,
) -> QrOnboardingOperationReceipt:
    if operation is RuntimeOperation.ISSUE:
        next_boundary = "explicit-qr-presentation-and-redemption"
    elif operation is RuntimeOperation.CONSUME:
        next_boundary = (
            "typed-guest-access-change-job"
            if after.invitation.subject is OnboardingSubject.GUEST
            else "typed-device-binding-change-job"
        )
    else:
        next_boundary = "typed-access-revocation-change-job"
    material = {
        "operation": operation.value,
        "runtime_record_id": after.runtime_record_id,
        "invitation_id": after.invitation.invitation_id,
        "household_id": after.invitation.household_id,
        "household_snapshot_id": after.household_snapshot_id,
        "household_resource_version": after.household_resource_version,
        "household_generation": after.household_generation,
        "target_member_id": after.target_member_id,
        "before_state": before.state.value if before else None,
        "after_state": after.state.value,
        "record_version": after.version,
        "occurred_at_epoch": now_epoch,
        "invitation_evidence_sha256": after.invitation_evidence_sha256,
        "next_required_boundary": next_boundary,
    }
    receipt_id = "hcqro-" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:24]
    return QrOnboardingOperationReceipt(
        receipt_id=receipt_id,
        operation=operation,
        runtime_record_id=after.runtime_record_id,
        invitation_id=after.invitation.invitation_id,
        household_id=after.invitation.household_id,
        household_snapshot_id=after.household_snapshot_id,
        household_resource_version=after.household_resource_version,
        household_generation=after.household_generation,
        target_member_id=after.target_member_id,
        before_state=before.state if before else None,
        after_state=after.state,
        record_version=after.version,
        occurred_at_epoch=now_epoch,
        invitation_evidence_sha256=after.invitation_evidence_sha256,
        next_required_boundary=next_boundary,
    )


class QrOnboardingRuntimeService:
    def __init__(self, repository: QrOnboardingRuntimeRepository) -> None:
        self.repository = repository

    @staticmethod
    def _member(snapshot: HouseholdSnapshot, member_id: str):
        member = next((item for item in snapshot.household.members if item.member_id == member_id), None)
        if member is None or not member.enabled:
            raise QrOnboardingRuntimeError("qr_runtime_member_unavailable")
        return member

    @classmethod
    def _require_parent(cls, snapshot: HouseholdSnapshot, member_id: str) -> None:
        member = cls._member(snapshot, member_id)
        if member.role is not HouseholdRole.PARENT:
            raise QrOnboardingRuntimeError("qr_runtime_parent_required")

    @staticmethod
    def _assert_binding(record: QrOnboardingRuntimeRecord, snapshot: HouseholdSnapshot) -> None:
        if (
            snapshot.household_id != record.invitation.household_id
            or snapshot.snapshot_id != record.household_snapshot_id
            or snapshot.resource_version != record.household_resource_version
            or snapshot.generation != record.household_generation
        ):
            raise QrOnboardingRuntimeError("qr_runtime_household_state_stale")

    def issue(
        self,
        *,
        snapshot: HouseholdSnapshot,
        issuer_member_id: str,
        target_member_id: str,
        subject: OnboardingSubject,
        created_at_epoch: int,
        expires_at_epoch: int,
        device_id: str | None = None,
        guest_scope: tuple[GuestScope, ...] = (),
        onboarding_code: str | None = None,
    ) -> QrOnboardingIssueResult:
        self._require_parent(snapshot, issuer_member_id)
        target = self._member(snapshot, target_member_id)
        if subject is OnboardingSubject.GUEST:
            if target.role is not HouseholdRole.GUEST:
                raise QrOnboardingRuntimeError("qr_runtime_guest_member_required")
            if guest_scope != (GuestScope.INTERNET_GUEST,):
                raise QrOnboardingRuntimeError("qr_runtime_guest_scope_not_bounded")
            if device_id is not None:
                raise QrOnboardingRuntimeError("qr_runtime_guest_device_invalid")
        elif subject is OnboardingSubject.DEVICE:
            if guest_scope:
                raise QrOnboardingRuntimeError("qr_runtime_device_scope_invalid")
            device = next(
                (
                    item
                    for item in snapshot.household.devices
                    if item.device_id == device_id and item.member_id == target_member_id
                ),
                None,
            )
            if device is None:
                raise QrOnboardingRuntimeError("qr_runtime_device_not_registered")
            if device.managed:
                raise QrOnboardingRuntimeError("qr_runtime_device_already_managed")
        else:
            raise QrOnboardingRuntimeError("qr_runtime_subject_invalid")

        raw_code = onboarding_code or secrets.token_urlsafe(32)
        invitation = build_qr_onboarding_invitation(
            household_id=snapshot.household_id,
            issuer_member_id=issuer_member_id,
            issuer_role=HouseholdRole.PARENT,
            subject=subject,
            onboarding_code=raw_code,
            created_at_epoch=created_at_epoch,
            expires_at_epoch=expires_at_epoch,
            device_id=device_id,
            guest_scope=guest_scope,
        )
        evidence_sha = hashlib.sha256(
            canonical_json(invitation.to_dict()).encode("utf-8")
        ).hexdigest()
        material = {
            "invitation_id": invitation.invitation_id,
            "household_id": snapshot.household_id,
            "household_snapshot_id": snapshot.snapshot_id,
            "household_resource_version": snapshot.resource_version,
            "household_generation": snapshot.generation,
            "target_member_id": target_member_id,
            "invitation_evidence_sha256": evidence_sha,
        }
        record = QrOnboardingRuntimeRecord(
            runtime_record_id="hcqrr-"
            + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:24],
            invitation=invitation,
            household_snapshot_id=snapshot.snapshot_id,
            household_resource_version=snapshot.resource_version,
            household_generation=snapshot.generation,
            target_member_id=target_member_id,
            invitation_evidence_sha256=evidence_sha,
            state=InvitationState.ACTIVE,
            version=1,
            updated_at_epoch=created_at_epoch,
        )
        receipt = _receipt(
            operation=RuntimeOperation.ISSUE,
            before=None,
            after=record,
            now_epoch=created_at_epoch,
        )
        self.repository.create(record, receipt)
        return QrOnboardingIssueResult(
            record=record,
            payload=build_qr_payload(invitation=invitation, onboarding_code=raw_code),
            receipt=receipt,
        )

    def plan_redemption(
        self,
        *,
        snapshot: HouseholdSnapshot,
        invitation_id: str,
        onboarding_code: str,
        now_epoch: int,
    ) -> QrOnboardingRedemptionPlan:
        record = self.repository.get(invitation_id, now_epoch=now_epoch)
        if record is None:
            raise QrOnboardingRuntimeError("qr_runtime_invitation_not_found")
        self._assert_binding(record, snapshot)
        self._member(snapshot, record.target_member_id)
        try:
            return plan_qr_redemption(
                invitation=record.invitation,
                onboarding_code=onboarding_code,
                now_epoch=now_epoch,
                revoked=record.state is InvitationState.REVOKED,
                consumed=record.state is InvitationState.CONSUMED,
            )
        except QrOnboardingError as exc:
            raise QrOnboardingRuntimeError(exc.code) from exc

    def consume(
        self,
        *,
        snapshot: HouseholdSnapshot,
        plan: QrOnboardingRedemptionPlan,
        onboarding_code: str,
        actor: str,
        idempotency_key: str,
        confirmed: bool,
        expected_version: int,
        now_epoch: int,
    ) -> tuple[QrOnboardingRuntimeRecord, QrOnboardingOperationReceipt]:
        if confirmed is not True:
            raise QrOnboardingRuntimeError("qr_runtime_confirmation_required")
        record = self.repository.get(plan.invitation_id, now_epoch=now_epoch)
        if record is None:
            raise QrOnboardingRuntimeError("qr_runtime_invitation_not_found")
        self._assert_binding(record, snapshot)
        self._member(snapshot, record.target_member_id)
        try:
            expected_plan = plan_qr_redemption(
                invitation=record.invitation,
                onboarding_code=onboarding_code,
                now_epoch=plan.presented_at_epoch,
                revoked=False,
                consumed=False,
            )
        except QrOnboardingError as exc:
            raise QrOnboardingRuntimeError(exc.code) from exc
        if expected_plan.to_dict() != plan.to_dict():
            raise QrOnboardingRuntimeError("qr_runtime_redemption_plan_stale")
        operation_key = _idempotency_digest(
            actor=actor, operation=RuntimeOperation.CONSUME, idempotency_key=idempotency_key
        )
        request_sha = hashlib.sha256(
            canonical_json(
                {"plan": plan.to_dict(), "expected_version": expected_version, "confirmed": True}
            ).encode("utf-8")
        ).hexdigest()

        def receipt_factory(before: QrOnboardingRuntimeRecord, after: QrOnboardingRuntimeRecord):
            return _receipt(
                operation=RuntimeOperation.CONSUME,
                before=before,
                after=after,
                now_epoch=now_epoch,
            )

        return self.repository.consume(
            plan.invitation_id,
            expected_version=expected_version,
            now_epoch=now_epoch,
            onboarding_code=onboarding_code,
            operation_key_sha256=operation_key,
            request_sha256=request_sha,
            receipt_factory=receipt_factory,
        )

    def revoke(
        self,
        *,
        snapshot: HouseholdSnapshot,
        invitation_id: str,
        actor_member_id: str,
        idempotency_key: str,
        expected_version: int,
        now_epoch: int,
    ) -> tuple[QrOnboardingRuntimeRecord, QrOnboardingOperationReceipt]:
        self._require_parent(snapshot, actor_member_id)
        record = self.repository.get(invitation_id, now_epoch=now_epoch)
        if record is None:
            raise QrOnboardingRuntimeError("qr_runtime_invitation_not_found")
        self._assert_binding(record, snapshot)
        operation_key = _idempotency_digest(
            actor=actor_member_id, operation=RuntimeOperation.REVOKE, idempotency_key=idempotency_key
        )
        request_sha = hashlib.sha256(
            canonical_json(
                {
                    "invitation_id": invitation_id,
                    "expected_version": expected_version,
                    "household_snapshot_id": snapshot.snapshot_id,
                }
            ).encode("utf-8")
        ).hexdigest()

        def receipt_factory(before: QrOnboardingRuntimeRecord, after: QrOnboardingRuntimeRecord):
            return _receipt(
                operation=RuntimeOperation.REVOKE,
                before=before,
                after=after,
                now_epoch=now_epoch,
            )

        return self.repository.revoke(
            invitation_id,
            expected_version=expected_version,
            now_epoch=now_epoch,
            operation_key_sha256=operation_key,
            request_sha256=request_sha,
            receipt_factory=receipt_factory,
        )
