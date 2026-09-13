"""Read-only source of exact QR effect handoffs from durable terminal invitation state.

The QR HTTP/runtime layer persists the invitation transition before any product
effect is admitted. This service reconstructs the exact consume/revoke operation
receipt and converts it to the existing closed effect handoff without trusting a
client-supplied handoff. It never creates a Job, executes an effect, grants provider
or infrastructure authority, or changes QR state.
"""
from __future__ import annotations

from .household_store import HouseholdSnapshot
from .qr_onboarding import InvitationState
from .qr_onboarding_effect_handoff import (
    QrOnboardingEffectHandoff,
    QrOnboardingEffectHandoffError,
    build_qr_onboarding_effect_handoff,
)
from .qr_onboarding_runtime import (
    QrOnboardingRuntimeError,
    QrOnboardingRuntimeRecord,
    QrOnboardingOperationReceipt,
    RuntimeOperation,
    SQLiteQrOnboardingRuntimeRepository,
    _receipt_from_json,
)


class QrOnboardingEffectSourceError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class QrOnboardingEffectSourceService:
    """Recover one exact terminal QR transition as a non-authorizing handoff."""

    def __init__(self, repository: SQLiteQrOnboardingRuntimeRepository) -> None:
        if not isinstance(repository, SQLiteQrOnboardingRuntimeRepository):
            raise QrOnboardingEffectSourceError("qr_effect_source_repository_invalid")
        self.repository = repository

    @staticmethod
    def _validate_snapshot(record: QrOnboardingRuntimeRecord, snapshot: HouseholdSnapshot) -> None:
        if not isinstance(snapshot, HouseholdSnapshot):
            raise QrOnboardingEffectSourceError("qr_effect_source_snapshot_invalid")
        if (
            snapshot.household_id != record.invitation.household_id
            or snapshot.snapshot_id != record.household_snapshot_id
            or snapshot.resource_version != record.household_resource_version
            or snapshot.generation != record.household_generation
        ):
            raise QrOnboardingEffectSourceError("qr_effect_source_household_state_stale")
        member = next(
            (item for item in snapshot.household.members if item.member_id == record.target_member_id),
            None,
        )
        if member is None or not member.enabled:
            raise QrOnboardingEffectSourceError("qr_effect_source_target_member_unavailable")

    @staticmethod
    def _terminal_receipt_matches(
        record: QrOnboardingRuntimeRecord,
        receipt: QrOnboardingOperationReceipt,
    ) -> bool:
        expected_operation = (
            RuntimeOperation.CONSUME
            if record.state is InvitationState.CONSUMED
            else RuntimeOperation.REVOKE
        )
        return bool(
            receipt.operation is expected_operation
            and receipt.runtime_record_id == record.runtime_record_id
            and receipt.invitation_id == record.invitation.invitation_id
            and receipt.household_id == record.invitation.household_id
            and receipt.household_snapshot_id == record.household_snapshot_id
            and receipt.household_resource_version == record.household_resource_version
            and receipt.household_generation == record.household_generation
            and receipt.target_member_id == record.target_member_id
            and receipt.after_state is record.state
            and receipt.record_version == record.version
            and receipt.invitation_evidence_sha256 == record.invitation_evidence_sha256
        )

    def recover(
        self,
        *,
        snapshot: HouseholdSnapshot,
        invitation_id: str,
        now_epoch: int,
    ) -> QrOnboardingEffectHandoff:
        if not isinstance(invitation_id, str) or not invitation_id.startswith("hcqri-"):
            raise QrOnboardingEffectSourceError("qr_effect_source_invitation_id_invalid")
        if type(now_epoch) is not int or now_epoch < 0:
            raise QrOnboardingEffectSourceError("qr_effect_source_now_invalid")

        try:
            record = self.repository.get(invitation_id, now_epoch=now_epoch)
        except QrOnboardingRuntimeError as exc:
            raise QrOnboardingEffectSourceError(exc.code) from exc
        if record is None:
            raise QrOnboardingEffectSourceError("qr_effect_source_invitation_missing")
        if record.state not in {InvitationState.CONSUMED, InvitationState.REVOKED}:
            raise QrOnboardingEffectSourceError("qr_effect_source_invitation_not_terminal")
        self._validate_snapshot(record, snapshot)

        with self.repository._lock, self.repository._connection:  # noqa: SLF001 - same-package read-only boundary
            rows = self.repository._connection.execute(  # noqa: SLF001
                """SELECT receipt_json
                   FROM qr_onboarding_runtime_operations
                   WHERE runtime_record_id=?
                   ORDER BY created_at_epoch, operation_key_sha256""",
                (record.runtime_record_id,),
            ).fetchall()
        receipts: list[QrOnboardingOperationReceipt] = []
        for row in rows:
            try:
                receipt = _receipt_from_json(row["receipt_json"])
            except (QrOnboardingRuntimeError, KeyError, TypeError, ValueError) as exc:
                raise QrOnboardingEffectSourceError("qr_effect_source_receipt_storage_rejected") from exc
            if self._terminal_receipt_matches(record, receipt):
                receipts.append(receipt)
        if len(receipts) != 1:
            raise QrOnboardingEffectSourceError("qr_effect_source_terminal_receipt_ambiguous")

        try:
            handoff = build_qr_onboarding_effect_handoff(receipt=receipts[0], record=record)
        except (QrOnboardingEffectHandoffError, QrOnboardingRuntimeError) as exc:
            raise QrOnboardingEffectSourceError("qr_effect_source_handoff_rejected") from exc
        if (
            handoff.effect_execution_authorized is not False
            or handoff.account_creation_authorized is not False
            or handoff.device_registration_authorized is not False
            or handoff.managed_state_change_authorized is not False
            or handoff.provider_execution_authorized is not False
            or handoff.infrastructure_mutation_authorized is not False
            or handoff.external_publication_authorized is not False
        ):
            raise QrOnboardingEffectSourceError("qr_effect_source_authority_invalid")
        return handoff
