"""Read-back verification for durable Home Center service-state transitions."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from home_center.home_service_state import HomeServiceInstanceStateStore
from home_center.home_service_transition_apply import HomeServiceTransitionApplyReceipt
from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.util import canonical_json


VERIFICATION_SCHEMA = "home-center.home-service-transition-verification.v1"


class TransitionVerificationStatus(StrEnum):
    VERIFIED = "verified"
    DRIFTED = "drifted"


class TransitionVerificationCode(StrEnum):
    INSTANCE_NOT_FOUND = "instance_not_found"
    STATE_MISMATCH = "state_mismatch"
    GENERATION_MISMATCH = "generation_mismatch"
    RESOURCE_VERSION_MISMATCH = "resource_version_mismatch"


@dataclass(frozen=True, slots=True)
class HomeServiceTransitionVerification:
    verification_id: str
    receipt_id: str
    authorization_id: str
    commit_id: str
    decision_id: str
    instance_id: str
    expected_state: str
    expected_generation: int
    expected_resource_version: str
    observed_state: str | None
    observed_generation: int | None
    observed_resource_version: str | None
    status: TransitionVerificationStatus
    mismatch_codes: tuple[TransitionVerificationCode, ...]
    schema: str = field(default=VERIFICATION_SCHEMA, init=False)
    evidence_record_only: bool = field(default=True, init=False)
    verified: bool = field(default=False, init=False)
    further_mutation_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        for name in (
            "verification_id",
            "receipt_id",
            "authorization_id",
            "commit_id",
            "decision_id",
            "instance_id",
            "expected_resource_version",
        ):
            object.__setattr__(self, name, _identifier(getattr(self, name), f"invalid_{name}"))
        if self.observed_resource_version is not None:
            object.__setattr__(
                self,
                "observed_resource_version",
                _identifier(self.observed_resource_version, "invalid_observed_resource_version"),
            )
        if (
            not isinstance(self.expected_generation, int)
            or isinstance(self.expected_generation, bool)
            or self.expected_generation < 1
        ):
            raise HomeServiceCatalogError("invalid_transition_generation")
        if self.observed_generation is not None and (
            not isinstance(self.observed_generation, int)
            or isinstance(self.observed_generation, bool)
            or self.observed_generation < 1
        ):
            raise HomeServiceCatalogError("invalid_observed_transition_generation")
        if not isinstance(self.status, TransitionVerificationStatus):
            raise HomeServiceCatalogError("invalid_transition_verification_status")
        verified = self.status is TransitionVerificationStatus.VERIFIED
        if verified == bool(self.mismatch_codes):
            raise HomeServiceCatalogError("invalid_transition_verification")
        object.__setattr__(self, "verified", verified)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "verification_id": self.verification_id,
            "receipt_id": self.receipt_id,
            "authorization_id": self.authorization_id,
            "commit_id": self.commit_id,
            "decision_id": self.decision_id,
            "instance_id": self.instance_id,
            "expected_state": self.expected_state,
            "expected_generation": self.expected_generation,
            "expected_resource_version": self.expected_resource_version,
            "observed_state": self.observed_state,
            "observed_generation": self.observed_generation,
            "observed_resource_version": self.observed_resource_version,
            "status": self.status.value,
            "mismatch_codes": [code.value for code in self.mismatch_codes],
            "evidence_record_only": True,
            "verified": self.verified,
            "further_mutation_authorized": False,
            "production_mutation_enabled": False,
        }


def verify_transition_apply(
    receipt: HomeServiceTransitionApplyReceipt,
    instances: HomeServiceInstanceStateStore,
) -> HomeServiceTransitionVerification:
    """Read durable state and verify it exactly matches the apply receipt."""

    if not isinstance(receipt, HomeServiceTransitionApplyReceipt):
        raise TypeError("invalid_transition_apply_receipt")
    if not isinstance(instances, HomeServiceInstanceStateStore):
        raise TypeError("invalid_instance_state_store")
    if receipt.further_mutation_authorized is not False:
        raise HomeServiceCatalogError("unsafe_transition_apply_receipt")
    if receipt.applied == receipt.idempotent_replay:
        raise HomeServiceCatalogError("invalid_transition_apply_receipt")

    current = instances.get(receipt.instance_id)
    mismatch_codes: list[TransitionVerificationCode] = []
    if current is None:
        mismatch_codes.append(TransitionVerificationCode.INSTANCE_NOT_FOUND)
        observed_state = None
        observed_generation = None
        observed_resource_version = None
    else:
        observed_state = str(current["state"])
        observed_generation = int(current["generation"])
        observed_resource_version = str(current["resource_version"])
        if observed_state != receipt.target_state:
            mismatch_codes.append(TransitionVerificationCode.STATE_MISMATCH)
        if observed_generation != receipt.generation:
            mismatch_codes.append(TransitionVerificationCode.GENERATION_MISMATCH)
        if observed_resource_version != receipt.resource_version:
            mismatch_codes.append(TransitionVerificationCode.RESOURCE_VERSION_MISMATCH)

    codes = tuple(mismatch_codes)
    status = TransitionVerificationStatus.DRIFTED if codes else TransitionVerificationStatus.VERIFIED
    material = {
        "receipt_id": receipt.receipt_id,
        "authorization_id": receipt.authorization_id,
        "commit_id": receipt.commit_id,
        "decision_id": receipt.decision_id,
        "instance_id": receipt.instance_id,
        "expected_state": receipt.target_state,
        "expected_generation": receipt.generation,
        "expected_resource_version": receipt.resource_version,
        "observed_state": observed_state,
        "observed_generation": observed_generation,
        "observed_resource_version": observed_resource_version,
        "mismatch_codes": [code.value for code in codes],
    }
    digest = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
    return HomeServiceTransitionVerification(
        verification_id=f"hstv-{digest[:24]}",
        receipt_id=receipt.receipt_id,
        authorization_id=receipt.authorization_id,
        commit_id=receipt.commit_id,
        decision_id=receipt.decision_id,
        instance_id=receipt.instance_id,
        expected_state=receipt.target_state,
        expected_generation=receipt.generation,
        expected_resource_version=receipt.resource_version,
        observed_state=observed_state,
        observed_generation=observed_generation,
        observed_resource_version=observed_resource_version,
        status=status,
        mismatch_codes=codes,
    )
