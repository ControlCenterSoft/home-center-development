from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_enrollment_post_condition_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    KEY_PREFIX,
    PLAN_SCHEMA,
    STATE_SCHEMA,
    DeviceManagementEnrollmentPostConditionRuntimeError,
)
from home_center.device_management_enrollment_post_condition_runtime_qualified import (
    QUALIFICATION_BINDING_FIELD,
    ContractQualifiedDeviceManagementEnrollmentPostConditionRuntimeService,
)
from home_center.device_management_enrollment_verification import RESULT_SCHEMA, SIGNAL_NAMES
from home_center.device_management_verifier_qualification import (
    PROFILE_SCHEMA,
    RECEIPT_SCHEMA,
    DeviceManagementVerifierQualificationError,
    qualify_read_back_adapter,
    validate_contract_qualification_receipt,
)
from home_center.step_up import StepUpGrantManager
from home_center.store import StateStore


PROVIDER = "android.mdm"
SOURCE_SHA = "a" * 64


class ContractVerifier:
    verification_read_only = True
    verifier_id = "android.mdm.readback"
    verifier_revision = "v1"
    result_schema = RESULT_SCHEMA
    signals = SIGNAL_NAMES

    def __init__(self) -> None:
        self.calls = 0

    def read_back(self, request: dict[str, object]) -> object:
        self.calls += 1
        raise AssertionError("contract qualification must not contact the provider")


def _profile(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": PROFILE_SCHEMA,
        "provider_id": PROVIDER,
        "verifier_id": "android.mdm.readback",
        "verifier_revision": "v1",
        "result_schema": RESULT_SCHEMA,
        "signals": list(SIGNAL_NAMES),
        "verification_read_only": True,
        "source_sha256": SOURCE_SHA,
    }
    value.update(overrides)
    return value


def _service(
    tmp_path: Path,
) -> tuple[StateStore, ContractQualifiedDeviceManagementEnrollmentPostConditionRuntimeService]:
    store = StateStore(tmp_path / "state.db", b"q" * 32, "cluster-test")
    return store, ContractQualifiedDeviceManagementEnrollmentPostConditionRuntimeService(
        store,
        StepUpGrantManager(),
    )


def test_contract_qualification_is_deterministic_read_only_and_never_claims_production() -> None:
    adapter = ContractVerifier()

    first = qualify_read_back_adapter(
        provider_id=PROVIDER,
        adapter=adapter,
        profile=_profile(),
    )
    second = qualify_read_back_adapter(
        provider_id=PROVIDER,
        adapter=adapter,
        profile=_profile(),
    )

    assert first == second
    assert first["schema"] == RECEIPT_SCHEMA
    assert first["state"] == "contract-qualified"
    assert first["qualification_level"] == "contract-only"
    assert first["production_qualified"] is False
    assert first["provider_read_performed"] is False
    assert first["provider_mutation_authorized"] is False
    assert first["managed_state_change_authorized"] is False
    assert first["policy_application_authorized"] is False
    assert first["infrastructure_mutation_authorized"] is False
    assert first["external_publication_authorized"] is False
    assert adapter.calls == 0


@pytest.mark.parametrize(
    ("profile", "mutator", "code"),
    (
        (_profile(provider_id="other.mdm"), None, "device_management_enrollment_verifier_provider_mismatch"),
        (_profile(result_schema="wrong"), None, "device_management_enrollment_verifier_profile_rejected"),
        (_profile(signals=["certificate", "profile"]), None, "device_management_enrollment_verifier_profile_rejected"),
        (_profile(verification_read_only=False), None, "device_management_enrollment_verifier_profile_rejected"),
        (_profile(source_sha256="not-a-sha"), None, "device_management_enrollment_verifier_profile_rejected"),
        (_profile(), "writable", "device_management_enrollment_verifier_not_read_only"),
        (_profile(), "revision", "device_management_enrollment_verifier_descriptor_mismatch"),
    ),
)
def test_contract_qualification_rejects_unsafe_or_mismatched_descriptors(
    profile: dict[str, object],
    mutator: str | None,
    code: str,
) -> None:
    adapter = ContractVerifier()
    if mutator == "writable":
        adapter.verification_read_only = False  # type: ignore[assignment]
    elif mutator == "revision":
        adapter.verifier_revision = "v2"  # type: ignore[assignment]

    with pytest.raises(DeviceManagementVerifierQualificationError, match=code):
        qualify_read_back_adapter(
            provider_id=PROVIDER,
            adapter=adapter,
            profile=profile,
        )
    assert adapter.calls == 0


def test_profile_is_closed_and_rejects_unexpected_authority_fields() -> None:
    profile = _profile()
    profile["production_qualified"] = True

    with pytest.raises(
        DeviceManagementVerifierQualificationError,
        match="device_management_enrollment_verifier_profile_rejected",
    ):
        qualify_read_back_adapter(
            provider_id=PROVIDER,
            adapter=ContractVerifier(),
            profile=profile,
        )


def test_contract_receipt_revalidation_rejects_authority_escalation_without_provider_io() -> None:
    adapter = ContractVerifier()
    receipt = qualify_read_back_adapter(
        provider_id=PROVIDER,
        adapter=adapter,
        profile=_profile(),
    )
    receipt["production_qualified"] = True

    with pytest.raises(
        DeviceManagementVerifierQualificationError,
        match="device_management_enrollment_verifier_qualification_receipt_rejected",
    ):
        validate_contract_qualification_receipt(
            provider_id=PROVIDER,
            adapter=adapter,
            receipt=receipt,
        )
    assert adapter.calls == 0


def test_strict_runtime_registry_requires_contract_qualification_without_provider_io(tmp_path: Path) -> None:
    store, service = _service(tmp_path)
    adapter = ContractVerifier()

    with pytest.raises(
        DeviceManagementVerifierQualificationError,
        match="device_management_enrollment_verifier_qualification_required",
    ):
        service.register_adapter(PROVIDER, adapter)
    assert adapter.calls == 0
    assert service.adapter_qualification(PROVIDER) is None

    receipt = service.register_adapter(
        PROVIDER,
        adapter,
        qualification_profile=_profile(),
    )
    assert receipt["provider_id"] == PROVIDER
    assert receipt["verification_read_only"] is True
    assert service.adapter_qualification(PROVIDER) == receipt
    assert adapter.calls == 0
    store.close()


def test_registered_adapter_descriptor_drift_fails_closed_before_provider_io(tmp_path: Path) -> None:
    store, service = _service(tmp_path)
    adapter = ContractVerifier()
    service.register_adapter(PROVIDER, adapter, qualification_profile=_profile())

    adapter.verifier_revision = "v2"  # type: ignore[assignment]

    with pytest.raises(
        DeviceManagementEnrollmentPostConditionRuntimeError,
        match="device_management_enrollment_verifier_qualification_stale",
    ):
        service._adapter(PROVIDER)
    assert adapter.calls == 0
    assert store.jobs() == []
    store.close()


def test_confirm_rejects_mismatched_durable_qualification_before_step_up_or_provider_io(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    adapter = ContractVerifier()
    receipt = service.register_adapter(PROVIDER, adapter, qualification_profile=_profile())

    verification_id = "dmpverify-" + ("1" * 24)
    tampered = dict(receipt)
    tampered["verifier_revision"] = "v0"
    store.set_meta(
        KEY_PREFIX + verification_id,
        {
            "schema": STATE_SCHEMA,
            "status": "planned",
            "plan": {
                "schema": PLAN_SCHEMA,
                "verification_id": verification_id,
                "provider_id": PROVIDER,
            },
            QUALIFICATION_BINDING_FIELD: tampered,
        },
    )

    with pytest.raises(
        DeviceManagementEnrollmentPostConditionRuntimeError,
        match="device_management_enrollment_verifier_qualification_binding_mismatch",
    ):
        service.confirm(
            actor="user:test",
            request={
                "schema": CONFIRM_REQUEST_SCHEMA,
                "verification_id": verification_id,
                "idempotency_key": "qual-binding-1",
                "confirmed": True,
            },
            step_up_token="not-consumed",
            correlation_id="test-qualification-binding",
        )

    assert adapter.calls == 0
    assert store.jobs() == []
    store.close()
