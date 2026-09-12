"""Contract-only qualification for Home Center 0.58 enrollment read-back verifiers.

This module proves only that an adapter exposes the exact static, read-only contract
expected by the 0.58 post-condition runtime. It deliberately does *not* perform a
provider call and never represents real-environment/provider qualification.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Protocol

from .device_management_enrollment_verification import RESULT_SCHEMA, SIGNAL_NAMES


PROFILE_SCHEMA = "home-center.device-management-enrollment-verifier-profile.v1"
RECEIPT_SCHEMA = "home-center.device-management-enrollment-verifier-contract-qualification-receipt.v1"
QUALIFICATION_LEVEL = "contract-only"
PROVIDER_ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
VERIFIER_ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DeviceManagementVerifierQualificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ContractQualifiedReadBackAdapter(Protocol):
    verification_read_only: bool
    verifier_id: str
    verifier_revision: str
    result_schema: str
    signals: tuple[str, ...]

    def read_back(self, request: dict[str, object]) -> object: ...


def _sha256(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _profile(value: object) -> dict[str, object]:
    expected = {
        "schema",
        "provider_id",
        "verifier_id",
        "verifier_revision",
        "result_schema",
        "signals",
        "verification_read_only",
        "source_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementVerifierQualificationError(
            "device_management_enrollment_verifier_profile_rejected"
        )
    raw = dict(value)
    provider_id = raw.get("provider_id")
    verifier_id = raw.get("verifier_id")
    revision = raw.get("verifier_revision")
    source_sha256 = raw.get("source_sha256")
    signals = raw.get("signals")
    if (
        raw.get("schema") != PROFILE_SCHEMA
        or not isinstance(provider_id, str)
        or PROVIDER_ID.fullmatch(provider_id) is None
        or not isinstance(verifier_id, str)
        or VERIFIER_ID.fullmatch(verifier_id) is None
        or not isinstance(revision, str)
        or REVISION.fullmatch(revision) is None
        or raw.get("result_schema") != RESULT_SCHEMA
        or signals != list(SIGNAL_NAMES)
        or raw.get("verification_read_only") is not True
        or not isinstance(source_sha256, str)
        or SHA256.fullmatch(source_sha256) is None
    ):
        raise DeviceManagementVerifierQualificationError(
            "device_management_enrollment_verifier_profile_rejected"
        )
    return raw


def qualify_read_back_adapter(
    *,
    provider_id: object,
    adapter: object,
    profile: object,
) -> dict[str, object]:
    """Return deterministic static qualification evidence without contacting a provider."""
    raw = _profile(profile)
    if raw["provider_id"] != provider_id:
        raise DeviceManagementVerifierQualificationError(
            "device_management_enrollment_verifier_provider_mismatch"
        )
    if (
        getattr(adapter, "verification_read_only", None) is not True
        or not callable(getattr(adapter, "read_back", None))
    ):
        raise DeviceManagementVerifierQualificationError(
            "device_management_enrollment_verifier_not_read_only"
        )

    declared_signals = getattr(adapter, "signals", None)
    if isinstance(declared_signals, list):
        declared_signals = tuple(declared_signals)
    if (
        getattr(adapter, "verifier_id", None) != raw["verifier_id"]
        or getattr(adapter, "verifier_revision", None) != raw["verifier_revision"]
        or getattr(adapter, "result_schema", None) != RESULT_SCHEMA
        or declared_signals != tuple(SIGNAL_NAMES)
    ):
        raise DeviceManagementVerifierQualificationError(
            "device_management_enrollment_verifier_descriptor_mismatch"
        )

    return {
        "schema": RECEIPT_SCHEMA,
        "state": "contract-qualified",
        "qualification_level": QUALIFICATION_LEVEL,
        "provider_id": raw["provider_id"],
        "verifier_id": raw["verifier_id"],
        "verifier_revision": raw["verifier_revision"],
        "result_schema": RESULT_SCHEMA,
        "signals": list(SIGNAL_NAMES),
        "verification_read_only": True,
        "source_sha256": raw["source_sha256"],
        "profile_sha256": _sha256(raw),
        "provider_read_performed": False,
        "production_qualified": False,
        "provider_mutation_authorized": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
