#!/usr/bin/env python3
"""Evaluate exact-bound Home Center provider-adapter evidence locally.

The tool is runner-free and mutation-free. It binds a closed evidence manifest to
an exact Home Center candidate artifact, provider adapter artifact, execution
transcript and real-environment qualification decision by recomputing SHA-256
locally. It never invokes a provider, reads credentials, deploys software,
grants release authority, or publishes artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "product/control-plane/src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from home_center.provider_adapter_qualification import (  # noqa: E402
    ProviderAdapterQualificationDecision,
    ProviderAdapterQualificationError,
    ProviderAdapterQualificationEvidence,
    evaluate_provider_adapter_qualification,
)

INPUT_SCHEMA = "home-center.provider-adapter-evidence.v1"
REAL_ENVIRONMENT_DECISION_SCHEMA = "home-center.real-environment-qualification.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_INPUT_KEYS = {
    "schema",
    "version",
    "revision",
    "adapter_id",
    "adapter_version",
    "candidate_artifact_sha256",
    "adapter_artifact_sha256",
    "execution_transcript_sha256",
    "environment_evidence_sha256",
    "real_provider_exercised",
    "real_target_exercised",
    "start_contract_validated",
    "cancel_contract_validated",
    "secret_reference_only",
    "secret_values_absent_from_evidence",
    "retry_safe_only_when_proven",
    "ambiguous_outcome_fail_closed",
    "post_condition_separate",
    "managed_state_change_forbidden",
}
_ENVIRONMENT_DECISION_KEYS = {
    "schema",
    "version",
    "revision",
    "candidate_artifact_sha256",
    "evidence_sha256",
    "qualified",
    "blockers",
    "release_authorized",
    "external_publication_authorized",
}
_BOOLEAN_KEYS = {
    "real_provider_exercised",
    "real_target_exercised",
    "start_contract_validated",
    "cancel_contract_validated",
    "secret_reference_only",
    "secret_values_absent_from_evidence",
    "retry_safe_only_when_proven",
    "ambiguous_outcome_fail_closed",
    "post_condition_separate",
    "managed_state_change_forbidden",
}
_DIGEST_BINDINGS = (
    ("candidate_artifact_sha256", "candidate_artifact_digest_mismatch"),
    ("adapter_artifact_sha256", "adapter_artifact_digest_mismatch"),
    ("execution_transcript_sha256", "execution_transcript_digest_mismatch"),
)


class ProviderAdapterEvidenceInputError(ValueError):
    """Reject unsafe, malformed, or incorrectly bound local evidence input."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ProviderAdapterEvidenceInputError(code)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProviderAdapterEvidenceInputError("json_duplicate_key")
        value[key] = item
    return value


def _load_json(path: Path, *, code: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_object_pairs,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderAdapterEvidenceInputError(code) from exc
    _require(isinstance(value, dict), f"{code}_not_object")
    return dict(value)


def _sha256_regular_file(path: Path, *, code: str) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProviderAdapterEvidenceInputError(code) from exc

    digest = hashlib.sha256()
    try:
        file_stat = os.fstat(fd)
        _require(stat.S_ISREG(file_stat.st_mode), code)
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _validated_manifest(value: dict[str, Any]) -> ProviderAdapterQualificationEvidence:
    _require(set(value) == _INPUT_KEYS, "input_shape")
    _require(value.get("schema") == INPUT_SCHEMA, "input_schema")

    for field in _BOOLEAN_KEYS:
        _require(type(value.get(field)) is bool, f"input_{field}")

    for field, _ in _DIGEST_BINDINGS:
        digest = value.get(field)
        _require(
            isinstance(digest, str) and _SHA256.fullmatch(digest) is not None,
            f"input_{field}",
        )
    environment_digest = value.get("environment_evidence_sha256")
    _require(
        isinstance(environment_digest, str)
        and _SHA256.fullmatch(environment_digest) is not None,
        "input_environment_evidence_sha256",
    )

    for field in ("version", "revision", "adapter_id", "adapter_version"):
        _require(isinstance(value.get(field), str), f"input_{field}")

    return ProviderAdapterQualificationEvidence(
        version=value["version"],
        revision=value["revision"],
        adapter_id=value["adapter_id"],
        adapter_version=value["adapter_version"],
        candidate_artifact_sha256=value["candidate_artifact_sha256"],
        adapter_artifact_sha256=value["adapter_artifact_sha256"],
        execution_transcript_sha256=value["execution_transcript_sha256"],
        environment_evidence_sha256=value["environment_evidence_sha256"],
        real_provider_exercised=value["real_provider_exercised"],
        real_target_exercised=value["real_target_exercised"],
        start_contract_validated=value["start_contract_validated"],
        cancel_contract_validated=value["cancel_contract_validated"],
        secret_reference_only=value["secret_reference_only"],
        secret_values_absent_from_evidence=value["secret_values_absent_from_evidence"],
        retry_safe_only_when_proven=value["retry_safe_only_when_proven"],
        ambiguous_outcome_fail_closed=value["ambiguous_outcome_fail_closed"],
        post_condition_separate=value["post_condition_separate"],
        managed_state_change_forbidden=value["managed_state_change_forbidden"],
    )


def _bind_real_environment_decision(
    value: dict[str, Any], evidence: ProviderAdapterQualificationEvidence
) -> None:
    _require(set(value) == _ENVIRONMENT_DECISION_KEYS, "environment_decision_shape")
    _require(
        value.get("schema") == REAL_ENVIRONMENT_DECISION_SCHEMA,
        "environment_decision_schema",
    )
    _require(value.get("version") == evidence.version, "environment_version_binding")
    _require(value.get("revision") == evidence.revision, "environment_revision_binding")
    _require(
        value.get("candidate_artifact_sha256") == evidence.candidate_artifact_sha256,
        "environment_candidate_artifact_binding",
    )
    _require(value.get("qualified") is True, "environment_not_qualified")
    _require(value.get("release_authorized") is False, "environment_release_authority_invalid")
    _require(
        value.get("external_publication_authorized") is False,
        "environment_publication_authority_invalid",
    )
    blockers = value.get("blockers")
    _require(isinstance(blockers, list) and not blockers, "environment_blockers_present")
    digest = value.get("evidence_sha256")
    _require(
        isinstance(digest, str) and _SHA256.fullmatch(digest) is not None and digest != "0" * 64,
        "environment_evidence_digest_invalid",
    )
    _require(digest == evidence.environment_evidence_sha256, "environment_evidence_digest_binding")


def qualify_manifest(
    value: dict[str, Any],
    *,
    candidate_artifact: Path,
    adapter_artifact: Path,
    execution_transcript: Path,
    environment_decision: Path,
) -> ProviderAdapterQualificationDecision:
    """Bind provider evidence to exact local artifacts and real-environment decision."""

    evidence = _validated_manifest(value)
    paths = (candidate_artifact, adapter_artifact, execution_transcript)
    actual_digests = tuple(
        _sha256_regular_file(path, code=f"evidence_file_invalid_{index}")
        for index, path in enumerate(paths, start=1)
    )
    expected_digests = tuple(getattr(evidence, field) for field, _ in _DIGEST_BINDINGS)
    for (_, mismatch_code), expected, actual in zip(
        _DIGEST_BINDINGS, expected_digests, actual_digests, strict=True
    ):
        _require(expected == actual, mismatch_code)

    environment_value = _load_json(environment_decision, code="environment_decision_invalid")
    _bind_real_environment_decision(environment_value, evidence)

    return evaluate_provider_adapter_qualification(evidence)


def _write_exclusive(path: Path, payload: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except OSError as exc:
        raise ProviderAdapterEvidenceInputError("output_unavailable") from exc
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bind and evaluate Home Center provider-adapter qualification evidence."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--candidate-artifact", required=True, type=Path)
    parser.add_argument("--adapter-artifact", required=True, type=Path)
    parser.add_argument("--execution-transcript", required=True, type=Path)
    parser.add_argument("--environment-decision", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        decision = qualify_manifest(
            _load_json(args.input, code="input_invalid"),
            candidate_artifact=args.candidate_artifact,
            adapter_artifact=args.adapter_artifact,
            execution_transcript=args.execution_transcript,
            environment_decision=args.environment_decision,
        )
        _write_exclusive(args.output, canonical_json(decision.to_dict()))
    except (ProviderAdapterEvidenceInputError, ProviderAdapterQualificationError) as exc:
        print(f"PROVIDER_ADAPTER_QUALIFICATION=ERROR code={exc}", file=sys.stderr)
        return 2

    if not decision.qualified:
        print(
            "PROVIDER_ADAPTER_QUALIFICATION=BLOCKED "
            f"blockers={','.join(decision.blockers)}"
        )
        return 3

    print(
        "PROVIDER_ADAPTER_QUALIFICATION=PASS "
        f"version={decision.version} revision={decision.revision} "
        f"adapter={decision.adapter_id}@{decision.adapter_version} "
        f"evidence_sha256={decision.evidence_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
