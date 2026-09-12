#!/usr/bin/env python3
"""Bind and evaluate exact Home Center target-node evidence locally.

This is a mutation-free release-evidence tool. It reads one closed manifest and
three exact files (candidate artifact, target environment snapshot and execution
transcript), recomputes their SHA-256 digests, validates that the environment and
transcript are closed semantic evidence bound to the same node/release/artifact,
and emits an owner-only decision.

It never deploys, restarts services, invokes a provider or grants publication.
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

from home_center.target_node_qualification import (  # noqa: E402
    TargetNodeQualificationDecision,
    TargetNodeQualificationError,
    TargetNodeQualificationEvidence,
    evaluate_target_node_qualification,
)

INPUT_SCHEMA = "home-center.target-node-evidence.v1"
ENVIRONMENT_SCHEMA = "home-center.target-node-environment.v1"
TRANSCRIPT_SCHEMA = "home-center.target-node-execution-transcript.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_NODE_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\Z")
_OS_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_OS_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}\Z")

_INPUT_KEYS = {
    "schema",
    "version",
    "revision",
    "candidate_artifact_sha256",
    "target_node_id",
    "target_environment_sha256",
    "target_execution_transcript_sha256",
    "install_or_upgrade_exercised",
    "health_ready",
    "user_state_preserved",
    "rollback_exercised",
}
_BOOLEAN_KEYS = {
    "install_or_upgrade_exercised",
    "health_ready",
    "user_state_preserved",
    "rollback_exercised",
}
_DIGEST_BINDINGS = (
    ("candidate_artifact_sha256", "candidate_artifact_digest_mismatch"),
    ("target_environment_sha256", "target_environment_digest_mismatch"),
    ("target_execution_transcript_sha256", "target_execution_transcript_digest_mismatch"),
)
_ENVIRONMENT_KEYS = {
    "schema",
    "target_node_id",
    "hostname",
    "architecture",
    "os_id",
    "os_version",
    "service_manager",
    "current_version",
    "current_revision",
}
_TRANSCRIPT_KEYS = {
    "schema",
    "version",
    "revision",
    "candidate_artifact_sha256",
    "target_node_id",
    "operation",
    "source_version",
    "source_revision",
    "target_version",
    "target_revision",
    "deployment_transaction_sha256",
    "install_or_upgrade_exercised",
    "service_active",
    "readyz_status",
    "user_state_preserved",
    "rollback_exercised",
    "rollback_version",
    "rollback_revision",
    "rollback_service_active",
    "rollback_readyz_status",
}
_TRANSCRIPT_BOOLEAN_KEYS = {
    "install_or_upgrade_exercised",
    "service_active",
    "user_state_preserved",
    "rollback_exercised",
    "rollback_service_active",
}


class TargetNodeEvidenceInputError(ValueError):
    """Reject unsafe, malformed or incorrectly bound local evidence input."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise TargetNodeEvidenceInputError(code)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise TargetNodeEvidenceInputError("input_duplicate_key")
        value[key] = item
    return value


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_object_pairs,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TargetNodeEvidenceInputError("input_invalid") from exc
    _require(isinstance(value, dict), "input_not_object")
    return dict(value)


def _sha256_regular_file(path: Path, *, code: str) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise TargetNodeEvidenceInputError(code) from exc

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


def _validated_manifest(value: dict[str, Any]) -> TargetNodeQualificationEvidence:
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
    for field in ("version", "revision", "target_node_id"):
        _require(isinstance(value.get(field), str), f"input_{field}")

    return TargetNodeQualificationEvidence(
        version=value["version"],
        revision=value["revision"],
        candidate_artifact_sha256=value["candidate_artifact_sha256"],
        target_node_id=value["target_node_id"],
        target_environment_sha256=value["target_environment_sha256"],
        target_execution_transcript_sha256=value["target_execution_transcript_sha256"],
        install_or_upgrade_exercised=value["install_or_upgrade_exercised"],
        health_ready=value["health_ready"],
        user_state_preserved=value["user_state_preserved"],
        rollback_exercised=value["rollback_exercised"],
    )


def _validated_environment(
    value: dict[str, Any],
    evidence: TargetNodeQualificationEvidence,
) -> dict[str, Any]:
    _require(set(value) == _ENVIRONMENT_KEYS, "target_environment_shape")
    _require(value.get("schema") == ENVIRONMENT_SCHEMA, "target_environment_schema")

    for field in ("target_node_id", "hostname", "architecture", "os_id", "os_version", "service_manager", "current_version", "current_revision"):
        _require(isinstance(value.get(field), str), f"target_environment_{field}")

    _require(_NODE_ID.fullmatch(value["target_node_id"]) is not None, "target_environment_node_id")
    _require(_NODE_ID.fullmatch(value["hostname"]) is not None, "target_environment_hostname")
    _require(value["target_node_id"] == evidence.target_node_id, "target_environment_node_binding")
    _require(value["hostname"] == evidence.target_node_id, "target_environment_hostname_binding")
    _require(value["architecture"] in {"x86_64", "amd64"}, "target_environment_architecture")
    _require(_OS_ID.fullmatch(value["os_id"]) is not None, "target_environment_os_id")
    _require(_OS_VERSION.fullmatch(value["os_version"]) is not None, "target_environment_os_version")
    _require(value["service_manager"] == "systemd", "target_environment_service_manager")
    _require(_SEMVER.fullmatch(value["current_version"]) is not None, "target_environment_current_version")
    _require(_REVISION.fullmatch(value["current_revision"]) is not None, "target_environment_current_revision")
    return value


def _validated_transcript(
    value: dict[str, Any],
    *,
    evidence: TargetNodeQualificationEvidence,
    environment: dict[str, Any],
) -> dict[str, Any]:
    _require(set(value) == _TRANSCRIPT_KEYS, "target_transcript_shape")
    _require(value.get("schema") == TRANSCRIPT_SCHEMA, "target_transcript_schema")

    for field in (
        "version",
        "revision",
        "candidate_artifact_sha256",
        "target_node_id",
        "operation",
        "source_version",
        "source_revision",
        "target_version",
        "target_revision",
        "deployment_transaction_sha256",
        "rollback_version",
        "rollback_revision",
    ):
        _require(isinstance(value.get(field), str), f"target_transcript_{field}")
    for field in _TRANSCRIPT_BOOLEAN_KEYS:
        _require(type(value.get(field)) is bool, f"target_transcript_{field}")
    for field in ("readyz_status", "rollback_readyz_status"):
        _require(type(value.get(field)) is int, f"target_transcript_{field}")
        _require(100 <= value[field] <= 599, f"target_transcript_{field}")

    _require(_SEMVER.fullmatch(value["version"]) is not None, "target_transcript_version")
    _require(_REVISION.fullmatch(value["revision"]) is not None, "target_transcript_revision")
    _require(_SHA256.fullmatch(value["candidate_artifact_sha256"]) is not None, "target_transcript_candidate_artifact_sha256")
    _require(_NODE_ID.fullmatch(value["target_node_id"]) is not None, "target_transcript_target_node_id")
    _require(value["operation"] == "upgrade", "target_transcript_operation")
    for field in ("source_version", "target_version", "rollback_version"):
        _require(_SEMVER.fullmatch(value[field]) is not None, f"target_transcript_{field}")
    for field in ("source_revision", "target_revision", "rollback_revision"):
        _require(_REVISION.fullmatch(value[field]) is not None, f"target_transcript_{field}")
    _require(_SHA256.fullmatch(value["deployment_transaction_sha256"]) is not None, "target_transcript_deployment_transaction_sha256")

    _require(
        value["version"] == evidence.version and value["revision"] == evidence.revision,
        "target_transcript_release_binding",
    )
    _require(
        value["candidate_artifact_sha256"] == evidence.candidate_artifact_sha256,
        "target_transcript_candidate_binding",
    )
    _require(value["target_node_id"] == evidence.target_node_id, "target_transcript_node_binding")
    _require(
        value["source_version"] == environment["current_version"]
        and value["source_revision"] == environment["current_revision"],
        "target_transcript_source_binding",
    )
    _require(
        value["target_version"] == evidence.version and value["target_revision"] == evidence.revision,
        "target_transcript_target_binding",
    )
    _require(
        value["rollback_version"] == value["source_version"]
        and value["rollback_revision"] == value["source_revision"],
        "target_transcript_rollback_identity_binding",
    )

    _require(
        value["install_or_upgrade_exercised"] is evidence.install_or_upgrade_exercised,
        "target_transcript_install_binding",
    )
    _require(
        value["user_state_preserved"] is evidence.user_state_preserved,
        "target_transcript_user_state_binding",
    )
    _require(
        value["rollback_exercised"] is evidence.rollback_exercised,
        "target_transcript_rollback_binding",
    )

    if evidence.health_ready:
        _require(value["service_active"] is True, "target_transcript_service_active")
        _require(value["readyz_status"] == 200, "target_transcript_readyz")
    if evidence.rollback_exercised:
        _require(value["rollback_service_active"] is True, "target_transcript_rollback_service_active")
        _require(value["rollback_readyz_status"] == 200, "target_transcript_rollback_readyz")

    return value


def qualify_manifest(
    value: dict[str, Any],
    *,
    candidate_artifact: Path,
    target_environment: Path,
    target_transcript: Path,
) -> TargetNodeQualificationDecision:
    evidence = _validated_manifest(value)
    paths = (candidate_artifact, target_environment, target_transcript)
    actual_digests = tuple(
        _sha256_regular_file(path, code=f"evidence_file_invalid_{index}")
        for index, path in enumerate(paths, start=1)
    )
    expected_digests = tuple(getattr(evidence, field) for field, _ in _DIGEST_BINDINGS)
    for (_, mismatch_code), expected, actual in zip(
        _DIGEST_BINDINGS, expected_digests, actual_digests, strict=True
    ):
        _require(expected == actual, mismatch_code)

    environment = _validated_environment(_load_json(target_environment), evidence)
    _validated_transcript(
        _load_json(target_transcript),
        evidence=evidence,
        environment=environment,
    )
    return evaluate_target_node_qualification(evidence)


def _write_exclusive(path: Path, payload: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise TargetNodeEvidenceInputError("output_unavailable") from exc
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
        description="Bind and evaluate Home Center single target-node qualification evidence."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--candidate-artifact", required=True, type=Path)
    parser.add_argument("--target-environment", required=True, type=Path)
    parser.add_argument("--target-transcript", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        decision = qualify_manifest(
            _load_json(args.input),
            candidate_artifact=args.candidate_artifact,
            target_environment=args.target_environment,
            target_transcript=args.target_transcript,
        )
        _write_exclusive(args.output, canonical_json(decision.to_dict()))
    except (TargetNodeEvidenceInputError, TargetNodeQualificationError) as exc:
        print(f"TARGET_NODE_QUALIFICATION=ERROR code={exc}", file=sys.stderr)
        return 2

    if not decision.qualified:
        print(
            "TARGET_NODE_QUALIFICATION=BLOCKED "
            f"blockers={','.join(decision.blockers)}"
        )
        return 3

    print(
        "TARGET_NODE_QUALIFICATION=PASS "
        f"version={decision.version} revision={decision.revision} "
        f"evidence_sha256={decision.evidence_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
