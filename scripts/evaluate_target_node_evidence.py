#!/usr/bin/env python3
"""Bind and evaluate exact Home Center target-node evidence locally.

This is a mutation-free release-evidence tool.  It reads one closed manifest and
three exact files (candidate artifact, target environment snapshot and execution
transcript), recomputes their SHA-256 digests and emits an owner-only decision.
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
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
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
        _require(isinstance(digest, str) and _SHA256.fullmatch(digest) is not None, f"input_{field}")
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
