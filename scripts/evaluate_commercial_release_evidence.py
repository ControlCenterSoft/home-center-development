#!/usr/bin/env python3
"""Bind and evaluate Home Center commercial/legal release evidence locally.

The evaluator verifies exact file digests and review dispositions. It cannot
perform legal review and never grants release or external-publication authority.
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

from home_center.commercial_release_qualification import (  # noqa: E402
    CommercialReleaseEvidence,
    CommercialReleaseQualificationDecision,
    CommercialReleaseQualificationError,
    evaluate_commercial_release_qualification,
)

INPUT_SCHEMA = "home-center.commercial-release-evidence.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_INPUT_KEYS = {
    "schema",
    "version",
    "revision",
    "candidate_artifact_sha256",
    "dependencies_evidence_sha256",
    "redistribution_evidence_sha256",
    "notices_sha256",
    "source_obligations_evidence_sha256",
    "sbom_sha256",
    "legal_terms_sha256",
    "support_terms_sha256",
    "release_claims_sha256",
    "disposition",
    "dependencies_reviewed",
    "redistribution_reviewed",
    "notices_prepared",
    "source_obligations_resolved",
    "sbom_reviewed",
    "legal_terms_dispositioned",
    "release_claims_reviewed",
}
_BOOLEAN_KEYS = {
    "dependencies_reviewed",
    "redistribution_reviewed",
    "notices_prepared",
    "source_obligations_resolved",
    "sbom_reviewed",
    "legal_terms_dispositioned",
    "release_claims_reviewed",
}
_DIGEST_BINDINGS = (
    ("candidate_artifact_sha256", "candidate_artifact_digest_mismatch"),
    ("dependencies_evidence_sha256", "dependencies_evidence_digest_mismatch"),
    ("redistribution_evidence_sha256", "redistribution_evidence_digest_mismatch"),
    ("notices_sha256", "notices_digest_mismatch"),
    ("source_obligations_evidence_sha256", "source_obligations_evidence_digest_mismatch"),
    ("sbom_sha256", "sbom_digest_mismatch"),
    ("legal_terms_sha256", "legal_terms_digest_mismatch"),
    ("support_terms_sha256", "support_terms_digest_mismatch"),
    ("release_claims_sha256", "release_claims_digest_mismatch"),
)


class CommercialEvidenceInputError(ValueError):
    """Reject malformed or incorrectly bound local commercial evidence."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CommercialEvidenceInputError(code)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CommercialEvidenceInputError("input_invalid") from exc
    _require(isinstance(value, dict), "input_not_object")
    return dict(value)


def _sha256_regular_file(path: Path, *, code: str) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CommercialEvidenceInputError(code) from exc

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


def _validated_manifest(value: dict[str, Any]) -> CommercialReleaseEvidence:
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
    for field in ("version", "revision", "disposition"):
        _require(isinstance(value.get(field), str), f"input_{field}")

    return CommercialReleaseEvidence(
        version=value["version"],
        revision=value["revision"],
        candidate_artifact_sha256=value["candidate_artifact_sha256"],
        dependencies_evidence_sha256=value["dependencies_evidence_sha256"],
        redistribution_evidence_sha256=value["redistribution_evidence_sha256"],
        notices_sha256=value["notices_sha256"],
        source_obligations_evidence_sha256=value["source_obligations_evidence_sha256"],
        sbom_sha256=value["sbom_sha256"],
        legal_terms_sha256=value["legal_terms_sha256"],
        support_terms_sha256=value["support_terms_sha256"],
        release_claims_sha256=value["release_claims_sha256"],
        disposition=value["disposition"],
        dependencies_reviewed=value["dependencies_reviewed"],
        redistribution_reviewed=value["redistribution_reviewed"],
        notices_prepared=value["notices_prepared"],
        source_obligations_resolved=value["source_obligations_resolved"],
        sbom_reviewed=value["sbom_reviewed"],
        legal_terms_dispositioned=value["legal_terms_dispositioned"],
        release_claims_reviewed=value["release_claims_reviewed"],
    )


def qualify_manifest(
    value: dict[str, Any],
    *,
    candidate_artifact: Path,
    dependencies_evidence: Path,
    redistribution_evidence: Path,
    notices: Path,
    source_obligations_evidence: Path,
    sbom: Path,
    legal_terms: Path,
    support_terms: Path,
    release_claims: Path,
) -> CommercialReleaseQualificationDecision:
    evidence = _validated_manifest(value)
    paths = (
        candidate_artifact,
        dependencies_evidence,
        redistribution_evidence,
        notices,
        source_obligations_evidence,
        sbom,
        legal_terms,
        support_terms,
        release_claims,
    )
    actual_digests = tuple(
        _sha256_regular_file(path, code=f"evidence_file_invalid_{index}")
        for index, path in enumerate(paths, start=1)
    )
    expected_digests = tuple(getattr(evidence, field) for field, _ in _DIGEST_BINDINGS)
    for (_, mismatch_code), expected, actual in zip(
        _DIGEST_BINDINGS, expected_digests, actual_digests, strict=True
    ):
        _require(expected == actual, mismatch_code)
    return evaluate_commercial_release_qualification(evidence)


def _write_exclusive(path: Path, payload: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except OSError as exc:
        raise CommercialEvidenceInputError("output_unavailable") from exc
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
        description="Bind and evaluate exact Home Center commercial release evidence."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--candidate-artifact", required=True, type=Path)
    parser.add_argument("--dependencies-evidence", required=True, type=Path)
    parser.add_argument("--redistribution-evidence", required=True, type=Path)
    parser.add_argument("--notices", required=True, type=Path)
    parser.add_argument("--source-obligations-evidence", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--legal-terms", required=True, type=Path)
    parser.add_argument("--support-terms", required=True, type=Path)
    parser.add_argument("--release-claims", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        decision = qualify_manifest(
            _load_json(args.input),
            candidate_artifact=args.candidate_artifact,
            dependencies_evidence=args.dependencies_evidence,
            redistribution_evidence=args.redistribution_evidence,
            notices=args.notices,
            source_obligations_evidence=args.source_obligations_evidence,
            sbom=args.sbom,
            legal_terms=args.legal_terms,
            support_terms=args.support_terms,
            release_claims=args.release_claims,
        )
        _write_exclusive(args.output, canonical_json(decision.to_dict()))
    except (CommercialEvidenceInputError, CommercialReleaseQualificationError) as exc:
        print(f"COMMERCIAL_RELEASE_QUALIFICATION=ERROR code={exc}", file=sys.stderr)
        return 2

    if not decision.qualified:
        print(
            "COMMERCIAL_RELEASE_QUALIFICATION=BLOCKED "
            f"blockers={','.join(decision.blockers)}"
        )
        return 3

    print(
        "COMMERCIAL_RELEASE_QUALIFICATION=PASS "
        f"version={decision.version} revision={decision.revision} "
        f"evidence_sha256={decision.evidence_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
