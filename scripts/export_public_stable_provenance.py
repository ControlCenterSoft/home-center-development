#!/usr/bin/env python3
"""Export a sanitized public Stable provenance record from an internal mapping."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


SEMVER = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
INPUT_KEYS = {
    "schema",
    "product",
    "version",
    "approved_repository",
    "approved_revision",
    "approved_manifest_sha256",
    "stable_release_boundary_revision",
    "summary",
    "files",
}
FILE_KEYS = {"path", "approved_sha256", "disposition", "stable_sha256", "reason"}
DISPOSITIONS = {"identical", "adapted", "excluded"}
EXCLUDED_REASONS = {
    "stable-public-surface",
    "stable-release-boundary",
    "stable-release-documentation",
}


class PublicStableProvenanceError(ValueError):
    """Raised when a provenance mapping is unsafe or internally inconsistent."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise PublicStableProvenanceError(code)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _identity_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicStableProvenanceError("input_invalid") from exc
    _require(isinstance(value, dict), "input_not_object")
    return value


def _validated_file(item: object) -> dict[str, Any]:
    _require(isinstance(item, dict) and set(item) == FILE_KEYS, "file_shape")
    value = dict(item)
    path = value["path"]
    approved_sha256 = value["approved_sha256"]
    disposition = value["disposition"]
    stable_sha256 = value["stable_sha256"]
    reason = value["reason"]

    _require(
        isinstance(path, str)
        and SAFE_PATH.fullmatch(path) is not None
        and not path.startswith("/")
        and ".." not in path.split("/"),
        "file_path",
    )
    _require(
        isinstance(approved_sha256, str) and HEX64.fullmatch(approved_sha256) is not None,
        "file_approved_sha256",
    )
    _require(disposition in DISPOSITIONS, "file_disposition")

    if disposition == "excluded":
        _require(stable_sha256 is None, "file_excluded_stable_sha256")
        _require(reason in EXCLUDED_REASONS, "file_excluded_reason")
    else:
        _require(
            isinstance(stable_sha256, str) and HEX64.fullmatch(stable_sha256) is not None,
            "file_stable_sha256",
        )
        if disposition == "identical":
            _require(
                stable_sha256 == approved_sha256 and reason == "approved-byte-copy",
                "file_identical_binding",
            )
        else:
            _require(
                stable_sha256 != approved_sha256
                and reason == "hardened-stable-integration",
                "file_adapted_binding",
            )
    return value


def export_public_provenance(value: dict[str, Any]) -> dict[str, Any]:
    """Validate a private v1 mapping and return a deterministic public v2 record."""

    _require(set(value) == INPUT_KEYS, "input_shape")
    _require(
        value.get("schema") == "home-center.approved-source-provenance.v1",
        "input_schema",
    )
    _require(value.get("product") == "home-center", "input_product")

    version = value.get("version")
    repository = value.get("approved_repository")
    revision = value.get("approved_revision")
    approved_manifest_sha256 = value.get("approved_manifest_sha256")
    boundary_revision = value.get("stable_release_boundary_revision")

    _require(
        isinstance(version, str) and SEMVER.fullmatch(version) is not None,
        "input_version",
    )
    _require(
        isinstance(repository, str)
        and 1 <= len(repository) <= 255
        and "\x00" not in repository,
        "input_repository",
    )
    _require(
        isinstance(revision, str) and HEX40.fullmatch(revision) is not None,
        "input_revision",
    )
    _require(
        isinstance(approved_manifest_sha256, str)
        and HEX64.fullmatch(approved_manifest_sha256) is not None,
        "input_manifest_sha256",
    )
    _require(
        isinstance(boundary_revision, str)
        and HEX40.fullmatch(boundary_revision) is not None,
        "input_boundary_revision",
    )

    files_raw = value.get("files")
    _require(isinstance(files_raw, list) and bool(files_raw), "files")
    files = [_validated_file(item) for item in files_raw]
    paths = [item["path"] for item in files]
    _require(paths == sorted(set(paths)), "files_order")

    approved_manifest = "".join(
        f'{item["approved_sha256"]}  {item["path"]}\n' for item in files
    ).encode("utf-8")
    _require(
        hashlib.sha256(approved_manifest).hexdigest() == approved_manifest_sha256,
        "input_manifest_binding",
    )

    counts = Counter(item["disposition"] for item in files)
    expected_summary = {
        "total": len(files),
        "identical": counts["identical"],
        "adapted": counts["adapted"],
        "excluded": counts["excluded"],
    }
    _require(value.get("summary") == expected_summary, "input_summary")

    result = {
        "schema": "home-center.public-stable-provenance.v2",
        "product": "home-center",
        "version": version,
        "source_identity_sha256": _identity_digest(
            {
                "approved_manifest_sha256": approved_manifest_sha256,
                "repository": repository,
                "revision": revision,
                "version": version,
            }
        ),
        "release_boundary_identity_sha256": _identity_digest(
            {
                "boundary_revision": boundary_revision,
                "product": "home-center",
                "version": version,
            }
        ),
        "approved_manifest_sha256": approved_manifest_sha256,
        "summary": expected_summary,
        "files": files,
    }

    payload = canonical_json(result)
    for forbidden in (repository, revision, boundary_revision):
        _require(forbidden.encode("utf-8") not in payload, "identity_leak")
    for forbidden_field in (
        b"approved_repository",
        b"approved_revision",
        b"stable_release_boundary_revision",
    ):
        _require(forbidden_field not in payload, "identity_field_leak")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    result = export_public_provenance(_load(args.input))
    if args.output.exists() or args.output.is_symlink():
        raise PublicStableProvenanceError("output_exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(result))
    print(f"PUBLIC_STABLE_PROVENANCE=PASS version={result['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
