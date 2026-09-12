from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts/export_public_stable_provenance.py"
SCHEMA_PATH = ROOT / "contracts/releases/public-stable-provenance.v2.schema.json"
SPEC = importlib.util.spec_from_file_location("home_center_public_stable_provenance", TOOL)
assert SPEC is not None and SPEC.loader is not None
provenance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = provenance
SPEC.loader.exec_module(provenance)


def _fixture() -> dict[str, object]:
    files = [
        {
            "path": ".github/workflows/private-ci.yml",
            "approved_sha256": "1" * 64,
            "disposition": "excluded",
            "stable_sha256": None,
            "reason": "stable-release-boundary",
        },
        {
            "path": "README.md",
            "approved_sha256": "2" * 64,
            "disposition": "adapted",
            "stable_sha256": "3" * 64,
            "reason": "hardened-stable-integration",
        },
        {
            "path": "VERSION",
            "approved_sha256": "4" * 64,
            "disposition": "identical",
            "stable_sha256": "4" * 64,
            "reason": "approved-byte-copy",
        },
    ]
    approved_manifest = "".join(
        f'{item["approved_sha256"]}  {item["path"]}\n' for item in files
    ).encode("utf-8")
    return {
        "schema": "home-center.approved-source-provenance.v1",
        "product": "home-center",
        "version": "7.8.9",
        "approved_repository": "example.internal/home-center-source",
        "approved_revision": "a" * 40,
        "approved_manifest_sha256": hashlib.sha256(approved_manifest).hexdigest(),
        "stable_release_boundary_revision": "b" * 40,
        "summary": {"total": 3, "identical": 1, "adapted": 1, "excluded": 1},
        "files": files,
    }


def _schema() -> dict[str, object]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_export_is_schema_valid_deterministic_and_opaque() -> None:
    source = _fixture()
    first = provenance.export_public_provenance(copy.deepcopy(source))
    second = provenance.export_public_provenance(copy.deepcopy(source))

    assert first == second
    jsonschema.Draft202012Validator(_schema()).validate(first)
    assert first["schema"] == "home-center.public-stable-provenance.v2"
    assert first["version"] == source["version"]
    assert first["approved_manifest_sha256"] == source["approved_manifest_sha256"]
    assert first["summary"] == source["summary"]
    assert first["files"] == source["files"]

    payload = provenance.canonical_json(first)
    assert source["approved_repository"].encode("utf-8") not in payload
    assert source["approved_revision"].encode("ascii") not in payload
    assert source["stable_release_boundary_revision"].encode("ascii") not in payload
    assert b"approved_repository" not in payload
    assert b"approved_revision" not in payload
    assert b"stable_release_boundary_revision" not in payload


def test_source_identity_changes_when_private_revision_changes() -> None:
    source = _fixture()
    original = provenance.export_public_provenance(copy.deepcopy(source))
    changed = copy.deepcopy(source)
    changed["approved_revision"] = "c" * 40
    updated = provenance.export_public_provenance(changed)

    assert original["source_identity_sha256"] != updated["source_identity_sha256"]
    assert (
        original["release_boundary_identity_sha256"]
        == updated["release_boundary_identity_sha256"]
    )


def test_export_rejects_manifest_tampering_unknown_fields_and_traversal() -> None:
    source = _fixture()
    source["approved_manifest_sha256"] = "f" * 64
    with pytest.raises(provenance.PublicStableProvenanceError, match="input_manifest_binding"):
        provenance.export_public_provenance(source)

    source = _fixture()
    source["approved_repository_url"] = "https://example.invalid"
    with pytest.raises(provenance.PublicStableProvenanceError, match="input_shape"):
        provenance.export_public_provenance(source)

    source = _fixture()
    source["files"][0]["path"] = "../private"
    with pytest.raises(provenance.PublicStableProvenanceError, match="file_path"):
        provenance.export_public_provenance(source)


def test_public_schema_does_not_name_private_source_fields() -> None:
    payload = SCHEMA_PATH.read_bytes()
    for forbidden in (
        b"approved_repository",
        b"approved_revision",
        b"stable_release_boundary_revision",
        b"home-center-development",
    ):
        assert forbidden not in payload
