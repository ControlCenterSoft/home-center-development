from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/capture_target_node_acceptance.py"
SPEC = importlib.util.spec_from_file_location("capture_target_node_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CaptureTargetNodeAcceptanceTests(unittest.TestCase):
    def test_parse_key_lines_is_bounded_and_rejects_duplicates(self) -> None:
        parsed = MODULE._parse_key_lines(
            "noise\nNODE_DEPLOYMENT=PASS\nVERSION=0.57.0\nREVISION=" + "a" * 40 + "\n"
        )
        self.assertEqual(parsed["NODE_DEPLOYMENT"], "PASS")
        self.assertEqual(parsed["VERSION"], "0.57.0")
        with self.assertRaisesRegex(MODULE.AcceptanceError, "deployment_output_duplicate_key"):
            MODULE._parse_key_lines("VERSION=0.57.0\nVERSION=0.57.0\n")

    def test_sqlite_semantic_digest_ignores_only_runtime_volatile_tables(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            db = Path(raw) / "state.sqlite3"
            con = sqlite3.connect(db)
            try:
                con.executescript(
                    """
                    CREATE TABLE cluster_meta (key TEXT PRIMARY KEY, value_json TEXT, updated_at TEXT);
                    CREATE TABLE nodes (node_id TEXT PRIMARY KEY, status TEXT);
                    CREATE TABLE audit (seq INTEGER PRIMARY KEY, details_json TEXT);
                    CREATE TABLE desired_state (resource_key TEXT PRIMARY KEY, generation INTEGER, value_json TEXT, updated_at TEXT);
                    INSERT INTO cluster_meta VALUES ('x','1','a');
                    INSERT INTO nodes VALUES ('node-a','ready');
                    INSERT INTO audit VALUES (1,'a');
                    INSERT INTO desired_state VALUES ('household',1,'{"x":1}','a');
                    """
                )
                con.commit()
            finally:
                con.close()
            first, tables = MODULE._sqlite_semantic_digest(db)
            self.assertEqual(tables, ("desired_state",))

            con = sqlite3.connect(db)
            try:
                con.execute("UPDATE nodes SET status='offline'")
                con.execute("INSERT INTO audit VALUES (2,'b')")
                con.commit()
            finally:
                con.close()
            second, _ = MODULE._sqlite_semantic_digest(db)
            self.assertEqual(first, second)

            con = sqlite3.connect(db)
            try:
                con.execute("UPDATE desired_state SET value_json='{}'")
                con.commit()
            finally:
                con.close()
            third, _ = MODULE._sqlite_semantic_digest(db)
            self.assertNotEqual(first, third)

    def test_candidate_inspection_binds_exact_artifact_and_script_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive_path = root / "candidate.tar.gz"
            content = {
                "VERSION": b"0.57.0\n",
                "REVISION": (b"a" * 40) + b"\n",
                "deploy/install-node.sh": b"#!/bin/sh\nexit 0\n",
                "deploy/rollback-node.sh": b"#!/bin/sh\nexit 0\n",
            }
            manifest = b"".join(
                f"{hashlib.sha256(payload).hexdigest()}  ./{name}\n".encode("ascii")
                for name, payload in content.items()
            )
            content["MANIFEST.sha256"] = manifest
            for name, payload in list(content.items()):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
            with tarfile.open(archive_path, "w:gz") as archive:
                for name in content:
                    archive.add(root / name, arcname=f"./{name}")

            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            result = MODULE.inspect_candidate(archive_path, digest, "0.57.0", "a" * 40)
            self.assertEqual(result["version"], "0.57.0")
            self.assertEqual(result["revision"], "a" * 40)
            with self.assertRaisesRegex(MODULE.AcceptanceError, "candidate_artifact_digest_mismatch"):
                MODULE.inspect_candidate(archive_path, "f" * 64, "0.57.0", "a" * 40)

    def test_plan_does_not_claim_provider_or_publication(self) -> None:
        plan = MODULE._plan(
            {"version": "0.57.0", "revision": "a" * 40, "sha256": "b" * 64},
            "/opt/home-center/releases/baseline",
            "0.56.0",
            "c" * 40,
            "node-a",
        )
        self.assertFalse(plan["provider_execution"])
        self.assertFalse(plan["external_publication"])
        self.assertEqual(plan["final_expected_state"], "original-release-restored")


if __name__ == "__main__":
    unittest.main()
