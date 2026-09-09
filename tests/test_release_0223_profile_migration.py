from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "deploy" / "scripts" / "install-node.sh"


class Release0223DeploymentProfileMigrationTests(unittest.TestCase):
    def test_legacy_profile_is_migrated_to_persistent_etc_path(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        self.assertIn('/opt/home-center/current/deployment-profile.json', text)
        self.assertIn('/etc/home-center/deployment-profile.json', text)
        self.assertIn('DEPLOYMENT_PROFILE_MIGRATION=PASS', text)
        self.assertIn('DEPLOYMENT_PROFILE_CONFLICT', text)
        self.assertIn('os.replace(tmp, path)', text)
        self.assertIn('os.fsync', text)

    def test_verified_immutable_core_remains_required(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        self.assertIn('ARTIFACT_CHECKSUM_MISMATCH', text)
        self.assertIn('./deploy/install-node-core.sh', text)
        self.assertIn('INSTALLER_CORE_SYNTAX_INVALID', text)


if __name__ == "__main__":
    unittest.main()
