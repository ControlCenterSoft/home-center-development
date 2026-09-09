from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "deploy" / "scripts" / "install-node.sh"
CORE = ROOT / "deploy" / "scripts" / "install-node-core.sh"
BUILDER = ROOT / "deploy" / "scripts" / "build-deployment-artifact.sh"


class Release022DeploymentProfileTests(unittest.TestCase):
    def test_wrapper_declares_persistent_deployment_profile_migration(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("deployment-profile.json", text)
        self.assertIn("ARTIFACT_CHECKSUM_MISMATCH", text)
        self.assertIn("sha256sum", text)
        self.assertIn("./deploy/install-node-core.sh", text)
        self.assertIn("DEPLOYMENT_PROFILE_UNSAFE", text)

    def test_builder_packages_immutable_installer_core(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertTrue(CORE.is_file())
        self.assertIn("install-node-core.sh", text)

    def test_wrapper_core_and_builder_have_valid_bash_syntax(self) -> None:
        for script in (WRAPPER, CORE, BUILDER):
            with self.subTest(script=script.name):
                subprocess.run(["bash", "-n", str(script)], check=True)


if __name__ == "__main__":
    unittest.main()
