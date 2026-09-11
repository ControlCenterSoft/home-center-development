from __future__ import annotations

import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "deploy/scripts/home-center-auto-update.sh"
AUTO_INSTALLER = ROOT / "deploy/scripts/install-home-center-auto-update.sh"
NODE_INSTALLER = ROOT / "deploy/scripts/install-node.sh"
ROLLBACK = ROOT / "deploy/scripts/rollback-node.sh"
BOOTSTRAP = ROOT / "deploy/scripts/bootstrap-two-node.sh"
BUILDER = ROOT / "deploy/scripts/build-deployment-artifact.sh"
SERVICE = ROOT / "deploy/systemd/home-center-auto-update.service"
TIMER = ROOT / "deploy/systemd/home-center-auto-update.timer"


class AutoUpdateDeploymentTests(unittest.TestCase):
    def test_shell_scripts_have_valid_bash_syntax(self) -> None:
        for script in (UPDATER, AUTO_INSTALLER, NODE_INSTALLER, ROLLBACK, BOOTSTRAP, BUILDER):
            with self.subTest(script=script.name):
                subprocess.run(["bash", "-n", str(script)], check=True)

    def test_timer_runs_every_ten_minutes(self) -> None:
        text = TIMER.read_text(encoding="utf-8")
        self.assertIn("OnUnitInactiveSec=10min", text)
        self.assertIn("Persistent=true", text)
        self.assertIn("Unit=home-center-auto-update.service", text)

    def test_service_uses_root_owned_updater_and_required_environment(self) -> None:
        text = SERVICE.read_text(encoding="utf-8")
        self.assertIn("User=root", text)
        self.assertIn("EnvironmentFile=/etc/home-center/auto-update.env", text)
        self.assertIn("ExecStart=/usr/local/sbin/home-center-auto-update", text)
        self.assertNotIn("home-center-sync.sh", text)

    def test_updater_accepts_only_qualified_deployment_assets(self) -> None:
        text = UPDATER.read_text(encoding="utf-8")
        self.assertIn("HOME_CENTER_UPDATE_COORDINATOR", text)
        self.assertIn("HOME_CENTER_UPDATE_PEER", text)
        self.assertIn("home-center-stable/releases?per_page=30", text)
        self.assertIn("home-center-stable/releases/download/", text)
        self.assertNotIn("home-center-development/releases", text)
        self.assertIn("DEPLOYMENT-ARTIFACT.json", text)
        self.assertIn("blocked.sha256", text)
        self.assertIn("flock -n", text)
        self.assertIn("./deploy/bootstrap-two-node.sh", text)
        self.assertIn("./deploy/install-node.sh", text)
        self.assertIn("./deploy/rollback-node.sh", text)
        self.assertIn("no compatible deployment release", text)
        self.assertNotRegex(text, r"\bdc[0-9]{2}\b")

    def test_installer_keeps_topology_bindings_local(self) -> None:
        text = AUTO_INSTALLER.read_text(encoding="utf-8")
        self.assertIn("--coordinator is required", text)
        self.assertIn("--peer is required", text)
        self.assertIn("HOME_CENTER_UPDATE_COORDINATOR", text)
        self.assertIn("HOME_CENTER_UPDATE_PEER", text)
        self.assertIn("HOME_CENTER_RELEASES_API", text)
        self.assertIn("home-center-stable/releases?per_page=30", text)
        self.assertNotIn("home-center-development/releases", text)
        self.assertIn("install -m 0600", text)
        self.assertIn("systemctl enable --now home-center-auto-update.timer", text)
        self.assertNotRegex(text, r"\bdc[0-9]{2}\b")

    def test_generic_rollout_scripts_do_not_bind_an_environment(self) -> None:
        for script in (NODE_INSTALLER, ROLLBACK, BOOTSTRAP):
            text = script.read_text(encoding="utf-8")
            with self.subTest(script=script.name):
                self.assertNotRegex(text, r"\bdc[0-9]{2}\b")
                self.assertNotRegex(text, r"(?<![0-9])192\.168\.")
                self.assertNotRegex(text, r"\bS-1-5-21-[0-9]+")

    def test_builder_produces_infrastructure_neutral_deployment_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                ["bash", str(BUILDER), directory],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            artifact_line = next(
                line for line in completed.stdout.splitlines() if line.startswith("DEPLOYMENT_ARTIFACT=")
            )
            artifact = Path(artifact_line.split("=", 1)[1])
            self.assertTrue(artifact.is_file())
            self.assertTrue(Path(str(artifact) + ".sha256").is_file())
            with tarfile.open(artifact, "r:gz") as archive:
                names = set(archive.getnames())
                for required in (
                    "./DEPLOYMENT-ARTIFACT.json",
                    "./VERSION",
                    "./REVISION",
                    "./MANIFEST.sha256",
                    "./deploy/bootstrap-two-node.sh",
                    "./deploy/install-node.sh",
                    "./deploy/rollback-node.sh",
                    "./deploy/home-center.service",
                ):
                    self.assertIn(required, names)
                self.assertFalse(any("current-environment" in name for name in names))
                self.assertFalse(any("private-overlays" in name for name in names))
                self.assertFalse(any("production-overlays" in name for name in names))


if __name__ == "__main__":
    unittest.main()
