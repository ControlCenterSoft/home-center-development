from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "deploy/scripts/home-center-auto-update.sh"
INSTALLER = ROOT / "deploy/scripts/install-home-center-auto-update.sh"
SERVICE = ROOT / "deploy/systemd/home-center-auto-update.service"
TIMER = ROOT / "deploy/systemd/home-center-auto-update.timer"


class AutoUpdateDeploymentTests(unittest.TestCase):
    def test_shell_scripts_have_valid_bash_syntax(self) -> None:
        for script in (WRAPPER, INSTALLER):
            with self.subTest(script=script.name):
                subprocess.run(["bash", "-n", str(script)], check=True)

    def test_timer_runs_every_ten_minutes(self) -> None:
        text = TIMER.read_text(encoding="utf-8")
        self.assertIn("OnUnitInactiveSec=10min", text)
        self.assertIn("Persistent=true", text)
        self.assertIn("Unit=home-center-auto-update.service", text)

    def test_service_uses_root_owned_wrapper_and_environment(self) -> None:
        text = SERVICE.read_text(encoding="utf-8")
        self.assertIn("User=root", text)
        self.assertIn("EnvironmentFile=-/etc/home-center/auto-update.env", text)
        self.assertIn("ExecStart=/usr/local/sbin/home-center-auto-update", text)
        self.assertIn("ConditionPathExists=/opt/home-center/scripts/home-center-sync.sh", text)

    def test_wrapper_is_single_coordinator_and_single_process_safe(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("HOME_CENTER_UPDATE_COORDINATOR", text)
        self.assertIn("flock -n", text)
        self.assertIn("/opt/home-center/scripts/home-center-sync.sh", text)
        self.assertIn("HOME_CENTER_UPDATE_TIMEOUT_SECONDS", text)
        self.assertNotIn("dc01", text)
        self.assertNotIn("dc02", text)

    def test_installer_requires_explicit_coordinator(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("--coordinator is required", text)
        self.assertIn("systemctl enable --now home-center-auto-update.timer", text)
        self.assertIn("systemctl start home-center-auto-update.service", text)


if __name__ == "__main__":
    unittest.main()
