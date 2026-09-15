from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from home_center.ha_update_interlock import (
    HAUpdateInterlockRejected,
    hold_update_interlock,
)


class HAUpdateInterlockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state_dir = self.root / "home-center-auto-update"
        self.state_dir.mkdir(mode=0o700)
        self.lock = self.state_dir / "update.lock"
        self.expected_uid = os.geteuid()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_manual_ha_holds_the_same_exclusive_lock_as_auto_update(self) -> None:
        script = Path("deploy/scripts/home-center-auto-update.sh").read_text(encoding="utf-8")
        self.assertIn('STATE_DIR="${HOME_CENTER_UPDATE_STATE_DIR:-/var/lib/home-center-auto-update}"', script)
        self.assertIn('LOCK_FILE="${STATE_DIR}/update.lock"', script)
        self.assertIn('flock -n 9', script)

        with hold_update_interlock(self.lock, expected_uid=self.expected_uid) as evidence:
            self.assertTrue(evidence.acquired)
            self.assertEqual(str(self.lock), evidence.lock_path)
            with self.assertRaisesRegex(
                HAUpdateInterlockRejected,
                "update_or_rollout_in_progress",
            ):
                with hold_update_interlock(self.lock, expected_uid=self.expected_uid):
                    self.fail("a second update/failover mutation lock must not be admitted")

        with hold_update_interlock(self.lock, expected_uid=self.expected_uid) as evidence:
            self.assertTrue(evidence.acquired)

    def test_missing_or_unsafe_update_state_directory_fails_closed(self) -> None:
        missing = self.root / "missing" / "update.lock"
        with self.assertRaisesRegex(
            HAUpdateInterlockRejected,
            "update_state_directory_missing",
        ):
            with hold_update_interlock(missing, expected_uid=self.expected_uid):
                self.fail("missing updater state must not be treated as idle")

        self.state_dir.chmod(0o755)
        with self.assertRaisesRegex(
            HAUpdateInterlockRejected,
            "update_state_directory_unsafe",
        ):
            with hold_update_interlock(self.lock, expected_uid=self.expected_uid):
                self.fail("unsafe updater state must not authorize failover")

    def test_symlinked_update_lock_is_rejected(self) -> None:
        target = self.root / "attacker-lock"
        target.write_text("", encoding="utf-8")
        self.lock.symlink_to(target)
        with self.assertRaisesRegex(
            HAUpdateInterlockRejected,
            "update_lock_unavailable",
        ):
            with hold_update_interlock(self.lock, expected_uid=self.expected_uid):
                self.fail("symlinked lock must fail closed")

    def test_update_lock_replacement_between_open_and_validation_is_rejected(self) -> None:
        self.lock.write_text("", encoding="utf-8")
        self.lock.chmod(0o600)
        original_open = os.open
        swapped = False

        def open_then_replace(path: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
            nonlocal swapped
            fd = original_open(path, flags, mode)
            if not swapped and Path(path) == self.lock:
                swapped = True
                self.lock.unlink()
                self.lock.write_text("", encoding="utf-8")
                self.lock.chmod(0o600)
            return fd

        with patch("home_center.ha_update_interlock.os.open", side_effect=open_then_replace):
            with self.assertRaisesRegex(
                HAUpdateInterlockRejected,
                "update_lock_changed",
            ):
                with hold_update_interlock(self.lock, expected_uid=self.expected_uid):
                    self.fail("a replaced lock path must never authorize the HA/update interlock")


if __name__ == "__main__":
    unittest.main()
