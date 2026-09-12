from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROLLBACK = ROOT / "deploy/scripts/rollback-node.sh"


class ManualRollbackSystemdStateTests(unittest.TestCase):
    def test_manual_rollback_restores_recorded_unit_presence_enablement_and_activity(self) -> None:
        text = ROLLBACK.read_text(encoding="utf-8")

        self.assertIn("systemd_state_v1=0", text)
        self.assertIn('$ROLLBACK_POINT/$unit.existed', text)
        self.assertIn('$ROLLBACK_POINT/$unit.enabled', text)
        self.assertIn('$ROLLBACK_POINT/$unit.active', text)
        self.assertIn('ROLLBACK_UNIT_BACKUP_MISSING:$unit', text)
        self.assertIn('rm -f "/etc/systemd/system/$unit"', text)
        self.assertIn('systemctl enable "$unit"', text)
        self.assertIn('systemctl disable "$unit"', text)
        self.assertIn('systemctl start "$unit"', text)
        self.assertIn('systemctl stop "$unit"', text)
        self.assertIn('ROLLBACK_ENABLED_STATE_MISMATCH:$unit', text)
        self.assertIn('ROLLBACK_ACTIVE_STATE_MISMATCH:$unit', text)

    def test_manual_rollback_keeps_legacy_backup_compatibility(self) -> None:
        text = ROLLBACK.read_text(encoding="utf-8")

        self.assertIn('if [[ "$systemd_state_v1" -eq 1 ]]; then', text)
        self.assertIn('systemctl start home-center.service', text)
        self.assertIn('ROLLBACK_SERVICE_NOT_ACTIVE', text)


if __name__ == "__main__":
    unittest.main()
