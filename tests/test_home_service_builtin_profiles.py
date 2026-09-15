from __future__ import annotations

import unittest

from home_center.home_services import (
    HOME_SERVICE_BY_ID,
    BackupPolicy,
)


class BuiltinHomeServiceProfileTests(unittest.TestCase):
    def test_builtin_profiles_keep_exact_capability_and_capacity_contracts(self) -> None:
        expected = {
            "android-mdm": {
                "required": (
                    "certificates.lifecycle.v1",
                    "network.lan.v1",
                    "runtime.container.v1",
                ),
                "provided": ("android.enrollment.v1", "android.policy.v1"),
                "minimum_storage_gib": 8,
                "backup_policy": BackupPolicy.STATE,
            },
            "minecraft-server": {
                "required": ("network.lan.v1", "runtime.container.v1"),
                "provided": ("games.minecraft.v1",),
                "minimum_storage_gib": 16,
                "backup_policy": BackupPolicy.STATE,
            },
            "torrent-client": {
                "required": (
                    "network.lan.v1",
                    "runtime.container.v1",
                    "storage.bulk.v1",
                ),
                "provided": ("downloads.torrent.v1",),
                "minimum_storage_gib": 8,
                "backup_policy": BackupPolicy.STATE,
            },
            "torrserver": {
                "required": (
                    "network.lan.v1",
                    "runtime.container.v1",
                    "storage.bulk.v1",
                ),
                "provided": ("media.torrent-stream.v1",),
                "minimum_storage_gib": 8,
                "backup_policy": BackupPolicy.STATE,
            },
            "yandex-smart-home": {
                "required": (
                    "devices.registry.v1",
                    "network.outbound.v1",
                    "runtime.container.v1",
                ),
                "provided": ("smart-home.yandex.v1",),
                "minimum_storage_gib": 4,
                "backup_policy": BackupPolicy.CONFIGURATION,
            },
            "zigbee-bridge": {
                "required": (
                    "devices.usb.v1",
                    "network.lan.v1",
                    "runtime.container.v1",
                ),
                "provided": ("devices.zigbee.v1",),
                "minimum_storage_gib": 4,
                "backup_policy": BackupPolicy.CONFIGURATION,
            },
        }

        self.assertEqual(set(expected), set(HOME_SERVICE_BY_ID))
        for service_id, contract in expected.items():
            with self.subTest(service_id=service_id):
                profile = HOME_SERVICE_BY_ID[service_id]
                self.assertEqual(contract["required"], profile.required_capabilities)
                self.assertEqual(contract["provided"], profile.provided_capabilities)
                self.assertEqual(contract["minimum_storage_gib"], profile.minimum_storage_gib)
                self.assertEqual(contract["backup_policy"], profile.backup_policy)

    def test_outbound_and_local_capabilities_do_not_grant_external_publication(self) -> None:
        for service_id in (
            "android-mdm",
            "minecraft-server",
            "torrent-client",
            "torrserver",
            "yandex-smart-home",
            "zigbee-bridge",
        ):
            with self.subTest(service_id=service_id):
                self.assertNotIn(
                    "network.external-publication.v1",
                    HOME_SERVICE_BY_ID[service_id].required_capabilities,
                )

        self.assertIn("network.outbound.v1", HOME_SERVICE_BY_ID["yandex-smart-home"].required_capabilities)
        self.assertIn("network.lan.v1", HOME_SERVICE_BY_ID["zigbee-bridge"].required_capabilities)
        self.assertIn("network.lan.v1", HOME_SERVICE_BY_ID["torrserver"].required_capabilities)


if __name__ == "__main__":
    unittest.main()
