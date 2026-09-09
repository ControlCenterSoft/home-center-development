from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from home_center.home_service_operations import HomeServiceInstanceState
from home_center.home_service_state import HomeServiceInstanceStateStore, InstanceTransition
from home_center.store import IdempotencyConflict, StatePreconditionFailed, StateStore


class HomeServiceInstanceStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.store = StateStore(self.path, b"a" * 32, "home-test")
        self.instances = HomeServiceInstanceStateStore(self.store)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_state_is_durable_and_compare_and_swap_guarded(self) -> None:
        created = self.instances.create(instance_id="minecraft-main", service_id="minecraft-server", target_node_id="home-node-a")
        transition = InstanceTransition("minecraft-main", 1, str(created["resource_version"]), "install-001", HomeServiceInstanceState.INSTALLED)
        installed, changed = self.instances.transition(transition)
        self.assertTrue(changed)
        self.assertEqual(2, installed["generation"])
        self.store.close()
        self.store = StateStore(self.path, b"a" * 32, "home-test")
        self.instances = HomeServiceInstanceStateStore(self.store)
        self.assertEqual(installed, self.instances.get("minecraft-main"))
        with self.assertRaises(StatePreconditionFailed):
            self.instances.transition(InstanceTransition("minecraft-main", 1, str(created["resource_version"]), "install-002", HomeServiceInstanceState.INSTALLED))

    def test_transition_is_idempotent_and_conflicting_reuse_fails(self) -> None:
        created = self.instances.create(instance_id="zigbee-main", service_id="zigbee-bridge", target_node_id="home-node-a")
        request = InstanceTransition("zigbee-main", 1, str(created["resource_version"]), "configure-001", HomeServiceInstanceState.CONFIGURED, "config:12")
        first, changed = self.instances.transition(request)
        second, replayed = self.instances.transition(request)
        self.assertTrue(changed)
        self.assertFalse(replayed)
        self.assertEqual(first, second)
        with self.assertRaises(IdempotencyConflict):
            self.instances.transition(InstanceTransition("zigbee-main", 1, str(created["resource_version"]), "configure-001", HomeServiceInstanceState.REMOVED))

    def test_persisted_shape_is_secret_free(self) -> None:
        value = self.instances.create(instance_id="yandex-main", service_id="yandex-smart-home", target_node_id="home-node-a")
        self.assertNotIn("secret", repr(value).lower())
        self.assertFalse(value["external_publication_enabled"])


if __name__ == "__main__":
    unittest.main()
