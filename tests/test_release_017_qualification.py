from __future__ import annotations

import copy
import json
import tomllib
import unittest
from pathlib import Path

import home_center
from home_center.automation_engine import (
    AutomationError,
    AutomationPlan,
    AutomationPlanner,
    AutomationRule,
    PlannedAction,
    Trigger,
    TriggerKind,
)
from home_center.device_registry import DeviceRegistryError, normalize_device_registry
from home_center.zigbee import (
    PairingPlan,
    PairingRequest,
    ProviderHealth,
    ZigbeeError,
    ZigbeePlanner,
    ZigbeeProviderSnapshot,
)
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]
RELEASE_FLOOR = (0, 17, 0)


def device_registry_document() -> dict[str, object]:
    return {
        "schema": "home-center.device-registry.v1",
        "observed_at": "2026-09-08T12:00:00+03:00",
        "source": "local-trusted",
        "devices": [
            {
                "device_id": "sensor-b",
                "name": " Hall Sensor ",
                "kind": "sensor",
                "state": "online",
                "location_id": "hall-main",
                "owner_subject": "local-admin",
                "permission_refs": ["devices.read", "devices.control"],
                "capabilities": ["sensor.temperature.v1", "sensor.motion.v1"],
                "last_observed_at": "2026-09-08T11:59:00+03:00",
                "last_event": {
                    "event_type": "motion.detected",
                    "occurred_at": "2026-09-08T08:58:30Z",
                },
            },
            {
                "device_id": "light-a",
                "name": "Desk Light",
                "kind": "light",
                "state": "offline",
                "location_id": None,
                "owner_subject": None,
                "permission_refs": [],
                "capabilities": ["light.switch.v1"],
                "last_observed_at": "2026-09-08T08:57:00Z",
                "last_event": None,
            },
        ],
    }


class ReleaseIdentityTests(unittest.TestCase):
    def test_release_metadata_is_aligned_at_or_after_017(self) -> None:
        version_file = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        release = tuple(int(component) for component in version_file.split("."))
        self.assertEqual(len(release), 3)
        self.assertGreaterEqual(release, RELEASE_FLOOR)
        self.assertEqual(project["project"]["version"], version_file)
        self.assertEqual(home_center.__version__, version_file)
        self.assertIn(
            f"# Home Center {version_file}",
            (ROOT / f"docs/releases/{version_file}.md").read_text(encoding="utf-8"),
        )

    def test_artifact_qualification_covers_the_complete_017_surface(self) -> None:
        expected = {
            "home_center/automation_engine.py",
            "home_center/automation_execution.py",
            "home_center/automation_retry.py",
            "home_center/automation_runbook.py",
            "home_center/device_registry.py",
            "home_center/runbook_state.py",
            "home_center/zigbee.py",
        }
        self.assertLessEqual(expected, REQUIRED_MEMBERS)

    def test_017_contracts_are_closed_and_non_authoritative(self) -> None:
        paths = {
            "automation": ROOT / "contracts/automation/automation-plan.v1.schema.json",
            "devices": ROOT / "contracts/devices/device-registry.v1.schema.json",
            "zigbee": ROOT / "contracts/devices/zigbee-pairing-plan.v1.schema.json",
        }
        for name, path in paths.items():
            with self.subTest(contract=name):
                contract = json.loads(path.read_text(encoding="utf-8"))
                self.assertIs(contract["additionalProperties"], False)
                self.assertIs(
                    contract["properties"]["production_mutation_enabled"]["const"],
                    False,
                )
        for name in ("automation", "zigbee"):
            contract = json.loads(paths[name].read_text(encoding="utf-8"))
            self.assertIs(contract["properties"]["execution_authorized"]["const"], False)
        device_contract = json.loads(paths["devices"].read_text(encoding="utf-8"))
        self.assertIs(
            device_contract["$defs"]["device"]["properties"]["command_authority"]["const"],
            False,
        )


class DeviceRegistryBoundaryTests(unittest.TestCase):
    def test_registry_is_canonical_deterministic_and_observation_only(self) -> None:
        registry = normalize_device_registry(device_registry_document())
        value = registry.to_dict()
        self.assertEqual("2026-09-08T09:00:00Z", value["observed_at"])
        self.assertEqual(["light-a", "sensor-b"], [row["device_id"] for row in value["devices"]])
        self.assertEqual("Hall Sensor", value["devices"][1]["name"])
        self.assertEqual(
            ["sensor.motion.v1", "sensor.temperature.v1"],
            value["devices"][1]["capabilities"],
        )
        self.assertEqual(
            "2026-09-08T08:59:00Z",
            value["devices"][1]["last_observed_at"],
        )
        self.assertIs(value["production_mutation_enabled"], False)
        self.assertTrue(all(row["command_authority"] is False for row in value["devices"]))

    def test_registry_rejects_unknown_duplicate_and_invalid_timestamp_facts(self) -> None:
        unknown = device_registry_document()
        unknown["endpoint"] = "not-part-of-the-contract"
        with self.assertRaisesRegex(DeviceRegistryError, "invalid_registry_shape"):
            normalize_device_registry(unknown)

        duplicate = device_registry_document()
        duplicate["devices"].append(copy.deepcopy(duplicate["devices"][0]))
        with self.assertRaisesRegex(DeviceRegistryError, "duplicate_device_id"):
            normalize_device_registry(duplicate)

        invalid_time = device_registry_document()
        invalid_time["observed_at"] = "2026-09-08T12:00:00-00:00"
        with self.assertRaisesRegex(DeviceRegistryError, "invalid_observed_at"):
            normalize_device_registry(invalid_time)


class DeviceAutomationBoundaryTests(unittest.TestCase):
    def trigger(self) -> Trigger:
        return Trigger(TriggerKind.DEVICE_EVENT, "sensor-a", "motion.detected")

    def action(self, parameters: dict[str, object] | None = None) -> PlannedAction:
        return PlannedAction(
            "light-a",
            "light.switch.v1",
            "turn_on",
            parameters or {"brightness": {"level": 50}},
        )

    def test_automation_plan_is_deterministic_and_never_authoritative(self) -> None:
        parameters = {"brightness": {"level": 50}}
        action = self.action(parameters)
        parameters["brightness"]["level"] = 100
        trigger = self.trigger()
        rule = AutomationRule(
            "hall-light",
            True,
            trigger,
            (action,),
            ("devices.control",),
        )
        plan = AutomationPlanner().plan(
            rule,
            trigger=trigger,
            permissions=("devices.control",),
            available_capabilities={"light-a": ("light.switch.v1",)},
        )
        value = plan.to_dict()
        self.assertEqual("planned", value["state"])
        self.assertEqual(50, value["steps"][0]["parameters"]["brightness"]["level"])
        self.assertIs(value["steps"][0]["requires_execution_authority"], True)
        self.assertIs(value["production_mutation_enabled"], False)
        self.assertIs(value["execution_authorized"], False)
        with self.assertRaises(TypeError):
            AutomationPlan("hall-light", "planned", (), (), True)

    def test_automation_fails_closed_on_permissions_capabilities_and_secrets(self) -> None:
        trigger = self.trigger()
        rule = AutomationRule(
            "hall-light",
            True,
            trigger,
            (self.action(),),
            ("devices.control",),
        )
        plan = AutomationPlanner().plan(
            rule,
            trigger=trigger,
            permissions=(),
            available_capabilities={"light-a": ()},
        )
        self.assertEqual("blocked", plan.state)
        self.assertEqual((), plan.steps)
        self.assertEqual(
            ("permission_denied", "capability_unavailable:light-a"),
            plan.blockers,
        )
        with self.assertRaisesRegex(AutomationError, "secret_parameter_rejected"):
            self.action({"settings": {"token": "not-admitted"}})
        cyclic: dict[str, object] = {}
        cyclic["settings"] = cyclic
        with self.assertRaisesRegex(AutomationError, "invalid_parameters"):
            self.action(cyclic)
        with self.assertRaisesRegex(AutomationError, "invalid_trigger_kind"):
            Trigger("device-event", "sensor-a", "motion.detected")
        with self.assertRaisesRegex(AutomationError, "invalid_capability_inventory"):
            AutomationPlanner().plan(
                rule,
                trigger=trigger,
                permissions=("devices.control",),
                available_capabilities={"light-a": ("light.switch.v1", "light.switch.v1")},
            )


class ZigbeeBoundaryTests(unittest.TestCase):
    def snapshot(self, **overrides: object) -> ZigbeeProviderSnapshot:
        values = {
            "provider_id": "provider-a",
            "coordinator_id": "coordinator-a",
            "health": ProviderHealth.HEALTHY,
            "permit_join": False,
            "capabilities": ("zigbee.pairing.v1",),
            "known_devices": (),
        }
        values.update(overrides)
        return ZigbeeProviderSnapshot(**values)

    def test_pairing_is_provider_neutral_plan_only_and_bounded(self) -> None:
        request = PairingRequest("pair-device", "provider-a", "sensor-a", 120)
        plan = ZigbeePlanner().plan_pairing(request, self.snapshot())
        value = plan.to_dict()
        self.assertEqual("planned", value["state"])
        self.assertIn("request-permit-join", value["steps"])
        self.assertIs(value["production_mutation_enabled"], False)
        self.assertIs(value["execution_authorized"], False)
        with self.assertRaises(TypeError):
            PairingPlan("pair-device", "provider-a", "planned", (), (), True)

    def test_pairing_fails_closed_on_provider_facts_and_replay(self) -> None:
        request = PairingRequest("pair-device", "provider-a", "sensor-a")
        plan = ZigbeePlanner().plan_pairing(
            request,
            self.snapshot(
                health=ProviderHealth.DEGRADED,
                capabilities=(),
                known_devices=("sensor-a",),
            ),
        )
        self.assertEqual("blocked", plan.state)
        self.assertEqual((), plan.steps)
        self.assertEqual(
            (
                "provider_not_healthy",
                "pairing_capability_missing",
                "device_already_registered",
            ),
            plan.blockers,
        )
        with self.assertRaisesRegex(ZigbeeError, "invalid_provider_state"):
            self.snapshot(health="healthy")
        with self.assertRaisesRegex(ZigbeeError, "invalid_timeout"):
            PairingRequest("pair-device", "provider-a", timeout_seconds=True)
        with self.assertRaisesRegex(ZigbeeError, "invalid_capability"):
            self.snapshot(capabilities=("zigbee.pairing.v1", "zigbee.pairing.v1"))


if __name__ == "__main__":
    unittest.main()
