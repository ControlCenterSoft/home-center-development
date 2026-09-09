from __future__ import annotations

import copy
import hashlib
import http.client
import json
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from home_center.api import RuntimeRequestHandler
from home_center.automation_execution import (
    AutomationPlanningService,
    AutomationPlanningError,
    action_catalog,
    plan_automation_runbook,
)
from home_center.external_access import ExternalRequestContext
from home_center.server import HomeCenterServer


def _node(
    node_id: str,
    *,
    status: str = "ready",
    capabilities: tuple[str, ...] = ("inventory.v1", "health.v1", "backup.sqlite.v1"),
) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "status": status,
        "capabilities": {
            "schema": "home-center.node-capability.v1",
            "capabilities": list(capabilities),
        },
    }


def _request() -> dict[str, Any]:
    return {
        "schema": "home-center.automation-runbook-plan-request.v1",
        "runbook_id": "routine-check",
        "steps": [
            {
                "step_id": "verify",
                "action_id": "health.verify.v1",
                "target_node_id": "node-b",
                "depends_on": ["refresh"],
                "input": {},
            },
            {
                "step_id": "refresh",
                "action_id": "inventory.refresh.v1",
                "target_node_id": "node-a",
                "depends_on": [],
                "input": {},
            },
        ],
    }


class AutomationExecutionPlanningTests(unittest.TestCase):
    def test_dependency_order_and_output_are_deterministic(self) -> None:
        request = _request()
        nodes = [_node("node-b"), _node("node-a")]
        first = plan_automation_runbook(request, nodes=nodes)

        reordered_request = copy.deepcopy(request)
        reordered_request["steps"].reverse()
        second = plan_automation_runbook(reordered_request, nodes=reversed(nodes))

        self.assertEqual(first, second)
        self.assertEqual(["refresh", "verify"], [step["step_id"] for step in first["steps"]])
        self.assertEqual("planned", first["state"])
        self.assertTrue(first["planning_ready"])
        self.assertFalse(first["execution_authorized"])
        self.assertFalse(first["production_mutation_enabled"])
        self.assertFalse(first["arbitrary_commands_allowed"])
        self.assertRegex(first["plan_sha256"], r"^[0-9a-f]{64}$")

    def test_missing_capability_blocks_only_the_affected_step(self) -> None:
        plan = plan_automation_runbook(
            _request(),
            nodes=[_node("node-a"), _node("node-b", capabilities=("inventory.v1",))],
        )
        self.assertEqual("blocked", plan["state"])
        self.assertFalse(plan["planning_ready"])
        self.assertEqual("pass", plan["steps"][0]["target_check"])
        self.assertEqual("fail", plan["steps"][1]["target_check"])
        self.assertEqual(
            [
                {
                    "code": "target_capability_unavailable",
                    "step_id": "verify",
                    "target_node_id": "node-b",
                    "required_capability": "health.v1",
                }
            ],
            plan["blockers"],
        )

    def test_unknown_unready_and_unknown_capability_targets_fail_closed(self) -> None:
        request = _request()
        missing = plan_automation_runbook(request, nodes=[_node("node-a")])
        self.assertEqual("target_not_found", missing["blockers"][0]["code"])

        unready = plan_automation_runbook(
            request, nodes=[_node("node-a"), _node("node-b", status="unreachable")]
        )
        self.assertEqual("target_not_ready", unready["blockers"][0]["code"])

        node_b = _node("node-b")
        node_b["capabilities"] = {"schema": "unsupported", "capabilities": ["health.v1"]}
        unknown = plan_automation_runbook(request, nodes=[_node("node-a"), node_b])
        self.assertEqual("target_capabilities_unknown", unknown["blockers"][0]["code"])

    def test_arbitrary_shell_and_unregistered_actions_are_rejected(self) -> None:
        request = _request()
        request["steps"][0]["action_id"] = "shell.run.v1"
        request["steps"][0]["input"] = {"command": "example-command --unsafe"}
        with self.assertRaisesRegex(AutomationPlanningError, "action_not_registered"):
            plan_automation_runbook(request, nodes=[_node("node-a"), _node("node-b")])

        request = _request()
        request["steps"][0]["command"] = "example-command --unsafe"
        with self.assertRaisesRegex(AutomationPlanningError, "invalid_runbook_step"):
            plan_automation_runbook(request, nodes=[_node("node-a"), _node("node-b")])

        request = _request()
        request["steps"][0]["input"] = {"script": "example-command --unsafe"}
        with self.assertRaisesRegex(AutomationPlanningError, "invalid_action_input"):
            plan_automation_runbook(request, nodes=[_node("node-a"), _node("node-b")])

    def test_dependency_errors_have_stable_codes(self) -> None:
        request = _request()
        request["steps"][0]["depends_on"] = ["missing"]
        with self.assertRaisesRegex(AutomationPlanningError, "unknown_step_dependency"):
            plan_automation_runbook(request, nodes=[_node("node-a"), _node("node-b")])

        request = _request()
        request["steps"][1]["depends_on"] = ["verify"]
        with self.assertRaisesRegex(AutomationPlanningError, "runbook_dependency_cycle"):
            plan_automation_runbook(request, nodes=[_node("node-a"), _node("node-b")])

    def test_typed_bounded_change_input_is_normalized(self) -> None:
        request = {
            "schema": "home-center.automation-runbook-plan-request.v1",
            "runbook_id": "protected-backup",
            "steps": [
                {
                    "step_id": "backup",
                    "action_id": "backup.create.v1",
                    "target_node_id": "node-a",
                    "depends_on": [],
                    "input": {"retention_class": "protected"},
                }
            ],
        }
        plan = plan_automation_runbook(request, nodes=[_node("node-a")])
        self.assertEqual({"retention_class": "protected"}, plan["steps"][0]["input"])
        self.assertEqual("bounded-change", plan["steps"][0]["risk"])
        self.assertFalse(plan["execution_authorized"])

    def test_catalog_is_sorted_and_explicitly_denies_commands(self) -> None:
        catalog = action_catalog()
        action_ids = [item["action_id"] for item in catalog["actions"]]
        self.assertEqual(sorted(action_ids), action_ids)
        self.assertFalse(catalog["arbitrary_commands_allowed"])

        request_schema = json.loads(
            Path("contracts/automation/runbook-plan-request.v1.schema.json").read_text(encoding="utf-8")
        )
        documented_ids = request_schema["$defs"]["step"]["properties"]["action_id"]["enum"]
        self.assertEqual(action_ids, documented_ids)

    def test_service_reads_fresh_trusted_capabilities_for_each_plan(self) -> None:
        snapshots = [[_node("node-a", status="unreachable")], [_node("node-a")]]
        service = AutomationPlanningService(lambda: snapshots.pop(0))
        request = _request()
        request["steps"] = [request["steps"][1]]
        self.assertEqual("blocked", service.plan(request)["state"])
        self.assertEqual("planned", service.plan(request)["state"])


class _AllowAllLimiter:
    def allow(self, _key: object) -> bool:
        return True


class _LocalAccess:
    def classify(self, address: str, _headers: object) -> ExternalRequestContext:
        return ExternalRequestContext(external=False, client_address=address)


class _Sessions:
    def actor_from_headers(self, _cookie: object) -> str:
        return "local-admin:admin"


class _Store:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def nodes(self) -> list[dict[str, Any]]:
        return [_node("node-a")]

    def audit(self, **event: Any) -> str:
        self.events.append(event)
        return hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()[:32]


class _Runtime:
    def __init__(self) -> None:
        self.config = SimpleNamespace(node_id="node-a")
        self.sessions = _Sessions()
        self.external_access = _LocalAccess()
        self.external_request_limiter = _AllowAllLimiter()
        self.store = _Store()
        self.automation = AutomationPlanningService(self.store.nodes)

    @staticmethod
    def actor_requires_password_change(_actor: str) -> bool:
        return False


class AutomationPlanningEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = _Runtime()
        self.server = HomeCenterServer(("127.0.0.1", 0), RuntimeRequestHandler, self.runtime)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _post(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        payload = json.dumps(body).encode("utf-8")
        connection.request(
            "POST",
            "/api/v1/automation/runbooks/plan",
            body=payload,
            headers={"Content-Type": "application/json", "X-Correlation-ID": "test-request"},
        )
        response = connection.getresponse()
        value = json.loads(response.read())
        status = response.status
        connection.close()
        return status, value

    def test_authenticated_endpoint_returns_plan_and_audits_decision(self) -> None:
        request = _request()
        request["steps"] = [request["steps"][1]]
        status, value = self._post(request)
        self.assertEqual(200, status)
        self.assertEqual("home-center.automation-runbook-plan.v1", value["schema"])
        self.assertEqual("automation.runbook.plan", self.runtime.store.events[0]["action"])
        self.assertEqual("accepted", self.runtime.store.events[0]["outcome"])

    def test_endpoint_rejects_shell_shaped_request_with_stable_error(self) -> None:
        request = _request()
        request["steps"] = [request["steps"][1]]
        request["steps"][0]["action_id"] = "shell.run.v1"
        request["steps"][0]["input"] = {"command": "example-command --unsafe"}
        status, value = self._post(request)
        self.assertEqual(400, status)
        self.assertEqual("action_not_registered", value["error"]["code"])
        self.assertEqual("denied", self.runtime.store.events[0]["outcome"])


if __name__ == "__main__":
    unittest.main()
