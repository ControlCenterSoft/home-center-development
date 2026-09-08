from __future__ import annotations

import http.client
import json
import threading
import unittest
from pathlib import Path
from typing import Any

from home_center.api import RuntimeRequestHandler
from home_center.external_access import ExternalRequestContext
from home_center.node_inventory_api import NodeInventoryError, NodeInventoryService
from home_center.server import HomeCenterServer


GENERATED_AT = "2026-01-01T00:00:30Z"


def _stored_node(
    *,
    node_id: str = "node-a",
    name: str = "node-a.example.test",
    role: str = "control-plane",
    address: str = "192.0.2.10",
    status: str = "ready",
) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "name": name,
        "role": role,
        "address": address,
        "status": status,
        "last_seen": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:01Z",
        "capabilities": {
            "schema": "home-center.node-capability.v1",
            "observed_at": "2026-01-01T00:00:00Z",
            "node": {
                "id": node_id,
                "name": name,
                "role": role,
                "address": address,
                "machine_identity_hash": "a" * 24,
            },
            "operating_system": {
                "id": "example-linux",
                "version": "1",
                "kernel": "6.1.0",
                "architecture": "x86_64",
            },
            "hardware": {"cpu_count": 4, "memory_bytes": 8 * 1024**3},
            "storage": {
                "root": {
                    "total_bytes": 100 * 1024**3,
                    "used_bytes": 20 * 1024**3,
                    "free_bytes": 70 * 1024**3,
                }
            },
            "services": {"ssh.service": "active", "home-center.service": "active"},
            "capabilities": ["inventory.v1", "health.v1"],
        },
    }


class _Store:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def nodes(self) -> list[dict[str, Any]]:
        return self.rows


class NodeInventoryServiceTests(unittest.TestCase):
    def test_snapshot_is_deterministic_typed_and_secret_free(self) -> None:
        rows = [
            _stored_node(
                node_id="node-b",
                name="node-b.example.test",
                role="worker",
                address="2001:db8::20",
                status="unreachable",
            ),
            _stored_node(),
        ]
        service = NodeInventoryService(
            _Store(rows), product_version="0.15.0", clock=lambda: GENERATED_AT
        )

        result = service.snapshot()

        self.assertEqual(result["schema"], "home-center.infrastructure-inventory-list.v1")
        self.assertEqual(result["generated_at"], GENERATED_AT)
        self.assertEqual(result["state"], "degraded")
        self.assertFalse(result["production_mutation_enabled"])
        self.assertEqual(
            result["summary"],
            {"total_nodes": 2, "ready_nodes": 1, "unreachable_nodes": 1},
        )
        self.assertEqual([node["id"] for node in result["nodes"]], ["node-a", "node-b"])
        self.assertEqual(result["capabilities"], ["health.v1", "inventory.v1"])
        self.assertEqual(
            result["nodes"][0]["services"],
            [
                {"id": "home-center.service", "state": "active"},
                {"id": "ssh.service", "state": "active"},
            ],
        )
        serialized = json.dumps(result)
        self.assertNotIn("machine_identity_hash", serialized)
        self.assertNotIn("aaaaaaaaaaaaaaaaaaaaaaaa", serialized)

    def test_empty_inventory_has_explicit_state(self) -> None:
        result = NodeInventoryService(
            _Store([]), product_version="0.15.0", clock=lambda: GENERATED_AT
        ).snapshot()
        self.assertEqual(result["state"], "empty")
        self.assertEqual(result["summary"]["total_nodes"], 0)

    def test_identity_mismatch_is_rejected_fail_closed(self) -> None:
        row = _stored_node()
        row["capabilities"]["node"]["name"] = "different-node.example.test"
        with self.assertRaisesRegex(NodeInventoryError, "node_identity_mismatch"):
            NodeInventoryService(
                _Store([row]), product_version="0.15.0", clock=lambda: GENERATED_AT
            ).snapshot()

    def test_boolean_capacity_is_not_accepted_as_integer(self) -> None:
        row = _stored_node()
        row["capabilities"]["hardware"]["cpu_count"] = True
        with self.assertRaisesRegex(NodeInventoryError, "invalid_cpu_count"):
            NodeInventoryService(
                _Store([row]), product_version="0.15.0", clock=lambda: GENERATED_AT
            ).snapshot()

    def test_contract_and_openapi_bind_the_runtime_path(self) -> None:
        schema = json.loads(
            Path("contracts/inventory/infrastructure-inventory-list.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        openapi = json.loads(
            Path("contracts/openapi/home-center-inventory.v1.openapi.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["schema"]["const"],
            "home-center.infrastructure-inventory-list.v1",
        )
        response_schema = openapi["paths"]["/api/v1/infrastructure"]["get"]["responses"][
            "200"
        ]["content"]["application/json"]["schema"]
        self.assertEqual(
            response_schema["$ref"],
            "../inventory/infrastructure-inventory-list.v1.schema.json",
        )


class _Sessions:
    @staticmethod
    def actor_from_headers(cookie: str | None) -> str | None:
        return "local-admin:admin" if cookie == "hc_session=valid" else None


class _ExternalAccess:
    @staticmethod
    def classify(address: str, _headers: object) -> ExternalRequestContext:
        return ExternalRequestContext(external=False, client_address=address)


class _Limiter:
    @staticmethod
    def allow(_context: ExternalRequestContext) -> bool:
        return True


class _Inventory:
    def __init__(self, result: dict[str, Any] | Exception) -> None:
        self.result = result

    def snapshot(self) -> dict[str, Any]:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class _Runtime:
    def __init__(self, inventory: _Inventory) -> None:
        self.sessions = _Sessions()
        self.external_access = _ExternalAccess()
        self.external_request_limiter = _Limiter()
        self.node_inventory = inventory


class NodeInventoryEndpointTests(unittest.TestCase):
    def _request(self, runtime: _Runtime, *, cookie: str | None) -> tuple[int, dict[str, Any]]:
        server = HomeCenterServer(("127.0.0.1", 0), RuntimeRequestHandler, runtime)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        headers = {"Cookie": cookie} if cookie is not None else {}
        try:
            connection.request("GET", "/api/v1/infrastructure", headers=headers)
            response = connection.getresponse()
            payload = json.loads(response.read())
            return response.status, payload
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_endpoint_requires_an_authenticated_session(self) -> None:
        status, payload = self._request(_Runtime(_Inventory({})), cookie=None)
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "authentication_required")

    def test_endpoint_returns_typed_inventory(self) -> None:
        expected = {"schema": "home-center.infrastructure-inventory-list.v1", "nodes": []}
        status, payload = self._request(
            _Runtime(_Inventory(expected)), cookie="hc_session=valid"
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, expected)

    def test_endpoint_maps_invalid_persisted_facts_to_generic_503(self) -> None:
        status, payload = self._request(
            _Runtime(_Inventory(NodeInventoryError("node_identity_mismatch"))),
            cookie="hc_session=valid",
        )
        self.assertEqual(status, 503)
        self.assertEqual(payload["error"]["code"], "infrastructure_inventory_unavailable")
        self.assertNotIn("node_identity_mismatch", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
