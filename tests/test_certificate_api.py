from __future__ import annotations

import json
import hashlib
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from home_center.certificate_api import (
    CertificateApiError,
    CertificateInventoryUnavailable,
    CertificateLifecycleApi,
    CertificateNotFound,
    CertificateRenewalPolicy,
)
from home_center.core import (
    CertificateLifecycleError,
    CertificateLifecyclePlanner,
    CertificateRecord,
    CertificateStatus,
    classify_certificate,
)
from home_center.api import RuntimeRequestHandler


NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def record(
    certificate_id: str,
    *,
    expires_in: timedelta,
    chain_valid: bool = True,
    name_valid: bool = True,
) -> CertificateRecord:
    return CertificateRecord(
        certificate_id=certificate_id,
        fingerprint_sha256=hashlib.sha256(certificate_id.encode("ascii")).hexdigest(),
        service_id=f"{certificate_id}-service",
        not_after=NOW + expires_in,
        chain_valid=chain_valid,
        name_valid=name_valid,
    )


def policy(default_certificate_id: str, **overrides: object) -> CertificateRenewalPolicy:
    value: dict[str, object] = {
        "schema": "home-center.certificate-renewal-policy.v1",
        "certificate_id": default_certificate_id,
        "evaluated_at": "2026-01-15T15:00:00+03:00",
        "warning_days": 30,
        "issuer_available": True,
        "service_reload_supported": True,
        "mode": "plan",
    }
    value.update(overrides)
    return CertificateRenewalPolicy.from_mapping(value)


class AuditSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def audit(self, **event: Any) -> None:
        self.events.append(event)


class ApiHandlerHarness(RuntimeRequestHandler):
    def __init__(self, *, path: str, certificates: CertificateLifecycleApi, body: dict[str, Any] | None = None) -> None:
        self.path = path
        self._body = body
        self.responses: list[tuple[int, dict[str, Any]]] = []
        self.errors: list[tuple[int, str]] = []
        self.server = SimpleNamespace(runtime=SimpleNamespace(certificates=certificates, store=AuditSink()))

    def _correlation_id(self) -> str:
        return "certificate-api-test"

    def _classify_request(self, correlation_id: str) -> object:
        return object()

    @staticmethod
    def _blocked_for_external(path: str, context: object) -> bool:
        return False

    def _require_actor(self, correlation_id: str) -> str:
        return "local-admin:admin"

    def _same_origin_post_allowed(self, context: object) -> bool:
        return True

    def _read_json(self, max_bytes: int = 4096) -> dict[str, Any]:
        if self._body is None:
            raise ValueError("body unavailable")
        self._request_body_complete = True
        return self._body

    def _json(self, status: int, value: Any, **kwargs: Any) -> None:
        self.responses.append((int(status), value))

    def _error(self, status: int, code: str, message: str, correlation_id: str, **kwargs: Any) -> None:
        self.errors.append((int(status), code))


class CertificateLifecycleTimeTests(unittest.TestCase):
    def test_lifecycle_boundaries_use_normalized_instants(self) -> None:
        offset = timezone(timedelta(hours=5, minutes=30))
        now_with_offset = NOW.astimezone(offset)
        self.assertEqual(
            classify_certificate(record("valid-cert", expires_in=timedelta(days=30, seconds=1)), now=now_with_offset),
            CertificateStatus.VALID,
        )
        self.assertEqual(
            classify_certificate(record("renew-cert", expires_in=timedelta(days=30)), now=now_with_offset),
            CertificateStatus.RENEWAL_DUE,
        )
        self.assertEqual(
            classify_certificate(record("expired-cert", expires_in=timedelta(0)), now=now_with_offset),
            CertificateStatus.EXPIRED,
        )

    def test_naive_times_and_non_boolean_validation_are_rejected(self) -> None:
        with self.assertRaisesRegex(CertificateLifecycleError, "certificate_expiry_must_be_timezone_aware"):
            CertificateRecord("web-cert", "a" * 64, "web-service", datetime(2026, 1, 1), True, True)
        with self.assertRaisesRegex(CertificateLifecycleError, "current_time_must_be_timezone_aware"):
            classify_certificate(record("web-cert", expires_in=timedelta(days=1)), now=datetime(2026, 1, 1))
        with self.assertRaisesRegex(CertificateLifecycleError, "invalid_certificate_validation_state"):
            CertificateRecord("web-cert", "a" * 64, "web-service", NOW, 1, True)  # type: ignore[arg-type]
        with self.assertRaisesRegex(CertificateLifecycleError, "invalid_certificate_issuer_availability"):
            CertificateLifecyclePlanner().plan_renewal(
                record("web-cert", expires_in=timedelta(days=1)),
                now=NOW,
                issuer_available=1,  # type: ignore[arg-type]
                service_reload_supported=True,
            )

    def test_legacy_expiring_name_serializes_as_renewal_due(self) -> None:
        self.assertIs(CertificateStatus.EXPIRING, CertificateStatus.RENEWAL_DUE)
        plan = CertificateLifecyclePlanner().plan_renewal(
            record("web-cert", expires_in=timedelta(days=7)),
            now=NOW,
            issuer_available=True,
            service_reload_supported=True,
        )
        self.assertEqual(plan.to_dict()["status"], "renewal_due")

    def test_expiry_status_wins_while_invalid_identity_still_blocks_plan(self) -> None:
        invalid_expired = record(
            "expired-cert",
            expires_in=timedelta(seconds=-1),
            chain_valid=False,
        )
        self.assertEqual(classify_certificate(invalid_expired, now=NOW), CertificateStatus.EXPIRED)
        plan = CertificateLifecyclePlanner().plan_renewal(
            invalid_expired,
            now=NOW,
            issuer_available=True,
            service_reload_supported=True,
        )
        self.assertEqual(plan.status, CertificateStatus.EXPIRED)
        self.assertEqual(plan.blockers, ("certificate_identity_invalid",))


class CertificateApiTests(unittest.TestCase):
    def test_inventory_is_sorted_secret_free_and_has_exact_public_statuses(self) -> None:
        records = (
            record("valid-cert", expires_in=timedelta(days=31)),
            record("expired-cert", expires_in=timedelta(seconds=-1)),
            record("renew-cert", expires_in=timedelta(days=10)),
            record("invalid-cert", expires_in=timedelta(days=100), chain_valid=False),
        )
        inventory = CertificateLifecycleApi(lambda: records, clock=lambda: NOW).inventory()
        self.assertEqual(inventory["evaluated_at"], "2026-01-15T12:00:00Z")
        self.assertEqual(
            [(item["certificate_id"], item["status"]) for item in inventory["items"]],
            [
                ("expired-cert", "expired"),
                ("invalid-cert", "renewal_due"),
                ("renew-cert", "renewal_due"),
                ("valid-cert", "valid"),
            ],
        )
        serialized = json.dumps(inventory, sort_keys=True)
        for forbidden in ("private_key", "password", "secret", "token"):
            self.assertNotIn(forbidden, serialized)

    def test_planned_renewal_is_deterministic_and_approval_gated(self) -> None:
        api = CertificateLifecycleApi(
            lambda: (record("web-cert", expires_in=timedelta(days=10)),),
            clock=lambda: NOW,
        )
        first = api.plan(policy("web-cert"))
        second = api.plan(policy("web-cert"))
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "renewal_due")
        self.assertEqual(first["state"], "planned")
        self.assertFalse(first["production_execution_enabled"])
        self.assertEqual([step["sequence"] for step in first["steps"]], [1, 2, 3, 4])
        self.assertTrue(all(step["execution_requires_approval"] for step in first["steps"]))
        self.assertEqual(len(first["plan_id"]), 64)

    def test_valid_certificate_and_invalid_identity_are_blocked(self) -> None:
        api = CertificateLifecycleApi(
            lambda: (
                record("valid-cert", expires_in=timedelta(days=31)),
                record("invalid-cert", expires_in=timedelta(days=10), name_valid=False),
            )
        )
        valid_plan = api.plan(policy("valid-cert"))
        invalid_plan = api.plan(policy("invalid-cert", issuer_available=False))
        self.assertEqual(valid_plan["blockers"], ["certificate_renewal_not_required"])
        self.assertEqual(valid_plan["steps"], [])
        self.assertEqual(invalid_plan["status"], "renewal_due")
        self.assertEqual(
            invalid_plan["blockers"],
            ["certificate_identity_invalid", "certificate_issuer_unavailable"],
        )

    def test_policy_parser_rejects_unsafe_or_ambiguous_input(self) -> None:
        cases = (
            {"warning_days": True},
            {"evaluated_at": "2026-01-15T12:00:00"},
            {"evaluated_at": "2026-01-15T12:00:00.123Z"},
            {"issuer_available": 1},
            {"service_reload_supported": "true"},
            {"mode": "execute"},
            {"certificate_id": "../private-key"},
            {"private_key": "rejected"},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(CertificateApiError):
                policy("web-cert", **changes)

    def test_unknown_and_inconsistent_inventory_fail_closed(self) -> None:
        api = CertificateLifecycleApi(lambda: (record("web-cert", expires_in=timedelta(days=1)),))
        with self.assertRaises(CertificateNotFound):
            api.plan(policy("other-cert"))
        duplicate = CertificateLifecycleApi(
            lambda: (
                record("web-cert", expires_in=timedelta(days=1)),
                record("web-cert", expires_in=timedelta(days=2)),
            )
        )
        with self.assertRaises(CertificateInventoryUnavailable):
            duplicate.inventory()

    def test_contracts_describe_only_the_three_public_states(self) -> None:
        root = Path("contracts/certificates")
        inventory = json.loads((root / "certificate-inventory.v1.schema.json").read_text(encoding="utf-8"))
        plan_schema = json.loads((root / "certificate-renewal-plan.v2.schema.json").read_text(encoding="utf-8"))
        expected = ["valid", "renewal_due", "expired"]
        self.assertEqual(inventory["$defs"]["item"]["properties"]["status"]["enum"], expected)
        self.assertEqual(plan_schema["properties"]["status"]["enum"], expected)
        self.assertFalse(plan_schema["properties"]["production_execution_enabled"]["const"])

    def test_authenticated_http_boundary_exposes_inventory_and_plan(self) -> None:
        certificates = CertificateLifecycleApi(
            lambda: (record("web-cert", expires_in=timedelta(days=10)),),
            clock=lambda: NOW,
        )
        get_handler = ApiHandlerHarness(path="/api/v1/certificates", certificates=certificates)
        get_handler.do_GET()
        self.assertEqual(get_handler.responses[0][0], 200)
        self.assertEqual(get_handler.responses[0][1]["items"][0]["status"], "renewal_due")

        post_handler = ApiHandlerHarness(
            path="/api/v1/certificates/renewal-plan",
            certificates=certificates,
            body=policy("web-cert").to_dict(),
        )
        post_handler.do_POST()
        self.assertEqual(post_handler.responses[0][0], 200)
        self.assertEqual(post_handler.responses[0][1]["state"], "planned")
        self.assertEqual(post_handler.runtime.store.events[0]["action"], "certificate.renewal.plan")

    def test_http_boundary_rejects_invalid_policy(self) -> None:
        certificates = CertificateLifecycleApi(lambda: (), clock=lambda: NOW)
        handler = ApiHandlerHarness(
            path="/api/v1/certificates/renewal-plan",
            certificates=certificates,
            body={"schema": "home-center.certificate-renewal-policy.v1", "private_key": "rejected"},
        )
        handler.do_POST()
        self.assertEqual(handler.errors, [(400, "invalid_certificate_policy_envelope")])
        self.assertEqual(handler.runtime.store.events[0]["outcome"], "denied")


if __name__ == "__main__":
    unittest.main()
