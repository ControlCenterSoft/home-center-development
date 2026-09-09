from __future__ import annotations

import json
import tomllib
import unittest
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from pathlib import Path

import home_center
from home_center.authorization_0180 import (
    AuthorizationEngine,
    AuthorizationError,
    AuthorizationPolicy,
    Binding,
    EffectiveAccess,
    Role,
    SubjectProvider,
    SubjectRef,
)
from home_center.certificate_inventory_0180 import (
    CertificateInventory,
    CertificateInventoryError,
    CertificateInventoryPlanner,
    CertificateInventoryRecord,
    CertificateState,
    RenewalBatchItem,
)
from home_center.remote_access_0180 import (
    PLAN_STEPS,
    PublicationIntent,
    PublicationMode,
    PublicationPlan,
    ReadinessSnapshot,
    RemoteAccessError,
    RemoteAccessPlanner,
)
from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)


def certificate(
    certificate_id: str,
    *,
    issuer_id: str = "issuer-a",
    service_id: str = "service-a",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    chain_valid: bool = True,
    name_valid: bool = True,
    renewable: bool = True,
) -> CertificateInventoryRecord:
    return CertificateInventoryRecord(
        certificate_id=certificate_id,
        service_id=service_id,
        issuer_id=issuer_id,
        fingerprint_sha256="a" * 64,
        not_before=not_before or NOW - timedelta(days=30),
        not_after=not_after or NOW + timedelta(days=10),
        chain_valid=chain_valid,
        name_valid=name_valid,
        renewable=renewable,
    )


class ReleaseIdentityAndContractTests(unittest.TestCase):
    def test_release_versions_are_identical(self) -> None:
        version_file = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        with (ROOT / "pyproject.toml").open("rb") as stream:
            project = tomllib.load(stream)
        package_version = project["project"]["version"]
        self.assertGreaterEqual(tuple(int(part) for part in version_file.split(".")), (0, 18, 0))
        self.assertEqual(package_version, version_file)
        self.assertEqual(home_center.__version__, version_file)
        self.assertIn(
            "*.json",
            project["tool"]["setuptools"]["package-data"]["home_center"],
        )

    def test_018_schemas_are_closed_bounded_and_plan_only(self) -> None:
        paths = (
            ROOT / "contracts/authorization/authorization-policy.v1.schema.json",
            ROOT / "contracts/authorization/effective-access.v1.schema.json",
            ROOT / "contracts/certificates/certificate-inventory.v1.schema.json",
            ROOT / "contracts/certificates/certificate-renewal-batch.v1.schema.json",
            ROOT / "contracts/remote-access/remote-access-publication-plan.v1.schema.json",
        )
        for path in paths:
            with self.subTest(contract=path.name):
                contract = json.loads(path.read_text(encoding="utf-8"))
                self.assertIs(contract["additionalProperties"], False)
                self.assertIs(
                    contract["properties"]["production_mutation_enabled"]["const"],
                    False,
                )
                self.assertIn("production_mutation_enabled", contract["required"])

    def test_artifact_qualification_covers_the_complete_018_surface(self) -> None:
        expected = {
            "home_center/authorization_0180.py",
            "home_center/certificate_inventory_0180.py",
            "home_center/remote_access_0180.py",
        }
        self.assertLessEqual(expected, REQUIRED_MEMBERS)

    def test_018_contracts_expose_no_secret_or_execution_fields(self) -> None:
        forbidden = {
            "command",
            "credential",
            "endpoint",
            "password",
            "private_key",
            "secret",
        }
        contract_paths = (
            ROOT / "contracts/authorization/authorization-policy.v1.schema.json",
            ROOT / "contracts/authorization/effective-access.v1.schema.json",
            ROOT / "contracts/certificates/certificate-inventory.v1.schema.json",
            ROOT / "contracts/certificates/certificate-renewal-batch.v1.schema.json",
            ROOT / "contracts/remote-access/remote-access-publication-plan.v1.schema.json",
        )
        for path in contract_paths:
            document = json.loads(path.read_text(encoding="utf-8"))
            property_names: set[str] = set()

            def collect(value: object) -> None:
                if isinstance(value, dict):
                    properties = value.get("properties")
                    if isinstance(properties, dict):
                        property_names.update(properties)
                    for nested in value.values():
                        collect(nested)
                elif isinstance(value, list):
                    for nested in value:
                        collect(nested)

            collect(document)
            with self.subTest(contract=path.name):
                self.assertTrue(property_names.isdisjoint(forbidden))


class AuthorizationBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.subject = SubjectRef(SubjectProvider.LOCAL, "user:alice")
        self.global_role = Role("role-reader", ("certificate.read.v1",))
        self.scoped_role = Role("role-publisher", ("remote.publish.plan.v1",))

    def test_global_and_scoped_bindings_are_deterministic(self) -> None:
        policy = AuthorizationPolicy(
            "policy-main",
            (self.scoped_role, self.global_role),
            (
                Binding(self.subject, "role-publisher", "lab-a"),
                Binding(self.subject, "role-reader"),
            ),
        )
        engine = AuthorizationEngine()
        access = engine.evaluate(policy, self.subject, scope_id="lab-a")
        self.assertEqual(
            access.permissions,
            ("certificate.read.v1", "remote.publish.plan.v1"),
        )
        self.assertEqual(access.decision_source, ("role-publisher", "role-reader"))
        self.assertTrue(engine.authorize(access, "certificate.read.v1"))
        self.assertFalse(engine.authorize(access, "compute.delete.v1"))
        self.assertIs(access.to_dict()["production_mutation_enabled"], False)
        json.dumps(access.to_dict())

    def test_unbound_subject_is_denied_by_empty_effective_access(self) -> None:
        policy = AuthorizationPolicy("policy-main", (self.global_role,), ())
        access = AuthorizationEngine().evaluate(policy, self.subject)
        self.assertEqual(access.permissions, ())
        self.assertFalse(AuthorizationEngine().authorize(access, "certificate.read.v1"))

    def test_orphan_and_duplicate_policy_facts_fail_closed(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "binding_role_not_found"):
            AuthorizationPolicy(
                "policy-main",
                (self.global_role,),
                (Binding(self.subject, "role-missing"),),
            )
        binding = Binding(self.subject, "role-reader")
        with self.assertRaisesRegex(AuthorizationError, "duplicate_binding"):
            AuthorizationPolicy(
                "policy-main",
                (self.global_role,),
                (binding, binding),
            )

    def test_security_flags_and_unbounded_permissions_fail_closed(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "default_deny_required"):
            AuthorizationPolicy("policy-main", (), (), default_deny=False)
        with self.assertRaisesRegex(AuthorizationError, "production_mutation_forbidden"):
            AuthorizationPolicy(
                "policy-main", (), (), production_mutation_enabled=True
            )
        permissions = tuple(f"capability.item{index}.v1" for index in range(257))
        with self.assertRaisesRegex(AuthorizationError, "invalid_permissions"):
            Role("role-large", permissions)
        with self.assertRaisesRegex(AuthorizationError, "invalid_scope_id"):
            AuthorizationEngine().evaluate(
                AuthorizationPolicy("policy-main", (), ()),
                self.subject,
                scope_id="INVALID SCOPE",
            )

    def test_effective_access_cannot_enable_mutation(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "production_mutation_forbidden"):
            EffectiveAccess(
                self.subject,
                "global",
                (),
                (),
                production_mutation_enabled=True,
            )


class CertificateInventoryBoundaryTests(unittest.TestCase):
    def test_not_yet_valid_certificate_is_invalid(self) -> None:
        record = certificate(
            "cert-future",
            not_before=NOW + timedelta(days=1),
            not_after=NOW + timedelta(days=31),
        )
        self.assertIs(record.state_at(NOW), CertificateState.INVALID)

    def test_batch_is_sorted_and_missing_readiness_blocks(self) -> None:
        inventory = CertificateInventory(
            NOW,
            (
                certificate("cert-b", issuer_id="issuer-b", service_id="service-b"),
                certificate("cert-a"),
            ),
        )
        batch = CertificateInventoryPlanner().plan_batch(
            inventory,
            batch_id="batch-a",
            issuer_availability={"issuer-b": True},
            reload_support={"service-a": True, "service-b": True},
        )
        self.assertEqual([item.certificate_id for item in batch.items], ["cert-a", "cert-b"])
        self.assertEqual(batch.state, "blocked")
        self.assertEqual(batch.blockers, ("blocked:cert-a",))
        self.assertEqual(batch.items[0].blockers, ("issuer_unavailable",))
        self.assertIs(batch.to_dict()["production_mutation_enabled"], False)
        json.dumps(batch.to_dict())

    def test_valid_certificates_are_not_scheduled(self) -> None:
        inventory = CertificateInventory(
            NOW,
            (certificate("cert-valid", not_after=NOW + timedelta(days=31)),),
        )
        batch = CertificateInventoryPlanner().plan_batch(
            inventory,
            batch_id="batch-a",
            issuer_availability={},
            reload_support={},
        )
        self.assertEqual(batch.state, "planned")
        self.assertEqual(batch.items, ())
        self.assertEqual(batch.blockers, ())

    def test_batch_item_cannot_emit_a_schema_invalid_valid_state(self) -> None:
        with self.assertRaisesRegex(
            CertificateInventoryError, "invalid_certificate_state"
        ):
            RenewalBatchItem(
                certificate_id="cert-valid",
                service_id="service-a",
                state=CertificateState.VALID,
                action="renew",
                blockers=(),
            )

    def test_time_windows_and_readiness_maps_are_bounded(self) -> None:
        record = certificate("cert-a")
        with self.assertRaisesRegex(CertificateInventoryError, "invalid_warning_window"):
            record.state_at(NOW, 366)
        far_future = certificate(
            "cert-future",
            not_before=datetime.max.replace(tzinfo=timezone.utc) - timedelta(days=2),
            not_after=datetime.max.replace(tzinfo=timezone.utc),
        )
        with self.assertRaisesRegex(CertificateInventoryError, "invalid_evaluation_time"):
            far_future.state_at(
                datetime.max.replace(tzinfo=timezone.utc) - timedelta(days=1),
                30,
            )
        inventory = CertificateInventory(NOW, (record,))
        with self.assertRaisesRegex(
            CertificateInventoryError, "invalid_issuer_availability"
        ):
            CertificateInventoryPlanner().plan_batch(
                inventory,
                batch_id="batch-a",
                issuer_availability={"issuer-a": 1},
                reload_support={"service-a": True},
            )

    def test_inventory_cannot_enable_mutation_or_contain_secret_fields(self) -> None:
        with self.assertRaisesRegex(
            CertificateInventoryError, "production_mutation_forbidden"
        ):
            CertificateInventory(NOW, (), production_mutation_enabled=True)
        field_names = {field.name for field in fields(CertificateInventoryRecord)}
        self.assertTrue(
            field_names.isdisjoint({"certificate", "private_key", "password", "secret"})
        )


class RemoteAccessBoundaryTests(unittest.TestCase):
    @staticmethod
    def intent(**overrides: object) -> PublicationIntent:
        values: dict[str, object] = {
            "intent_id": "intent-a",
            "service_id": "service-a",
            "provider_id": "provider-a",
            "mode": PublicationMode.REVERSE_PROXY,
            "hostname": "service.example.test",
        }
        values.update(overrides)
        return PublicationIntent(**values)  # type: ignore[arg-type]

    @staticmethod
    def snapshot(**overrides: object) -> ReadinessSnapshot:
        values: dict[str, object] = {
            "provider_id": "provider-a",
            "mode": PublicationMode.REVERSE_PROXY,
            "public_hostname": "service.example.test",
            "tls_ready": True,
            "dns_ready": True,
            "network_ready": True,
            "authentication_ready": True,
            "trusted_proxy_ready": True,
        }
        values.update(overrides)
        return ReadinessSnapshot(**values)  # type: ignore[arg-type]

    def test_ready_publication_is_a_plan_without_execution_authority(self) -> None:
        plan = RemoteAccessPlanner().plan(self.intent(), self.snapshot())
        self.assertEqual(plan.state, "planned")
        self.assertEqual(plan.steps, PLAN_STEPS)
        self.assertEqual(plan.blockers, ())
        self.assertIs(plan.to_dict()["production_mutation_enabled"], False)
        json.dumps(plan.to_dict())

    def test_missing_hostname_and_trusted_proxy_fail_closed(self) -> None:
        missing_hostname = RemoteAccessPlanner().plan(
            self.intent(), self.snapshot(public_hostname=None)
        )
        self.assertEqual(missing_hostname.state, "blocked")
        self.assertIn("public_hostname_unavailable", missing_hostname.blockers)
        self.assertEqual(missing_hostname.steps, ())

        untrusted = RemoteAccessPlanner().plan(
            self.intent(), self.snapshot(trusted_proxy_ready=False)
        )
        self.assertEqual(untrusted.state, "blocked")
        self.assertIn("trusted_proxy_not_ready", untrusted.blockers)

    def test_public_modes_cannot_disable_tls_or_authentication(self) -> None:
        with self.assertRaisesRegex(RemoteAccessError, "authentication_required"):
            self.intent(require_authentication=False)
        with self.assertRaisesRegex(RemoteAccessError, "tls_required"):
            self.intent(require_tls=False)
        with self.assertRaisesRegex(RemoteAccessError, "hostname_required"):
            self.intent(hostname=None)

    def test_vpn_may_omit_dns_and_tls_but_still_requires_authentication(self) -> None:
        intent = self.intent(
            mode=PublicationMode.VPN,
            hostname=None,
            require_tls=False,
        )
        snapshot = self.snapshot(
            mode=PublicationMode.VPN,
            public_hostname=None,
            tls_ready=False,
            dns_ready=False,
            trusted_proxy_ready=False,
        )
        plan = RemoteAccessPlanner().plan(intent, snapshot)
        self.assertEqual(plan.state, "planned")

    def test_invalid_hostname_and_mutating_plan_are_rejected(self) -> None:
        with self.assertRaisesRegex(RemoteAccessError, "invalid_hostname"):
            self.intent(hostname="bad..example.test")
        with self.assertRaisesRegex(RemoteAccessError, "production_mutation_forbidden"):
            PublicationPlan(
                "intent-a",
                "service-a",
                "planned",
                PLAN_STEPS,
                (),
                production_mutation_enabled=True,
            )


if __name__ == "__main__":
    unittest.main()
