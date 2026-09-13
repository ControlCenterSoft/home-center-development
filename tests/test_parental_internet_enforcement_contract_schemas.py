from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.parental_internet_policy_adapter import (
    ParentalInternetEnforcementApplyRequest,
    ParentalInternetEnforcementObservation,
    ParentalInternetEnforcementReadbackRequest,
    ParentalInternetEnforcementRollbackRequest,
    ParentalInternetEnforcementRollbackResult,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts" / "household"


def _schema(name: str) -> dict[str, object]:
    value = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(value)
    return value


def _validate(name: str, payload: dict[str, object]) -> None:
    jsonschema.Draft202012Validator(_schema(name)).validate(payload)


def _policy() -> dict[str, object]:
    return {
        "schema": "home-center.parental-internet-policy.v1",
        "policy_id": "hcip-" + "a" * 24,
        "household_id": "home",
        "member_id": "child",
        "subject_role": "child",
        "base_policy_id": "hcpol-" + "b" * 24,
        "base_policy_sha256": "c" * 64,
        "rule_source_id": "family-filter",
        "rule_source_version": "2026.09.13",
        "rule_source_sha256": "d" * 64,
        "allow_domains": ["school.example"],
        "deny_domains": ["blocked.example"],
        "allow_categories": ["education"],
        "deny_categories": ["adult"],
        "schedule": [],
        "daily_quota_minutes": 180,
        "weekly_quota_minutes": 900,
        "continuous_session_minutes": 60,
        "break_minutes": 15,
        "grace_minutes": 5,
        "bonus_minutes": 0,
        "default_decision": "deny",
        "dns_policy_required": True,
        "proxy_policy_required": True,
        "enforcement_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def test_apply_request_schema_requires_closed_child_policy_contract() -> None:
    request = ParentalInternetEnforcementApplyRequest(
        job_id="job-parental-001",
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        household_id="home",
        member_id="child",
        desired_generation=4,
        desired_plan_id="hpip-" + "e" * 24,
        desired_state_sha256="a" * 64,
        verified_base_state_sha256="f" * 64,
        policy_id="hcip-" + "a" * 24,
        policy_sha256="b" * 64,
        policy=_policy(),
    )
    schema = _schema("parental-internet-enforcement-apply-request.v1.schema.json")
    raw = request.to_dict()
    jsonschema.Draft202012Validator(schema).validate(raw)

    weakened = json.loads(json.dumps(raw))
    weakened["policy"]["default_decision"] = "allow"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(weakened)

    extra_authority = json.loads(json.dumps(raw))
    extra_authority["policy"]["provider_execution_authorized"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(extra_authority)

    incomplete = json.loads(json.dumps(raw))
    del incomplete["policy"]["rule_source_sha256"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(incomplete)


def test_readback_request_schema_matches_typed_read_only_contract() -> None:
    request = ParentalInternetEnforcementReadbackRequest(
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        provider_operation_id="op-001",
        desired_state_sha256="a" * 64,
        policy_sha256="b" * 64,
    )
    _validate("parental-internet-enforcement-readback-request.v1.schema.json", request.to_dict())


def test_observation_schema_matches_typed_contract_and_blocks_false_success() -> None:
    observation = ParentalInternetEnforcementObservation(
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        provider_operation_id="op-001",
        desired_state_sha256="a" * 64,
        policy_sha256="b" * 64,
        observed_at="2026-09-13T00:00:00Z",
        dns_state="enforced",
        proxy_state="enforced",
        dns_policy_sha256="b" * 64,
        proxy_policy_sha256="b" * 64,
        blocker=None,
    )
    schema = _schema("parental-internet-enforcement-observation.v1.schema.json")
    raw = observation.to_dict()
    jsonschema.Draft202012Validator(schema).validate(raw)

    false_success = dict(raw)
    false_success["enforcement_verified"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(false_success)

    ambiguous = dict(raw)
    ambiguous["proxy_state"] = "unknown"
    ambiguous["proxy_policy_sha256"] = None
    ambiguous["blocker"] = None
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(ambiguous)


def test_rollback_schemas_keep_acceptance_separate_from_verified_recovery() -> None:
    request = ParentalInternetEnforcementRollbackRequest(
        job_id="job-rollback-001",
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        provider_operation_id="op-001",
        failed_desired_state_sha256="a" * 64,
        failed_policy_sha256="b" * 64,
        recovery_evidence_sha256="c" * 64,
    )
    _validate("parental-internet-enforcement-rollback-request.v1.schema.json", request.to_dict())

    result = ParentalInternetEnforcementRollbackResult(
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        provider_operation_id="rollback-op-001",
    )
    result_schema = _schema("parental-internet-enforcement-rollback-result.v1.schema.json")
    raw = result.to_dict()
    jsonschema.Draft202012Validator(result_schema).validate(raw)

    false_success = dict(raw)
    false_success["rollback_verified"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(result_schema).validate(false_success)
