from __future__ import annotations

import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts/household"


def _schema(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def test_qr_contracts_are_closed() -> None:
    for name in (
        "qr-onboarding-invitation.v1.schema.json",
        "qr-onboarding-payload.v1.schema.json",
        "qr-onboarding-redemption-plan.v1.schema.json",
    ):
        schema = _schema(name)
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False


def test_invitation_contract_forbids_authority_and_long_lived_credentials() -> None:
    props = _schema("qr-onboarding-invitation.v1.schema.json")["properties"]
    assert props["single_use"] == {"const": True}
    assert props["max_uses"] == {"const": 1}
    assert props["revocation_supported"] == {"const": True}
    assert props["administrative_credential_included"] == {"const": False}
    assert props["long_lived_credential_included"] == {"const": False}
    assert props["account_creation_authorized"] == {"const": False}
    assert props["device_binding_authorized"] == {"const": False}
    assert props["execution_authorized"] == {"const": False}
    assert props["infrastructure_mutation_authorized"] == {"const": False}
    assert props["external_publication_authorized"] == {"const": False}


def test_qr_payload_is_explicitly_ephemeral() -> None:
    props = _schema("qr-onboarding-payload.v1.schema.json")["properties"]
    assert props["credential_class"] == {"const": "ephemeral-onboarding-code"}
    assert props["single_use"] == {"const": True}
    assert props["administrative_credential_included"] == {"const": False}
    assert props["long_lived_credential_included"] == {"const": False}


def test_redemption_plan_cannot_mutate_without_later_confirmation() -> None:
    props = _schema("qr-onboarding-redemption-plan.v1.schema.json")["properties"]
    assert props["explicit_confirmation_required"] == {"const": True}
    assert props["account_creation_authorized"] == {"const": False}
    assert props["device_binding_authorized"] == {"const": False}
    assert props["execution_authorized"] == {"const": False}
    assert props["infrastructure_mutation_authorized"] == {"const": False}
    assert props["external_publication_authorized"] == {"const": False}
