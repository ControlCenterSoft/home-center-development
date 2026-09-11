from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore


def _household(*, display_name: str = "Parent") -> Household:
    return Household(
        household_id="home",
        members=(
            FamilyMember(
                member_id="member-parent",
                display_name=display_name,
                role=HouseholdRole.PARENT,
            ),
        ),
        devices=(),
    )


def _validator() -> jsonschema.Draft202012Validator:
    schema_path = Path(__file__).parents[1] / "contracts/household/household-store.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_store_schema_accepts_runtime_snapshot_and_commit_evidence() -> None:
    validator = _validator()
    store = HouseholdStore()
    created = store.create(_household())
    first_snapshot = store.read("home")

    validator.validate(first_snapshot.to_dict())
    validator.validate(created.to_dict())

    replaced = store.replace(
        _household(display_name="Parent Updated"),
        expected_resource_version=created.resource_version,
    )
    second_snapshot = store.read("home")
    validator.validate(second_snapshot.to_dict())
    validator.validate(replaced.to_dict())


def test_store_schema_rejects_generation_one_with_previous_snapshot() -> None:
    validator = _validator()
    store = HouseholdStore()
    store.create(_household())
    payload = store.read("home").to_dict()
    payload["previous_snapshot_id"] = "hsnap-" + "0" * 24

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(payload)


def test_store_schema_rejects_replace_commit_without_previous_resource_version() -> None:
    validator = _validator()
    store = HouseholdStore()
    first = store.create(_household())
    replaced = store.replace(
        _household(display_name="Parent Updated"),
        expected_resource_version=first.resource_version,
    )
    payload = replaced.to_dict()
    payload["previous_resource_version"] = None

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(payload)


def test_store_schema_rejects_create_commit_with_non_initial_generation() -> None:
    validator = _validator()
    store = HouseholdStore()
    created = store.create(_household())
    payload = created.to_dict()
    payload["generation"] = 2

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(payload)


def test_store_schema_rejects_out_of_range_generation() -> None:
    validator = _validator()
    store = HouseholdStore()
    store.create(_household())
    payload = store.read("home").to_dict()
    payload["generation"] = 2**63
    payload["previous_snapshot_id"] = "hsnap-" + "0" * 24

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(payload)
