from __future__ import annotations

import ast
import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "contracts/openapi/home-center-device-management.v1.openapi.json"
SRC = ROOT / "product/control-plane/src/home_center"


def _class_constant(path: Path, class_name: str, attribute: str):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        for statement in node.body:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id == attribute:
                return ast.literal_eval(statement.value)
    raise AssertionError(f"{class_name}.{attribute} not found in {path}")


def _spec() -> dict[str, object]:
    return json.loads(SPEC_PATH.read_text(encoding="utf-8"))


def _request_schema(operation: dict[str, object]) -> dict[str, object]:
    return operation["requestBody"]["content"]["application/json"]["schema"]


def test_device_management_openapi_tracks_exact_v3_v4_v5_runtime_paths() -> None:
    runtime_paths = set(
        _class_constant(SRC / "api_v3.py", "RuntimeRequestHandlerV3", "EXECUTION_POSTS")
    )
    runtime_paths.update(
        _class_constant(SRC / "api_v4.py", "RuntimeRequestHandlerV4", "VERIFICATION_POSTS")
    )
    runtime_paths.update(
        _class_constant(SRC / "api_v4.py", "RuntimeRequestHandlerV4", "DEENROLLMENT_POSTS")
    )
    runtime_paths.update(
        _class_constant(SRC / "api_v4.py", "RuntimeRequestHandlerV4", "CLEANUP_POSTS")
    )
    runtime_paths.add(
        _class_constant(SRC / "api_v4.py", "RuntimeRequestHandlerV4", "REAUTH_PATH")
    )
    runtime_paths.update(
        _class_constant(
            SRC / "api_v5.py",
            "RuntimeRequestHandlerV5",
            "DEENROLLMENT_EXECUTION_POSTS",
        )
    )
    runtime_paths.update(
        _class_constant(
            SRC / "api_v5.py",
            "RuntimeRequestHandlerV5",
            "FAILED_ENROLLMENT_CLEANUP_EXECUTION_POSTS",
        )
    )

    document = _spec()
    assert document["openapi"] == "3.1.0"
    assert document["info"]["version"] == "0.58.0-development"
    assert set(document["paths"]) == runtime_paths


def test_device_management_openapi_is_post_only_and_preserves_http_fences() -> None:
    document = _spec()
    for path, path_item in document["paths"].items():
        assert set(path_item) == {"post"}, path
        operation = path_item["post"]
        boundary = operation["x-home-center-boundary"]
        assert boundary["authenticated_session_required"] is True
        assert boundary["same_origin_required"] is True
        assert boundary["external_access_blocked"] is True
        assert boundary["external_publication_authorized"] is False
        assert boundary["max_body_bytes"] == (
            4096 if path == "/api/v1/session/reauth" else 8192
        )
        assert operation["requestBody"]["required"] is True
        assert {"400", "401", "403", "404", "409", "429", "503"} <= set(
            operation["responses"]
        )


def test_inline_request_contracts_are_closed_and_external_request_refs_are_real() -> None:
    document = _spec()
    for path, path_item in document["paths"].items():
        schema = _request_schema(path_item["post"])
        ref = schema.get("$ref")
        if ref is None:
            assert schema.get("type") == "object", path
            assert schema.get("additionalProperties") is False, path
            continue

        assert ref.startswith("../devices/"), (path, ref)
        referenced = (SPEC_PATH.parent / ref).resolve()
        assert referenced.is_file(), (path, referenced)
        contract = json.loads(referenced.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(contract)
        assert contract.get("type") == "object", (path, ref)
        assert contract.get("additionalProperties") is False, (path, ref)


def test_all_external_schema_refs_resolve_and_validate() -> None:
    document = _spec()

    def walk(value: object):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref" and isinstance(item, str) and item.startswith("../"):
                    yield item
                else:
                    yield from walk(item)
        elif isinstance(value, list):
            for item in value:
                yield from walk(item)

    for ref in sorted(set(walk(document))):
        referenced = (SPEC_PATH.parent / ref).resolve()
        assert referenced.is_file(), referenced
        jsonschema.Draft202012Validator.check_schema(
            json.loads(referenced.read_text(encoding="utf-8"))
        )


def test_step_up_is_required_only_on_exact_risk_confirmation_boundaries() -> None:
    document = _spec()
    expected = {
        "/api/v1/household/devices/enrollment/verification/confirm",
        "/api/v1/household/devices/deenrollment/confirm",
    }
    actual = {
        path
        for path, path_item in document["paths"].items()
        if path_item["post"].get("parameters")
    }
    assert actual == expected
    for path in expected:
        assert document["paths"][path]["post"]["parameters"] == [
            {"$ref": "#/components/parameters/StepUpHeader"}
        ]


def test_authority_metadata_prevents_false_success_and_hidden_escalation() -> None:
    document = _spec()
    paths = document["paths"]

    start = paths[
        "/api/v1/household/devices/enrollment/execution/start"
    ]["post"]["x-home-center-boundary"]
    assert start["authority"] == "typed-provider-execution-no-managed-state"

    receipt_ref = paths[
        "/api/v1/household/devices/enrollment/execution/start"
    ]["post"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    receipt = json.loads((SPEC_PATH.parent / receipt_ref).resolve().read_text(encoding="utf-8"))
    for name in (
        "enrollment_completed",
        "post_condition_verified",
        "managed_state_change_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert receipt["properties"][name] == {"const": False}

    reconcile = paths[
        "/api/v1/household/devices/deenrollment/reconcile"
    ]["post"]["x-home-center-boundary"]
    assert reconcile["authority"] == "read-only-provider-reconciliation-no-provider-retry"

    cleanup = paths[
        "/api/v1/household/devices/enrollment/cleanup/execute"
    ]["post"]["x-home-center-boundary"]
    assert cleanup["authority"] == "local-transient-reference-redaction-only"


def test_surface_has_no_generic_command_secret_value_or_publication_endpoint() -> None:
    document = _spec()
    serialized_paths = "\n".join(sorted(document["paths"])).lower()
    for forbidden in (
        "/shell",
        "/command",
        "/exec/",
        "/credentials",
        "/secret-value",
        "/publish",
        "/external-access",
    ):
        assert forbidden not in serialized_paths

    reauth = document["paths"]["/api/v1/session/reauth"]["post"]
    request_schema = _request_schema(reauth)
    assert set(request_schema["properties"]) == {
        "schema",
        "provider",
        "username",
        "password",
        "scope",
    }
    response_schema = reauth["responses"]["200"]["content"]["application/json"]["schema"]
    assert "password" not in response_schema["properties"]
    assert response_schema["properties"]["single_use"] == {"const": True}
