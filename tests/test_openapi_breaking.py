"""The breaking-change gate for docs/api/openapi.json (#408).

Small hand-written documents pin each rule, and planted breaks in the real committed
document show the gate catches them there too: a removed response field, a flipped
type, a new required parameter, a removed operation and a newly required request
field. Additive changes must pass. No database or app import.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "api" / "openapi.json"


def _load():
    path = ROOT / "scripts" / "openapi" / "breaking.py"
    spec = importlib.util.spec_from_file_location("_openapi_breaking", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bk = _load()


def _doc() -> dict:
    """A tiny document with one GET (query param, $ref response) and one POST body."""
    return {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/api/v1/items/{item_id}": {
                "get": {
                    "parameters": [
                        {"name": "item_id", "in": "path", "required": True,
                         "schema": {"type": "string"}},
                        {"name": "limit", "in": "query", "required": False,
                         "schema": {"type": "integer"}},
                        {"name": "mode", "in": "query", "required": False,
                         "schema": {"type": "string", "enum": ["a", "b"]}},
                    ],
                    "responses": {
                        "200": {"description": "ok", "content": {"application/json": {
                            "schema": {"$ref": "#/components/schemas/Item"}}}},
                        "404": {"description": "missing"},
                    },
                },
            },
            "/api/v1/items": {
                "post": {
                    "requestBody": {"required": True, "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/ItemIn"}}}},
                    "responses": {"201": {"description": "made", "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Item"}}}}},
                },
            },
        },
        "components": {"schemas": {
            "Item": {
                "type": "object",
                "required": ["id", "score"],
                "properties": {
                    "id": {"type": "string"},
                    "score": {"type": "integer"},
                    "note": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "tags": {"type": "array", "items": {"$ref": "#/components/schemas/Tag"}},
                    "parent": {"anyOf": [{"$ref": "#/components/schemas/Item"},
                                         {"type": "null"}]},
                },
            },
            "Tag": {"type": "object", "required": ["name"],
                    "properties": {"name": {"type": "string"}}},
            "ItemIn": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"},
                    "size": {"type": "integer"},
                },
            },
        }},
    }


GET = "GET /api/v1/items/{item_id}"
POST = "POST /api/v1/items"


def _breaks(mutate) -> list[str]:
    base = _doc()
    head = copy.deepcopy(base)
    mutate(head)
    return bk.find_breaks(base, head)


def _schemas(d: dict) -> dict:
    return d["components"]["schemas"]


def _get(d: dict) -> dict:
    return d["paths"]["/api/v1/items/{item_id}"]["get"]


# --- no change and additive changes pass -------------------------------------------


def test_identical_documents_have_no_breaks():
    assert bk.find_breaks(_doc(), _doc()) == []


def test_recursive_schema_terminates():
    assert _breaks(lambda d: None) == []


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda d: d["paths"].__setitem__("/api/v1/new", {"get": {
        "responses": {"200": {"description": "ok"}}}}), id="new path"),
    pytest.param(lambda d: d["paths"]["/api/v1/items"].__setitem__("get", {
        "responses": {"200": {"description": "ok"}}}), id="new operation"),
    pytest.param(lambda d: _get(d)["parameters"].append(
        {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}}),
        id="new optional param"),
    pytest.param(lambda d: _schemas(d)["Item"]["properties"].__setitem__(
        "extra", {"type": "string"}), id="new response field"),
    pytest.param(lambda d: _schemas(d)["Item"]["required"].append("note"),
                 id="response field now always present"),
    pytest.param(lambda d: _schemas(d)["ItemIn"]["properties"].__setitem__(
        "colour", {"type": "string"}), id="new optional request field"),
    pytest.param(lambda d: _schemas(d)["ItemIn"]["required"].remove("name"),
                 id="request field made optional"),
    pytest.param(lambda d: _get(d)["responses"].__setitem__(
        "429", {"description": "slow down"}), id="new response status"),
    pytest.param(lambda d: _get(d)["parameters"][1].__setitem__(
        "schema", {"type": "number"}), id="request integer widened to number"),
    pytest.param(lambda d: _get(d)["parameters"][2]["schema"]["enum"].append("c"),
                 id="request enum value added"),
    pytest.param(lambda d: _schemas(d)["Item"]["properties"]["note"].__setitem__(
        "anyOf", [{"type": "string"}]), id="response no longer nullable"),
    pytest.param(lambda d: d["info"].__setitem__("description", "new words"),
                 id="description only"),
])
def test_additive_changes_pass(mutate):
    assert _breaks(mutate) == []


# --- each kind of break is caught --------------------------------------------------


def test_removed_path_is_a_break():
    assert _breaks(lambda d: d["paths"].pop("/api/v1/items")) == [
        f"{POST}: operation removed"]


def test_removed_operation_is_a_break():
    def mutate(d):
        d["paths"]["/api/v1/items/{item_id}"].pop("get")
        d["paths"]["/api/v1/items/{item_id}"]["put"] = {"responses": {}}
    assert _breaks(mutate) == [f"{GET}: operation removed"]


def test_removed_parameter_is_a_break():
    assert _breaks(lambda d: _get(d)["parameters"].pop(1)) == [
        f"{GET}: query parameter 'limit' removed"]


def test_new_required_parameter_is_a_break():
    assert _breaks(lambda d: _get(d)["parameters"].append(
        {"name": "org", "in": "query", "required": True, "schema": {"type": "string"}}
    )) == [f"{GET}: new required query parameter 'org'"]


def test_new_required_header_is_a_break():
    assert _breaks(lambda d: _get(d)["parameters"].append(
        {"name": "X-Org", "in": "header", "required": True, "schema": {"type": "string"}}
    )) == [f"{GET}: new required header parameter 'X-Org'"]


def test_parameter_made_required_is_a_break():
    assert _breaks(lambda d: _get(d)["parameters"][1].__setitem__("required", True)) == [
        f"{GET}: query parameter 'limit' became required"]


def test_parameter_type_change_is_a_break():
    assert _breaks(lambda d: _get(d)["parameters"][1].__setitem__(
        "schema", {"type": "string"})) == [
        f"{GET}: query parameter 'limit' type changed from integer to string"]


def test_request_enum_value_removed_is_a_break():
    assert _breaks(lambda d: _get(d)["parameters"][2]["schema"]["enum"].remove("b")) == [
        f"{GET}: query parameter 'mode' no longer accepts ['b']"]


def test_removed_response_field_is_a_break():
    out = _breaks(lambda d: _schemas(d)["Item"]["properties"].pop("note"))
    assert f"{GET} response 200 application/json: response property 'note' removed" in out
    assert f"{POST} response 201 application/json: response property 'note' removed" in out


def test_removed_nested_response_field_is_a_break():
    def mutate(d):
        _schemas(d)["Tag"]["properties"].pop("name")
        _schemas(d)["Tag"]["required"] = []
    out = _breaks(mutate)
    assert f"{GET} response 200 application/json: response property 'tags[].name' removed" \
        in out


def test_response_field_no_longer_always_present_is_a_break():
    out = _breaks(lambda d: _schemas(d)["Item"]["required"].remove("score"))
    assert (f"{GET} response 200 application/json: response property 'score' no longer "
            f"always present") in out


def test_response_type_flip_is_a_break():
    out = _breaks(lambda d: _schemas(d)["Item"]["properties"].__setitem__(
        "score", {"type": "string"}))
    assert f"{GET} response 200 application/json: score type changed from integer to " \
        f"string" in out


def test_response_newly_nullable_is_a_break():
    out = _breaks(lambda d: _schemas(d)["Item"]["properties"].__setitem__(
        "score", {"anyOf": [{"type": "integer"}, {"type": "null"}]}))
    assert f"{GET} response 200 application/json: score type changed from integer to " \
        f"integer|null" in out


def test_response_integer_widened_to_number_is_a_break():
    out = _breaks(lambda d: _schemas(d)["Item"]["properties"].__setitem__(
        "score", {"type": "number"}))
    assert any("score type changed from integer to number" in b for b in out)


def test_removed_response_status_is_a_break():
    assert _breaks(lambda d: _get(d)["responses"].pop("404")) == [
        f"{GET}: response 404 removed"]


def test_removed_response_media_type_is_a_break():
    def mutate(d):
        content = _get(d)["responses"]["200"]["content"]
        content["text/plain"] = content.pop("application/json")
    assert _breaks(mutate) == [f"{GET}: response 200 media type application/json removed"]


def test_new_required_request_field_is_a_break():
    out = _breaks(lambda d: _schemas(d)["ItemIn"]["required"].append("size"))
    assert out == [f"{POST} request body application/json: request property 'size' is "
                   f"newly required"]


def test_new_required_request_field_added_is_a_break():
    def mutate(d):
        _schemas(d)["ItemIn"]["properties"]["owner"] = {"type": "string"}
        _schemas(d)["ItemIn"]["required"].append("owner")
    assert _breaks(mutate) == [
        f"{POST} request body application/json: request property 'owner' is newly required"]


def test_removed_request_field_is_a_break():
    out = _breaks(lambda d: _schemas(d)["ItemIn"]["properties"].pop("size"))
    assert out == [f"{POST} request body application/json: request property 'size' no "
                   f"longer accepted"]


def test_request_type_narrowed_is_a_break():
    out = _breaks(lambda d: _schemas(d)["ItemIn"]["properties"].__setitem__(
        "size", {"type": "string"}))
    assert out == [f"{POST} request body application/json: size type changed from "
                   f"integer to string"]


def test_request_body_made_required_is_a_break():
    def mutate(d):
        _get(d)["requestBody"] = {"required": True, "content": {}}
    assert _breaks(mutate) == [f"{GET}: request body became required"]


# --- planted breaks in the real committed document ---------------------------------


@pytest.fixture(scope="module")
def real() -> dict:
    return json.loads(DOC.read_text(encoding="utf-8"))


def _real_response_schema(spec: dict) -> tuple[str, str]:
    """(operation 'METHOD path', component name) of a 200 JSON response whose $ref
    component has a required string or integer property."""
    for path in sorted(spec["paths"]):
        op = spec["paths"][path].get("get")
        if not op:
            continue
        schema = (op.get("responses", {}).get("200", {}).get("content", {})
                  .get("application/json", {}).get("schema", {}))
        ref = schema.get("$ref", "")
        if not ref.startswith("#/components/schemas/"):
            continue
        name = ref.rsplit("/", 1)[1]
        comp = spec["components"]["schemas"][name]
        props = comp.get("properties", {})
        for field in comp.get("required", []):
            if props.get(field, {}).get("type") in ("string", "integer"):
                return f"GET {path}", name
    raise AssertionError("no suitable response schema in the committed document")


def test_real_document_against_itself_has_no_breaks(real):
    assert bk.find_breaks(real, copy.deepcopy(real)) == []


def test_real_document_additive_change_passes(real):
    head = copy.deepcopy(real)
    head["paths"]["/api/v1/brand-new"] = {"get": {"responses": {"200": {
        "description": "ok"}}}}
    _, name = _real_response_schema(real)
    head["components"]["schemas"][name]["properties"]["brand_new_field"] = {
        "type": "string"}
    assert bk.find_breaks(real, head) == []


def test_planted_removed_field_in_real_document(real):
    where, name = _real_response_schema(real)
    comp = real["components"]["schemas"][name]
    field = comp["required"][0]
    head = copy.deepcopy(real)
    head["components"]["schemas"][name]["properties"].pop(field)
    head["components"]["schemas"][name]["required"].remove(field)
    out = bk.find_breaks(real, head)
    assert f"{where} response 200 application/json: response property '{field}' removed" \
        in out


def test_planted_type_flip_in_real_document(real):
    where, name = _real_response_schema(real)
    comp = real["components"]["schemas"][name]
    field = next(f for f in comp["required"]
                 if comp["properties"][f].get("type") in ("string", "integer"))
    old = comp["properties"][field]["type"]
    head = copy.deepcopy(real)
    head["components"]["schemas"][name]["properties"][field] = {
        "type": "boolean" if old != "boolean" else "string"}
    out = bk.find_breaks(real, head)
    assert any(b.startswith(f"{where} response 200 application/json: {field} type changed")
               for b in out), out


def test_planted_required_param_in_real_document(real):
    path = "/api/v1/public/scan/{owner}/{repo}"
    assert "get" in real["paths"][path], "pick another operation if this one moves"
    head = copy.deepcopy(real)
    head["paths"][path]["get"].setdefault("parameters", []).append(
        {"name": "tenant", "in": "query", "required": True, "schema": {"type": "string"}})
    assert bk.find_breaks(real, head) == [
        f"GET {path}: new required query parameter 'tenant'"]


def test_planted_removed_operation_in_real_document(real):
    path = "/api/v1/public/scan/{owner}/{repo}"
    head = copy.deepcopy(real)
    del head["paths"][path]["get"]
    assert f"GET {path}: operation removed" in bk.find_breaks(real, head)


# --- approvals (the escape hatch) --------------------------------------------------


def _write(tmp_path: Path, name: str, data: object) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_approved_break_is_let_through_and_unused_is_reported():
    breaks = [f"{GET}: query parameter 'limit' removed", f"{GET}: response 404 removed"]
    approved = [
        {"break": f"{GET}: query parameter 'limit' removed", "reason": "dead param"},
        {"break": "DELETE /api/v1/gone: operation removed", "reason": "old"},
    ]
    left, ok, unused = bk.split_approved(breaks, approved)
    assert left == [f"{GET}: response 404 removed"]
    assert ok == [f"{GET}: query parameter 'limit' removed"]
    assert [e["break"] for e in unused] == ["DELETE /api/v1/gone: operation removed"]


def test_approval_star_matches_and_brackets_are_literal():
    breaks = [
        f"{GET} response 200 application/json: response property 'tags[].name' removed",
        f"{POST} response 201 application/json: response property 'tags[].name' removed",
        f"{GET} response 200 application/json: response property 'tagsX.name' removed",
    ]
    approved = [{"break": "* response property 'tags[].name' removed", "reason": "r" * 20}]
    left, ok, _ = bk.split_approved(breaks, approved)
    assert len(ok) == 2
    assert left == [breaks[2]]


def test_approval_needs_a_reason(tmp_path):
    p = _write(tmp_path, "a.json", {"approved": [{"break": "x", "reason": " "}]})
    with pytest.raises(ValueError, match="reason"):
        bk.load_approved(p)


def test_committed_approvals_file_is_valid():
    bk.load_approved(bk.DEFAULT_APPROVED)


# --- command line ------------------------------------------------------------------


def test_cli_fails_on_a_break_and_names_the_fix(tmp_path, capsys):
    base = _write(tmp_path, "base.json", _doc())
    head_doc = _doc()
    _get(head_doc)["parameters"].pop(1)
    head = _write(tmp_path, "head.json", head_doc)
    approvals = _write(tmp_path, "approved.json", {"approved": []})
    code = bk.main(["--base", str(base), "--head", str(head), "--approved", str(approvals)])
    err = capsys.readouterr().err
    assert code == 1
    assert "query parameter 'limit' removed" in err
    assert "approved-breaks.json" in err


def test_cli_passes_an_approved_break(tmp_path, capsys):
    base = _write(tmp_path, "base.json", _doc())
    head_doc = _doc()
    _get(head_doc)["parameters"].pop(1)
    head = _write(tmp_path, "head.json", head_doc)
    approvals = _write(tmp_path, "approved.json", {"approved": [
        {"break": f"{GET}: query parameter 'limit' removed", "reason": "owner approved"}]})
    code = bk.main(["--base", str(base), "--head", str(head), "--approved", str(approvals)])
    assert code == 0
    assert "approved break" in capsys.readouterr().out


def test_cli_passes_additive_change(tmp_path):
    base = _write(tmp_path, "base.json", _doc())
    head_doc = _doc()
    head_doc["paths"]["/api/v1/new"] = {"get": {"responses": {}}}
    head = _write(tmp_path, "head.json", head_doc)
    assert bk.main(["--base", str(base), "--head", str(head)]) == 0


def test_cli_base_ref_without_a_document_passes(capsys):
    # The empty tree has no docs/api/openapi.json (as on main before this landed).
    empty_tree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    assert bk.main(["--base-ref", empty_tree]) == 0
    assert "nothing to compare" in capsys.readouterr().out
