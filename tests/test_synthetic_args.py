"""Deterministic synthetic-argument generation + README example mining for the MCP
exerciser (src/scanner/behavioral/synthetic_args.py). Golden files under
tests/fixtures/behavioral/schemas pin the output; the JS port is checked against the same
goldens in test_behavioral_exerciser.py."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.scanner.behavioral.synthetic_args import (
    FALLBACK,
    SAMPLE_PATH,
    SAMPLE_URL,
    args_for_tool,
    generate_args,
    mine_examples,
)

SCHEMAS = Path(__file__).parent / "fixtures" / "behavioral" / "schemas"
GOLDEN = sorted(p for p in SCHEMAS.glob("*.json") if not p.name.endswith(".expected.json"))


def _obj(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or []}


# --- precedence + per-type rules --------------------------------------------------------

def test_const_examples_default_enum_precedence():
    assert generate_args(_obj({"a": {"const": "C", "examples": ["E"], "default": "D"}})) == {"a": "C"}
    assert generate_args(_obj({"a": {"examples": ["E"], "default": "D"}})) == {"a": "E"}
    assert generate_args(_obj({"a": {"default": "D", "enum": ["X"]}})) == {"a": "D"}
    assert generate_args(_obj({"a": {"enum": ["X", "Y"], "type": "string"}})) == {"a": "X"}
    assert generate_args(_obj({"a": {"default": None}})) == {"a": None}


def test_string_formats():
    out = generate_args(_obj({
        "u": {"type": "string", "format": "uri"}, "e": {"type": "string", "format": "email"},
        "d": {"type": "string", "format": "date"}, "dt": {"type": "string", "format": "date-time"},
        "id": {"type": "string", "format": "uuid"}, "h": {"type": "string", "format": "hostname"},
        "ip": {"type": "string", "format": "ipv4"}, "x": {"type": "string", "format": "weird"},
    }, ["u", "e", "d", "dt", "id", "h", "ip", "x"]))
    assert out == {
        "u": SAMPLE_URL, "e": "agentavow@example.com", "d": "2024-01-01",
        "dt": "2024-01-01T00:00:00Z", "id": "00000000-0000-4000-8000-000000000000",
        "h": "example.com", "ip": "192.0.2.1", "x": FALLBACK,
    }


@pytest.mark.parametrize("name,expected", [
    ("path", SAMPLE_PATH), ("file_path", SAMPLE_PATH), ("filePath", SAMPLE_PATH),
    ("directory", SAMPLE_PATH), ("outputFile", SAMPLE_PATH), ("dir", SAMPLE_PATH),
    ("url", SAMPLE_URL), ("imageUrl", SAMPLE_URL), ("base_uri", SAMPLE_URL),
    ("query", FALLBACK), ("search", FALLBACK), ("name", FALLBACK), ("message", FALLBACK),
    ("id", "1"), ("issue_id", "1"), ("userId", "1"), ("video", FALLBACK), ("valid", FALLBACK),
    ("email", "agentavow@example.com"), ("host", "example.com"),
])
def test_property_name_hints(name, expected):
    assert generate_args(_obj({name: {"type": "string"}}, [name])) == {name: expected}


def test_format_beats_name_hint():
    assert generate_args(_obj({"path": {"type": "string", "format": "uri"}})) == {"path": SAMPLE_URL}


def test_string_length_bounds():
    assert generate_args(_obj({"a": {"type": "string", "minLength": 12}})) == {"a": "agentavowxxx"}
    assert generate_args(_obj({"a": {"type": "string", "maxLength": 3}})) == {"a": "age"}


def test_numbers_respect_bounds():
    out = generate_args(_obj({
        "n": {"type": "number"}, "i": {"type": "integer", "minimum": 7},
        "em": {"type": "integer", "exclusiveMinimum": 0}, "d4": {"type": "integer", "minimum": 0,
                                                                 "exclusiveMinimum": True},
        "mx": {"type": "integer", "maximum": -3}, "emx": {"type": "number", "exclusiveMaximum": 1},
        "f": {"type": "number", "minimum": 2.5}, "clamp": {"type": "integer", "minimum": 50,
                                                           "maximum": 10},
    }, ["f", "clamp"]))
    assert out == {"n": 1, "i": 7, "em": 1, "d4": 1, "mx": -3, "emx": 0, "f": 2.5, "clamp": 10}
    assert all(not isinstance(v, bool) for v in out.values())


def test_boolean_null_and_type_lists():
    out = generate_args(_obj({"b": {"type": "boolean"}, "n": {"type": "null"},
                              "s": {"type": ["null", "string"]}}))
    assert out == {"b": False, "n": None, "s": FALLBACK}


def test_arrays_one_item_and_min_items():
    assert generate_args(_obj({"a": {"type": "array", "items": {"type": "integer"}}})) == {"a": [1]}
    assert generate_args(_obj({"a": {"type": "array", "items": {"type": "string"},
                                     "minItems": 3}})) == {"a": [FALLBACK] * 3}
    assert generate_args(_obj({"a": {"type": "array", "minItems": 100,
                                     "items": {"type": "boolean"}}})) == {"a": [False] * 4}
    assert generate_args(_obj({"a": {"type": "array"}})) == {"a": [FALLBACK]}
    assert generate_args(_obj({"a": {"prefixItems": [{"type": "integer"}]}})) == {"a": [1]}


def test_objects_required_plus_six_optional():
    props = {f"opt{i}": {"type": "string"} for i in range(10)}
    props["req"] = {"type": "integer"}
    out = generate_args(_obj(props, ["req", "ghost"]))
    assert out["req"] == 1
    assert out["ghost"] == FALLBACK  # required but undeclared
    assert [k for k in out if k.startswith("opt")] == [f"opt{i}" for i in range(6)]


def test_composition_first_branch_and_refs():
    schema = {
        "$defs": {"P": {"type": "object", "properties": {"path": {"type": "string"}},
                        "required": ["path"]}},
        "definitions": {"Q": {"type": "integer", "minimum": 3}},
        "type": "object",
        "properties": {
            "a": {"anyOf": [{"$ref": "#/$defs/P"}, {"type": "string"}]},
            "o": {"oneOf": [{"type": "boolean"}, {"type": "string"}]},
            "all": {"allOf": [{"$ref": "#/definitions/Q"}, {"maximum": 100}]},
            "bad": {"$ref": "#/$defs/missing"},
            "ext": {"$ref": "https://example.com/schema.json"},
        },
    }
    assert generate_args(schema) == {"a": {"path": SAMPLE_PATH}, "o": False, "all": 3,
                                     "bad": FALLBACK, "ext": FALLBACK}


def test_recursive_ref_is_depth_capped():
    schema = {"$defs": {"Node": {"type": "object", "properties": {
        "child": {"$ref": "#/$defs/Node"}, "v": {"type": "integer"}}, "required": ["child"]}},
        "type": "object", "properties": {"root": {"$ref": "#/$defs/Node"}}}
    out = generate_args(schema)
    depth, node = 0, out["root"]
    while isinstance(node, dict):
        depth, node = depth + 1, node.get("child")
    assert node == FALLBACK
    assert 1 <= depth <= 6


def test_untyped_schema_infers_from_keywords():
    out = generate_args({"properties": {"n": {"minimum": 4}, "s": {"pattern": "^a"},
                                        "arr": {"items": {"type": "string"}},
                                        "nested": {"properties": {"x": {"type": "string"}}}}})
    assert out == {"n": 4, "s": FALLBACK, "arr": [FALLBACK], "nested": {"x": FALLBACK}}


# --- determinism, goldens, robustness ---------------------------------------------------

@pytest.mark.parametrize("schema_path", GOLDEN, ids=lambda p: p.stem)
def test_golden_files(schema_path: Path):
    schema = json.loads(schema_path.read_text())
    expected = json.loads(schema_path.with_suffix(".expected.json").read_text())
    assert generate_args(schema) == expected
    assert generate_args(copy.deepcopy(schema)) == expected  # no input mutation / hidden state


@pytest.mark.parametrize("schema_path", GOLDEN, ids=lambda p: p.stem)
def test_golden_is_a_deterministic_json_document(schema_path: Path):
    schema = json.loads(schema_path.read_text())
    a = json.dumps(generate_args(schema), sort_keys=True)
    b = json.dumps(generate_args(json.loads(schema_path.read_text())), sort_keys=True)
    assert a == b


@pytest.mark.parametrize("garbage", [
    None, 42, "str", [], {"type": 42}, {"type": "object", "properties": "nope"},
    {"type": "object", "required": None, "properties": None},
    {"type": "object", "required": [1, None], "properties": {1: {"type": "string"}}},
    {"$ref": "#/$defs/self", "$defs": {"self": {"$ref": "#/$defs/self"}}},
    {"$ref": 7}, {"type": "array", "items": 3, "minItems": "x"},
    {"type": "string", "minLength": True, "maxLength": -1},
    {"type": "integer", "minimum": "9", "exclusiveMaximum": None},
    {"anyOf": "x", "oneOf": [], "allOf": [None]},
    {"type": "object", "properties": {"a": True, "b": False, "c": None}},
    {"examples": "not-a-list", "enum": {}},
])
def test_never_raises_on_garbage(garbage):
    out = generate_args(garbage)
    assert isinstance(out, dict)
    json.dumps(out)  # always serializable


# --- README mining ----------------------------------------------------------------------

README = """
# my-mcp

## Tools

### read_file
Reads a file.

```json
{"path": "/etc/hosts", "encoding": "utf8"}
```

### search_code — JSON-RPC example

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "search_code", "arguments": {"q": "TODO", "limit": 5}}}
```

### list_dir
```
$ some shell output, not json
```

Also usable from Python:

```python
client.call_tool({"name": "create_issue", "args": {"title": "bug", "labels": ["x"]}})
```
"""


def test_mine_examples_named_call_and_heading_forms():
    names = ["read_file", "search_code", "list_dir", "create_issue", "missing"]
    mined = mine_examples(README, names)
    assert mined == {
        "read_file": {"path": "/etc/hosts", "encoding": "utf8"},
        "search_code": {"q": "TODO", "limit": 5},
        "create_issue": {"title": "bug", "labels": ["x"]},
    }
    assert mine_examples(README, names) == mined  # deterministic


def test_mine_examples_first_match_wins_and_never_raises():
    text = "## echo\n```json\n{\"message\": \"first\"}\n```\n## echo\n```json\n{\"message\": \"second\"}\n```"
    assert mine_examples(text, ["echo"])["echo"] == {"message": "first"}
    assert mine_examples(None, ["echo"]) == {}
    assert mine_examples("```json\n{\"name\": \"echo\", \"arguments\": [1]}\n```", ["echo"]) == {}
    assert mine_examples("```json\n{\"name\": \"echo\"\n", ["echo"]) == {}
    assert mine_examples(README, None) == {}
    assert mine_examples(README * 50, ["x" * 10_000]) == {}
    assert mine_examples("echo ```{\n", [".*", "(echo"]) == {}


def test_mine_examples_ignores_lines_inside_fences():
    text = "```\nread_file is great\n```\n```json\n{\"path\": \"/x\"}\n```"
    assert mine_examples(text, ["read_file"]) == {}


def test_args_for_tool_merges_mined_over_generated():
    schema = _obj({"path": {"type": "string"}, "limit": {"type": "integer"}}, ["path", "limit"])
    mined = {"read_file": {"path": "/etc/hosts", "extra": True}}
    assert args_for_tool("read_file", schema, mined) == {
        "path": "/etc/hosts", "limit": 1, "extra": True}
    assert args_for_tool("other", schema, mined) == {"path": SAMPLE_PATH, "limit": 1}
    assert args_for_tool("read_file", None, {"read_file": "junk"}) == {}
    assert args_for_tool("read_file", None, None) == {}
