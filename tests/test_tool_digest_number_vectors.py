"""The per-tool digest's number handling: the issuer, the Python gate, the Claude Code
plugin gate and (when node is available) the JavaScript readers agree.

The issuer (src/scanner/mcp_scan.py) reads every JSON number as an IEEE 754 double,
as JSON.parse does, and signs over its ECMAScript form. The gates must compute the
same bytes, or they cannot bind to a tool the issuer signed. Vectors:
docs/standards/tool-manifest-digest-vectors-v1-numbers. No database, no network.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import random
import shutil
import struct
import subprocess

import pytest

from src.bridges import tool_gate as tg
from src.scanner import mcp_scan

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKET = ROOT / "docs" / "standards" / "tool-manifest-digest-vectors-v1-numbers"
VECTORS = PACKET / "tool-manifest-digest-v1-numbers-vectors.json"
PLUGIN_GATES = [
    ROOT / "plugins" / "agentavow-trust" / "scripts" / "agentavow_pretool_gate.py",
    ROOT / "integrations" / "claude-code" / "agentavow_pretool_gate.py",
]
CANONICALIZE = ROOT / "sdk" / "js" / "node_modules" / "canonicalize"


def _load(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(f"gate_{path.parent.name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(VECTORS.read_text())


@pytest.fixture(scope="module")
def plugins() -> list:
    return [_load(p) for p in PLUGIN_GATES]


def _local_digest(definition: dict) -> str:
    """The gate's stdlib derivation, not the issuer import it prefers."""
    return tg.tool_digest(definition)


def test_vector_file_is_what_the_issuer_generates(vectors):
    spec = importlib.util.spec_from_file_location("gen_numbers", PACKET / "generate.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert gen.build() == vectors
    assert {c["name"] for c in vectors["cases"]} == {
        "fraction", "integer-2^53", "integer-2^53+1", "large-exponent", "negative-zero"}


def test_issuer_gate_and_plugins_agree_on_every_vector(vectors, plugins):
    for case in vectors["cases"]:
        definition = json.loads(case["definition_json"])
        want = case["digest"]
        assert mcp_scan.tool_definition_digest(definition) == want, case["name"]
        assert _local_digest(definition) == want, case["name"]
        assert tg.served_tool_digest(definition) == want, case["name"]
        body = {f: definition[f] for f in tg.DIGEST_FIELDS if definition.get(f) is not None}
        assert tg.jcs({"profile": tg.PROFILE, "tool": tg._ijson(body)}) == case["preimage"]
        for plugin in plugins:
            assert plugin.tool_digest(definition) == want, (plugin.__name__, case["name"])
    by_name = {c["name"]: c["digest"] for c in vectors["cases"]}
    for group in vectors["same_digest"]:
        assert len({by_name[n] for n in group}) == 1


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_packet_verifier_agrees():
    out = subprocess.run(["node", str(PACKET / "verify.mjs")], capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAIL" not in out.stdout


@pytest.mark.skipif(shutil.which("node") is None or not CANONICALIZE.exists(),
                    reason="node or sdk/js node_modules (canonicalize) not installed")
def test_the_npm_gate_canonicalizer_agrees(vectors):
    # sdk/js/src/gate.ts hashes canonicalize({profile, tool}); run that library here.
    script = (
        "const c=require(process.argv[1]);const h=require('node:crypto');"
        "const F=['name','title','description','inputSchema','outputSchema','annotations'];"
        "const out=JSON.parse(require('node:fs').readFileSync(0,'utf8')).map(t=>{"
        "const d=JSON.parse(t),b={};for(const f of F)if(d[f]!==undefined&&d[f]!==null)b[f]=d[f];"
        "return 'sha256:'+h.createHash('sha256').update(c({profile:"
        "'agentavow.mcp-tool-definition.v1',tool:b})).digest('hex')});"
        "process.stdout.write(JSON.stringify(out))")
    texts = [c["definition_json"] for c in vectors["cases"]]
    out = subprocess.run(["node", "-e", script, str(CANONICALIZE)], input=json.dumps(texts),
                         capture_output=True, text=True, timeout=60, check=True)
    assert json.loads(out.stdout) == [c["digest"] for c in vectors["cases"]]


# ── differential: the gate's stdlib JCS against the issuer's, beyond the vectors ──


def _double(rng: random.Random) -> float:
    if rng.random() < 0.6:
        return struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0]
    return rng.choice([1, -1]) * rng.random() * 10 ** rng.randint(-30, 30)


def test_number_form_matches_rfc8785_on_random_doubles():
    rfc8785 = pytest.importorskip("rfc8785")
    rng = random.Random(8785)
    edges = [0.0, -0.0, 0.1, 1e21, 1e20, 9.999999999999999e20, 1e-6, 1e-7, 5e-324,
             1.7976931348623157e308, 2.0**53, 2.0**53 + 2, 123456789012345680000.0]
    for x in edges + [_double(rng) for _ in range(20000)]:
        if x != x or x in (float("inf"), float("-inf")):
            continue
        assert tg._es_number(x) == rfc8785.dumps(x).decode(), repr(x)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_number_form_matches_ecmascript():
    rng = random.Random(262)
    xs = [x for x in (_double(rng) for _ in range(5000))
          if x == x and x not in (float("inf"), float("-inf"))]
    out = subprocess.run(
        ["node", "-e", "const a=JSON.parse(require('node:fs').readFileSync(0,'utf8'));"
         "process.stdout.write(JSON.stringify(a.map(String)))"],
        input="[" + ",".join(repr(x) for x in xs) + "]", capture_output=True, text=True,
        timeout=60, check=True)
    assert [tg._es_number(x) for x in xs] == json.loads(out.stdout)


def _scalar(rng: random.Random):
    return rng.choice([
        lambda: _double(rng), lambda: rng.randint(-2**70, 2**70),
        lambda: rng.choice([2**53 - 1, 2**53, 2**53 + 1, -(2**53) - 1, 10**21, 10**400]),
        lambda: rng.choice([float("nan"), float("inf"), float("-inf")]),
        lambda: rng.choice(["\ud800", "a\udfffb", "ok", "é😀", "\x00\x1f\"\\", " "]),
        lambda: rng.choice([True, False, None, 0, -0.0]),
    ])()


def _tree(rng: random.Random, depth: int = 0):
    r = rng.random()
    if depth > 3 or r < 0.4:
        return _scalar(rng)
    if r < 0.7:
        return [_tree(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    if r < 0.75:
        return tuple(_tree(rng, depth + 1) for _ in range(rng.randint(0, 3)))
    keys = ["a", "b", "é", "😀", "＀", "\ud83d", "type", "max"]
    node = {rng.choice(keys): _tree(rng, depth + 1) for _ in range(rng.randint(0, 4))}
    if rng.random() < 0.05:
        node[1] = "a non-string key"
    return node


def test_gate_digest_equals_the_issuer_on_random_definitions(plugins):
    rng = random.Random(53)
    for _ in range(3000):
        tool = {"name": "t", "inputSchema": _tree(rng), "annotations": _tree(rng)}
        if rng.random() < 0.3:
            tool["description"] = _scalar(rng)
        want = mcp_scan.tool_definition_digest(tool)
        assert _local_digest(tool) == want, repr(tool)[:200]
        for plugin in plugins:
            assert plugin.tool_digest(tool) == want, repr(tool)[:200]


def test_non_finite_numbers_keep_the_issuers_distinct_label(plugins):
    # NaN / Infinity are not JCS: the issuer digests them under a ".noncanonical" label
    # that no portable digest can equal. The gates now compute that same digest.
    for value in (float("nan"), float("inf"), float("-inf"), 10**400):
        tool = {"name": "t", "inputSchema": {"max": value}}
        want = mcp_scan.tool_definition_digest(tool)
        body = {"name": "t", "inputSchema": {"max": value}}
        assert want == tg._sha256(tg.PROFILE + ".noncanonical\n" + json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        assert _local_digest(tool) == want
        assert all(p.tool_digest(tool) == want for p in plugins)
