"""The issuer's fallback digest for definitions RFC 8785 cannot carry (a lone
surrogate, a number too large for a double): the issuer, the Python gate, the Claude
Code plugin gate and the packet verifier agree, and the fallback carries the text, so a
change to such a tool is drift. Vectors:
docs/standards/tool-manifest-digest-vectors-v1-noncanonical. No database, no network.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import subprocess

import pytest

from src.bridges import tool_gate as tg
from src.scanner import mcp_scan

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKET = ROOT / "docs" / "standards" / "tool-manifest-digest-vectors-v1-noncanonical"
VECTORS = PACKET / "tool-manifest-digest-v1-noncanonical-vectors.json"
PLUGIN_GATES = [
    ROOT / "plugins" / "agentavow-trust" / "scripts" / "agentavow_pretool_gate.py",
    ROOT / "integrations" / "claude-code" / "agentavow_pretool_gate.py",
]


def _load(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(f"gate_nc_{path.parent.name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(VECTORS.read_text())


def test_vector_file_is_what_the_issuer_generates(vectors):
    spec = importlib.util.spec_from_file_location("gen_noncanonical", PACKET / "generate.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert gen.build() == vectors


def test_issuer_gate_and_plugins_agree_on_every_vector(vectors):
    plugins = [_load(p) for p in PLUGIN_GATES]
    for case in vectors["cases"]:
        definition = json.loads(case["definition_json"])
        want = case["digest"]
        assert want != tg.UNBOUND_DIGEST
        assert mcp_scan.tool_definition_digest(definition) == want, case["name"]
        assert tg.tool_digest(definition) == want, case["name"]
        assert tg.served_tool_digest(definition) == want, case["name"]
        for plugin in plugins:
            assert plugin.tool_digest(definition) == want, (plugin.__name__, case["name"])
    by_name = {c["name"]: c["digest"] for c in vectors["cases"]}
    for a, b in vectors["different_digest"]:
        assert by_name[a] != by_name[b]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_packet_verifier_agrees():
    out = subprocess.run(["node", str(PACKET / "verify.mjs")], capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAIL" not in out.stdout


def test_drift_on_a_lone_surrogate_tool_reaches_the_watch_signal(vectors):
    # The watch loop compares compute_tool_digests maps and the manifest fold.
    from src.scanner.scan import _compute_manifest_digest
    by_name = {c["name"]: json.loads(c["definition_json"]) for c in vectors["cases"]}
    before = mcp_scan.compute_tool_digests([by_name["lone-surrogate"]])
    after = mcp_scan.compute_tool_digests([by_name["lone-surrogate-drift"]])
    assert before.keys() == after.keys() and before != after
    assert _compute_manifest_digest(before) != _compute_manifest_digest(after)
