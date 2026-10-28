"""Trust card v14: the small 'why' line says what was not read (runbook §0.1 item 7a).

v13 stays byte-identical (the card the ChatGPT app was approved with) and keeps serving
at its URI; v14 adds the partial-coverage line. The card script runs in node against a
stub DOM, as in tests/test_mcp_result_phrases.py.
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import shutil
import subprocess

import pytest

from src.bridges import mcp_app_view as view
from src.bridges import mcp_streamable as ms
from tests.test_mcp_result_phrases import _HARNESS

WIRE = pathlib.Path(__file__).parent / "fixtures" / "mcp_wire_2025_11_25"


def _render(sc: dict, version: int) -> dict:
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    proc = subprocess.run(["node", "-e", _HARNESS, json.dumps(sc)],
                          input=view.trust_card_html(True, card_version=version),
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


_BASE = {"target": "acme/mcp", "target_type": "mcp", "trust_score": 88, "tier": "trusted",
         "critical": 0, "high": 0, "subscores": {}, "top_findings": [], "adoption": None}
CLEAN_PARTIAL = {**_BASE, "verdict": "safe", "verdict_reason": "clean_partial",
                 "decision": "safe", "decision_reason": "no critical or high findings",
                 "not_checked": ["only the first 20 pages of the server's tool list were read"],
                 "coverage_gaps": {"tool_list_paged": True, "pages_read": 20}}
GAP_REVIEW = {**_BASE, "trust_score": 74, "verdict": "needs_review",
              "verdict_reason": "low_signals", "decision": "review",
              "decision_reason": "the server's prompt list could not be read",
              "not_checked": ["the server's prompt list could not be read"],
              "coverage_gaps": {"prompt_list_unread": True}}
BLOCKING_REVIEW = {**_BASE, "trust_score": 60, "high": 1, "verdict": "needs_review",
                   "verdict_reason": "blocking_findings", "decision": "review",
                   "decision_reason": "one high finding",
                   "not_checked": ["the server's prompt list could not be read"]}


def test_v14_why_line_names_what_was_not_read_on_a_partial_safe():
    out = _render(CLEAN_PARTIAL, 14)
    assert out["why"]["text"] == (
        "Not everything was read: only the first 20 pages of the server's tool list "
        "were read.")


def test_v14_why_line_on_a_review_caused_only_by_a_gap():
    out = _render(GAP_REVIEW, 14)
    assert out["why"]["text"] == (
        "No risks found in what was read, but the server's prompt list could not be read.")


def test_v14_leaves_a_findings_review_alone():
    out = _render(BLOCKING_REVIEW, 14)
    assert "No risks found" not in out["why"]["text"]
    assert "high" in out["why"]["text"]


def test_v14_partial_safe_without_notes_still_says_so():
    out = _render({**CLEAN_PARTIAL, "not_checked": []}, 14)
    assert out["why"]["text"] == "Not everything was read."


def test_v13_is_byte_identical_to_the_approved_card():
    v13 = asyncio.run(ms._read_resource("ui://agentavow/trust-card-v13.html"))
    assert len(v13) == 1
    wire = json.loads((WIRE / "resources_read.json").read_text(encoding="utf-8"))
    assert v13[0].content == wire["result"]["contents"][0]["text"]
    assert "__PARTIAL_WHY__" not in v13[0].content


def test_v13_still_renders_the_old_line():
    out = _render(GAP_REVIEW, 13)
    assert out["why"]["text"].startswith("No risks found; below the bar")


def test_tools_point_at_v14_and_both_cards_are_listed_and_readable():
    assert ms._CARD_URI == "ui://agentavow/trust-card-v14.html"
    assert ms._CARD_META["openai/outputTemplate"] == ms._CARD_URI
    uris = [str(r.uri) for r in asyncio.run(ms._list_resources())]
    assert uris == ["ui://agentavow/trust-card-v14.html",
                    "ui://agentavow/trust-card-v13.html"]
    v14 = asyncio.run(ms._read_resource(ms._CARD_URI))
    assert v14 and "not_checked" in v14[0].content and "__PARTIAL_WHY__" not in v14[0].content


def test_unknown_card_version_is_rejected():
    with pytest.raises(ValueError):
        view.trust_card_html(True, card_version=99)
