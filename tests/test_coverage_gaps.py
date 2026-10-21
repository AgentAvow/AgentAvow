"""Partial-coverage honesty: what a scan selected but could NOT read is recorded
(``coverage_gaps``), signed, and stated beside the answer on every surface — and it
never changes the score, ``sampled``, Certified or the decision (disclosure only)."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from src.scanner import scan as scanmod
from src.scanner.verdict import coverage_gap_notes, coverage_gap_suffix, decide

ROOT = Path(__file__).resolve().parent.parent

FIXTURE = {
    "app.py": "def add(a, b):\n    return a + b\n",
    "util.py": "def sub(a, b):\n    return a - b\n",
    "lost.py": "def mul(a, b):\n    return a * b\n",
    "empty.py": "",
    "README.md": "# demo\nA demo tool.\n",
}


def _tree(extra: list[dict] | None = None) -> list[dict]:
    return [{"path": p, "type": "blob", "size": len(t)} for p, t in FIXTURE.items()] + (
        extra or [])


def _patch_repo(monkeypatch, *, oversized: list[dict], fail: set[str]) -> None:
    async def fake_tree(owner, repo, token, meta_out=None):
        if meta_out is not None:
            meta_out["oversized"] = list(oversized)
            meta_out["tree_sha"] = "abc123"
        return (_tree(), False, True, "main")

    async def fake_content(owner, repo, path, token, ref=None, *a, **k):
        if path in fail:
            return None
        return FIXTURE.get(path)

    async def fake_pkg(*a, **k):
        return {}

    async def fake_noop(*a, **k):
        return None

    monkeypatch.setattr(scanmod, "_fetch_repo_tree", fake_tree)
    monkeypatch.setattr(scanmod, "_fetch_file_content", fake_content)
    monkeypatch.setattr(scanmod, "_resolve_repo_package", fake_pkg)
    monkeypatch.setattr(scanmod, "_run_supply_chain", fake_noop)
    monkeypatch.setattr(scanmod, "_maybe_scan_artifact", fake_noop)
    monkeypatch.setattr(scanmod, "_maybe_maintainer_signals", fake_noop)


# ── the scanner records what it could not read ─────────────────────────────────────

def test_tree_blobs_collects_oversized():
    tree = [{"path": "a.py", "type": "blob", "size": 10},
            {"path": "big.py", "type": "blob", "size": scanmod._MAX_FILE_SIZE + 1},
            {"path": "dir", "type": "tree"}]
    out: list = []
    assert [i["path"] for i in scanmod._tree_blobs(tree, out)] == ["a.py"]
    assert [i["path"] for i in out] == ["big.py"]
    # without the out-list the old behaviour is unchanged
    assert [i["path"] for i in scanmod._tree_blobs(tree)] == ["a.py"]


@pytest.mark.asyncio
async def test_scan_repo_records_gaps_without_moving_score(monkeypatch):
    big = scanmod._MAX_FILE_SIZE + 1
    oversized = [{"path": "payload.js", "type": "blob", "size": big},
                 {"path": "logo.png", "type": "blob", "size": big}]  # not source: not a gap
    _patch_repo(monkeypatch, oversized=[], fail=set())
    clean = await scanmod.scan_repo("owner/repo", token="x")
    _patch_repo(monkeypatch, oversized=oversized, fail={"lost.py"})
    gappy = await scanmod.scan_repo("owner/repo", token="x")

    assert clean.error is None and gappy.error is None
    assert clean.coverage_gaps == {}
    # the padded payload file and the failed fetch are disclosed; the empty file and
    # the oversized image are not gaps
    assert gappy.coverage_gaps == {"fetch_failed": 1, "oversized_files": 1}
    # disclosure only: score, sampled and Certified checks do not move
    assert gappy.trust_score == clean.trust_score
    assert gappy.sampled is clean.sampled is False
    assert gappy.certified == clean.certified
    # the read scope is pinned: selection rule, tree sha, digest of the texts read
    assert gappy.coverage["selection"] == scanmod.REPO_SELECTION_RULE
    assert gappy.coverage["tree_sha"] == "abc123"
    assert gappy.coverage["files_read_digest"].startswith("sha256:")
    assert gappy.coverage["files_read_digest"] != clean.coverage["files_read_digest"]


def test_files_read_digest_is_order_independent():
    a = scanmod.files_read_digest({"a.py": "1", "b.py": "2"})
    b = scanmod.files_read_digest({"b.py": "2", "a.py": "1"})
    assert a == b and a.startswith("sha256:")
    assert scanmod.files_read_digest({"a.py": "1", "b.py": "3"}) != a
    assert scanmod.files_read_digest({}) is None


def test_finish_repo_coverage_folds_dependency_and_artifact_gaps():
    r = scanmod.ScanResult(repo="o/r", stars=0, description="", framework="")
    r.artifact_scan = {"ok": True, "skipped": {"scannable": 3, "oversized_scannable": 2}}
    gaps = {"oversized_files": 1, "_dep_unread": {"requirements.txt", "poetry.lock"}}
    scanmod._finish_repo_coverage(r, gaps, None, {})
    assert r.coverage_gaps == {"dependency_files_unread": 2, "oversized_files": 3,
                               "package_skipped": 3}
    assert "tree_sha" not in r.coverage and "files_read_digest" not in r.coverage


@pytest.mark.asyncio
async def test_supply_chain_failure_is_a_gap(monkeypatch):
    from src.scanner import supply_chain

    async def boom(*a, **k):
        raise RuntimeError("osv down")

    async def fake_pkg(*a, **k):
        return {}

    monkeypatch.setattr(supply_chain, "analyze_supply_chain", boom)
    monkeypatch.setattr(scanmod, "_resolve_repo_package", fake_pkg)

    async def fake_content(*a, **k):
        return "requests==2.31.0\n"

    monkeypatch.setattr(scanmod, "_fetch_file_content", fake_content)
    import asyncio

    from src.config import settings
    monkeypatch.setattr(settings, "scanner_use_osv", True, raising=False)
    r = scanmod.ScanResult(repo="o/r", stars=0, description="", framework="")
    gaps: dict = {}
    await scanmod._run_supply_chain(
        r, "o", "r", [{"path": "requirements.txt", "type": "blob", "size": 10}],
        None, "main", asyncio.Semaphore(2), 5.0, gaps)
    assert gaps["advisory_lookup"] == "failed"
    assert r.supply_chain == {}  # shape unchanged; the gap is what says it failed


@pytest.mark.asyncio
async def test_scan_mcp_discloses_unread_and_paged_tool_list(monkeypatch):
    from src.scanner import mcp_scan

    async def fake_fetch(url):
        return {"tools": [], "resources": [{"uri": "x://a", "name": "a"}], "prompts": [],
                "server_info": {"name": "demo"}, "tools_list_failed": True,
                "tools_more_pages": True}

    monkeypatch.setattr(mcp_scan, "fetch_mcp_tools", fake_fetch)
    res = await scanmod.scan_mcp("https://mcp.example.com/mcp")
    assert res.error is None
    assert res.coverage_gaps == {"tool_list_unread": True, "tool_list_paged": True}


class _Resp:
    def __init__(self, status: int, body: dict | None):
        self.status_code = status
        self.text = json.dumps(body) if body is not None else ""


class _Client:
    def __init__(self, resp):
        self._resp = resp

    async def post(self, *a, **k):
        if isinstance(self._resp, Exception):
            raise self._resp
        return self._resp


@pytest.mark.asyncio
@pytest.mark.parametrize("resp,failed,paged,n", [
    (_Resp(200, {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "a"}]}}),
     False, False, 1),
    # The same nextCursor on every page is a cursor loop: two pages read, then the
    # read stops and is disclosed as partial.
    (_Resp(200, {"jsonrpc": "2.0", "id": 2,
                 "result": {"tools": [{"name": "a"}], "nextCursor": "p2"}}), False, True, 2),
    (_Resp(500, None), True, False, 0),
    (_Resp(200, {"jsonrpc": "2.0", "id": 2, "error": {"code": -32601}}), True, False, 0),
    (RuntimeError("down"), True, False, 0),
])
async def test_mcp_session_list_records_failure_and_paging(resp, failed, paged, n):
    from src.scanner.mcp_scan import McpSession

    s = McpSession(_Client(resp), "https://mcp.example.com/mcp")
    tools = await s.list("tools/list", "tools")
    assert len(tools) == n
    assert ("tools/list" in s.list_failed) is failed
    assert ("tools/list" in s.list_more_pages) is paged


def test_bounded_unpack_counts_oversized_source_members():
    from src.scanner.artifact_fetch import MAX_MEMBER_BYTES, SkipReport, _BoundedMembers

    rep = SkipReport()
    bm = _BoundedMembers(1000, rep)
    assert bm.admit("pkg/huge.py", MAX_MEMBER_BYTES + 1) is False
    assert bm.admit("pkg/huge.png", MAX_MEMBER_BYTES + 1) is False
    assert rep.oversized_scannable == 1
    assert rep.scannable == 0  # not a sampling loss: `sampled` is unchanged
    assert rep.summary()["oversized_scannable"] == 1
    assert "oversized_scannable" not in SkipReport().summary()


def test_artifact_scan_records_oversized_kept_files():
    from src.scanner.artifact_fetch import ArtifactFetchResult, ArtifactFile

    big = "x = 1\n" * (scanmod._MAX_FILE_SIZE // 6 + 10)
    fetched = ArtifactFetchResult(ecosystem="npm", name="demo", version="1.0.0",
                                  kind="tarball", ok=True, digest="sha256:00")
    for path, text in (("index.js", "module.exports = 1\n"), ("payload.js", big),
                       ("README.md", "# demo\n")):
        fetched.files[path] = ArtifactFile(path=path, size=len(text), sha256="0", text=text)
    r = scanmod.ScanResult(repo="npm:demo", stars=0, description="", framework="")
    scanmod.apply_artifact_scan(r, "npm", fetched)
    assert r.coverage_gaps == {"oversized_files": 1}
    assert r.sampled is False


# ── every surface states it ────────────────────────────────────────────────────────

def _result_with_gaps():
    r = scanmod.ScanResult(repo="o/r", stars=0, description="", framework="",
                           files_scanned=120, total_scannable_files=120)
    r.trust_score = 92
    r.coverage_gaps = {"oversized_files": 2}
    return r


def test_api_dict_signed_payload_and_response_carry_gaps():
    from src.api.public_scan_router import (
        _build_scan_payload,
        _package_response,
        _scan_result_to_dict,
    )

    data = _scan_result_to_dict(_result_with_gaps())
    assert data["coverage_gaps"] == {"oversized_files": 2}
    payload = _build_scan_payload("o/r", data)
    assert payload["scan"]["coverageGaps"] == {"oversized_files": 2}
    resp = _package_response("o/r", data, "jws", False)
    assert resp.not_checked == ["2 files over 500 KB were not fully read"]
    assert resp.coverage_gaps == {"oversized_files": 2}
    assert resp.decision == "safe"
    assert resp.decision_reason.endswith("; 2 files over 500 KB were not fully read")
    # nothing missed: no signed key, empty note list
    data2 = _scan_result_to_dict(scanmod.ScanResult(repo="o/r", stars=0, description="",
                                                   framework=""))
    assert "coverageGaps" not in _build_scan_payload("o/r", data2)["scan"]


def test_badge_title_says_partial_scan_only_when_gaps():
    from src.api.badge_avow import render_avow_badge

    base = dict(style="card", decision="safe", score=92)
    plain = render_avow_badge(**base)
    gappy = render_avow_badge(**base, not_checked=2)
    assert "partial scan" not in plain
    assert "partial scan: 2 coverage gaps, see report" in gappy
    # the drawn badge is the same apart from the accessible title
    assert plain.split("</title>", 1)[1] == gappy.split("</title>", 1)[1]


def test_mcp_text_lists_not_checked_and_silent_sandbox():
    from src.bridges.mcp_streamable import _sandbox_section, _scan_block

    data = {"trust_score": 92, "trust_tier": "trusted", "metadata": {"files_scanned": 120},
            "findings": {"items": [], "total": 0}, "coverage_gaps": {"oversized_files": 1}}
    text = _scan_block(data, "connect", "/check/o/r", "o/r")
    assert "**Not checked:** 1 file over 500 KB was not fully read. A clean result covers only " \
           "what was read." in text
    assert "1 file over 500 KB" in text.splitlines()[0]  # in the Safe reason too
    assert "Not checked" not in _scan_block({**data, "coverage_gaps": {}}, "connect",
                                            "/check/o/r", "o/r")
    lines = _sandbox_section({"behavioral": {"ran": False, "reason": "behavioral tier error"}})
    assert lines and "did not run (behavioral tier error)" in lines[0]


def test_notes_never_change_the_decision():
    """Every gap but the MCP list gaps is disclosure only (an unread or partly read tool
    list, and an unread or oversized resources/prompts list, read Review, Kenne
    2026-10-20; tests/test_decision.py pins them)."""
    base = {"trust_score": 92, "findings": {"items": []}, "metadata": {"files_scanned": 120}}
    gaps = {"oversized_files": 9, "fetch_failed": 3, "over_file_cap": 50,
            "tree_truncated": True, "package_skipped": 2, "dependency_files_unread": 1,
            "advisory_lookup": "failed", "tool_list_unread": True, "tool_list_paged": True}
    review_kinds = {"tool_list_unread", "tool_list_paged"}
    disclosure_only = {k: v for k, v in gaps.items() if k not in review_kinds}
    for score in (20, 55, 92):
        a = decide({**base, "trust_score": score})
        b = decide({**base, "trust_score": score, "coverage_gaps": disclosure_only})
        assert (a.decision, a.final) == (b.decision, b.final)
        c = decide({**base, "trust_score": score, "coverage_gaps": gaps})
        assert c.decision == "review"
    assert len(coverage_gap_notes({"coverage_gaps": gaps})) == 9
    assert coverage_gap_suffix({"coverage_gaps": gaps}).endswith("; and 7 more coverage gaps")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_ts_coverage_gap_notes_twin():
    cases = [{"coverage_gaps": g} for g in (
        {}, {"oversized_files": 1}, {"oversized_files": 1234, "fetch_failed": "2"},
        {"over_file_cap": 1, "file_cap": 0}, {"tree_truncated": True, "package_skipped": 1},
        {"dependency_files_unread": 3, "advisory_lookup": "failed", "tool_list_unread": True,
         "tool_list_paged": True, "time_limit_unread": 1},
        {"tool_list_paged": True, "pages_read": 1},
        {"tool_list_paged": True, "pages_read": 20},
        {"tool_list_paged": True, "pages_read": "1234"},
        {"tool_list_paged": True, "pages_read": 0},
        {"pages_read": 5},
        {"resource_list_unread": True, "prompt_list_too_large": True},
        {"resource_list_unread": True, "resource_list_too_large": True,
         "prompt_list_unread": "yes"},
        {"tree_truncated": "yes", "advisory_lookup": "ok"},
    )] + [{"coverage_gaps": ["x"]}, {}]
    script = (
        "const m = await import(process.argv[1]);"
        "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{"
        "const out=JSON.parse(s).map(x=>[m.coverageGapNotes(x), m.coverageGapSuffix(x)]);"
        "process.stdout.write(JSON.stringify(out));});"
    )
    ts = ROOT / "web" / "src" / "components" / "trust" / "gradeSystem.ts"
    proc = subprocess.run(
        ["node", "--no-warnings", "--experimental-strip-types", "--input-type=module",
         "-e", script, str(ts)],
        input=json.dumps(cases), capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 and "strip-types" in proc.stderr:
        pytest.skip("node lacks type stripping")
    assert proc.returncode == 0, proc.stderr
    want = [[coverage_gap_notes(c), coverage_gap_suffix(c)] for c in cases]
    assert json.loads(proc.stdout) == want
