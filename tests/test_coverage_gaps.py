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


@pytest.mark.parametrize("path,agent,display", [
    ("SKILL.md", True, True), ("pkg/AGENTS.md", True, True), ("CLAUDE.md", True, False),
    (".mcp.json", True, True), ("server.json", True, True), ("tools.json", True, True),
    ("deep/dir/mcp.json", True, True),
    # display only: agent text by directory, rules, other names, OpenAPI specs
    ("skills/pdf/reference.md", False, True), ("x/.cursor/rules/a.mdc", False, True),
    ("plugin.json", False, True), ("openapi.json", False, True),
    ("api/openapi.yaml", False, True),
    # neither
    ("README.md", False, False), ("docs/readme.json", False, False),
    (".github/workflows/ci.md", False, False), ("docs/CHANGELOG.md", False, False),
    ("skills/pdf/run.py", False, False), ("prompts/data.json", False, False),
    ("src/app.js", False, False),
])
def test_oversized_agent_and_display_files(path, agent, display):
    assert scanmod.is_oversized_agent_file(path) is agent
    if not agent:
        assert scanmod.is_oversized_display_file(path) is display


def test_oversized_gap_counts_include_non_code_and_agent_files():
    big = scanmod._MAX_FILE_SIZE + 1
    tree = [{"path": p, "type": "blob", "size": big} for p in (
        "payload.js", "AGENTS.md", "CLAUDE.md", "config/huge.yaml", "logo.png",
        "node_modules/x/index.js", "data/table.json", "openapi.yaml",
        "skills/x/notes.md", "docs/CHANGELOG.md")]
    tree.append({"path": "small.md", "type": "blob", "size": 10})
    # payload.js, AGENTS.md, CLAUDE.md, huge.yaml, table.json, openapi.yaml, notes.md;
    # only AGENTS.md and CLAUDE.md are agent files by name (a decision input)
    assert scanmod._oversized_gap_counts(tree) == (7, 2)
    assert scanmod._oversized_gap_counts(tree, {"config/"}) == (6, 2)


@pytest.mark.asyncio
async def test_scan_repo_counts_oversized_agent_files_and_scan_errors(monkeypatch):
    big = scanmod._MAX_FILE_SIZE + 1
    oversized = [{"path": "AGENTS.md", "type": "blob", "size": big},
                 {"path": "tools.json", "type": "blob", "size": big}]
    _patch_repo(monkeypatch, oversized=oversized, fail=set())
    real = scanmod._scan_content

    def flaky(content, path, *a, **k):
        if path == "util.py":
            raise RuntimeError("engine bug")
        return real(content, path, *a, **k)

    monkeypatch.setattr(scanmod, "_scan_content", flaky)
    r = await scanmod.scan_repo("owner/repo", token="x")
    assert r.error is None
    assert r.coverage_gaps == {"oversized_files": 2, "oversized_agent_files": 2,
                               "scan_errors": 1}


def test_fold_fetch_gaps_hf_and_docker():
    from types import SimpleNamespace

    gaps: dict = {"oversized_files": 1}
    hf = SimpleNamespace(packaged_manifest={"hf": {"coverage": {
        "tree_unavailable": True, "over_cap": 3, "oversized": 2, "fetch_failed": 1,
        "custom_code_unread": 2}}})
    scanmod._fold_fetch_gaps(gaps, "huggingface", hf)
    assert gaps == {"oversized_files": 3, "package_skipped": 3, "fetch_failed": 1,
                    "custom_code_unread": 2, "tree_unavailable": True}
    gaps = {}
    img = SimpleNamespace(image={"layers": {"layers_skipped": [
        {"reason": "unsupported compression", "count": 2},
        {"reason": "time budget reached", "count": 1}]}})
    scanmod._fold_fetch_gaps(gaps, "docker", img)
    assert gaps == {"image_layers_unread": 3, "image_layers_reason": "unsupported compression"}
    gaps = {}
    scanmod._fold_fetch_gaps(gaps, "docker", SimpleNamespace(image={"layers": {}}))
    scanmod._fold_fetch_gaps(gaps, "huggingface", SimpleNamespace(packaged_manifest=None))
    scanmod._fold_fetch_gaps(gaps, "npm", SimpleNamespace())
    assert gaps == {}


@pytest.mark.asyncio
async def test_hf_fetch_reports_what_it_did_not_read(monkeypatch):
    from src.scanner import artifact_fetch as af
    from src.scanner import hf_facts

    big = af._HF_MAX_TEXT_BYTES + 1
    tree = [{"type": "file", "path": "config.json", "size": 10},
            {"type": "file", "path": "modeling_x.py", "size": big},
            {"type": "file", "path": "broken.py", "size": 10}]
    tree += [{"type": "file", "path": f"deep/a/cfg{i:02d}.json", "size": 10}
             for i in range(af._HF_MAX_TEXT_FILES + 2)]

    async def fake_json(url, client, *a, **k):
        return {"sha": "0" * 40}

    async def fake_list(url, client):
        return tree

    async def fake_text(url, client):
        return None if url.endswith("broken.py") else b"{}"

    async def fake_classify(*a, **k):
        return {}

    monkeypatch.setattr(af, "_get_json", fake_json)
    monkeypatch.setattr(af, "_get_json_list", fake_list)
    monkeypatch.setattr(af, "_download_hf_text", fake_text)
    monkeypatch.setattr(hf_facts, "classify_weights", fake_classify)
    res = await af.fetch_huggingface_artifact("org/model", client=object())
    cov = res.packaged_manifest["hf"]["coverage"]
    # 44 text targets (modeling_x.py is too large to be one), 40 attempted: 4 past the
    # cap, broken.py failed; both .py files are custom code that was not read
    assert cov == {"over_cap": 4, "oversized": 1, "fetch_failed": 1,
                   "custom_code_unread": 2}

    async def no_tree(url, client):
        raise af.ArtifactFetchError("down")

    monkeypatch.setattr(af, "_get_json_list", no_tree)
    res = await af.fetch_huggingface_artifact("org/model", client=object())
    assert res.packaged_manifest["hf"]["coverage"] == {"tree_unavailable": True}
    assert res.files == {}


def test_artifact_scan_counts_oversized_agent_files():
    from src.scanner.artifact_fetch import ArtifactFetchResult, ArtifactFile

    big = "# rules\n" * (scanmod._MAX_FILE_SIZE // 8 + 10)
    fetched = ArtifactFetchResult(ecosystem="npm", name="demo", version="1.0.0",
                                  kind="tarball", ok=True, digest="sha256:00")
    for path, text in (("index.js", "module.exports = 1\n"), ("CLAUDE.md", big),
                       ("SKILL.md", big), ("README.md", big)):
        fetched.files[path] = ArtifactFile(path=path, size=len(text), sha256="0", text=text)
    r = scanmod.ScanResult(repo="npm:demo", stars=0, description="", framework="")
    scanmod.apply_artifact_scan(r, "npm", fetched)
    assert r.coverage_gaps == {"oversized_files": 2, "oversized_agent_files": 2}


def test_artifact_scan_unreferenced_agent_text_is_display_only():
    from src.scanner.artifact_fetch import ArtifactFetchResult, ArtifactFile

    big = "# notes\n" * (scanmod._MAX_FILE_SIZE // 8 + 10)
    fetched = ArtifactFetchResult(ecosystem="npm", name="demo", version="1.0.0",
                                  kind="tarball", ok=True, digest="sha256:00")
    for path, text in (("index.js", "module.exports = 1\n"),
                       ("skills/x/notes.md", big), ("openapi.yaml", "a: 1\n" * 110000)):
        fetched.files[path] = ArtifactFile(path=path, size=len(text), sha256="0", text=text)
    r = scanmod.ScanResult(repo="npm:demo", stars=0, description="", framework="")
    scanmod.apply_artifact_scan(r, "npm", fetched)
    assert r.coverage_gaps == {"oversized_files": 2}


def _patch_skill(monkeypatch, files: dict, oversized: list[str], fail: set[str],
                 truncated: bool = False):
    big = scanmod._MAX_FILE_SIZE + 1

    async def fake_tree(owner, repo, token, meta_out=None):
        if meta_out is not None:
            meta_out["oversized"] = [{"path": p, "type": "blob", "size": big}
                                     for p in oversized]
        return ([{"path": p, "type": "blob", "size": len(t)} for p, t in files.items()],
                truncated, True, "main")

    async def fake_content(owner, repo, path, token=None, ref=None, *a, **k):
        if path in fail:
            return None
        return files.get(path)

    async def fake_token():
        return None

    import src.github_auth as gh
    monkeypatch.setattr(scanmod, "_fetch_repo_tree", fake_tree)
    monkeypatch.setattr(scanmod, "_fetch_file_content", fake_content)
    monkeypatch.setattr(gh, "get_github_token", fake_token)


SKILL_MD = ("---\nname: demo\ndescription: A demo skill.\n---\n"
            "Read [the guide](reference.md) and [notes](notes.md) first.\n")


@pytest.mark.asyncio
async def test_skill_scan_records_unread_files(monkeypatch):
    files = {"SKILL.md": SKILL_MD, "notes.md": "notes\n", "helper.sh": "echo hi\n"}
    files.update({f"docs/d{i:02d}.md": "doc\n" for i in range(40)})
    _patch_skill(monkeypatch, files, oversized=["reference.md"], fail={"notes.md"},
                 truncated=True)
    r = await scanmod.scan_skill("o", "r")
    assert r.error is None
    # notes.md (linked) failed; reference.md (linked) is over the cap; 42 candidates
    # past SKILL.md, 39 read: 3 past the cap
    assert r.coverage_gaps == {"fetch_failed": 1, "file_cap": 40, "over_file_cap": 3,
                               "oversized_files": 1, "skill_refs_unread": 2,
                               "tree_truncated": True}


@pytest.mark.asyncio
async def test_skill_scan_clean_read_has_no_gaps(monkeypatch):
    files = {"SKILL.md": SKILL_MD.replace("(reference.md)", "(notes.md)"),
             "notes.md": "notes\n"}
    # a root skill reads the repo's .md files; a big image is not one of them
    _patch_skill(monkeypatch, files, oversized=["assets/big.png"], fail=set())
    r = await scanmod.scan_skill("o", "r")
    assert r.error is None and r.coverage_gaps == {}


def test_merge_skill_gaps():
    from src.scanner.skill_collection import merge_skill_gaps

    assert merge_skill_gaps([{"fetch_failed": 1, "file_cap": 40},
                             {"fetch_failed": 2, "tree_truncated": True},
                             None, {}], 3) == {
        "fetch_failed": 3, "file_cap": 40, "skills_ungraded": 3, "tree_truncated": True}
    assert merge_skill_gaps([{}, {}], 0) == {}


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


@pytest.mark.parametrize("style,word", [("card", ">partial scan<"),
                                        ("card-stacked", ">partial scan<"),
                                        ("compact", ">partial<")])
def test_avow_badges_show_a_visible_partial_marker(style, word):
    from src.api.badge_avow import render_avow_badge

    base = dict(style=style, decision="safe", score=92)
    plain = render_avow_badge(**base)
    gappy = render_avow_badge(**base, not_checked=2)
    assert "partial" not in plain
    assert "partial scan: 2 coverage gaps, see report" in gappy  # the accessible title
    body = gappy.split("</title>", 1)[1]
    assert word in body  # and the drawn pixels, not only the title
    # an unscanned badge has nothing to call partial
    assert "partial" not in render_avow_badge(style=style, decision=None, score=None,
                                              not_checked=2).split("</title>", 1)[1]


def test_classic_certified_and_combined_badges_show_partial():
    from src.api.public_scan_router import (
        PARTIAL_SUFFIX,
        _certified_badge_response,
        _combined_badge_response,
    )

    cert = _certified_badge_response(92, "safe", partial=PARTIAL_SUFFIX).body.decode()
    assert "✓ Certified 92 · partial" in cert
    assert "partial" not in _certified_badge_response(92, "safe").body.decode()
    comb = _combined_badge_response(92, 10, decision="safe", partial=PARTIAL_SUFFIX)
    assert "92/100 · partial" in comb.body.decode()
    comb_cert = _combined_badge_response(92, 10, certified=True, decision="safe",
                                         partial=PARTIAL_SUFFIX)
    assert "✓ Certified 92 · partial" in comb_cert.body.decode()


def test_classic_card_shows_partial():
    from src.api.card_svg import render_card_svg

    kw = dict(coordinate="o/r", score=92, adoption_display=None, adoption_pct=0,
              adoption_tier=None, decision="safe")
    assert "Safe to connect · partial scan" in render_card_svg(**kw, partial=True)
    assert "partial" not in render_card_svg(**kw)


@pytest.mark.parametrize("style", ["compact", "detailed", "minimal", "flat-square"])
def test_entity_badges_show_partial(style):
    from src.api.badge_router import _render_badge_svg

    kw = dict(score=0.9, has_operator=True, style=style, entity_name="demo",
              scan_status="safe")
    assert "Safe · partial" in _render_badge_svg(**kw, partial=True)
    assert "partial" not in _render_badge_svg(**kw)
    # a legacy scan word or no scan never gains the marker
    assert "partial" not in _render_badge_svg(**{**kw, "scan_status": None}, partial=True)


def test_embed_badge_shows_partial():
    from src.api.badge_embed_router import _render_embed_badge_svg

    assert "· partial" in _render_embed_badge_svg("demo", 0.9, True, decision="safe",
                                                  partial=True)
    assert "partial" not in _render_embed_badge_svg("demo", 0.9, True, decision="safe")


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
    """Every gap is disclosure only except the ones that mean we could not read what we
    exist to read (an unread MCP tool list, an agent-instruction file over the cap, a
    file a skill links, a model's custom code, no code read at all): those read Review
    (Kenne 2026-10-20; tests/test_decision.py pins each reason)."""
    base = {"trust_score": 92, "findings": {"items": []}, "metadata": {"files_scanned": 120}}
    gaps = {"oversized_files": 9, "fetch_failed": 3, "over_file_cap": 50,
            "tree_truncated": True, "package_skipped": 2, "dependency_files_unread": 1,
            "advisory_lookup": "failed", "tool_list_unread": True, "tool_list_paged": True,
            "oversized_agent_files": 1, "skill_refs_unread": 2, "custom_code_unread": 1,
            "scan_errors": 1, "tree_unavailable": True, "image_layers_unread": 2,
            "image_layers_reason": "unsupported compression", "skills_ungraded": 4}
    review_keys = {"tool_list_unread", "oversized_agent_files", "skill_refs_unread",
                   "custom_code_unread"}
    disclosure_only = {k: v for k, v in gaps.items() if k not in review_keys}
    for score in (20, 55, 92):
        a = decide({**base, "trust_score": score})
        b = decide({**base, "trust_score": score, "coverage_gaps": disclosure_only})
        assert (a.decision, a.final) == (b.decision, b.final)
        c = decide({**base, "trust_score": score, "coverage_gaps": gaps})
        assert c.decision == "review"
    assert len(coverage_gap_notes({"coverage_gaps": gaps})) == 16
    assert coverage_gap_suffix({"coverage_gaps": gaps}).endswith("; and 14 more coverage gaps")


def test_new_gap_notes_read_plainly():
    notes = coverage_gap_notes({"coverage_gaps": {
        "oversized_agent_files": 1, "skill_refs_unread": 2, "custom_code_unread": 1,
        "scan_errors": 3, "tree_unavailable": True, "image_layers_unread": 2,
        "image_layers_reason": "unsupported compression", "skills_ungraded": 1}})
    assert notes == [
        "1 agent instruction file over 500 KB was not read",
        "2 files the skill's instructions link to were not read",
        "1 custom code file in the model was not read",
        "3 files could not be scanned",
        "the file list could not be read",
        "2 image layers were not read (unsupported compression)",
        "1 skill in the repo was not graded",
    ]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_ts_coverage_gap_notes_twin():
    cases = [{"coverage_gaps": g} for g in (
        {}, {"oversized_files": 1}, {"oversized_files": 1234, "fetch_failed": "2"},
        {"over_file_cap": 1, "file_cap": 0}, {"tree_truncated": True, "package_skipped": 1},
        {"dependency_files_unread": 3, "advisory_lookup": "failed", "tool_list_unread": True,
         "tool_list_paged": True, "time_limit_unread": 1},
        {"tree_truncated": "yes", "advisory_lookup": "ok"},
        {"oversized_agent_files": 1, "skill_refs_unread": "2", "custom_code_unread": 3,
         "scan_errors": 1, "tree_unavailable": True, "image_layers_unread": 1,
         "image_layers_reason": "layer too large", "skills_ungraded": 2},
        {"image_layers_unread": 3, "image_layers_reason": ""},
        {"image_layers_unread": 1, "image_layers_reason": 5, "tree_unavailable": "yes"},
        {"oversized_files": 2, "oversized_agent_files": 2, "fetch_failed": 1},
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


def test_skill_collection_reads_review_when_a_skill_link_was_not_read():
    from src.api.public_scan_router import _scan_result_to_dict
    from src.scanner.skill_collection import build_collection_result

    def skill(gaps):
        r = scanmod.ScanResult(repo="skill:o/r", stars=0, description="", framework="",
                               files_scanned=12, total_scannable_files=12)
        r.trust_score = 90
        r.coverage_gaps = gaps
        return r

    res = build_collection_result("skill:o/r", [
        ("skills/a/SKILL.md", skill({})),
        ("skills/b/SKILL.md", skill({"oversized_files": 1, "skill_refs_unread": 1}))], 3)
    by_path = {s["path"]: s["decision"] for s in res.artifact_scan["skills"]}
    assert by_path == {"skills/a": "safe", "skills/b": "review"}
    assert res.coverage_gaps == {"oversized_files": 1, "skill_refs_unread": 1,
                                 "skills_ungraded": 1}
    d = decide(_scan_result_to_dict(res))
    assert (d.decision, d.reason) == ("review",
                                      "a file the skill's instructions use could not be read")


# ── Review only for what we exist to read (agentgraph-72 design review) ──────────────

def _decided(r):
    from src.api.public_scan_router import _scan_result_to_dict
    d = decide(_scan_result_to_dict(r))
    return d.decision, d.reason


@pytest.mark.asyncio
async def test_root_skill_big_changelog_is_safe_with_note(monkeypatch):
    files = {"SKILL.md": SKILL_MD.replace("(reference.md)", "(notes.md)"),
             "notes.md": "notes\n"}
    files.update({f"src/m{i}.py": "x = 1\n" for i in range(8)})
    _patch_skill(monkeypatch, files, oversized=["docs/CHANGELOG.md"], fail=set())
    r = await scanmod.scan_skill("o", "r")
    assert r.error is None
    assert r.coverage_gaps == {"oversized_files": 1}
    decision, reason = _decided(r)
    assert decision == "safe"
    assert reason.endswith("; 1 file over 500 KB was not fully read")


@pytest.mark.asyncio
async def test_skill_big_referenced_guide_reads_review(monkeypatch):
    files = {"SKILL.md": SKILL_MD.replace("(reference.md)", "(guide.md)"),
             "notes.md": "notes\n"}
    _patch_skill(monkeypatch, files, oversized=["guide.md"], fail=set())
    r = await scanmod.scan_skill("o", "r")
    assert r.coverage_gaps == {"oversized_files": 1, "skill_refs_unread": 1}
    assert _decided(r) == ("review", "a file the skill's instructions use could not be read")


@pytest.mark.asyncio
async def test_skill_unreferenced_big_md_under_skills_is_display_only(monkeypatch):
    files = {"skills/pdf/SKILL.md": SKILL_MD.replace("(reference.md)", "(notes.md)"),
             "skills/pdf/notes.md": "notes\n"}
    files.update({f"skills/pdf/s{i}.py": "x = 1\n" for i in range(8)})
    _patch_skill(monkeypatch, files, oversized=["skills/pdf/extra.md"], fail=set())
    r = await scanmod.scan_skill("o", "r")
    assert r.coverage_gaps == {"oversized_files": 1}
    assert _decided(r)[0] == "safe"


@pytest.mark.asyncio
async def test_skill_big_agents_md_reads_review(monkeypatch):
    files = {"SKILL.md": SKILL_MD.replace("(reference.md)", "(notes.md)"),
             "notes.md": "notes\n"}
    _patch_skill(monkeypatch, files, oversized=["sub/AGENTS.md"], fail=set())
    r = await scanmod.scan_skill("o", "r")
    assert r.coverage_gaps == {"oversized_agent_files": 1, "oversized_files": 1}
    assert _decided(r) == ("review", "an agent instruction file was too large to read")


@pytest.mark.asyncio
async def test_repo_big_agents_md_reads_review_and_openapi_is_display_only(monkeypatch):
    big = scanmod._MAX_FILE_SIZE + 1
    _patch_repo(monkeypatch, oversized=[{"path": "AGENTS.md", "type": "blob", "size": big}],
                fail=set())
    r = await scanmod.scan_repo("owner/repo", token="x")
    assert r.coverage_gaps == {"oversized_files": 1, "oversized_agent_files": 1}
    assert _decided(r)[1] == "an agent instruction file was too large to read"
    _patch_repo(monkeypatch, oversized=[
        {"path": "openapi.yaml", "type": "blob", "size": big},
        {"path": "skills/x/notes.md", "type": "blob", "size": big}], fail=set())
    r = await scanmod.scan_repo("owner/repo", token="x")
    assert r.coverage_gaps == {"oversized_files": 2}
    assert _decided(r)[0] == "safe"
