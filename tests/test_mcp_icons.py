"""MCP icon checks (src/scanner/mcp_icons.py) and the unsigned icon-changed watch signal.

Icons are graded as findings and fingerprinted for the watch loop; they never enter the
signed per-tool digests (agentavow.mcp-tool-definition.v1), the manifest digest or the
attestation. No network, no DB: the watch loop runs over a faked session.
"""
from __future__ import annotations

import base64
import copy
import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.scanner import mcp_scan
from src.scanner.mcp_icons import (
    ICON_DATA_URI_MAX,
    active_content,
    compute_icon_fingerprint,
    icon_findings,
)
from src.scanner.mcp_scan import analyze_mcp, compute_tool_digests, tool_definition_digest
from src.scanner.scan import ScanResult, _calculate_trust_score, _compute_manifest_digest

SERVER = "https://mcp.acme.com/mcp"
PNG = ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
       "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
PLAIN_SVG = (b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"'
             b' viewBox="0 0 24 24"><title>Acme</title><path d="M0 0h24v24H0z" fill="#f60"/>'
             b'<use xlink:href="#a"/></svg>')


def _svg_uri(svg: bytes, b64: bool = True) -> str:
    if b64:
        return "data:image/svg+xml;base64," + base64.b64encode(svg).decode()
    from urllib.parse import quote
    return "data:image/svg+xml," + quote(svg.decode())


def _tool(name: str, *srcs: str, **extra) -> dict:
    t = {"name": name, "description": f"Look up {name}.",
         "inputSchema": {"type": "object", "properties": {}}}
    if srcs:
        t["icons"] = [{"src": s} for s in srcs]
    t.update(extra)
    return t


def _found(tools, **kw) -> list:
    kw.setdefault("server_url", SERVER)
    return icon_findings(tools, **kw)


def _sev(findings) -> list[tuple[str, str]]:
    return [(f.severity, f.category) for f in findings]


# ── benign icons: no finding ─────────────────────────────────────────────────
@pytest.mark.parametrize("src", [
    PNG,
    _svg_uri(PLAIN_SVG),
    _svg_uri(PLAIN_SVG, b64=False),
    "https://mcp.acme.com/icon.svg",          # the server's own host
    "https://static.acme.com/brand/icon.svg",  # same registrable domain
    "https://acme.com/favicon.png",
    "/icons/tool.png",                         # relative: nothing new is contacted
])
def test_benign_icons_get_no_finding(src):
    assert _found([_tool("t", src)]) == []


def test_icons_with_sizes_and_mime_and_theme_are_fine():
    t = {"name": "t", "icons": [
        {"src": "https://mcp.acme.com/i-48.png", "mimeType": "image/png", "sizes": ["48x48"]},
        {"src": PNG, "mimeType": "image/png", "sizes": ["any"], "theme": "dark"}]}
    assert _found([t]) == []


def test_no_icons_at_all_is_no_finding():
    assert _found([_tool("a"), {"name": "b", "icons": None}, {"name": "c", "icons": "x"}]) == []


def test_shared_hosting_matches_by_host_only():
    server = "https://acme-mcp.vercel.app/mcp"
    assert icon_findings([_tool("t", "https://acme-mcp.vercel.app/i.png")],
                         server_url=server) == []
    f = icon_findings([_tool("t", "https://someone-else.vercel.app/i.png")], server_url=server)
    assert _sev(f) == [("low", "dynamic_remote_load")]


def test_website_url_counts_as_the_servers_own_site():
    info = {"name": "acme", "websiteUrl": "https://www.acme-brand.io"}
    assert icon_findings([_tool("t", "https://cdn.acme-brand.io/i.png")],
                         server_info=info, server_url=SERVER) == []


# ── active content: high ─────────────────────────────────────────────────────
@pytest.mark.parametrize("svg", [
    b'<svg xmlns="http://www.w3.org/2000/svg"><script>fetch("//x")</script></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
    b'<svg><rect width="1" height="1" onclick=alert(1) /></svg>',
    b'<svg><a href="javascript:alert(1)"><rect/></a></svg>',
    b'<svg><a xlink:href="&#106;avascript:alert(1)"><rect/></a></svg>',  # entity-encoded
    b'<svg><a href="java\tscript:alert(1)"><rect/></a></svg>',           # tab in scheme
    b'<svg><foreignObject><iframe src="https://x"></iframe></foreignObject></svg>',
    b'<svg><set attributeName="href" to="javascript:alert(1)"/></svg>',
])
def test_active_svg_is_high(svg):
    for src in (_svg_uri(svg), _svg_uri(svg, b64=False)):
        f = _found([_tool("t", src)])
        assert _sev(f) == [("high", "obfuscation")], (svg, src)
        assert f[0].name.startswith("Icon carries active content")
        assert f[0].file_path == "tool:t:icons"


def test_javascript_src_is_high():
    f = _found([_tool("t", "javascript:alert(1)")])
    assert _sev(f) == [("high", "obfuscation")]


def test_active_content_in_a_non_image_data_uri_is_high_and_not_image():
    f = _found([_tool("t", "data:text/html,<script>alert(1)</script>")])
    assert sorted(_sev(f)) == [("high", "obfuscation"), ("medium", "obfuscation")]


# ── outside content in an SVG: medium ────────────────────────────────────────
@pytest.mark.parametrize("svg", [
    b'<svg><foreignObject><div xmlns="http://www.w3.org/1999/xhtml">hi</div>'
    b'</foreignObject></svg>',
    b'<svg><image href="https://tracker.example/p.gif"/></svg>',
    b'<svg><use xlink:href="//evil.example/sprite.svg#a"/></svg>',
    b'<svg><style>@import "https://evil.example/x.css";</style></svg>',
    b'<svg><rect style="fill:url(https://evil.example/p.png)"/></svg>',
])
def test_svg_pulling_outside_content_is_medium(svg):
    f = _found([_tool("t", _svg_uri(svg))])
    assert _sev(f) == [("medium", "dynamic_remote_load")], svg


def test_plain_svg_namespaces_and_internal_refs_are_not_outside_content():
    assert active_content(PLAIN_SVG.decode()) == ([], [])


# ── remote hosts / schemes ───────────────────────────────────────────────────
def test_third_party_https_host_is_low():
    f = _found([_tool("t", "https://cdn.other.net/icon.png")])
    assert _sev(f) == [("low", "dynamic_remote_load")]
    assert "cdn.other.net" in f[0].name and "third-party" in f[0].name


def test_third_party_rule_needs_a_known_server_host():
    assert icon_findings([_tool("t", "https://cdn.other.net/icon.png")]) == []


def test_plain_http_is_medium_even_on_the_own_domain():
    for src in ("http://mcp.acme.com/i.png", "http://cdn.other.net/i.png"):
        assert _sev(_found([_tool("t", src)])) == [("medium", "dynamic_remote_load")]
    assert _sev(icon_findings([_tool("t", "http://x.net/i.png")])) == [
        ("medium", "dynamic_remote_load")]


@pytest.mark.parametrize("src", ["file:///etc/passwd", "ftp://x.net/i.png"])
def test_other_schemes_are_medium(src):
    assert _sev(_found([_tool("t", src)])) == [("medium", "dynamic_remote_load")]


@pytest.mark.parametrize("src", [
    "https://localhost/i.png", "https://127.0.0.1/i.png", "https://192.168.1.10/i.png",
    "https://169.254.169.254/latest", "https://[::1]/i.png", "https://printer.local/i.png",
    "http://10.0.0.4:5174/i.png", "https://intranet/i.png",
])
def test_private_addresses_are_medium(src):
    f = _found([_tool("t", src)])
    assert _sev(f) == [("medium", "dynamic_remote_load")], src
    assert "private network" in f[0].name


def test_public_ip_literal_is_low_third_party():
    for src in ("https://93.184.216.34/i.png", "https://[2606:4700::1111]/i.png"):
        assert _sev(_found([_tool("t", src)])) == [("low", "dynamic_remote_load")], src


# ── data: URI type and size ──────────────────────────────────────────────────
@pytest.mark.parametrize("src", [
    "data:text/plain,hello", "data:application/octet-stream;base64,AAAA", "data:,hello",
    "data:application/javascript,alert(1)",
])
def test_non_image_data_uri_is_medium(src):
    f = _found([_tool("t", src)])
    assert ("medium", "obfuscation") in _sev(f)
    assert all(s != "critical" for s, _ in _sev(f))


def test_large_data_uri_is_low_and_small_is_not():
    big = "data:image/png;base64," + "A" * (ICON_DATA_URI_MAX + 10)
    assert _sev(_found([_tool("t", big)])) == [("low", "robustness")]
    small = "data:image/png;base64," + "A" * 1000
    assert _found([_tool("t", small)]) == []


# ── grouping, owners, bounds ─────────────────────────────────────────────────
def test_one_finding_per_rule_and_host_listing_where():
    tools = [_tool(f"t{i}", "https://cdn.other.net/i.png") for i in range(40)]
    f = _found(tools)
    assert len(f) == 1
    assert "(40 icons)" in f[0].name
    assert f[0].snippet.startswith("tool:t0, tool:t1") and "(+35 more)" in f[0].snippet


def test_resources_prompts_and_server_info_are_checked():
    f = icon_findings(
        [], resources=[{"name": "r", "uri": "x://r", "icons": [{"src": "http://a.net/i"}]}],
        prompts=[{"name": "p", "icons": [{"src": "javascript:x"}]}],
        server_info={"name": "s", "icons": [{"src": "https://localhost/i.png"}]},
        server_url=SERVER)
    where = {x.file_path for x in f}
    assert where == {"resource:r:icons", "prompt:p:icons", "server:serverInfo:icons"}


def test_server_icon_finding_reads_as_tool_definitions():
    from src.scanner.verdict import WHERE_TOOLS, finding_where
    assert finding_where({"category": "obfuscation",
                          "file_path": "server:serverInfo:icons"}) == WHERE_TOOLS
    assert finding_where({"category": "obfuscation", "file_path": "tool:t:icons"}) == WHERE_TOOLS


def test_malformed_icons_never_raise():
    tools = [{"name": "t", "icons": [None, 3, {"src": 5}, {"src": ""}, {"nosrc": 1},
                                     {"src": "data:image/svg+xml;base64,@@@notb64"},
                                     {"src": "data:image/png"}, {"src": "https://[bad/"}]}]
    _found(tools)


def test_nothing_icon_related_is_ever_critical():
    worst = b'<svg onload="x"><script>x</script><foreignObject><iframe/></foreignObject></svg>'
    tools = [_tool("a", _svg_uri(worst), "javascript:x", "http://10.0.0.1/x",
                   "data:text/html,<script>x</script>", "https://cdn.x.net/i",
                   "data:image/png;base64," + "A" * (ICON_DATA_URI_MAX + 1))]
    sevs = {f.severity for f in _found(tools)}
    assert "critical" not in sevs and "high" in sevs


# ── analyze_mcp + score + decision ───────────────────────────────────────────
def test_analyze_mcp_reports_icon_findings_and_keeps_others():
    tools = [_tool("t", "https://cdn.other.net/i.png")]
    res = analyze_mcp(tools, server_url=SERVER)
    assert [f.name for f in res.findings if f.file_path.endswith(":icons")]
    # without a server_url the third-party rule cannot apply
    assert not [f for f in analyze_mcp(tools).findings if f.file_path.endswith(":icons")]


def _score(findings, n=6) -> int:
    r = ScanResult(repo="mcp:x", stars=0, description="", framework="")
    r.is_mcp_server = True
    r.files_scanned = r.total_scannable_files = n
    r.findings = list(findings)
    return _calculate_trust_score(r)


def test_benign_and_third_party_icons_do_not_move_the_score():
    plain = [_tool(f"t{i}") for i in range(6)]
    with_icons = [_tool(f"t{i}", PNG, "https://static.acme.com/i.svg",
                        "https://avatars.githubusercontent.com/u/1") for i in range(6)]
    base = _score(analyze_mcp(plain, server_url=SERVER).findings)
    assert _score(analyze_mcp(with_icons, server_url=SERVER).findings) == base


def test_active_icon_reads_review_never_do_not_connect():
    from src.scanner.verdict import DECISION_REVIEW, decide
    bad = _svg_uri(b'<svg onload="alert(1)"/>')
    findings = analyze_mcp([_tool("t", bad)], server_url=SERVER).findings
    items = [{"severity": f.severity, "category": f.category, "name": f.name,
              "file_path": f.file_path} for f in findings]
    data = {"trust_score": _score(findings), "coverage": {"surface": "mcp"},
            "findings": {"items": items, "critical": 0,
                         "high": sum(1 for f in findings if f.severity == "high")},
            "metadata": {"files_scanned": 1}}
    d = decide(data)
    assert d.decision == DECISION_REVIEW
    assert "in its tool definitions" in d.reason


# ── fingerprint ──────────────────────────────────────────────────────────────
def _icons_tools():
    return [
        _tool("a", "https://mcp.acme.com/a.png", PNG),
        {"name": "b", "description": "B", "icons": [
            {"src": "https://mcp.acme.com/b.svg", "mimeType": "image/svg+xml",
             "sizes": ["any"]}]},
        _tool("c"),
    ]


def test_fingerprint_shape_and_column_fit():
    fp = compute_icon_fingerprint(_icons_tools())
    assert fp.startswith("sha256:") and len(fp) == 71 <= 128


def test_fingerprint_is_stable_under_key_tool_and_icon_reordering():
    base = compute_icon_fingerprint(_icons_tools(), {"name": "s", "icons": [{"src": PNG}]})
    shuffled = list(reversed(_icons_tools()))
    shuffled[1]["icons"] = [{"sizes": ["any"], "mimeType": "image/svg+xml",
                             "src": "https://mcp.acme.com/b.svg"}]  # key order
    shuffled[2]["icons"] = list(reversed(shuffled[2]["icons"]))       # array order
    assert compute_icon_fingerprint(shuffled, {"icons": [{"src": PNG}], "name": "s"}) == base


@pytest.mark.parametrize("mutate", [
    lambda t, s: t[0]["icons"][0].update(src="https://mcp.acme.com/a2.png"),
    lambda t, s: t[1]["icons"][0].update(sizes=["48x48"]),
    lambda t, s: t[1]["icons"][0].pop("mimeType"),
    lambda t, s: t[2].update(icons=[{"src": PNG}]),          # icon added to a tool
    lambda t, s: t[0].pop("icons"),                           # icons removed
    lambda t, s: s.update(icons=[{"src": "https://cdn.x/s.png"}]),  # server icon changed
    lambda t, s: t[0].update(name="a_renamed"),               # icons moved to a new name
])
def test_fingerprint_changes_when_an_icon_changes(mutate):
    tools, info = _icons_tools(), {"name": "s", "icons": [{"src": PNG}]}
    base = compute_icon_fingerprint(tools, info)
    tools2, info2 = copy.deepcopy(tools), copy.deepcopy(info)
    mutate(tools2, info2)
    assert compute_icon_fingerprint(tools2, info2) != base


@pytest.mark.parametrize("mutate", [
    lambda t: t[0].update(description="Now does something else entirely."),
    lambda t: t[0].update(inputSchema={"type": "object", "properties": {"q": {"type": "string"}}}),
    lambda t: t[0].update(annotations={"readOnlyHint": True}, title="A"),
    lambda t: t[0].update(_meta={"x": 1}),
    lambda t: t.append(_tool("d")),                           # a new tool without icons
    lambda t: t[2].update(icons=[]),                          # [] is the same as no icons
])
def test_fingerprint_ignores_everything_but_icons(mutate):
    tools = _icons_tools()
    base = compute_icon_fingerprint(tools)
    mutate(tools)
    assert compute_icon_fingerprint(tools) == base


def test_fingerprint_none_without_tools_and_defined_without_icons():
    assert compute_icon_fingerprint(None) is None
    assert compute_icon_fingerprint([]) is None
    assert compute_icon_fingerprint(["junk"]) is None
    empty = compute_icon_fingerprint([_tool("a")])
    assert empty and empty != compute_icon_fingerprint([_tool("a", PNG)])
    assert compute_icon_fingerprint([_tool("a")], {"name": "s"}) == empty


def test_fingerprint_never_raises_on_non_canonical_values():
    fp = compute_icon_fingerprint([{"name": "a", "icons": [{"src": PNG, "sizes": float("nan")}]}])
    assert fp.startswith("sha256:")


# ── the signed digests do not see icons ──────────────────────────────────────
def test_per_tool_and_manifest_digests_ignore_icons():
    plain = [_tool("a"), _tool("b")]
    iconed = [_tool("a", PNG, "https://cdn.x.net/a.png"), _tool("b", "javascript:x")]
    for p, i in zip(plain, iconed):
        assert tool_definition_digest(p) == tool_definition_digest(i)
    assert compute_tool_digests(plain) == compute_tool_digests(iconed)
    assert (_compute_manifest_digest(compute_tool_digests(plain))
            == _compute_manifest_digest(compute_tool_digests(iconed)))


_VECTORS = (Path(__file__).resolve().parent.parent / "docs" / "standards"
            / "tool-manifest-digest-vectors-v1" / "tool-manifest-digest-v1-vectors.json")


def test_published_v1_vectors_still_match_with_icons_added():
    doc = json.loads(_VECTORS.read_text())
    tools = copy.deepcopy(doc["observed_tools"])
    for t in tools:
        t["icons"] = [{"src": "https://cdn.example.net/i.svg", "mimeType": "image/svg+xml"},
                      {"src": PNG, "sizes": ["16x16"]}]
    att = doc["attestation"]
    digests = compute_tool_digests(tools)
    assert digests == att["toolDigests"]
    assert _compute_manifest_digest(digests) == att["toolManifestDigest"]


# ── scan_mcp ─────────────────────────────────────────────────────────────────
def _served(tools, **extra):
    async def fake_fetch(url):
        return {"tools": tools, "resources": [], "prompts": [],
                "server_info": {"name": "demo-mcp"}, **extra}
    return fake_fetch


async def test_scan_mcp_sets_icon_fingerprint_and_leaves_the_digests_alone(monkeypatch):
    from src.scanner.scan import scan_mcp
    plain = [_tool("a"), _tool("b")]
    iconed = [_tool("a", "https://cdn.other.net/a.png"), _tool("b", PNG)]
    monkeypatch.setattr(mcp_scan, "fetch_mcp_tools", _served(plain))
    r0 = await scan_mcp(SERVER)
    monkeypatch.setattr(mcp_scan, "fetch_mcp_tools", _served(iconed))
    r1 = await scan_mcp(SERVER)
    assert r1.tool_digests == r0.tool_digests
    assert r1.tool_manifest_digest == r0.tool_manifest_digest
    assert r1.icon_fingerprint == compute_icon_fingerprint(iconed, {"name": "demo-mcp"})
    assert r0.icon_fingerprint and r0.icon_fingerprint != r1.icon_fingerprint
    assert [f.file_path for f in r1.findings if f.file_path.endswith(":icons")] == [
        "tool:a:icons"]
    assert r1.trust_score == r0.trust_score  # a low third-party icon is free


async def test_scan_mcp_failed_tool_list_has_no_icon_fingerprint(monkeypatch):
    from src.scanner.scan import scan_mcp
    monkeypatch.setattr(mcp_scan, "fetch_mcp_tools", _served(
        [], resources=[{"name": "r", "description": "d"}], tools_list_failed=True))
    assert (await scan_mcp(SERVER)).icon_fingerprint is None


async def test_watch_target_detail_carries_icon_digest_for_mcp(monkeypatch):
    from src.api import watch_router
    monkeypatch.setattr(mcp_scan, "fetch_mcp_tools", _served(
        [_tool("a", "http://cdn.other.net/a.png")]))
    ws = await watch_router.scan_watch_target_detail("mcp", "mcp", SERVER, db=None)
    assert ws.icon_digest == compute_icon_fingerprint(
        [_tool("a", "http://cdn.other.net/a.png")], {"name": "demo-mcp"})
    assert ws.icon_findings == [{"severity": "medium", "where": "tool:a:icons",
                                 "name": "Icon loads over plain http, not https"}]
    # other surfaces carry none
    assert watch_router.WatchScan(1, None).icon_digest is None


# ── the watch loop, with a fake session ──────────────────────────────────────
class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeSession:
    def __init__(self, state):
        self.state = state

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt):
        desc = str(stmt)
        if "tool_watches" in desc:
            return _Result(self.state["watches"])
        if "alert_webhooks" in desc:
            return _Result([self.state["hook"]] if self.state.get("hook") else [])
        return _Result([])

    async def get(self, model, key):
        if model.__name__ == "ToolWatch":
            return next((w for w in self.state["watches"] if w.id == key), None)
        return None

    async def commit(self):
        self.state["commits"] = self.state.get("commits", 0) + 1


FP_A = compute_icon_fingerprint([_tool("a", PNG)])
FP_B = compute_icon_fingerprint([_tool("a", "https://cdn.other.net/a.png")])
MANIFEST = "sha256:" + "1" * 64


@pytest.fixture
def loop_env(monkeypatch):
    from src.models import AlertWebhook, ToolWatch

    watch = ToolWatch(
        id=uuid.uuid4(), watcher_id=uuid.uuid4(), surface="mcp", owner="mcp", repo=SERVER,
        last_score=88, last_manifest_digest=MANIFEST, last_behavioral_digest=None,
        last_icon_digest=None, active=True,
    )
    hook = AlertWebhook(id=uuid.uuid4(), entity_id=watch.watcher_id,
                        url="https://hooks.example/x", active=True)
    state = {"watches": [watch], "hook": hook, "notes": [], "delivered": [],
             "icon_digest": FP_A, "icon_findings": []}
    monkeypatch.setattr("src.database.async_session", lambda: _FakeSession(state))

    async def _scan(surface, owner, repo, db):
        from src.api.watch_router import WatchScan
        return WatchScan(88, MANIFEST, icon_digest=state["icon_digest"],
                         icon_findings=list(state["icon_findings"]))

    monkeypatch.setattr("src.api.watch_router.scan_watch_target_detail", _scan)

    async def _none(*a, **k):
        return None

    monkeypatch.setattr("src.scanner.behavioral.trigger.cached_scan_data", _none)
    monkeypatch.setattr("src.scanner.behavioral.trigger.on_watch_rescan", _none)

    async def _notify(db, entity_id, kind, title, body, reference_id=None, **kw):
        state["notes"].append((kind, title, body))

    monkeypatch.setattr("src.api.notification_router.create_notification", _notify)

    async def _deliver(hook_, payload):
        state["delivered"].append(payload)
        return 204

    monkeypatch.setattr("src.api.account_webhook_router.deliver_to_hook", _deliver)
    return state, watch


async def test_loop_first_icon_observation_sets_the_baseline_silently(loop_env):
    from src.jobs import scheduler
    state, watch = loop_env
    await scheduler._run_watch_rescan()
    assert watch.last_icon_digest == FP_A
    assert state["notes"] == [] and state["delivered"] == []


async def test_loop_icon_change_alerts_once_and_not_as_definition_drift(loop_env):
    from src.jobs import scheduler
    state, watch = loop_env
    watch.last_icon_digest = FP_A
    state["icon_digest"] = FP_B
    state["icon_findings"] = [{"severity": "low", "where": "tool:a:icons",
                               "name": "Icon loads from a third-party host (cdn.other.net)"}]
    await scheduler._run_watch_rescan()
    assert [(k, t) for k, t, _b in state["notes"]] == [("watch_alert", f"mcp/{SERVER} — icon changed")]
    assert "not part of the signed tool definition" in state["notes"][0][2]
    assert "third-party host" in state["notes"][0][2]
    assert len(state["delivered"]) == 1
    p = state["delivered"][0]
    assert p["type"] == "agentavow.alert.icon_change" and p["event"] == "icon_change"
    assert (p["old_icon_fingerprint"], p["new_icon_fingerprint"]) == (FP_A, FP_B)
    assert p["icon_findings"] == state["icon_findings"]
    assert p["surface"] == "mcp" and p["score"] == 88 and "decision" in p
    assert watch.last_icon_digest == FP_B
    assert watch.last_manifest_digest == MANIFEST  # the signed digest is untouched
    assert state["hook"].last_status == 204

    # Same icons next cycle: quiet.
    await scheduler._run_watch_rescan()
    assert len(state["notes"]) == 1 and len(state["delivered"]) == 1


async def test_loop_without_an_icon_fingerprint_keeps_the_baseline(loop_env):
    from src.jobs import scheduler
    state, watch = loop_env
    watch.last_icon_digest = FP_A
    state["icon_digest"] = None
    await scheduler._run_watch_rescan()
    assert watch.last_icon_digest == FP_A
    assert state["notes"] == [] and state["delivered"] == []


def test_icon_payload_shape():
    from src.jobs.scheduler import _icon_alert_payload
    w = SimpleNamespace(owner="mcp", repo=SERVER, surface="mcp")
    ws = SimpleNamespace(icon_digest=FP_B, icon_findings=[])
    p = _icon_alert_payload(w, 90, FP_A, ws, {"decision": "safe"})
    assert p == {
        "type": "agentavow.alert.icon_change", "event": "icon_change", "owner": "mcp",
        "repo": SERVER, "surface": "mcp", "score": 90, "reason": "icon changed",
        "old_icon_fingerprint": FP_A, "new_icon_fingerprint": FP_B, "icon_findings": [],
        "decision": "safe",
    }
