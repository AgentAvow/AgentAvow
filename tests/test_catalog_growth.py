"""Catalog growth (src/catalog_growth): discovery, version refresh, switches, safety.

All network is faked (a routing fake HTTP client); sleeps are recorded, not slept. The
DB tests use the session from conftest's ``db`` fixture (rolled back after each test).
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import src.api.scan_catalog_router as scr
from src.catalog_growth import discover, execute, refresh
from src.catalog_growth import state as st
from src.catalog_growth.__main__ import run_job
from src.catalog_growth.http import Fetcher
from src.catalog_growth.index import CatalogIndex, add_community, add_corpus

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


# -- fakes -------------------------------------------------------------------------
class Resp:
    def __init__(self, status: int = 200, body: Any = None, headers: dict | None = None,
                 text: str | None = None) -> None:
        self.status_code = status
        self._body = body
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.text = text if text is not None else json.dumps(body)

    def json(self) -> Any:
        return self._body


class FakeClient:
    """Routes GETs by URL prefix to a handler(url, params, headers) -> Resp."""

    def __init__(self, routes: dict[str, Any] | None = None) -> None:
        self.routes = routes or {}
        self.calls: list[tuple[str, dict | None, dict | None]] = []

    async def get(self, url: str, params: dict | None = None, headers: dict | None = None):
        self.calls.append((url, params, headers))
        for prefix, h in self.routes.items():
            if url.startswith(prefix):
                return h(url, params or {}, headers or {}) if callable(h) else h
        return Resp(404, {})

    async def aclose(self) -> None:
        pass


class Sleeps:
    def __init__(self) -> None:
        self.t = 0.0
        self.waits: list[float] = []

    async def sleep(self, s: float) -> None:
        self.waits.append(s)
        self.t += s

    def clock(self) -> float:
        return self.t


def fetcher(client: FakeClient, **kw) -> Fetcher:
    s = Sleeps()
    f = Fetcher(client, sleep=s.sleep, clock=s.clock, **kw)
    f._sleeps = s  # type: ignore[attr-defined]
    return f


def corpus_rows() -> list:
    raws = [
        ("mcp", {"name": "io.github.Acme/tool", "full_name": "Acme/tool", "trust_score": 90,
                 "critical": 0, "high": 0, "stars": 50}),
        ("mcp", {"name": "com.example/remote-only", "repository_url": None,
                 "skipped": "non_github_repo"}),
        ("mcp", {"name": "com.example/nothing", "repository_url": None,
                 "skipped": "non_github_repo"}),
        ("npm", {"name": "left-pad-mcp", "trust_score": 80, "critical": 0, "high": 0,
                 "stars": 10}),
        ("pypi", {"name": "Fancy_Agent", "trust_score": 70, "critical": 0, "high": 0}),
        ("openclaw", {"repo": "skillz/one", "trust_score": 60, "critical_count": 0,
                      "high_count": 0, "stars": 3}),
    ]
    return [scr._normalize_row(s, r) for s, r in raws]


def make_index(community: list[tuple] | None = None) -> CatalogIndex:
    idx = CatalogIndex()
    add_corpus(idx, scr._dedupe_static(corpus_rows()))
    add_community(idx, community or [
        ("mcp", "mcp", "https://live.example.com/mcp", "mcp/https://live.example.com/mcp",
         None, NOW, "safe"),
        ("npm", "npm", "popular-pkg", "npm/popular-pkg", 50_000, NOW - timedelta(days=3),
         "safe"),
    ])
    return idx


# -- switches ----------------------------------------------------------------------
def test_flags_default_off():
    from src.config import Settings

    s = Settings(_env_file=None)
    assert s.catalog_discovery == "off" and s.catalog_refresh == "off"
    assert st.mode_for("discover", s) == "off"
    assert st.mode_for("refresh", s) == "off"


@pytest.mark.parametrize("raw,want", [
    ("on", "on"), ("ON", "on"), ("dry-run", "dry-run"), ("dry_run", "dry-run"),
    ("dryrun", "dry-run"), ("", "off"), (None, "off"), ("yes", "off"), ("true", "off"),
])
def test_mode_parsing(raw, want):
    assert st.mode_for("discover", SimpleNamespace(catalog_discovery=raw)) == want


@pytest.mark.asyncio
async def test_off_does_nothing(tmp_path):
    client = FakeClient()
    settings = SimpleNamespace(catalog_discovery="off", catalog_refresh="off",
                               catalog_growth_data_dir=str(tmp_path / "cg"))
    for job in ("discover", "refresh"):
        run = await run_job(job, settings=settings, client=client)
        assert run == {"job": job, "mode": "off"}
    assert client.calls == []
    assert not (tmp_path / "cg").exists()


# -- rate limiting / backoff ---------------------------------------------------------
@pytest.mark.asyncio
async def test_retry_after_is_honoured_then_succeeds():
    seq = [Resp(429, {}, {"Retry-After": "7"}), Resp(200, {"ok": 1})]
    client = FakeClient({"https://x": lambda u, p, h: seq.pop(0)})
    f = fetcher(client)
    assert await f.get_json("https://x/a", policy="npm") == {"ok": 1}
    assert 7.0 in f._sleeps.waits
    assert f.retries["npm"] == 1 and f.calls["npm"] == 2


@pytest.mark.asyncio
async def test_exponential_backoff_on_5xx_and_gives_up():
    client = FakeClient({"https://x": Resp(503, {})})
    f = fetcher(client, max_attempts=4, base_backoff=2.0)
    resp = await f.get("https://x/a", policy="pypi")
    assert resp.status_code == 503
    backoffs = [w for w in f._sleeps.waits if w >= 2.0]
    assert backoffs == [2.0, 4.0, 8.0]
    assert f.calls["pypi"] == 4


@pytest.mark.asyncio
async def test_no_retry_on_4xx_and_backoff_capped():
    client = FakeClient({"https://x": Resp(404, {})})
    f = fetcher(client)
    assert (await f.get("https://x/a", policy="npm")).status_code == 404
    assert f.calls["npm"] == 1
    assert Fetcher(client, max_backoff=60).backoff_for(Resp(429, {}, {"Retry-After": "9999"}),
                                                         1) == 60


@pytest.mark.asyncio
async def test_pacing_keeps_the_per_registry_gap():
    client = FakeClient({"https://x": Resp(200, {})})
    f = fetcher(client)
    for _ in range(5):
        await f.get("https://x/a", policy="npm")
    # npm: one call per second at most (3,600/h, under the 5,000/h limit)
    assert f._sleeps.t >= 4.0
    assert 3600 / f.policies["npm"] <= 5000
    assert 3600 / f.policies["github_search"] <= 30 * 60


@pytest.mark.asyncio
async def test_github_budget_read_from_headers():
    client = FakeClient({"https://api.github.com": Resp(
        200, {}, {"x-ratelimit-remaining": "1234"}, text="a" * 40)})
    f = fetcher(client)
    await f.get("https://api.github.com/x", policy="github")
    assert f.github_remaining == 1234


# -- discovery dedupe ----------------------------------------------------------------
def test_dedupe_uses_the_catalog_page_key():
    idx = make_index()
    report: dict = {"by_source": {}}
    queued: dict = {}
    cands = [
        # same repo as the corpus row, different case -> already listed
        discover.Candidate("mcp_registry", "mcp", "io.github.acme/tool", full_name="acme/TOOL"),
        # endpoint already live in community_scans -> already
        discover.Candidate("mcp_registry", "mcp", "https://live.example.com/mcp",
                           endpoint_url="https://live.example.com/mcp"),
        # packages already listed (PyPI by its PEP 503 name)
        discover.Candidate("npm", "npm", "left-pad-mcp", adoption=100),
        discover.Candidate("npm", "npm", "popular-pkg", adoption=100),
        discover.Candidate("pypi", "pypi", "fancy-agent", adoption=100),
        # skill repo already listed via the corpus
        discover.Candidate("openclaw", "openclaw", "Skillz/One", full_name="Skillz/One"),
        # genuinely new
        discover.Candidate("npm", "npm", "brand-new-mcp", version="1.0.0", adoption=900),
        discover.Candidate("smithery", "github", "new/repo", full_name="new/repo",
                           adoption=5),
        # the same new repo from another source: queued once
        discover.Candidate("mcp_registry", "mcp", "io.github.new/repo", full_name="New/Repo"),
        # no code, no URL
        discover.Candidate("mcp_registry", "mcp", "com.example/pkgless"),
        # under the adoption floor
        discover.Candidate("npm", "npm", "tiny-experiment", adoption=1, below_floor=True),
    ]
    discover.classify(cands, idx, {}, retry_after_iso="2026-10-01", report=report,
                      queued=queued)
    assert set(queued) == {"/check/pkg/npm/brand-new-mcp", "/check/new/repo"}
    assert queued["/check/pkg/npm/brand-new-mcp"]["surface"] == "npm"
    assert queued["/check/new/repo"]["surface"] == "github"
    bs = report["by_source"]
    assert bs["mcp_registry"]["already"] == 3  # acme/tool, live endpoint, New/Repo
    assert bs["mcp_registry"]["no_code_no_url"] == 1
    assert bs["npm"]["already"] == 2 and bs["npm"]["below_floor"] == 1
    assert bs["pypi"]["already"] == 1 and bs["openclaw"]["already"] == 1


def test_failed_tool_waits_before_retry():
    idx = make_index()
    rep: dict = {"by_source": {}}
    q: dict = {}
    key = "/check/pkg/npm/flaky"
    discover.classify([discover.Candidate("npm", "npm", "flaky", adoption=100)], idx,
                      {key: "2026-11-10T00:00:00+00:00"},
                      retry_after_iso="2026-10-13T00:00:00+00:00", report=rep, queued=q)
    assert q == {} and rep["by_source"]["npm"]["retry_wait"] == 1


@pytest.mark.asyncio
async def test_mcp_registry_source_parses_latest_servers():
    page1 = {"servers": [
        {"server": {"name": "io.github.a/b", "version": "1.2.0",
                    "repository": {"url": "https://github.com/a/b.git"}}},
        {"server": {"name": "com.r/remote", "version": "2",
                    "remotes": [{"type": "sse", "url": "https://r.example/sse"},
                                {"type": "streamable-http", "url": "https://r.example/mcp"}]}},
        {"server": {"name": "com.p/pkg", "packages": [
            {"registryType": "pypi", "identifier": "p-mcp", "version": "0.3"}]}},
        {"server": {"name": "com.t/templated",
                    "remotes": [{"type": "streamable-http", "url": "https://{tenant}.t/mcp"}]}},
        {"server": {"name": "com.gone/x"},
         "_meta": {"io.modelcontextprotocol.registry/official": {"status": "deleted"}}},
    ], "metadata": {"nextCursor": "c1"}}
    page2 = {"servers": [{"server": {"name": "io.github.a/b", "version": "1.2.0"}}],
             "metadata": {}}
    pages = [page1, page2]
    client = FakeClient({discover.MCP_REGISTRY_URL: lambda u, p, h: Resp(200, pages.pop(0))})
    cands, remotes = await discover.mcp_registry(fetcher(client))
    by_name = {c.registry_name: c for c in cands}
    assert by_name["io.github.a/b"].full_name == "a/b"
    assert by_name["com.r/remote"].endpoint_url == "https://r.example/mcp"
    assert by_name["com.p/pkg"].surface == "pypi" and by_name["com.p/pkg"].name == "p-mcp"
    assert by_name["com.t/templated"].endpoint_url is None
    assert "com.gone/x" not in by_name
    assert remotes == {"com.r/remote": "https://r.example/mcp"}
    assert client.calls[0][1]["version"] == "latest"
    assert client.calls[1][1]["cursor"] == "c1"



@pytest.mark.asyncio
async def test_mcp_registry_warns_when_page_cap_hit(caplog):
    n = iter(range(10))
    client = FakeClient({discover.MCP_REGISTRY_URL: lambda u, p, h: Resp(200, {
        "servers": [{"server": {"name": f"com.x/s{next(n)}"}}],
        "metadata": {"nextCursor": "more"}})})
    with caplog.at_level("WARNING"):
        cands, _ = await discover.mcp_registry(fetcher(client), max_pages=2)
    assert len(cands) == 2 and len(client.calls) == 2
    assert "page cap" in caplog.text


def test_mcp_registry_cap_reads_past_60k():
    assert discover.MCP_REGISTRY_MAX_PAGES * 100 > 60_000

def test_skipped_with_url_pass():
    idx = make_index()
    assert {"com.example/remote-only", "com.example/nothing"} <= idx.skipped_mcp_names
    rep: dict = {"by_source": {}}
    q: dict = {}
    discover.skipped_with_url(
        idx, {"com.example/remote-only": "https://remote.example.com/mcp"},
        {"com.example/nothing": "http://insecure.example/mcp"}, rep, q, {}, "2026-01-01")
    item = q["/check/mcp?endpoint=https%3A%2F%2Fremote.example.com%2Fmcp"]
    assert item["surface"] == "mcp" and item["reason"] == "skipped_url"
    assert item["registry_name"] == "com.example/remote-only"
    counts = rep["by_source"]["skipped_corpus"]
    assert counts["skipped_with_url"] == 1 and counts["no_code_no_url"] == 1


def test_endpoint_identity_refuses_credentialed_or_plain_http():
    assert discover.endpoint_identity("https://a.example/mcp?key=1#x") == "https://a.example/mcp"
    assert discover.endpoint_identity("http://a.example/mcp") is None
    assert discover.endpoint_identity(
        "https://a.example/mcp/0123456789abcdef0123456789abcdef") is None


# -- version-change detection ---------------------------------------------------------
@pytest.mark.parametrize("baseline,observed,sv,rel,scanned,want", [
    ("1.0.0", "1.0.0", None, None, None, "same"),
    ("1.0.0", "1.1.0", None, None, None, "changed"),
    (None, "1.1.0", "1.0.0", None, None, "changed"),
    (None, "1.0.0", "1.0.0", None, None, "same"),
    (None, "2.0", None, NOW, NOW - timedelta(days=1), "changed"),
    (None, "2.0", None, NOW - timedelta(days=2), NOW, "baselined"),
    (None, "2.0", None, None, None, "baselined"),
    ("1.0", None, None, None, None, "unknown"),
])
def test_detect_change(baseline, observed, sv, rel, scanned, want):
    assert refresh.detect_change(baseline, observed, scanned_version=sv, released_at=rel,
                                 last_scanned_at=scanned) == want


def test_tiering_top_daily_rest_weekly():
    idx = CatalogIndex()
    rows = [("npm", "npm", f"p{i}", f"npm/p{i}", 1000 - i, NOW, "safe") for i in range(70)]
    add_community(idx, rows)
    seen: set[str] = set()
    for day in range(7):
        picked, top = refresh.select_entries(idx, top_n=10, today=day)
        assert {f"/check/pkg/npm/p{i}" for i in range(10)} == top
        assert top <= {e.key for e in picked}
        seen |= {e.key for e in picked} - top
    assert len(seen) == 60  # every other page exactly once a week


@pytest.mark.asyncio
async def test_plan_refresh_detects_changes_cheaply():
    idx = CatalogIndex()
    add_community(idx, [
        ("npm", "npm", "same-pkg", "npm/same-pkg", 900, NOW, "safe"),
        ("npm", "npm", "moved-pkg", "npm/moved-pkg", 800, NOW, "safe"),
        ("pypi", "pypi", "newpy", "pypi/newpy", 700, NOW - timedelta(days=5), "review"),
        ("github", "o", "same-repo", "o/same-repo", 600, NOW, "safe"),
        ("github", "o", "moved-repo", "o/moved-repo", 500, NOW, "safe"),
        ("crates", "crates", "serde", "crates/serde", 400, NOW, "safe"),
    ])
    state = {"baselines": {
        "/check/pkg/npm/same-pkg": {"v": "1.0.0"},
        "/check/pkg/npm/moved-pkg": {"v": "1.0.0"},
        "/check/o/same-repo": {"v": "a" * 40, "etag": '"e1"'},
        "/check/o/moved-repo": {"v": "b" * 40, "etag": '"e2"'},
    }, "last_run": {}}

    def npm_latest(url, p, h):
        return Resp(200, {"version": "2.0.0" if "moved-pkg" in url else "1.0.0"})

    def gh(url, p, h):
        if "same-repo" in url:
            assert h.get("If-None-Match") == '"e1"'
            return Resp(304, None, {"x-ratelimit-remaining": "4000"}, text="")
        return Resp(200, None, {"etag": '"e3"', "x-ratelimit-remaining": "3999"},
                    text="c" * 40)

    client = FakeClient({
        "https://registry.npmjs.org/": npm_latest,
        "https://pypi.org/pypi/newpy/json": Resp(200, {
            "info": {"version": "0.9"},
            "urls": [{"upload_time_iso_8601": (NOW - timedelta(days=1)).isoformat()}]}),
        "https://api.github.com/": gh,
    })

    async def no_cached(*a):
        return None

    items, rep, updates = await refresh.plan_refresh(
        fetcher(client), idx, state, top_n=100, now=NOW, github_token="t",
        github_calls=100, github_min_budget=100, scanned_version=no_cached)
    keys = {i["key"]: i for i in items}
    assert set(keys) == {"/check/pkg/npm/moved-pkg", "/check/pkg/pypi/newpy",
                         "/check/o/moved-repo"}
    assert keys["/check/pkg/npm/moved-pkg"]["version"] == "2.0.0"
    assert keys["/check/o/moved-repo"]["etag"] == '"e3"'
    assert keys["/check/o/moved-repo"]["priority"] == refresh.PRIORITY_CHANGED_TOP
    assert "/check/pkg/npm/same-pkg" in updates
    assert rep["by_source"]["crates"]["unsupported"] == 1
    assert rep["by_source"]["github"]["unchanged"] == 1
    # a registry metadata call per package, one HEAD call per repo; nothing else
    assert len(client.calls) == 5


@pytest.mark.asyncio
async def test_refresh_stops_github_checks_at_budget_floor():
    idx = CatalogIndex()
    add_community(idx, [("github", "o", f"r{i}", f"o/r{i}", 100 - i, NOW, "safe")
                        for i in range(5)])
    client = FakeClient({"https://api.github.com/": Resp(
        200, None, {"x-ratelimit-remaining": "900"}, text="d" * 40)})
    items, rep, _ = await refresh.plan_refresh(
        fetcher(client), idx, {"baselines": {}, "last_run": {}}, top_n=100, now=NOW,
        github_token="t", github_calls=100, github_min_budget=1000)
    assert len(client.calls) == 1  # the first reply showed the budget under the floor
    assert rep["stopped"].startswith("github budget")
    assert rep["by_source"]["github"]["deferred"] == 4


# -- execution: SSRF guard, Do-not-connect held back ------------------------------------
@pytest.fixture
def launch_dir(tmp_path, monkeypatch):
    d = tmp_path / "launch-scans"
    d.mkdir()
    monkeypatch.setattr(scr, "_DATA_DIR", d)
    return d


def _session_factory(db=None):
    @asynccontextmanager
    async def factory():
        yield db
    return factory


@pytest.mark.asyncio
async def test_skipped_with_url_scan_goes_through_ssrf_guard(tmp_path, launch_dir,
                                                             monkeypatch):
    import src.ssrf as ssrf

    checked: list[str] = []
    real = ssrf.validate_url_https

    def spy(url, *, field_name="url"):
        checked.append(url)
        return real(url, field_name=field_name)

    monkeypatch.setattr(ssrf, "validate_url_https", spy)
    scanned: list[tuple] = []

    async def scan(surface, owner, repo, db):
        scanned.append((surface, owner, repo))
        return True

    store = st.Store(tmp_path / "cg")
    state = store.load_state()
    items = [
        {"key": "k-internal", "surface": "mcp", "owner": "mcp",
         "repo": "https://127.0.0.1/mcp", "reason": "skipped_url", "registry_name": "a"},
        {"key": "k-localhost", "surface": "mcp", "owner": "mcp",
         "repo": "https://localhost/mcp", "reason": "skipped_url", "registry_name": "b"},
        {"key": "k-meta", "surface": "mcp", "owner": "mcp",
         "repo": "https://169.254.169.254/latest", "reason": "skipped_url",
         "registry_name": "c"},
    ]

    async def gh_ok(_):
        return True

    async def nosleep(_):
        return None

    left, rep = await execute.execute(
        store, state, items, session_factory=_session_factory(), max_scans=10, spacing=0,
        github_min_budget=0, scan_fn=scan, gh_ok_fn=gh_ok, sleep=nosleep)
    assert scanned == []
    assert checked == [i["repo"] for i in items]
    assert set(state["failed"]) == {"k-internal", "k-localhost", "k-meta"}
    assert not (launch_dir / scr._MCP_ENDPOINTS_FILE).exists()
    assert left == []

    # A public endpoint that passes the guard is scanned and lands in the overlay.
    monkeypatch.setattr(ssrf, "_check_resolved_ips", lambda host, field: None)
    ok_item = {"key": "k-ok", "surface": "mcp", "owner": "mcp",
               "repo": "https://mcp.example.com/mcp", "reason": "skipped_url",
               "registry_name": "com.example/remote-only"}

    async def decision(*a):
        return "safe"

    monkeypatch.setattr(execute, "_stored_decision", decision)
    await execute.execute(store, state, [ok_item], session_factory=_session_factory(),
                          max_scans=10, spacing=0, github_min_budget=0, scan_fn=scan,
                          gh_ok_fn=gh_ok, sleep=nosleep)
    assert scanned == [("mcp", "mcp", "https://mcp.example.com/mcp")]
    overlay = scr.load_mcp_endpoints(launch_dir / scr._MCP_ENDPOINTS_FILE)
    assert overlay == {"com.example/remote-only": "https://mcp.example.com/mcp"}


@pytest.mark.asyncio
async def test_execute_defers_github_on_low_budget_and_resumes(tmp_path):
    store = st.Store(tmp_path / "cg")
    state = store.load_state()
    scanned: list[str] = []

    async def scan(surface, owner, repo, db):
        scanned.append(repo)
        return repo != "bad"

    async def low(_):
        return False

    async def decision(*a):
        return "safe"

    async def nosleep(_):
        return None

    items = [{"key": f"/check/o/{n}", "surface": "github", "owner": "o", "repo": n}
             for n in ("a", "b")] + [
        {"key": f"/check/pkg/npm/{n}", "surface": "npm", "owner": "npm", "repo": n,
         "version": "1"} for n in ("x", "bad", "y", "z")]
    import src.catalog_growth.execute as ex
    orig = ex._stored_decision
    ex._stored_decision = decision
    try:
        left, rep = await execute.execute(
            store, state, items, session_factory=_session_factory(), max_scans=2,
            spacing=0, github_min_budget=0, scan_fn=scan, gh_ok_fn=low, sleep=nosleep)
    finally:
        ex._stored_decision = orig
    assert scanned == ["x", "bad"]
    assert [i["repo"] for i in left] == ["a", "b", "y", "z"]
    assert [i["repo"] for i in store.load_pending()] == ["a", "b", "y", "z"]
    assert "/check/pkg/npm/bad" in state["failed"]
    assert store.load_state()["baselines"]["/check/pkg/npm/x"]["v"] == "1"


@pytest.mark.asyncio
async def test_do_not_connect_is_held_for_review_not_indexed(tmp_path, db):
    from src.models import CommunityScan

    async def scan(surface, owner, repo, sess):
        sess.add(CommunityScan(surface=surface, owner=owner, repo=repo,
                               full_name=f"{owner}/{repo}", trust_score=12, critical=2,
                               high=0, findings_count=3, decision="do_not_connect",
                               decision_reason="shipped critical"))
        await sess.flush()
        return True

    async def ok(_):
        return True

    async def nosleep(_):
        return None

    store = st.Store(tmp_path / "cg")
    state = store.load_state()
    item = {"key": "/check/pkg/npm/evil-mcp", "surface": "npm", "owner": "npm",
            "repo": "evil-mcp", "reason": "new", "source": "npm"}
    _, rep = await execute.execute(store, state, [item], session_factory=_session_factory(db),
                                   max_scans=5, spacing=0, github_min_budget=0, scan_fn=scan,
                                   gh_ok_fn=ok, sleep=nosleep)
    assert rep["by_source"]["npm"]["dnc_held"] == 1
    lines = (tmp_path / "cg" / "dnc-review.jsonl").read_text().splitlines()
    rec = json.loads(lines[0])
    assert rec["key"] == "/check/pkg/npm/evil-mcp"
    assert rec["indexable"] is False and rec["review"] == "pending"


def test_catalog_growth_never_touches_search_surfaces():
    root = Path(__file__).resolve().parents[1]
    src = "\n".join(p.read_text() for p in (root / "src" / "catalog_growth").glob("*.py"))
    code = "\n".join(line for line in src.splitlines()
                     if not line.strip().startswith("#") and "IndexNow" not in line)
    for word in ("indexnow_ping", "sitemap.xml", "indexnow_record", "gen_spa_routes"):
        assert word not in code
    # Tool pages are not in the sitemap at all today: a discovered tool cannot reach
    # search through it.
    sitemap = (root / "web" / "public" / "sitemap.xml").read_text()
    locs = [loc for loc in sitemap.split("<loc>")[1:]]
    assert not [x for x in locs if "/check/" in x.split("</loc>")[0]]


# -- dry run writes nothing to the catalog --------------------------------------------
def _registry_routes() -> dict:
    return {
        discover.MCP_REGISTRY_URL: Resp(200, {"servers": [
            {"server": {"name": "io.github.fresh/server", "version": "1.0",
                        "repository": {"url": "https://github.com/fresh/server"}}},
            {"server": {"name": "com.example/remote-only", "version": "1.0",
                        "remotes": [{"type": "streamable-http",
                                     "url": "https://remote.example.com/mcp"}]}},
        ], "metadata": {}}),
        "https://packages.ecosyste.ms/": Resp(200, {"packages": [
            {"ecosystem": "pypi", "name": "agent-thing", "latest_release_number": "1.0",
             "downloads": 4000, "downloads_period": "last-month"}]}),
        discover.NPM_SEARCH_URL: Resp(200, {"objects": [
            {"package": {"name": "brand-new-mcp", "version": "0.1.0"},
             "downloads": {"weekly": 500}}]}),
        "https://api.github.com/search": Resp(200, {"items": [
            {"full_name": "claw/new-skill", "stargazers_count": 7}]}),
        discover.CLAWHUB_SKILLS_URL: Resp(200, {"items": [
            {"ownerHandle": "x", "slug": "hosted-only"}]}),
        discover.SMITHERY_LIST_URL: Resp(200, {"servers": [
            {"qualifiedName": "acme/srv", "useCount": 10, "remote": True,
             "homepage": "https://github.com/acme/srv"}],
            "pagination": {"totalPages": 1}}),
    }


@pytest.mark.asyncio
async def test_dry_run_discovers_and_writes_nothing_to_the_catalog(tmp_path, launch_dir, db):
    from sqlalchemy import func, select

    from src.models import CommunityScan

    for name, raws, key in (("mcp-registry-results.json", [
            {"name": "com.example/remote-only", "repository_url": None,
             "skipped": "non_github_repo"}], "results"),):
        (launch_dir / name).write_text(json.dumps({key: raws}))
    before = {p.name: p.stat().st_mtime_ns for p in launch_dir.iterdir()}
    rows_before = await db.scalar(select(func.count()).select_from(CommunityScan))

    async def never_scan(*a):
        raise AssertionError("a dry run must not scan")

    recorded: list = []

    async def record(run):
        recorded.append(run)
        return True

    settings = SimpleNamespace(catalog_discovery="dry-run", catalog_refresh="off",
                               catalog_growth_data_dir=str(tmp_path / "cg"))
    run = await run_job("discover", settings=settings, client=FakeClient(_registry_routes()),
                        session_factory=_session_factory(db), github_token="t",
                        execute_kwargs={"scan_fn": never_scan}, record=record,
                        fetcher_kwargs={"sleep": Sleeps().sleep})
    assert run["mode"] == "dry-run"
    t = run["totals"]
    # fresh/server, the skipped row's endpoint, npm, pypi, skill, smithery repo + the
    # curated PyPI seed (in the launch corpus on prod, absent from this fixture)
    assert t["queued"] == 6 + len(discover.PYPI_SEED)
    assert t["skipped_with_url"] == 1
    plan = json.loads((tmp_path / "cg" / "plan-discover-dry-run.json").read_text())
    assert {i["reason"] for i in plan["items"]} == {"new", "skipped_url"}
    # nothing that feeds Browse changed
    assert {p.name: p.stat().st_mtime_ns for p in launch_dir.iterdir()} == before
    assert not (launch_dir / scr._MCP_ENDPOINTS_FILE).exists()
    assert await db.scalar(select(func.count()).select_from(CommunityScan)) == rows_before
    # and no queue or baselines were written for an "on" run to inherit
    assert not (tmp_path / "cg" / "pending.json").exists()
    assert not (tmp_path / "cg" / "state.json").exists()
    assert recorded and recorded[0]["mode"] == "dry-run"


@pytest.mark.asyncio
async def test_on_run_queues_and_scans(tmp_path, launch_dir, db, monkeypatch):
    (launch_dir / "mcp-registry-results.json").write_text(json.dumps({"results": []}))
    scanned: list = []

    async def scan(surface, owner, repo, sess):
        scanned.append((surface, owner, repo))
        return True

    async def decision(*a):
        return "review"

    async def ok(_):
        return True

    monkeypatch.setattr(execute, "_stored_decision", decision)
    monkeypatch.setattr(execute, "ssrf_check_endpoint", lambda u: u)
    settings = SimpleNamespace(catalog_discovery="on", catalog_refresh="off",
                               catalog_growth_data_dir=str(tmp_path / "cg"),
                               catalog_growth_max_scans_per_run=3,
                               catalog_growth_scan_spacing_seconds=0)

    async def nosleep(_):
        return None

    async def record(run):
        return True

    run = await run_job("discover", settings=settings, client=FakeClient(_registry_routes()),
                        session_factory=_session_factory(db), github_token="t", record=record,
                        execute_kwargs={"scan_fn": scan, "gh_ok_fn": ok, "sleep": nosleep},
                        fetcher_kwargs={"sleep": Sleeps().sleep})
    assert len(scanned) == 3
    left = 6 + len(discover.PYPI_SEED) - 3
    assert run["totals"]["scanned"] == 3 and run["pending_left"] == left
    store = st.Store(tmp_path / "cg")
    assert len(store.load_pending()) == left
    assert "acme/srv" in store.load_state()["smithery_seen"]
    lines = (tmp_path / "cg" / "runs.jsonl").read_text().splitlines()
    assert json.loads(lines[-1])["job"] == "discover"


# -- catalog overlay + metrics -------------------------------------------------------
def test_overlay_gives_a_skipped_row_its_endpoint_page(tmp_path):
    p = tmp_path / "eps.json"
    p.write_text(json.dumps({"endpoints": {
        "com.example/remote-only": "https://remote.example.com/mcp",
        "bad/http": "http://x.example/mcp",
        "bad/query": "https://x.example/mcp?token=1",
    }}))
    eps = scr.load_mcp_endpoints(p)
    assert eps == {"com.example/remote-only": "https://remote.example.com/mcp"}
    rows = corpus_rows()
    scr._apply_mcp_endpoints(rows, eps)
    row = next(r for r in rows if r.name == "com.example/remote-only")
    assert row.page_path == "/check/mcp?endpoint=https%3A%2F%2Fremote.example.com%2Fmcp"
    live = scr.CatalogRow(surface="mcp", name="https://remote.example.com/mcp",
                          endpoint_url="https://remote.example.com/mcp", trust_score=88,
                          scan_source="live")
    cat = scr._build_catalog(rows)
    merged, _listed, dropped = scr._supersede(cat, [live])
    assert row in dropped
    assert sum(1 for r in merged if r.page_path == row.page_path) == 1


def test_community_row_coords_matches_catalog_routing():
    assert scr.community_row_coords("npm", "left-pad", "npm/left-pad") == (
        "npm", "left-pad", None, None)
    assert scr.community_row_coords("mcp", "https://a/mcp", "mcp/https://a/mcp") == (
        "mcp", "https://a/mcp", None, "https://a/mcp")
    assert scr.community_row_coords(None, "r", "o/r") == (
        "github", "o/r", "https://github.com/o/r", None)


def test_clean_run_keeps_small_known_fields():
    run = st.clean_run({"job": "discover", "mode": "on", "at": "2026-11-12T00:00:00+00:00",
                        "totals": {"new": 3, "scanned": 2, "bogus": 9, "failed": -1},
                        "by_source": {"npm": {"new": 3, "x": "y"}},
                        "requests": {"npm": 4}, "duration_s": 12.7, "items": [1, 2]})
    assert run["totals"] == {"new": 3, "scanned": 2}
    assert run["by_source"] == {"npm": {"new": 3}}
    assert run["duration_s"] == 12 and "items" not in run
    assert st.clean_run({"job": "other", "mode": "on"}) is None


@pytest.mark.asyncio
async def test_run_records_round_trip(monkeypatch):
    store: list[str] = []

    class R:
        async def lpush(self, k, v):
            store.insert(0, v)

        async def ltrim(self, k, a, b):
            del store[b + 1:]

        async def lrange(self, k, a, b):
            return store[a:b + 1]

    import src.redis_client as rc
    monkeypatch.setattr(rc, "get_redis", lambda: R())
    for i in range(st.RUNS_KEEP + 5):
        assert await st.record_run({"job": "refresh", "mode": "dry-run",
                                    "totals": {"changed": i}})
    runs = await st.recent_runs(3)
    assert [r["totals"]["changed"] for r in runs] == [34, 33, 32]
    assert len(store) == st.RUNS_KEEP


def test_merge_pending_dedupes_and_orders():
    a = {"key": "k1", "priority": 2, "adoption": 5}
    b = {"key": "k1", "priority": 0, "adoption": 1}
    c = {"key": "k2", "priority": 2, "adoption": 50}
    assert st.merge_pending([a], [b, c]) == [b, c]


def test_run_lock_is_exclusive(tmp_path):
    with st.run_lock(tmp_path) as one:
        assert one.acquired
        with st.run_lock(tmp_path) as two:
            assert not two.acquired


@pytest.mark.asyncio
async def test_refresh_skips_a_recently_failed_rescan():
    idx = CatalogIndex()
    add_community(idx, [("npm", "npm", "flaky", "npm/flaky", 10, NOW, "safe")])
    client = FakeClient({"https://registry.npmjs.org/": Resp(200, {"version": "9"})})
    items, rep, _ = await refresh.plan_refresh(
        fetcher(client), idx,
        {"baselines": {}, "last_run": {},
         "failed": {"/check/pkg/npm/flaky": (NOW - timedelta(days=1)).isoformat()}},
        top_n=10, now=NOW, github_token=None, github_calls=0, github_min_budget=0,
        retry_after_iso=(NOW - timedelta(days=7)).isoformat())
    assert items == [] and client.calls == []
    assert rep["by_source"]["npm"]["retry_wait"] == 1
