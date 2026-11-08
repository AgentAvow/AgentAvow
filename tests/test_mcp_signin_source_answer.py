"""scan_mcp_server on a sign-in (OAuth) MCP server, and on a common connector NAME.

A hosted server that needs sign-in hides its tools/list, so the live scan cannot run.
Where the vendor publishes its own source, the tool answers from that source, labeled as
such in the text and in structuredContent, never as a read of the live tool list. Where
it publishes none, or nothing is certain, the answer is a next step. Results only: the
tool contract (tools/list) is pinned by tests/test_mcp_tools_list_snapshot.py.
"""
from __future__ import annotations

import httpx
import jsonschema
import mcp.types as types
import pytest

from src.bridges import mcp_connector_sources as srcmap
from src.bridges import mcp_streamable as ms
from src.scanner.scan import MCP_SIGNIN_REQUIRED_ERROR

_REPO_SCAN = {
    "trust_score": 86,
    "trust_tier": "trusted",
    "jws": "eyJ.sig.ned",
    "certified": {"eligible": True},
    "category_scores": {"secret_hygiene": 100},
    "findings": {"total": 0, "items": []},
    "metadata": {"files_scanned": 120},
}


def _err(path: str, status: int, detail: str | None = None) -> httpx.HTTPStatusError:
    req = httpx.Request("GET", "http://internal/api" + path)
    kw = {"json": {"detail": detail}} if detail is not None else {}
    return httpx.HTTPStatusError("x", request=req,
                                 response=httpx.Response(status, request=req, **kw))


def _api(calls: list, *, mcp_detail: str = f"Scan error: {MCP_SIGNIN_REQUIRED_ERROR}",
         repo=_REPO_SCAN, catalog=None):
    async def _get(path, params=None):
        calls.append((path, dict(params or {})))
        if path == "/public/scan/mcp":
            raise _err(path, 422, mcp_detail)
        if path == "/public/scan-catalog":
            return catalog or {"rows": []}
        if isinstance(repo, Exception):
            raise repo
        return dict(repo)
    return _get


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    bumps: list[str] = []

    async def _bump(metric):
        bumps.append(metric)

    async def _no_adoption(surface, owner, repo):
        return None

    monkeypatch.setattr(ms, "_bump", _bump)
    monkeypatch.setattr(ms, "_adoption", _no_adoption)
    return bumps


async def _call(arguments: dict) -> types.CallToolResult:
    entry = ms.server.get_request_handler("tools/call")
    params = entry.params_type.model_validate({"name": "scan_mcp_server",
                                               "arguments": arguments})
    return await entry.handler(None, params)


# --- the reviewed maps ---------------------------------------------------------------

@pytest.mark.parametrize("url,vendor,repo", [
    ("https://api.githubcopilot.com/mcp/", "GitHub", "github/github-mcp-server"),
    ("https://api.githubcopilot.com/mcp/insiders", "GitHub", "github/github-mcp-server"),
    ("https://mcp.sentry.dev/mcp", "Sentry", "getsentry/sentry-mcp"),
    ("https://mcp.neon.tech/mcp", "Neon", "neondatabase/mcp-server-neon"),
    ("https://mcp.supabase.com/mcp", "Supabase", "supabase/mcp"),
    ("https://huggingface.co/mcp", "Hugging Face", "huggingface/hf-mcp-server"),
    ("https://mcp.cloudflare.com/mcp", "Cloudflare", "cloudflare/mcp"),
    ("https://docs.mcp.cloudflare.com/mcp", "Cloudflare", "cloudflare/mcp-server-cloudflare"),
])
def test_official_source_map(url, vendor, repo):
    src = srcmap.official_source_for(url)
    assert src is not None
    assert (src.vendor, src.repo) == (vendor, repo)
    assert srcmap.no_public_source(url) is None


@pytest.mark.parametrize("url", [
    "https://api.githubcopilot.com/chat",          # same host, not the MCP path
    "https://huggingface.co/spaces/x/y",          # shared host, not /mcp
    "https://huggingface.co/mcpfoo",
    "https://mcp.notion.com.evil.example/mcp",    # look-alike host
    "https://evilmcp.cloudflare.com.example/mcp",
    "https://mcp.deepwiki.com/mcp",
    "not a url",
    "",
])
def test_unmapped_urls_have_no_source(url):
    assert srcmap.official_source_for(url) is None
    assert srcmap.no_public_source(url) is None


@pytest.mark.parametrize("url,vendor,self_hosted", [
    ("https://mcp.linear.app/mcp", "Linear", None),
    ("https://mcp.atlassian.com/v2/mcp", "Atlassian", None),
    ("https://mcp.stripe.com", "Stripe", None),
    # The vendor's separate self-hosted server is a different codebase: named as a next
    # step, never graded in place of the hosted server.
    ("https://mcp.notion.com/mcp", "Notion", "makenotion/notion-mcp-server"),
    ("https://MCP.Notion.com/mcp", "Notion", "makenotion/notion-mcp-server"),
    ("https://mcp.squareup.com/mcp", "Square", "square/square-mcp-server"),
])
def test_hosts_checked_and_found_without_public_source(url, vendor, self_hosted):
    assert srcmap.official_source_for(url) is None
    entry = srcmap.no_public_source(url)
    assert entry is not None
    assert (entry.vendor, entry.self_hosted_repo) == (vendor, self_hosted)


def test_every_source_is_owned_by_the_vendors_own_org():
    """A reviewed list: an entry owned by anyone else (a fork, a community port) fails."""
    vendor_orgs = {
        "GitHub": {"github"}, "Sentry": {"getsentry"}, "Neon": {"neondatabase"},
        "Supabase": {"supabase"}, "Hugging Face": {"huggingface"},
        "Cloudflare": {"cloudflare"}, "Notion": {"makenotion"}, "Square": {"square"},
    }
    entries = list(srcmap.OFFICIAL_SOURCES.values()) + [srcmap._CLOUDFLARE_PRODUCTS]
    for s in entries:
        if s.owner is not None:  # a no-source host without a self-hosted repo has none
            assert s.owner in vendor_orgs[s.vendor], s


@pytest.mark.parametrize("name,vendor,endpoint", [
    ("Notion", "Notion", "https://mcp.notion.com/mcp"),
    ("notion mcp", "Notion", "https://mcp.notion.com/mcp"),
    ("Linear", "Linear", "https://mcp.linear.app/mcp"),
    ("GitHub", "GitHub", "https://api.githubcopilot.com/mcp/"),
    ("GitHub MCP Server", "GitHub", "https://api.githubcopilot.com/mcp/"),
    ("Sentry", "Sentry", "https://mcp.sentry.dev/mcp"),
    ("Atlassian", "Atlassian", "https://mcp.atlassian.com/v2/mcp"),
    ("Jira", "Atlassian", "https://mcp.atlassian.com/v2/mcp"),
    ("Confluence", "Atlassian", "https://mcp.atlassian.com/v2/mcp"),
    ("Hugging Face", "Hugging Face", "https://huggingface.co/mcp"),
    ("Supabase", "Supabase", "https://mcp.supabase.com/mcp"),
    ("Neon", "Neon", "https://mcp.neon.tech/mcp"),
    ("Stripe", "Stripe", "https://mcp.stripe.com"),
    ("Square", "Square", "https://mcp.squareup.com/mcp"),
    ("Google Drive", "Google Drive", None),
    ("google-drive connector", "Google Drive", None),
    ("Gmail", "Gmail", None),
    ("Google Calendar", "Google Calendar", None),
    ("Slack", "Slack", None),
    ("Asana", "Asana", None),
])
def test_known_connector_names(name, vendor, endpoint):
    kc = srcmap.known_connector(name)
    assert kc is not None and kc.vendor == vendor and kc.endpoint == endpoint


@pytest.mark.parametrize("name", ["DeepWiki", "notion-helper", "my github tools", "mcp",
                                  "", "slackbot", "Linearizer"])
def test_other_names_are_not_known_connectors(name):
    assert srcmap.known_connector(name) is None


# --- sign-in server answered from the vendor's published source ------------------------

@pytest.mark.asyncio
async def test_signin_server_with_hosted_source_answers_from_that_source(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ms, "_get", _api(calls))
    res = await _call({"endpoint_url": "https://api.githubcopilot.com/mcp/"})
    assert res.is_error is False
    assert [p for p, _ in calls] == ["/public/scan/mcp",
                                     "/public/scan/github/github-mcp-server"]
    text = res.content[0].text
    assert text.startswith("Based on GitHub's published source code "
                           "(github/github-mcp-server), not the live server, which requires "
                           "sign-in.")
    assert "Its live tool definitions were not read." in text
    s = res.structured_content
    jsonschema.validate(instance=s, schema=ms._SCAN_OUTPUT_SCHEMA)
    assert s["target"] == "github/github-mcp-server" and s["target_type"] == "github"
    assert s["trust_score"] == 86
    assert s["not_checked"][0].startswith("The live server at api.githubcopilot.com requires "
                                          "sign-in (OAuth), so its tool definitions were "
                                          "not read.")
    assert s["coverage_gaps"]["live_tool_definitions_unread"] is True
    assert s["coverage_gaps"]["answered_from_published_source"] is True
    # A clean source read is never a clean bill of the whole live tool.
    assert s["verdict_reason"] == "clean_partial"
    assert s["report_url"].endswith("/check/github/github-mcp-server")


@pytest.mark.asyncio
@pytest.mark.parametrize("url,host,vendor,repo", [
    ("https://mcp.notion.com/mcp", "mcp.notion.com", "Notion", "makenotion/notion-mcp-server"),
    ("https://mcp.squareup.com/mcp", "mcp.squareup.com", "Square",
     "square/square-mcp-server"),
])
async def test_separate_self_hosted_server_is_a_next_step_not_an_answer(
        monkeypatch, url, host, vendor, repo):
    calls: list = []
    monkeypatch.setattr(ms, "_get", _api(calls))
    res = await _call({"endpoint_url": url})
    # A different codebase is never graded in place of the hosted server.
    assert res.is_error is True and res.structured_content is None
    assert [p for p, _ in calls] == ["/public/scan/mcp"]
    text = res.content[0].text
    assert text.startswith(f"Not scanned: {host} requires sign-in (OAuth)")
    assert f"{vendor}'s hosted server code isn't public" in text
    assert (f"{vendor} also publishes a self-hosted server, {repo}; you can check that "
            "with scan_repo.") in text
    assert "Based on" not in text


@pytest.mark.asyncio
async def test_name_resolves_through_the_reviewed_map_then_the_source(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ms, "_get", _api(calls))
    res = await _call({"endpoint_url": "GitHub"})
    assert res.is_error is False
    # The reviewed map wins: the catalog (third-party GitHub servers) is not consulted.
    assert [p for p, _ in calls] == ["/public/scan/mcp",
                                     "/public/scan/github/github-mcp-server"]
    assert calls[0][1] == {"endpoint": "https://api.githubcopilot.com/mcp/"}


@pytest.mark.asyncio
async def test_notion_by_name_gets_the_self_hosted_next_step(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ms, "_get", _api(calls))
    res = await _call({"endpoint_url": "Notion"})
    assert res.is_error is True
    assert calls == [("/public/scan/mcp", {"endpoint": "https://mcp.notion.com/mcp"})]
    assert "makenotion/notion-mcp-server; you can check that with scan_repo" in \
        res.content[0].text


@pytest.mark.asyncio
async def test_source_scan_still_running_is_a_next_step(monkeypatch):
    monkeypatch.setattr(ms, "_get", _api([], repo=_err("/public/scan/x/y", 503)))
    res = await _call({"endpoint_url": "https://mcp.sentry.dev/mcp"})
    assert res.is_error is True and res.structured_content is None
    text = res.content[0].text
    assert text.startswith("Not scanned yet")
    assert "getsentry/sentry-mcp" in text and "scan_repo" in text


@pytest.mark.asyncio
async def test_source_scan_over_budget_is_a_next_step(monkeypatch):
    import asyncio

    async def _get(path, params=None):
        if path == "/public/scan/mcp":
            raise _err(path, 422, f"Scan error: {MCP_SIGNIN_REQUIRED_ERROR}")
        await asyncio.sleep(5)
        return dict(_REPO_SCAN)

    monkeypatch.setattr(ms, "_get", _get)
    monkeypatch.setattr(ms, "_SIGNIN_SOURCE_BUDGET_S", 0.0)
    monkeypatch.setattr(ms, "_SIGNIN_SOURCE_MIN_S", 0.05)
    res = await _call({"endpoint_url": "https://mcp.neon.tech/mcp"})
    assert res.is_error is True
    assert "still running" in res.content[0].text


@pytest.mark.asyncio
async def test_source_scan_failure_is_an_error_with_a_next_step(monkeypatch):
    monkeypatch.setattr(ms, "_get", _api([], repo=_err("/public/scan/x/y", 404)))
    res = await _call({"endpoint_url": "https://mcp.supabase.com/mcp"})
    assert res.is_error is True
    assert "could not grade Supabase's published source code (supabase/mcp)" in \
        res.content[0].text


@pytest.mark.asyncio
async def test_force_rescans_the_source_in_the_background(monkeypatch):
    calls: list = []
    started: list = []
    monkeypatch.setattr(ms, "_get", _api(calls))
    monkeypatch.setattr(ms, "_schedule_rescan", lambda p, q: started.append(p) or True)
    res = await _call({"endpoint_url": "https://mcp.sentry.dev/mcp", "force": True})
    assert res.is_error is False
    assert started == ["/public/scan/getsentry/sentry-mcp"]
    assert res.structured_content["rescan_pending"] is True


# --- isError decisions --------------------------------------------------------------

@pytest.mark.asyncio
async def test_signin_server_without_public_source_says_so(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ms, "_get", _api(calls))
    res = await _call({"endpoint_url": "https://mcp.linear.app/mcp"})
    # No grade exists, and the outputSchema requires one (decision + trust_score): a
    # non-error result would have to invent it. Kept a tool error, with a next step.
    assert res.is_error is True and res.structured_content is None
    text = res.content[0].text
    assert text.startswith("Not scanned: mcp.linear.app requires sign-in (OAuth)")
    assert "Linear's hosted server code isn't public" in text
    assert "also publishes a self-hosted server" not in text
    assert "scan_package" in text
    assert [p for p, _ in calls] == ["/public/scan/mcp"]


@pytest.mark.asyncio
async def test_unmapped_signin_server_keeps_the_generic_guidance(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ms, "_get", _api(calls))
    res = await _call({"endpoint_url": "https://mcp.example.com/mcp"})
    assert res.is_error is True
    text = res.content[0].text
    assert text.startswith("Not scanned")
    assert "requires sign-in" in text and "scan_repo" in text
    assert [p for p, _ in calls] == ["/public/scan/mcp"]


@pytest.mark.asyncio
async def test_other_422_on_a_mapped_host_is_not_answered_from_source(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ms, "_get", _api(
        calls, mcp_detail="Scan error: Could not handshake the MCP server"))
    res = await _call({"endpoint_url": "https://api.githubcopilot.com/mcp/"})
    assert res.is_error is True
    assert "Could not handshake" in res.content[0].text
    assert [p for p, _ in calls] == ["/public/scan/mcp"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 500, 502, 503])
async def test_real_failures_stay_errors(monkeypatch, status):
    async def _get(path, params=None):
        raise _err(path, status)

    monkeypatch.setattr(ms, "_get", _get)
    res = await _call({"endpoint_url": "https://mcp.notion.com/mcp"})
    assert res.is_error is True and res.structured_content is None


@pytest.mark.asyncio
async def test_known_connector_without_endpoint_gives_the_next_step(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ms, "_get", _api(calls))
    res = await _call({"endpoint_url": "Google Drive"})
    assert res.is_error is True and res.structured_content is None
    text = res.content[0].text
    assert text.startswith("Not scanned: 'Google Drive' looks like the Google Drive connector.")
    assert "https endpoint URL" in text and "claude mcp get" in text
    assert "published by Google" in text
    assert "could not match" not in text
    assert calls == []  # no guess, no catalog lookup


@pytest.mark.asyncio
async def test_unknown_name_still_goes_to_the_catalog(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ms, "_get", _api(calls))
    res = await _call({"endpoint_url": "Some Other Tool"})
    assert res.is_error is True
    assert "could not match 'Some Other Tool'" in res.content[0].text
    assert [p for p, _ in calls] == ["/public/scan-catalog"]


@pytest.mark.asyncio
async def test_public_server_scan_is_unchanged(monkeypatch):
    calls: list = []

    async def _get(path, params=None):
        calls.append(path)
        return {"trust_score": 74, "trust_tier": "standard", "findings": {"items": []}}

    monkeypatch.setattr(ms, "_get", _get)
    res = await _call({"endpoint_url": "https://mcp.deepwiki.com/mcp"})
    assert res.is_error is False
    assert calls == ["/public/scan/mcp"]
    assert res.structured_content["target"] == "https://mcp.deepwiki.com/mcp"
    assert "Based on" not in res.content[0].text
