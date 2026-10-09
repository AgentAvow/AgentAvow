"""Fixes from the 2026-10-09 live-site audit: package cards and verify payloads, OG
cards for MCP endpoints and skills, OG glyphs, quiet drift history, italics inside
bold in the server-rendered docs, and the static files nginx now serves."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

PKG_SCAN = {
    "trust_score": 82, "grade": "A", "findings": {"critical": 0, "high": 0},
    "files_scanned": 40, "certified": {"eligible": False},
}


def _patch_pkg(monkeypatch, *, pkg=PKG_SCAN, repo_cached=None):
    from src.api import public_scan_router as r

    seen = {}

    async def _pkg(surface, name):
        seen["pkg"] = (surface, name)
        return pkg

    async def _cached(owner, repo):
        return repo_cached

    async def _entity(*a, **k):
        raise AssertionError("a package card must not read the GitHub entity")

    async def _boom(*a, **k):
        raise AssertionError("a package card must not scan a GitHub repo")

    async def _adopt(*a, **k):
        return (59, 866_979_583, "downloads/wk")

    async def _no_full(*a, **k):
        return None

    async def _beh(data):
        return None

    monkeypatch.setattr(r, "_package_badge_data", _pkg)
    monkeypatch.setattr(r, "_get_cached", _cached)
    monkeypatch.setattr(r, "_get_entity_trust", _entity)
    monkeypatch.setattr(r, "public_scan", _boom)
    monkeypatch.setattr(r, "surface_adoption_summary", _adopt)
    monkeypatch.setattr(r, "scan_adoption", _no_full)
    monkeypatch.setattr(r, "_cached_behavioral_for", _beh)
    return r, seen


@pytest.mark.asyncio
@pytest.mark.parametrize("style", ["card", "card-stacked", "classic"])
async def test_package_card_reads_the_package_result(monkeypatch, style):
    r, seen = _patch_pkg(monkeypatch)
    resp = await r.scan_card(owner="npm", repo="chalk", style=style, theme="auto", db=None)
    body = resp.body.decode()
    ET.fromstring(body)
    assert seen["pkg"] == ("npm", "chalk")
    assert "Not scanned" not in body and "not scanned" not in body
    assert "82" in body
    assert resp.headers["cache-control"] == "public, max-age=300, s-maxage=3600"


@pytest.mark.asyncio
async def test_scoped_package_card_route(monkeypatch):
    r, seen = _patch_pkg(monkeypatch)
    resp = await r.package_card(surface="npm", name="@react-email/components",
                                style="card", theme="dark", db=None)
    ET.fromstring(resp.body.decode())
    assert seen["pkg"] == ("npm", "@react-email/components")


@pytest.mark.asyncio
async def test_package_card_route_rejects_bad_input(monkeypatch):
    from fastapi import HTTPException
    r, _ = _patch_pkg(monkeypatch)
    with pytest.raises(HTTPException):
        await r.package_card(surface="gopher", name="x", style="card", theme="auto", db=None)
    with pytest.raises(HTTPException):
        await r.package_card(surface="npm", name="../etc", style="card", theme="auto", db=None)


def test_package_routes_are_declared_before_the_catch_all():
    from src.api.public_scan_router import router
    paths = [getattr(rt, "path", "") for rt in router.routes]
    catch_all = paths.index("/public/scan/package/{surface}/{name:path}")
    for p in ("card.svg", "verdict.json", "badge"):
        assert paths.index(f"/public/scan/package/{{surface}}/{{name:path}}/{p}") < catch_all


@pytest.mark.asyncio
async def test_package_verdict_links_to_the_package_report(monkeypatch):
    from src.api import public_scan_router as r

    async def _cached(owner, repo):
        if (owner, repo) != ("npm", "chalk"):
            return None
        return {**PKG_SCAN, "repo": "npm:chalk", "metadata": {}, "findings": {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0, "categories": {}, "items": []}}

    async def _stale(owner, repo):
        return None

    async def _view(data, score):
        return "safe", False

    monkeypatch.setattr(r, "_get_cached", _cached)
    monkeypatch.setattr(r, "_get_stale_cached", _stale)
    monkeypatch.setattr(r, "_badge_view", _view)
    monkeypatch.setattr(r, "_build_scan_payload", lambda full, data: {"subject": full})
    monkeypatch.setattr(r, "create_jws", lambda payload: "h.p.s")
    resp = await r.package_verdict(surface="npm", name="chalk", db=None)
    body = json.loads(resp.body)
    assert body["link"] == "https://agentavow.com/check/pkg/npm/chalk"
    assert body["jws"]


def test_widget_routes_packages_to_package_endpoints():
    js = (ROOT / "web/public/widget.js").read_text()
    assert "/api/v1/public/scan/package/" in js and "/check/pkg/" in js
    for s in ("npm", "pypi", "crates", "huggingface", "docker"):
        assert re.search(rf"\b{s}: '", js), s


# ── OG ────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_og_mcp_reads_the_endpoint_scan(monkeypatch):
    from src.api import og_router
    from src.api import public_scan_router as r

    keys = []

    async def _cached(owner, key):
        keys.append((owner, key))
        return {"trust_score": 74, "findings": {"critical": 0, "high": 0},
                "files_scanned": 0} if owner == "mcp" else None

    async def _stale(owner, key):
        return None

    monkeypatch.setattr(r, "_get_cached", _cached)
    monkeypatch.setattr(r, "_get_stale_cached", _stale)
    resp = await og_router.og_mcp(endpoint="https://mcp.deepwiki.com/mcp")
    html = resp.body.decode()
    assert keys and keys[0][0] == "mcp" and keys[0][1].startswith("mcp_")
    assert "74/100" in html
    assert "safety grade" not in html and "graded" not in html


@pytest.mark.asyncio
async def test_og_skill_reads_the_skill_result_not_the_repo(monkeypatch):
    from src.api import og_router
    from src.api import public_scan_router as r

    async def _cached(owner, key):
        if owner == "skill" and key == "anthropics/skills":
            return {"trust_score": 67, "findings": {"critical": 0, "high": 1}}
        if owner == "skill" and key == "anthropics/skills/skills/pdf":
            return {"trust_score": 87, "findings": {"critical": 0, "high": 0},
                    "files_scanned": 20}
        return {"trust_score": 90}  # the repo scan: must not be used

    async def _stale(owner, key):
        return None

    monkeypatch.setattr(r, "_get_cached", _cached)
    monkeypatch.setattr(r, "_get_stale_cached", _stale)
    html = (await og_router.og_skill(owner="anthropics", repo="skills", db=None)).body.decode()
    assert "67/100" in html and "90/100" not in html and "OpenClaw" not in html
    one = (await og_router.og_skill_one(owner="anthropics", repo="skills",
                                        skill_path="skills/pdf")).body.decode()
    assert "87/100" in one and "pdf skill" in one


def test_og_png_draws_no_tofu_glyphs():
    from src.api.og_image import _plain, render_og_png
    assert _plain("Safe to connect — nothing found · 12 ★") == "Safe to connect - nothing found · 12 stars"
    png = render_og_png(title="mcp.deepwiki.com/mcp — MCP server", grade="", score=74,
                        subtitle="Live-checked — tools clean", decision="safe",
                        adoption=1200, adoption_unit="stars", adoption_pct=30,
                        adoption_known=True)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"


# ── drift, docs, static files ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_drift_quiet_returns_empty_history(monkeypatch):
    from src.api import preflight_router as p

    class _Res:
        def scalars(self):
            return self

        def all(self):
            return []

    class _DB:
        async def execute(self, *a, **k):
            return _Res()

    out = await p._drift_payload("npm:x", "npm:x", _DB(), quiet=True)
    assert out["history"] == [] and out["summary"]["points"] == 0
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        await p._drift_payload("npm:x", "npm:x", _DB())


def test_ssr_docs_render_italics_inside_bold():
    from src.api.docs_content_router import _inline
    out = _inline("**local scanning does _not_ do: mint.** and snake_case_name")
    assert "<strong>local scanning does <em>not</em> do: mint.</strong>" in out
    assert "snake_case_name" in out


def test_static_llms_and_security_txt():
    llms = (ROOT / "web/public/llms.txt").read_text()
    assert llms.startswith("# AgentAvow") and "https://agentavow.com/mcp" in llms
    sec = (ROOT / "web/public/.well-known/security.txt").read_text()
    assert "Contact: mailto:kenne@agentavow.com" in sec and "Expires: 2027-" in sec
    conf = (ROOT / "nginx/nginx.conf").read_text()
    assert "location = /.well-known/security.txt" in conf
    assert "location = /llms.txt" in conf
    assert "location = /ai-catalog.json { return 301 /.well-known/ai-catalog.json; }" in conf
    # legal pages: browsers get the SPA, like docs
    for page in ("privacy", "terms"):
        block = conf[conf.index(f"location = /legal/{page} {{"):]
        block = block[:block.index("}\n        location")]
        assert "if ($docs_spa)" in block


def test_index_html_has_no_static_home_canonical():
    html = (ROOT / "web/index.html").read_text()
    assert 'rel="canonical"' not in html and 'property="og:url"' not in html


def test_ai_catalog_points_at_the_published_spec():
    from scripts import ai_catalog_wellknown as m
    assert m.SAFETY_MODEL_SPEC_URL.startswith("https://github.com/AgentAvow/AgentAvow/blob/main/")
    assert m._answer_phrase({"decision": "safe"}) == "Safe to connect, "


@pytest.mark.parametrize("count,unit", [
    (495_100_000, "downloads/wk"), (1_200_000_000, "downloads/wk"),
    (228_000_000, "downloads/mo"), (866_979_583, "downloads/wk"), (3_100_000, "pulls"),
])
def test_card_keeps_the_short_unit_for_long_counts(count, unit):
    from src.adoption_units import short_unit
    from src.api.badge_avow import render_avow_badge
    for cert in (False, True):
        svg = render_avow_badge(style="card", decision="safe", score=92, certified=cert,
                                coordinate="npm:x", adoption=count, adoption_unit=unit,
                                adoption_pct=60)
        assert f">{short_unit(unit)}<" in svg, (count, unit, cert)
