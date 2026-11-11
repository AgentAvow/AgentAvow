"""Account rows carry the Browse-row artwork (2026-11-11, design rule 11-10): the
watches, claims and notifications APIs add trust_score / decision / decision_reason /
certified_mark / adoption_count / adoption_unit from stored scan data, in one query
for the whole list, without scanning."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event

from src.api import tool_summary as ts
from src.api.notification_router import create_notification
from src.database import get_db
from src.main import app
from src.models import CommunityScan, PrivateScanResult, RepoClaim, ToolWatch

NOW = datetime.now(timezone.utc)


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _no_scans(monkeypatch):
    """Any scan from these endpoints is a bug: fail loudly."""
    async def boom(*a, **k):
        raise AssertionError("account list endpoints must not scan")

    for name in ("scan_package", "scan_mcp", "scan_skill", "scan_repo"):
        monkeypatch.setattr(f"src.scanner.scan.{name}", boom)

    # The Certified-mark check reads the scan cache; no cached scan = keep stored mark.
    async def no_page(*a, **k):
        return None

    monkeypatch.setattr("src.api.scan_catalog_router._mark_as_page_shows", no_page)


async def _user(client: AsyncClient, email: str) -> tuple[str, uuid.UUID]:
    user = {"email": email, "password": "Str0ngP@ss", "display_name": "RowArt"}
    await client.post("/api/v1/auth/register", json=user)
    tok = (await client.post("/api/v1/auth/login", json={
        "email": email, "password": user["password"]})).json()["access_token"]
    me = (await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"})).json()
    return tok, uuid.UUID(me["id"])


def _h(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


def _cs(surface, owner, repo, full, score, **kw) -> CommunityScan:
    return CommunityScan(
        surface=surface, owner=owner, repo=repo, full_name=full, trust_score=score,
        last_scanned_at=NOW, **kw,
    )


async def _seed_catalog(db) -> None:
    db.add_all([
        _cs("npm", "npm", "zod", "npm:zod", 92, grade="A+", critical=0, high=0,
            decision="safe", decision_reason="no blocking findings",
            adoption_count=453699764, adoption_unit="downloads/wk"),
        _cs("github", "Acme", "Weather-MCP", "Acme/Weather-MCP", 78, grade="B",
            critical=0, high=1, decision="review", decision_reason="one high finding",
            adoption_count=214, adoption_unit="stars"),
        # Scanned, no adoption signal yet ("New" in the UI).
        _cs("mcp", "mcp", "https://mcp.example.dev/mcp", "https://mcp.example.dev/mcp",
            90, grade="A", critical=0, high=0, decision="safe", decision_reason=""),
    ])
    await db.flush()


# ---- pure helpers ----

def test_coord_key_normalizes_per_surface():
    assert ts.coord_key("npm", "whatever", "Zod") == ("npm", "npm", "zod")
    assert ts.coord_key(None, "Acme", "Tool") == ("github", "acme", "tool")
    assert ts.coord_key("mcp", "", "https://X.dev/mcp") == ("mcp", "mcp", "https://x.dev/mcp")


def test_coords_from_reference():
    assert ts.coords_from_reference("npm/@scope/pkg") == [("npm", "npm", "@scope/pkg")]
    assert ts.coords_from_reference("mcp/https://a.dev/mcp") == [("mcp", "mcp", "https://a.dev/mcp")]
    assert ts.coords_from_reference("acme/tool") == [
        ("github", "acme", "tool"), ("openclaw", "acme", "tool")]
    assert ts.coords_from_reference(None) == []
    assert ts.coords_from_reference("nohead") == []


def test_mark_only_beside_safe_and_reason_is_a_string():
    s = ts._summary(70, "review", None, True, 0, "stars")
    assert s["certified_mark"] is False
    assert s["decision_reason"] == ""
    # No adoption signal → both adoption fields empty, so the UI shows "New".
    assert s["adoption_count"] is None and s["adoption_unit"] is None


def test_summary_from_score_decides_without_adoption():
    s = ts.summary_from_score(40, critical=1, high=0)
    assert s["decision"] == "do_not_connect"
    assert s["adoption_count"] is None
    assert ts.summary_from_score(None)["decision"] is None


def test_static_catalog_never_built_on_demand(monkeypatch):
    from src.api import scan_catalog_router as cat

    monkeypatch.setattr(cat, "_CATALOG_CACHE", None)

    def no_build(*a, **k):
        raise AssertionError("must not build the catalog")

    monkeypatch.setattr(cat, "_build_catalog", no_build)
    assert ts._static_index() == {}


@pytest.mark.asyncio
async def test_static_catalog_fills_a_miss(db, monkeypatch):
    from src.api import scan_catalog_router as cat

    row = cat.CatalogRow(surface="pypi", name="requests", trust_score=88, critical=0, high=0,
                         adoption_count=1000, adoption_unit="downloads/wk")
    monkeypatch.setattr(cat, "_CATALOG_CACHE", {"rows": [row]})
    out = await ts.tool_summaries(db, [ts.coord_key("pypi", "pypi", "Requests")])
    got = out[("pypi", "pypi", "requests")]
    assert got["trust_score"] == 88 and got["decision"] == "safe"
    assert got["adoption_count"] == 1000


# ---- endpoints ----

@pytest.mark.asyncio
async def test_watches_carry_row_artwork_in_one_query(client, db):
    tok, eid = await _user(client, "rowart-w@test.com")
    await _seed_catalog(db)
    db.add_all([
        ToolWatch(watcher_id=eid, surface="npm", owner="npm", repo="zod", last_score=92,
                  last_decision="safe", last_certified=True),
        # Case differs from the catalog row; the watch has no answer of its own yet.
        ToolWatch(watcher_id=eid, surface="github", owner="acme", repo="weather-mcp"),
        ToolWatch(watcher_id=eid, surface="mcp", owner="mcp", repo="https://mcp.example.dev/mcp",
                  last_score=84, last_decision="review", last_certified=False),
        ToolWatch(watcher_id=eid, surface="crates", owner="crates", repo="unscanned"),
    ])
    await db.flush()

    statements: list[str] = []

    def count(conn, cursor, statement, *a):
        if "community_scans" in statement:
            statements.append(statement)

    engine = db.bind.engine.sync_engine
    event.listen(engine, "before_cursor_execute", count)
    try:
        r = await client.get("/api/v1/watches", headers=_h(tok))
    finally:
        event.remove(engine, "before_cursor_execute", count)
    assert r.status_code == 200
    assert len(statements) == 1, "one community_scans read for the whole list"
    rows = {w["repo"]: w for w in r.json()}

    zod = rows["zod"]
    assert zod["last_score"] == 92  # old field unchanged
    assert zod["trust_score"] == 92 and zod["decision"] == "safe"
    assert zod["certified_mark"] is True
    assert zod["decision_reason"] == "no blocking findings"
    assert (zod["adoption_count"], zod["adoption_unit"]) == (453699764, "downloads/wk")

    wx = rows["weather-mcp"]
    assert wx["trust_score"] == 78 and wx["decision"] == "review"
    assert wx["adoption_count"] == 214 and wx["certified_mark"] is False

    # The watch's own re-scan leads; the catalog only adds adoption (none here).
    mcp = rows["https://mcp.example.dev/mcp"]
    assert mcp["trust_score"] == 84 and mcp["decision"] == "review"
    assert mcp["decision_reason"] == ""
    assert mcp["adoption_count"] is None

    un = rows["unscanned"]
    assert un["trust_score"] is None and un["decision"] is None
    assert un["adoption_count"] is None


@pytest.mark.asyncio
async def test_claims_carry_row_artwork(client, db):
    tok, eid = await _user(client, "rowart-c@test.com")
    await _seed_catalog(db)
    db.add_all([
        RepoClaim(entity_id=eid, surface="npm", owner="npm", repo="zod", full_name="npm:zod",
                  status="verified", verify_code="a1"),
        RepoClaim(entity_id=eid, surface="github", owner="Acme", repo="Weather-MCP",
                  full_name="Acme/Weather-MCP", status="verified", verify_code="a2"),
        RepoClaim(entity_id=eid, surface="github", owner="acme", repo="internal",
                  full_name="acme/internal", status="verified", verify_code="a3",
                  is_private=True),
        PrivateScanResult(entity_id=eid, owner="acme", repo="internal",
                          full_name="acme/internal", trust_score=40, grade="D",
                          result_json={"findings": {"critical": 1, "high": 0}}),
    ])
    await db.flush()

    r = await client.get("/api/v1/account/claims", headers=_h(tok))
    assert r.status_code == 200
    rows = {c["full_name"]: c for c in r.json()["claims"]}
    zod = rows["npm:zod"]
    assert zod["certified_mark"] is True and zod["adoption_count"] == 453699764
    assert rows["Acme/Weather-MCP"]["adoption_unit"] == "stars"
    priv = rows["acme/internal"]
    assert priv["score"] == 40  # old field unchanged
    assert priv["trust_score"] == 40 and priv["decision"] == "do_not_connect"
    assert priv["adoption_count"] is None and priv["certified_mark"] is False


@pytest.mark.asyncio
async def test_watch_alerts_carry_the_tool(client, db):
    tok, eid = await _user(client, "rowart-n@test.com")
    await _seed_catalog(db)
    db.add(ToolWatch(watcher_id=eid, surface="github", owner="acme", repo="weather-mcp",
                     last_score=70, last_decision="review", last_certified=False))
    await db.flush()
    await create_notification(db, eid, "watch_alert", "acme/weather-mcp: score dropped",
                              "Now: Review before you connect (one high).",
                              reference_id="acme/weather-mcp")
    await create_notification(db, eid, "watch_good_news", "zod is back",
                              "Now: Safe to connect.", reference_id="npm/zod")
    await create_notification(db, eid, "watch_alert", "gone", "x", reference_id="nobody/none")
    await create_notification(db, eid, "follow", "New follower", "x", reference_id="acme/weather-mcp")

    r = await client.get("/api/v1/notifications", headers=_h(tok))
    assert r.status_code == 200
    by_title = {n["title"]: n for n in r.json()["notifications"]}
    wx = by_title["acme/weather-mcp: score dropped"]["tool"]
    assert wx["surface"] == "github"
    assert wx["trust_score"] == 70 and wx["decision"] == "review"  # the watch leads
    assert wx["adoption_count"] == 214
    zod = by_title["zod is back"]["tool"]
    assert zod["surface"] == "npm" and zod["certified_mark"] is True
    assert by_title["gone"]["tool"] is None
    assert by_title["New follower"]["tool"] is None  # social kinds get nothing
