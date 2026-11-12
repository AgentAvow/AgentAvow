"""Read-only admin viewer role (``Entity.is_admin_viewer``, migration t31).

Guarantees under test:

* a viewer reads exactly the reviewed metrics GETs (``VIEWER_GETS``) and gets 403 on
  every other admin route: every POST / PUT / PATCH / DELETE, and the Post Studio,
  Replies, campaign, ad-spend list, user-management and access-list GETs;
* the route sweep reads the live app, so a newly added admin route cannot silently
  admit viewers: ``require_admin_or_viewer`` on a non-GET route, or on a GET that is
  not in ``VIEWER_GETS``, fails here;
* emails / IPs / names are masked for viewers and not for admins;
* a normal user gets 403 everywhere, as before;
* scripts/set_admin_viewer.py grants / revokes / lists and never touches is_admin.
"""
from __future__ import annotations

import inspect
import os
import re
import uuid
from pathlib import Path

import fastapi.routing
import pytest
import pytest_asyncio
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

import src.api.rate_limit as rl
from src.api.deps import get_current_entity
from src.api.redaction import mask_email, mask_ips, redact_for_viewer
from src.database import get_db
from src.main import app
from src.models import Entity, EntityType

V1 = "/api/v1"
REGISTER_URL = f"{V1}/auth/register"
LOGIN_URL = f"{V1}/auth/login"
ME_URL = f"{V1}/auth/me"

# The only routes a viewer may read. Adding one is a reviewed change: it must be a
# read-only GET serving metrics, and its response must go through viewer_safe().
VIEWER_GETS = {
    "/api/v1/admin/metrics",
    "/api/v1/admin/metrics/behavioral",
    "/api/v1/admin/metrics/traffic",
    "/api/v1/admin/metrics/growth",
    "/api/v1/admin/ad-spend/cost-per-action",
    "/api/v1/analytics/conversion/daily",
    "/api/v1/analytics/page-actions",
    "/api/v1/analytics/attribution/campaigns",
}

# GETs a viewer must never read even though they are "just reads": Post Studio,
# Replies, campaign controls, ad-spend rows, user management, the access list.
VIEWER_FORBIDDEN_GETS = [
    "/api/v1/admin/marketing/studio/posts",
    "/api/v1/admin/engagement/queue",
    "/api/v1/admin/engagement/stats",
    "/api/v1/admin/marketing/drafts",
    "/api/v1/admin/marketing/campaigns/proposed",
    "/api/v1/admin/marketing/dashboard",
    "/api/v1/admin/marketing/activity",
    "/api/v1/admin/ad-spend",
    "/api/v1/admin/entities",
    "/api/v1/admin/stats",
    "/api/v1/admin/access",
]

PW = "Str0ngP@ss"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def _user(client: AsyncClient, db, tag: str, *, admin=False, viewer=False):
    """Register + log in a fresh account; return (token, Entity)."""
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    r = await client.post(REGISTER_URL, json={
        "email": email, "password": PW, "display_name": f"{tag.title()} Person"})
    assert r.status_code in (200, 201), r.text
    r = await client.post(LOGIN_URL, json={"email": email, "password": PW})
    token = r.json()["access_token"]
    me = (await client.get(ME_URL, headers=_auth(token))).json()
    entity = await db.get(Entity, uuid.UUID(me["id"]))
    entity.is_admin = admin
    entity.is_admin_viewer = viewer
    await db.flush()
    return token, entity


# --- Unit: masking ---------------------------------------------------------------


def test_mask_email_and_ip():
    assert mask_email("someone@gmail.com") == "s•••@gmail.com"
    assert mask_email("write to a.b@example.co.uk now") == "write to a•••@example.co.uk now"
    assert mask_ips("from 203.0.113.42.") == "from 203.0.•••.•••."
    assert mask_ips("2001:db8:85a3::8a2e:370:7334") == "2001:•••"
    # Not addresses: versions, times, plain numbers stay as they are.
    for keep in ("0.1.28", "12:30", "2026-11-12", "v1.2.3"):
        assert mask_ips(keep) == keep


def test_redact_by_key_and_shape_without_mutating():
    data = {
        "email": "pat@example.com", "display_name": "Pat Example",
        "ip_address": "198.51.100.7", "rows": [{"note": "ping pat@example.com"}],
        "count": 3, "ok": True, "none": None,
    }
    out = redact_for_viewer(data)
    assert out["email"] == "p•••@example.com"
    assert out["display_name"] == "P•••"
    assert out["ip_address"] == "198.51.•••.•••"
    assert out["rows"][0]["note"] == "ping p•••@example.com"
    assert (out["count"], out["ok"], out["none"]) == (3, True, None)
    assert data["email"] == "pat@example.com"  # the cached original is untouched


# --- Route sweep over the live app ------------------------------------------------


def _source(endpoint) -> str:
    try:
        return inspect.getsource(inspect.unwrap(endpoint))
    except (OSError, TypeError):
        return ""


def _api_routes():
    """(full path, methods, endpoint) for every API route in the app. FastAPI >= 0.140
    keeps included routers lazily (``_IncludedRouter``); ``iter_route_contexts`` is
    the flattening the OpenAPI generator uses. Older versions list APIRoutes directly."""
    iter_ctx = getattr(fastapi.routing, "iter_route_contexts", None)
    if iter_ctx is None:
        for r in app.routes:
            if isinstance(r, APIRoute):
                yield r.path, set(r.methods), r.endpoint
        return
    for ctx in iter_ctx(app.routes):
        if isinstance(ctx.original_route, APIRoute):
            yield ctx.path, set(ctx.methods or ()), ctx.endpoint


def _admin_routes() -> list[tuple[str, str, str]]:
    """(method, path, source) for every API route whose handler checks admin."""
    out = []
    for path, methods, endpoint in _api_routes():
        src = _source(endpoint)
        if not re.search(r"\brequire_admin(_or_viewer)?\(", src):
            continue
        for m in sorted(methods - {"HEAD", "OPTIONS"}):
            out.append((m, path, src))
    return out


def test_viewer_gate_only_on_reviewed_metrics_gets():
    routes = _admin_routes()
    assert len(routes) > 100, "route sweep found too few admin routes"
    viewer_routes = {(m, p) for m, p, s in routes if "require_admin_or_viewer(" in s}
    bad = sorted((m, p) for m, p in viewer_routes if m != "GET")
    assert not bad, f"require_admin_or_viewer on a state-changing route: {bad}"
    assert {p for _, p in viewer_routes} == VIEWER_GETS, (
        "the viewer-readable routes changed: review the new route (read-only metrics "
        "only, response through viewer_safe) and update VIEWER_GETS")
    for _m, p, s in routes:
        if p in VIEWER_GETS:
            assert "viewer_safe(" in s, f"{p} must mask its response for viewers"


def test_viewer_flag_read_only_in_the_gate():
    """Only the gate reads is_admin_viewer (plus model, schema, access list): no other
    code path can grant a viewer anything."""
    allowed = {"src/models.py", "src/api/deps.py", "src/api/schemas.py",
               "src/admin_access.py"}
    root = Path(__file__).resolve().parent.parent
    hits = {str(p.relative_to(root)) for p in (root / "src").rglob("*.py")
            if "is_admin_viewer" in p.read_text(encoding="utf-8")}
    assert hits <= allowed, f"is_admin_viewer read outside the gate: {sorted(hits - allowed)}"


def _fill(path: str) -> str:
    return re.sub(r"\{[^}]+\}", lambda _: str(uuid.uuid4()), path)


_SPEC: dict = {}
_BODY_FIXUPS = {"/api/v1/admin/safety/alert": {"severity": "info"}}


def _resolve(schema: dict) -> dict:
    while "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        schema = _SPEC["components"]["schemas"][name]
    return schema


def _example(schema: dict):
    """A minimal value that satisfies ``schema`` (enough for the sweep's bodies)."""
    schema = _resolve(schema)
    if "default" in schema and schema["default"] is not None:
        return schema["default"]
    if "enum" in schema:
        return schema["enum"][0]
    if "const" in schema:
        return schema["const"]
    for key in ("anyOf", "oneOf", "allOf"):
        if key in schema:
            options = [o for o in schema[key] if _resolve(o).get("type") != "null"]
            return _example(options[0] if options else schema[key][0])
    t = schema.get("type")
    fmt = schema.get("format", "")
    if t == "object" or "properties" in schema:
        props = schema.get("properties", {})
        return {k: _example(props[k]) for k in schema.get("required", []) if k in props}
    if t == "array":
        n = schema.get("minItems", 0)
        return [_example(schema.get("items", {}))] * n
    if t == "integer":
        return max(int(schema.get("minimum", 1)), int(schema.get("exclusiveMinimum", 0)) + 1)
    if t == "number":
        return float(schema.get("minimum", 1))
    if t == "boolean":
        return False
    if t == "string":
        if fmt == "uuid":
            return str(uuid.uuid4())
        if fmt == "date":
            return "2026-11-01"
        if fmt == "date-time":
            return "2026-11-01T00:00:00Z"
        if fmt == "email":
            return "sweep@example.com"
        m = re.fullmatch(r"\^\(([\w|-]+)\)\$", schema.get("pattern", ""))
        if m:  # an enum written as a pattern: ^(add|remove)$
            return m.group(1).split("|")[0]
        return "x" * max(1, schema.get("minLength", 1))
    return None


def _valid_request(method: str, path: str) -> tuple[object, dict]:
    if not _SPEC:
        _SPEC.update(app.openapi())
    op = _SPEC["paths"].get(path, {}).get(method.lower(), {})
    body = None
    content = op.get("requestBody", {}).get("content", {})
    if "application/json" in content:
        body = _example(content["application/json"]["schema"])
        # Fields checked by a custom validator the schema cannot express.
        if isinstance(body, dict):
            body.update(_BODY_FIXUPS.get(path, {}))
    params = {p["name"]: _example(p.get("schema", {})) for p in op.get("parameters", [])
              if p.get("in") == "query" and p.get("required")}
    return body, params


@pytest_asyncio.fixture
async def sweep_client(db):
    """App with auth replaced by a settable transient entity and rate limits off."""
    holder: dict = {}

    async def override_get_db():
        yield db

    async def no_limit():
        return None

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_entity] = lambda: holder["entity"]
    for name, fn in vars(rl).items():
        if name.startswith("rate_limit_") and callable(fn):
            app.dependency_overrides[fn] = no_limit
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac, holder
    app.dependency_overrides.clear()


def _entity(*, viewer: bool) -> Entity:
    return Entity(
        id=uuid.uuid4(), type=EntityType.HUMAN, email="sweep@example.com",
        display_name="Sweep", did_web=f"did:web:sweep-{uuid.uuid4().hex[:6]}",
        is_active=True, is_admin=False, is_admin_viewer=viewer, is_quarantined=False,
        email_verified=True,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("who", ["viewer", "normal"])
async def test_sweep_every_admin_route_rejects(sweep_client, who):
    """Every admin route outside VIEWER_GETS answers a viewer and a normal user with
    403 from the admin gate itself: a request that fails validation first (422) is
    retried with a body built from the route's OpenAPI schema."""
    ac, holder = sweep_client
    holder["entity"] = _entity(viewer=(who == "viewer"))
    statuses: dict[tuple[str, str], int] = {}
    for method, path, _src in _admin_routes():
        if who == "viewer" and method == "GET" and path in VIEWER_GETS:
            continue
        r = await ac.request(method, _fill(path), json={})
        statuses[(method, path)] = r.status_code
        if r.status_code == 422:
            # Validation ran before the handler: retry with a body / query built from
            # the route's OpenAPI schema so the request reaches the admin gate.
            body, params = _valid_request(method, path)
            r = await ac.request(method, _fill(path), json=body, params=params)
            statuses[(method, path)] = r.status_code
    not_403 ={k: v for k, v in statuses.items() if v != 403}
    assert not not_403, f"{who} not rejected with 403: {not_403}"
    assert sum(1 for k in statuses if k[0] != "GET") > 40, "too few state-changing routes"


# --- End to end with real accounts ------------------------------------------------


@pytest.mark.asyncio
async def test_me_exposes_viewer_flag(client, db):
    token, _ = await _user(client, db, "viewer", viewer=True)
    me = (await client.get(ME_URL, headers=_auth(token))).json()
    assert me["is_admin_viewer"] is True and me["is_admin"] is False
    token, _ = await _user(client, db, "normal")
    assert (await client.get(ME_URL, headers=_auth(token))).json()["is_admin_viewer"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("path", sorted(VIEWER_GETS))
async def test_viewer_reads_metrics_normal_user_cannot(client, db, path):
    v_token, _ = await _user(client, db, "viewer", viewer=True)
    a_token, _ = await _user(client, db, "admin", admin=True)
    n_token, _ = await _user(client, db, "normal")
    assert (await client.get(path, headers=_auth(v_token))).status_code == 200
    assert (await client.get(path, headers=_auth(a_token))).status_code == 200
    assert (await client.get(path, headers=_auth(n_token))).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("path", VIEWER_FORBIDDEN_GETS)
async def test_viewer_403_on_studio_replies_campaign_users(client, db, path):
    v_token, _ = await _user(client, db, "viewer", viewer=True)
    n_token, _ = await _user(client, db, "normal")
    assert (await client.get(path, headers=_auth(v_token))).status_code == 403
    assert (await client.get(path, headers=_auth(n_token))).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", [
    ("POST", "/api/v1/admin/metrics/behavioral/eval", None),
    ("POST", "/api/v1/admin/metrics/behavioral/corpus",
     {"action": "add", "surface": "npm", "name": "x"}),
    ("PUT", "/api/v1/admin/ad-spend",
     {"day": "2026-11-01", "utm_campaign": "c", "spend_usd": "1.00"}),
    ("POST", "/api/v1/admin/ad-spend/import", {"csv": "a,b\n1,2"}),
    ("DELETE", f"/api/v1/admin/ad-spend/{uuid.uuid4()}", None),
    ("POST", "/api/v1/admin/marketing/trigger", {}),
    ("POST", "/api/v1/admin/marketing/campaigns/generate", {}),
])
async def test_viewer_403_on_writes_with_valid_bodies(client, db, method, path, body):
    """Writes the dashboard actually sends, with bodies that pass validation, so the
    403 comes from the admin gate itself."""
    v_token, _ = await _user(client, db, "viewer", viewer=True)
    r = await client.request(method, path, json=body, headers=_auth(v_token))
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_emails_and_ips_masked_for_viewer_not_admin(client, db):
    from src.models import AnalyticsEvent, AnalyticsFirstTouch

    sid = str(uuid.uuid4())
    term = "pat.example@example.com via 203.0.113.42"
    db.add(AnalyticsFirstTouch(session_id=sid, utm_campaign="viewer-test",
                               utm_term=term, landing_page="/"))
    db.add(AnalyticsEvent(event_type="lp_view", session_id=sid, page="/"))
    await db.flush()
    v_token, _ = await _user(client, db, "viewer", viewer=True)
    a_token, _ = await _user(client, db, "admin", admin=True)
    url = f"{V1}/analytics/attribution/campaigns"

    def term_of(resp):
        return [r["term"] for r in resp.json()["campaigns"] if r["campaign"] == "viewer-test"]

    assert term_of(await client.get(url, headers=_auth(a_token))) == [term]
    masked = term_of(await client.get(url, headers=_auth(v_token)))
    assert masked == ["p•••@example.com via 203.0.•••.•••"]


@pytest.mark.asyncio
async def test_access_list_admin_only(client, db):
    a_token, admin = await _user(client, db, "admin", admin=True)
    v_token, viewer = await _user(client, db, "viewer", viewer=True)
    n_token, _ = await _user(client, db, "normal")
    url = f"{V1}/admin/access"
    assert (await client.get(url, headers=_auth(v_token))).status_code == 403
    assert (await client.get(url, headers=_auth(n_token))).status_code == 403
    r = await client.get(url, headers=_auth(a_token))
    assert r.status_code == 200
    by_email = {a["email"]: a for a in r.json()["accounts"]}
    assert by_email[admin.email]["role"] == "Admin"
    assert by_email[viewer.email]["role"] == "Viewer"  # unmasked for admins
    assert by_email[viewer.email]["display_name"] == "Viewer Person"
    assert by_email[viewer.email]["created_at"]
    assert all(a["role"] in ("Admin", "Viewer") for a in r.json()["accounts"])


# --- Ops script ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_admin_viewer_script(monkeypatch, capsys):
    """Grant / revoke / list / unknown email against the test DB, on its own committed
    row (removed afterwards); is_admin is never touched."""
    from sqlalchemy import delete, select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    import scripts.set_admin_viewer as sav
    from src.models import AuditLog

    url = os.environ.get("DATABASE_URL", "postgresql+asyncpg://localhost:5432/agentgraph_test")
    monkeypatch.setenv("DATABASE_URL", url)
    engine = create_async_engine(url)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    eid = uuid.uuid4()
    email = f"script-{eid.hex[:8]}@example.com"
    async with maker() as s:
        s.add(Entity(id=eid, type=EntityType.HUMAN, email=email, display_name="Script Person",
                     did_web=f"did:web:script-{eid.hex[:8]}", is_admin=True))
        await s.commit()
    try:
        assert await sav.run("nobody-here@example.com", True, False) == 1
        assert await sav.run(email.upper(), True, False) == 0
        out = capsys.readouterr().out
        assert "Before:  is_admin_viewer=False" in out and "After:   is_admin_viewer=True" in out
        async with maker() as s:
            e = await s.get(Entity, eid)
            assert e.is_admin_viewer is True and e.is_admin is True
        assert await sav.run(None, None, True) == 0
        assert email in capsys.readouterr().out
        assert await sav.run(email, False, False) == 0
        async with maker() as s:
            e = await s.get(Entity, eid)
            assert e.is_admin_viewer is False and e.is_admin is True
            n = (await s.execute(select(AuditLog).where(AuditLog.resource_id == eid))).all()
            assert len(n) == 2
    finally:
        async with maker() as s:
            await s.execute(delete(AuditLog).where(AuditLog.resource_id == eid))
            await s.execute(delete(Entity).where(Entity.id == eid))
            await s.commit()
        await engine.dispose()


def test_set_admin_viewer_script_usage():
    import scripts.set_admin_viewer as sav

    with pytest.raises(SystemExit):
        sav.main(["--grant"])  # no email
    with pytest.raises(SystemExit):
        sav.main(["a@example.com", "--list"])
    with pytest.raises(SystemExit):
        sav.main(["a@example.com"])  # no action
