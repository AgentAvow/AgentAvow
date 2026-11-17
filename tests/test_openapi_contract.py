"""The committed OpenAPI document matches the code, and routes stay versioned (#408).

- docs/api/openapi.json must equal what scripts/openapi/generate.py builds from the
  code. If it doesn't, run `make openapi` and commit the result.
- Every route sits under /api/v<N>, or is listed with a reason in
  docs/api/route-allowlist.json.
- Every /api/v<N> route hidden from the OpenAPI document is listed there too, because
  the breaking-change gate cannot see it.

Needs no database: the document is generated in a child process with fixed settings.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "api" / "openapi.json"
ALLOWLIST = ROOT / "docs" / "api" / "route-allowlist.json"
_VERSIONED = re.compile(r"^/api/v\d+(/|$)")


def _load(name: str):
    path = ROOT / "scripts" / "openapi" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_openapi_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _load("generate")


@pytest.fixture(scope="module")
def fresh() -> str:
    return gen.generate()


# --- the committed document is current -------------------------------------------


def test_committed_document_is_current(fresh):
    ok, message = gen.check(DOC, fresh)
    assert ok, message


def test_committed_document_uses_the_stable_format():
    text = DOC.read_text(encoding="utf-8")
    assert text == gen.serialize(json.loads(text)), "run `make openapi`"


def test_planted_route_change_makes_the_check_fail(fresh, tmp_path):
    """A route added in code but not regenerated: the committed copy lacks it."""
    spec = json.loads(fresh)
    stale = copy.deepcopy(spec)
    stale["paths"].pop(sorted(stale["paths"])[0])
    path = tmp_path / "openapi.json"
    path.write_text(gen.serialize(stale), encoding="utf-8")
    ok, message = gen.check(path, fresh)
    assert not ok
    assert "make openapi" in message
    assert "stale" in message


def test_planted_model_change_makes_the_check_fail(fresh, tmp_path):
    spec = json.loads(fresh)
    name = sorted(spec["components"]["schemas"])[0]
    spec["components"]["schemas"][name]["description"] = "edited by hand"
    path = tmp_path / "openapi.json"
    path.write_text(gen.serialize(spec), encoding="utf-8")
    ok, message = gen.check(path, fresh)
    assert not ok and "make openapi" in message


def test_missing_document_fails_with_the_fix(fresh, tmp_path):
    ok, message = gen.check(tmp_path / "openapi.json", fresh)
    assert not ok and "make openapi" in message


def test_generation_ignores_the_callers_environment(fresh, monkeypatch, tmp_path):
    """Settings that could change routes or text never reach the generator."""
    monkeypatch.setenv("API_V1_PREFIX", "/api/v9")
    monkeypatch.setenv("APP_NAME", "Something Else")
    monkeypatch.setenv("ENABLE_SCHEDULER", "true")
    monkeypatch.setenv("BLUESKY_FEED_ENABLED", "true")
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("API_V1_PREFIX=/api/v8\n", encoding="utf-8")
    assert gen.generate() == fresh


# --- route allowlist -------------------------------------------------------------


def _allowlist() -> dict:
    return json.loads(ALLOWLIST.read_text(encoding="utf-8"))


def _routes() -> list[tuple[str, bool]]:
    """(full path, in the OpenAPI document) for every route the app registers."""
    import fastapi.routing
    from fastapi.routing import APIRoute
    from starlette.routing import Mount

    from src.main import app

    iter_ctx = getattr(fastapi.routing, "iter_route_contexts", None)
    out: list[tuple[str, bool]] = []
    if iter_ctx is None:  # FastAPI < 0.140 lists routes flat
        for r in app.routes:
            in_doc = isinstance(r, APIRoute) and r.include_in_schema
            out.append((r.path, in_doc))
        return out
    for ctx in iter_ctx(app.routes):
        route = ctx.original_route
        eff = getattr(ctx, "_route_context", None)
        path = ctx.path or getattr(getattr(eff, "starlette_route", None), "path", "") \
            or getattr(route, "path", "")
        if isinstance(route, Mount):
            out.append((route.path, False))
            continue
        include = eff.include_in_schema if eff is not None else getattr(
            route, "include_in_schema", False)
        out.append((path, isinstance(route, APIRoute) and bool(include)))
    return out


@pytest.mark.parametrize("section", ["outside_version_prefix", "not_in_openapi"])
def test_allowlist_entries_have_a_reason(section):
    entries = _allowlist()[section]
    assert entries
    for e in entries:
        assert e.get("path", "").startswith("/"), e
        assert len(e.get("reason", "").strip()) >= 15, f"{e['path']}: give a real reason"
    paths = [e["path"] for e in entries]
    assert len(paths) == len(set(paths)), "duplicate entries"


def test_every_route_is_versioned_or_allowlisted():
    allowed = {e["path"] for e in _allowlist()["outside_version_prefix"]}
    loose = sorted({p for p, _ in _routes() if not _VERSIONED.match(p)} - allowed)
    assert not loose, (
        f"routes outside /api/v<N>: {loose}. New public routes go under /api/v1. If one "
        f"truly must live elsewhere (a protocol-fixed path), add it to {ALLOWLIST.name} "
        f"with a reason."
    )


def test_every_hidden_versioned_route_is_listed():
    allowed = {e["path"] for e in _allowlist()["not_in_openapi"]}
    hidden = sorted({p for p, in_doc in _routes() if _VERSIONED.match(p) and not in_doc}
                    - allowed)
    assert not hidden, (
        f"/api/v<N> routes hidden from the OpenAPI document: {hidden}. The breaking-change "
        f"gate cannot see them. Put them in the document, or list them in "
        f"{ALLOWLIST.name} under not_in_openapi with a reason."
    )


def test_allowlist_has_no_stale_entries():
    present = {p for p, _ in _routes()}
    data = _allowlist()
    stale = [
        e["path"]
        for section in ("outside_version_prefix", "not_in_openapi")
        for e in data[section]
        if e["path"] not in present and not e.get("conditional")
    ]
    assert not stale, f"allowlisted routes that no longer exist (remove them): {stale}"


def test_allowlisted_outside_routes_are_really_outside():
    for e in _allowlist()["outside_version_prefix"]:
        assert not _VERSIONED.match(e["path"]), f"{e['path']} is versioned; drop the entry"


def test_document_paths_agree_with_the_route_rule():
    """Paths in the committed document are versioned or allowlisted too."""
    allowed = {e["path"] for e in _allowlist()["outside_version_prefix"]}
    paths = json.loads(DOC.read_text(encoding="utf-8"))["paths"]
    loose = sorted(p for p in paths if not _VERSIONED.match(p) and p not in allowed)
    assert not loose, loose
