"""npm v2/v3 workspaces: what only a private member uses is not a production
dependency (the npm twin of tests/test_pnpm_shipped_reachability.py). npm's own `dev`
flags are computed over the whole workspace, so a private docs site's deps read as
production without this."""
from __future__ import annotations

import json

from src.scanner import lockfiles as lf

LOCK = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "root", "workspaces": ["packages/*"], "devDependencies": {"vitest": "^4"}},
    "packages/lib": {"name": "@ws/lib", "version": "1.0.0",
                     "dependencies": {"left-pad": "^1.3.0", "@ws/helpers": "*"}},
    "packages/helpers": {"name": "@ws/helpers", "version": "1.0.0",
                         "dependencies": {"ms": "^2.1.3"}},
    "packages/docs": {"name": "@ws/docs", "version": "1.0.0",
                      "dependencies": {"next": "^15", "left-pad": "^1.0.0"}},
    "node_modules/@ws/lib": {"resolved": "packages/lib", "link": True},
    "node_modules/@ws/helpers": {"resolved": "packages/helpers", "link": True},
    "node_modules/@ws/docs": {"resolved": "packages/docs", "link": True},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/ms": {"version": "2.1.3"},
    "node_modules/next": {"version": "15.5.25", "dependencies": {"form-data": "^4"}},
    "node_modules/form-data": {"version": "4.0.2"},
    # docs pins an older left-pad, nested under its own node_modules
    "packages/docs/node_modules/left-pad": {"version": "1.0.0"},
    "node_modules/vitest": {"version": "4.1.5", "dev": True},
}})
PRIVATE = {"", "packages/docs", "packages/helpers"}


def _prod(priv=None):
    pv = {"package-lock.json": priv} if priv is not None else None
    return {f"{d.name}@{d.version}" for d in lf.parse_all({"package-lock.json": LOCK}, pv)
            if not d.dev}


def test_members_are_not_dependencies():
    names = {d.name for d in lf.parse_all({"package-lock.json": LOCK})}
    assert not any(n.startswith("packages/") for n in names)


def test_private_docs_deps_are_not_shipped():
    # the published lib, and its private helper it depends on, ship
    assert _prod(PRIVATE) == {"left-pad@1.3.0", "ms@2.1.3"}


def test_without_private_info_nothing_changes():
    assert _prod() == {"left-pad@1.3.0", "ms@2.1.3", "next@15.5.25", "form-data@4.0.2",
                       "left-pad@1.0.0"}


def test_all_private_app_keeps_runtime_deps():
    prod = _prod({"", "packages/lib", "packages/helpers", "packages/docs"})
    assert {"next@15.5.25", "form-data@4.0.2", "left-pad@1.3.0"} <= prod


def test_unresolvable_shipped_dep_changes_nothing():
    broken = json.loads(LOCK)
    del broken["packages"]["node_modules/left-pad"]
    text = json.dumps(broken)
    assert lf.npm_workspace_unshipped(text, PRIVATE) is None
    deps = lf.parse_all({"package-lock.json": text}, {"package-lock.json": PRIVATE})
    assert "next" in {d.name for d in deps if not d.dev}


def test_plain_project_is_not_a_workspace():
    plain = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "x", "dependencies": {"ms": "^2"}},
        "node_modules/ms": {"version": "2.1.3"}}})
    assert lf.npm_workspace_members(plain) == []
    assert lf.npm_workspace_unshipped(plain, {""}) is None
