"""nginx returns a real 404 for paths the SPA doesn't route. The route list is
generated from web/src/App.tsx; this fails CI when the two drift apart."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import gen_spa_routes as g  # noqa: E402


def test_nginx_route_map_matches_app_routes():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_spa_routes.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def _known(path: str) -> bool:
    pats = [g.to_regex(p) for p in g.route_paths(g.APP.read_text())]
    return any(re.match(p, path) for p in pats)


def test_real_routes_are_known():
    for path in ("/", "/browse", "/check/vercel/next.js", "/check/pkg/npm/@scope/x",
                 "/check/skill/anthropics/skills/skills/pdf", "/check/mcp",
                 "/docs/run-locally", "/legal/terms", "/certified/", "/feed"):
        assert _known(path), path


def test_nonsense_is_unknown():
    for path in ("/definitely-not-a-page", "/browse/extra/segments", "/docs/a/b"):
        assert not _known(path), path


def test_cutover_guarded_legacy_routes_are_skipped():
    src = ('{!CUTOVER && <Route path="/only-legacy" element={<X />} />}\n'
           '<Route path="kept" element={<Y />} />\n')
    assert g.route_paths(src) == ["/kept"]
