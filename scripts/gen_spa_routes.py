"""Generate nginx's list of known SPA routes from web/src/App.tsx.

nginx serves the single-page app's index.html for any path it has no file for. Without
a route list, a nonsense URL comes back "200 Page not found" (a soft 404). This script
reads the <Route path=...> entries the live site mounts (the cutover build, so routes
guarded by ``!CUTOVER &&`` are skipped and relative rebrand routes sit at the root) and
writes them as a ``map $uri $spa_known_route`` block between markers in
nginx/nginx.conf. Unknown paths then get a real 404 status with the same SPA page.

    python3 scripts/gen_spa_routes.py           # rewrite the block in nginx/nginx.conf
    python3 scripts/gen_spa_routes.py --check   # exit 1 if the block is out of date

tests/test_spa_routes_map.py runs the check, so a route added to App.tsx without
regenerating fails CI.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "web" / "src" / "App.tsx"
NGINX = ROOT / "nginx" / "nginx.conf"
BEGIN = "    # BEGIN GENERATED SPA ROUTES (scripts/gen_spa_routes.py; do not edit by hand)"
END = "    # END GENERATED SPA ROUTES"

_ROUTE_RE = re.compile(r"<Route\b([^>]*)>?")
_PATH_RE = re.compile(r'\bpath="([^"]*)"')


def route_paths(app_source: str) -> list[str]:
    """Absolute route patterns the cutover build mounts, sorted."""
    out: set[str] = set()
    for line in app_source.splitlines():
        if "<Route" not in line or "!CUTOVER" in line:
            continue
        m = _ROUTE_RE.search(line)
        if not m:
            continue
        attrs = m.group(1)
        if re.search(r"\bindex\b", attrs) and "path=" not in attrs:
            out.add("/")
            continue
        p = _PATH_RE.search(attrs)
        if p:
            path = p.group(1)
        elif "REBRAND_BASE" in attrs:
            path = "/"  # the rebrand layout itself, at the root after cutover
        else:
            continue
        if path == "*":
            continue  # the NotFound catch-all
        if not path.startswith("/"):
            path = "/" + path
        out.add(path)
    return sorted(out)


def to_regex(path: str) -> str:
    if path == "/":
        return "^/$"
    parts = []
    tail = ""
    segs = path.strip("/").split("/")
    if segs and segs[-1] == "*":
        segs = segs[:-1]
        tail = "(?:/.*)?"
    for seg in segs:
        parts.append("[^/]+" if seg.startswith(":") else re.escape(seg).replace("\\-", "-"))
    return "^/" + "/".join(parts) + tail + "/?$"


def render_block(paths: list[str]) -> str:
    lines = [
        BEGIN,
        "    # Every path the SPA routes. A path not listed here gets a real 404 status",
        "    # (with the SPA's \"Page not found\" page) from location @spa_route.",
        "    map $uri $spa_known_route {",
        "        default 0;",
    ]
    for p in paths:
        lines.append(f"        ~{to_regex(p)} 1;")
    lines += ["    }", END]
    return "\n".join(lines)


def updated_conf(conf: str, block: str) -> str:
    if BEGIN in conf and END in conf:
        start = conf.index(BEGIN)
        end = conf.index(END) + len(END)
        return conf[:start] + block + conf[end:]
    raise SystemExit("nginx.conf has no GENERATED SPA ROUTES markers")


def main(argv: list[str]) -> int:
    block = render_block(route_paths(APP.read_text()))
    conf = NGINX.read_text()
    new = updated_conf(conf, block)
    if "--check" in argv:
        if new != conf:
            print("nginx/nginx.conf SPA route map is out of date; "
                  "run: python3 scripts/gen_spa_routes.py", file=sys.stderr)
            return 1
        return 0
    if new != conf:
        NGINX.write_text(new)
        print("updated nginx/nginx.conf SPA route map")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
