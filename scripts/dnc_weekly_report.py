#!/usr/bin/env python3
"""Weekly "Do not connect" report: every stored scan whose answer is do_not_connect.

Runs on the Mac Mini (LaunchAgent ``com.agentavow.dnc-weekly-report``, Mondays 08:00
America/Los_Angeles). It reads prod over SSH, READ-ONLY:

- one-off container of the backend image (``docker-compose run --rm --no-deps``,
  ``nice -n 19``, ``--entrypoint`` so no migrations / app start), never ``docker exec``
  into the running backend;
- Postgres session with ``default_transaction_read_only=on`` (a write would error);
- Redis ``GET`` only, for the cached full scan (version + top finding).

The answer is the one stored on ``community_scans.decision`` at capture time (from
``src.scanner.verdict.decide()`` over the full result). Rows captured before that
column (decision NULL) are recomputed with the same ``decide()``, inside the prod
image, over the cached full result when there is one, else over score + counts (the
catalog's fallback).

Writes ``docs/internal/dnc-reports/YYYY-MM-DD.md`` (gitignored) and prepends a one-line
summary under ``## Weekly Do-not-connect reports`` in ``docs/internal/STATUS.md``.

The local side is stdlib only.

Usage:
    .venv312/bin/python scripts/dnc_weekly_report.py [--dry-run] [--date YYYY-MM-DD]
"""
from __future__ import annotations

import argparse
import datetime as dt
import inspect
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STATUS_HEADING = "## Weekly Do-not-connect reports"

SSH_KEY = Path.home() / ".ssh" / "agentgraph-key.pem"
SSH_HOST = "ec2-user@98.94.217.37"
REMOTE_CMD = (
    "cd ~/agentgraph && set -a && source .env.production && set +a && "
    "docker-compose -f docker-compose.prod.yml run --rm --no-deps -T "
    "--entrypoint nice backend -n 19 python -u -"
)
MARKER = "@@DNC_JSON@@"
KEYS_RE = re.compile(r"<!--\s*dnc-keys:\s*(\{.*?\})\s*-->", re.S)
REPORT_NAME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.md$")

PACKAGE_SURFACES = ("npm", "pypi", "crates", "huggingface", "docker")
SECTIONS = (
    ("Packages", PACKAGE_SURFACES, "Package"),
    ("Repos (GitHub)", ("github",), "Repo"),
    ("Skills (OpenClaw)", ("openclaw",), "Skill"),
    ("MCP servers", ("mcp",), "Endpoint"),
)

def pick_top(items: list, decides) -> dict | None:
    """The finding to name as a row's top finding: the highest-severity finding that
    drove the answer (``decides`` is ``verdict.finding_decides``: a blocking, i.e.
    shipped, critical/high, a known-malicious dependency, a sandbox finding). When none
    qualifies (a cached result whose tags predate the shipped/blocking alignment), the
    highest-severity finding ``decide()`` could have counted: a defect, installed, not a
    published-advisory or dependency item, shipped first. Never just ``items[0]`` (a
    medium named beside a critical reason). Self-contained: its source also runs in the
    prod image (``REMOTE_SCRIPT``)."""
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items = [i for i in (items or []) if isinstance(i, dict)]

    def sev(i):
        return rank.get(str(i.get("severity") or "").lower(), 5)

    deciding = [i for i in items if decides(i)]
    if deciding:
        return min(deciding, key=sev)  # min() keeps list order among equal severity
    counted = [i for i in items if i.get("kind") != "capability"
               and i.get("installed") is not False
               and i.get("category") not in ("known_vulnerability", "dependency")]
    if counted:
        return min(counted, key=lambda i: (sev(i), i.get("shipped") is False))
    return items[0] if items else None


# Runs inside the prod backend image (has asyncpg, redis, src/). Prints one JSON line.
# ``pick_top`` is prepended from this module (see ``remote_script``).
REMOTE_SCRIPT = r'''
import asyncio, json, os
import asyncpg
import redis.asyncio as aioredis
from src.scanner.verdict import decide, finding_decides

PKG = ("npm", "pypi", "crates", "huggingface", "docker")

def cache_key(s, o, r):
    if s in PKG:
        return f"{s}/{r}"
    if s == "openclaw":
        return f"skill/{o}/{r}"
    if s == "mcp":
        return f"mcp/{r}"
    return f"{o}/{r}"

async def cached(rd, key):
    for pref in ("public_scan:", "public_scan_stale:"):
        raw = await rd.get("ag:cache:" + pref + key)
        if raw:
            try:
                return json.loads(raw)
            except ValueError:
                pass
    return None

async def main():
    url = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")
    db = await asyncpg.connect(url, server_settings={"default_transaction_read_only": "on"})
    assert await db.fetchval("show default_transaction_read_only") == "on"
    rd = aioredis.from_url(os.environ["REDIS_URL"])
    rows = await db.fetch(
        "select surface, owner, repo, full_name, trust_score, critical, high, "
        "decision, decision_reason, last_scanned_at from community_scans "
        "where trust_score is not null and (decision = 'do_not_connect' or decision is null)")
    await db.close()
    out = []
    for r in rows:
        data = await cached(rd, cache_key(r["surface"], r["owner"], r["repo"]))
        decision, reason, recomputed = r["decision"], r["decision_reason"], False
        if decision is None:
            src = data if data else {"trust_score": r["trust_score"], "findings": {
                k: r[k] for k in ("critical", "high") if isinstance(r[k], int)}}
            d = decide(src)
            decision, reason, recomputed = d.decision, d.reason, True
        if decision != "do_not_connect":
            continue
        items = ((data or {}).get("findings") or {}).get("items") or []
        top = pick_top(items, finding_decides)
        out.append({
            "surface": r["surface"], "full_name": r["full_name"],
            "name": r["repo"] if r["surface"] in PKG or r["surface"] == "mcp" else r["full_name"],
            "version": (data or {}).get("package_version") or None,
            "score": r["trust_score"], "critical": r["critical"], "high": r["high"],
            "reason": reason, "recomputed": recomputed, "cached": data is not None,
            "scanned_at": r["last_scanned_at"].isoformat() if r["last_scanned_at"] else None,
            "top": None if not top else {
                "rule": top.get("name"), "category": top.get("category"),
                "severity": top.get("severity"), "file": top.get("file_path"),
                "line": top.get("line_number")},
        })
    await rd.aclose()
    print("@@DNC_JSON@@" + json.dumps(out))

asyncio.run(main())
'''


# ── Pure helpers (unit-tested) ─────────────────────────────────────────────────────

def remote_script() -> str:
    """The script piped to the prod image: ``pick_top``'s source, then the query."""
    return inspect.getsource(pick_top) + "\n" + REMOTE_SCRIPT


_PEP503_RE = re.compile(r"[-_.]+")


def normalize_name(surface: object, name: object) -> str:
    """A PyPI name per PEP 503 (lowercase, runs of ``-_.`` -> ``-``), so
    ``huggingface_hub`` and ``huggingface-hub`` are one project. Other surfaces as-is."""
    s = str(name if name is not None else "")
    return _PEP503_RE.sub("-", s).lower() if surface == "pypi" else s


def row_key(row: dict) -> str:
    """Stable identity of a target across weeks: ``surface:full_name`` (PyPI names
    PEP 503-normalized)."""
    surface = row.get("surface")
    return f"{surface}:{normalize_name(surface, row.get('full_name'))}"


def _key_from_text(key: str) -> str:
    """A previous report's key, normalized like ``row_key``."""
    surface, sep, full = key.partition(":")
    return f"{surface}:{normalize_name(surface, full)}" if sep else key


def dedupe_rows(rows: list[dict]) -> list[dict]:
    """One row per ``row_key``: ``community_scans`` can hold the same PyPI project
    under two spellings. Keeps the most recent ``scanned_at``; normalizes the kept
    row's ``name`` / ``full_name`` for PyPI. Order of first appearance is kept."""
    best: dict[str, dict] = {}
    for r in rows:
        key = row_key(r)
        if key not in best or str(r.get("scanned_at") or "") > str(
                best[key].get("scanned_at") or ""):
            best[key] = r
    out = []
    for r in best.values():
        if r.get("surface") == "pypi":
            r = {**r, "name": normalize_name("pypi", r.get("name")),
                 "full_name": normalize_name("pypi", r.get("full_name"))}
        out.append(r)
    return out


def parse_remote_output(stdout: str) -> list[dict]:
    """The JSON list after the marker line (compose / ssh noise ignored)."""
    for line in reversed(stdout.splitlines()):
        if line.startswith(MARKER):
            return json.loads(line[len(MARKER):])
    raise ValueError("no report payload in remote output")


def parse_prev_keys(text: str) -> dict[str, str | None] | None:
    """``{key: version}`` from a previous report's embedded comment, or None."""
    m = KEYS_RE.search(text or "")
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    out: dict[str, str | None] = {}
    for k, v in data.items():
        nk = _key_from_text(str(k))
        if nk not in out or (v and not out[nk]):
            out[nk] = v
    return out


def find_previous_report(report_dir: Path, today: str) -> Path | None:
    """The newest ``YYYY-MM-DD.md`` in ``report_dir`` dated strictly before ``today``."""
    if not report_dir.is_dir():
        return None
    dated = sorted(
        (m.group(1), p) for p in report_dir.iterdir()
        if (m := REPORT_NAME_RE.match(p.name)) and m.group(1) < today)
    return dated[-1][1] if dated else None


def _cell(v: object) -> str:
    s = " ".join(str(v if v is not None else "").split())
    return s.replace("|", "\\|") or "-"


def _location(top: dict | None) -> str:
    if not top or not top.get("file"):
        return "-"
    line = top.get("line")
    return f"`{top['file']}:{line}`" if line not in (None, "", 0) else f"`{top['file']}`"


def _rule(top: dict | None) -> str:
    if not top:
        return "(no cached findings)"
    rule = str(top.get("rule") or "unnamed")
    extra = ", ".join(str(x) for x in (top.get("severity"), top.get("category")) if x)
    return f"{rule} ({extra})" if extra else rule


def _scanned(ts: str | None) -> str:
    if not ts:
        return "-"
    try:
        t = dt.datetime.fromisoformat(ts).astimezone(dt.timezone.utc)
    except ValueError:
        return ts
    return t.strftime("%Y-%m-%d %H:%M")


def new_status(row: dict, prev: dict[str, str | None] | None) -> str:
    """``NEW`` / ``new version (was X)`` / ``""`` against last week's keys."""
    if prev is None:
        return "NEW"
    key = row_key(row)
    if key not in prev:
        return "NEW"
    old = prev.get(key)
    if old and row.get("version") and old != row.get("version"):
        return f"new version (was {old})"
    return ""


def render_report(rows: list[dict], prev: dict[str, str | None] | None, today: str,
                  generated_at: str, baseline: str | None) -> str:
    """The Markdown report. Packages first, then repos, skills, MCP servers."""
    counts = {title: 0 for title, _s, _h in SECTIONS}
    new_total = sum(1 for r in rows if new_status(r, prev) == "NEW")
    lines = [
        f"# Do-not-connect report, {today}",
        "",
        f"Generated {generated_at} UTC from prod `community_scans` (read-only). Every "
        "stored scan whose answer is **Do not connect**. Check each one: a wrong answer "
        "here is a false alarm on a real tool.",
        "",
        f"Baseline: {baseline or 'none (first report; every row counts as NEW)'}.",
        "",
    ]
    body: list[str] = []
    for title, surfaces, noun in SECTIONS:
        sec = [r for r in rows if r.get("surface") in surfaces]
        counts[title] = len(sec)
        if not sec:
            continue
        sec.sort(key=lambda r: (new_status(r, prev) != "NEW", r.get("score") or 0,
                                str(r.get("full_name")).lower()))
        n_new = sum(1 for r in sec if new_status(r, prev) == "NEW")
        body += [f"## {title} ({len(sec)}, {n_new} new)", "",
                 f"| New | Surface | {noun} | Version | Score | Top finding | Location "
                 "| Scanned (UTC) | Reason |",
                 "|---|---|---|---|---|---|---|---|---|"]
        for r in sec:
            reason = _cell(r.get("reason"))
            if r.get("recomputed"):
                reason += " *(recomputed)*"
            body.append("| " + " | ".join([
                _cell(new_status(r, prev)), _cell(r.get("surface")), _cell(r.get("name")),
                _cell(r.get("version")), _cell(r.get("score")), _cell(_rule(r.get("top"))),
                _location(r.get("top")), _scanned(r.get("scanned_at")), reason,
            ]) + " |")
        body.append("")
    gone = sorted(set(prev or {}) - {row_key(r) for r in rows})
    summary = ", ".join(f"{t.split(' (')[0].lower()} {counts[t]}" for t, _s, _h in SECTIONS)
    lines += [f"**{len(rows)} do-not-connect** ({summary}); **{new_total} new** since "
              "the baseline.", ""]
    lines += body
    if gone:
        lines += [f"## No longer Do not connect ({len(gone)})", ""]
        lines += [f"- `{k}`" for k in gone]
        lines.append("")
    keys = {row_key(r): r.get("version") for r in rows}
    lines.append(f"<!-- dnc-keys: {json.dumps(keys, sort_keys=True)} -->")
    return "\n".join(lines) + "\n"


def summary_line(rows: list[dict], prev: dict[str, str | None] | None, today: str) -> str:
    n_new = sum(1 for r in rows if new_status(r, prev) == "NEW")
    n_pkg = sum(1 for r in rows if r.get("surface") in PACKAGE_SURFACES)
    return (f"- {today}: {len(rows)} do-not-connect ({n_pkg} packages), {n_new} new. "
            f"[dnc-reports/{today}.md](dnc-reports/{today}.md)")


def update_status(text: str, line: str, today: str) -> str:
    """Prepend ``line`` under the weekly heading; replace a same-date line (re-run).

    Creates the heading after the file's opening title + blockquote when missing.
    Nothing else in the file changes."""
    lines = text.split("\n")
    if STATUS_HEADING in lines:
        i = lines.index(STATUS_HEADING) + 1
        if i < len(lines) and lines[i] == "":
            i += 1
        prefix = f"- {today}:"
        j = i
        while j < len(lines) and lines[j].startswith("- "):
            if lines[j].startswith(prefix):
                del lines[j]
                continue
            j += 1
        lines.insert(i, line)
        return "\n".join(lines)
    # Insert after the title and the blockquote that follows it.
    i = 0
    if lines and lines[0].startswith("# "):
        i = 1
        while i < len(lines) and (lines[i] == "" or lines[i].startswith(">")):
            if lines[i] == "" and i > 1 and lines[i - 1].startswith(">"):
                break
            i += 1
    block = [STATUS_HEADING, "", line, ""]
    if i < len(lines) and lines[i] == "":
        lines[i + 1:i + 1] = block
    else:
        lines[i:i] = ["", *block]
    return "\n".join(lines)


# ── I/O ────────────────────────────────────────────────────────────────────────────

def fetch_rows() -> list[dict]:
    proc = subprocess.run(
        ["ssh", "-i", str(SSH_KEY), "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
         SSH_HOST, REMOTE_CMD],
        input=remote_script(), capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit(f"remote query failed (exit {proc.returncode})")
    return dedupe_rows(parse_remote_output(proc.stdout))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--date", help="report date YYYY-MM-DD (default: today, local)")
    ap.add_argument("--dry-run", action="store_true", help="print, write nothing")
    ap.add_argument("--root", type=Path, default=REPO_ROOT,
                    help="checkout whose docs/internal receives the report")
    args = ap.parse_args()
    report_dir = args.root / "docs" / "internal" / "dnc-reports"
    status_path = args.root / "docs" / "internal" / "STATUS.md"
    today = args.date or dt.date.today().isoformat()
    rows = fetch_rows()
    prev_path = find_previous_report(report_dir, today)
    prev = parse_prev_keys(prev_path.read_text()) if prev_path else None
    generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
    report = render_report(rows, prev, today, generated,
                           prev_path.name if prev_path and prev is not None else None)
    line = summary_line(rows, prev, today)
    if args.dry_run:
        print(report)
        print(line)
        return 0
    report_dir.mkdir(parents=True, exist_ok=True)
    out = report_dir / f"{today}.md"
    out.write_text(report)
    status_path.write_text(update_status(status_path.read_text(), line, today))
    print(f"wrote {out}")
    print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
