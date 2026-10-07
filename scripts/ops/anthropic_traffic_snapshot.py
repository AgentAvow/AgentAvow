#!/usr/bin/env python3
"""Daily snapshot of Claude-origin traffic → a CSV that outlives the nginx log window.

The prod nginx container keeps ~4 days of JSON access logs (json-file, 5 × 10 MB) and the
Redis MCP counters expire after 45 days, so the per-day series — Claude Code machines
connecting, claude.ai connector requests, plugin-hook machines, tool calls and distinct
callers by surface — only survives if something writes it down. This does, once a day for
the previous UTC day (cron on the prod host, see docs/internal/metrics-log.md), and is
idempotent: re-running for a day replaces that day's row.

Runs on the PROD HOST with its system python (3.9): stdlib only. Reads the nginx log with
``docker logs`` and the Redis counters through the backend container's own client.

    python3 scripts/ops/anthropic_traffic_snapshot.py                 # yesterday (UTC)
    python3 scripts/ops/anthropic_traffic_snapshot.py --day 2026-10-05 --since-hours 120

Privacy: no IP is stored. "New machines" uses a rolling 30-day set of salted SHA-256
hashes (salt generated once on the host, never committed); entries older than 30 days
are purged on every run. Owner/self traffic can be excluded by listing IPs in
``data/owner-ips.txt`` (one per line, not committed) — reported as separate columns.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import secrets
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

HOME = os.path.expanduser("~")
REPO = os.path.join(HOME, "agentgraph")
DATA = os.path.join(REPO, "data")
CSV_PATH = os.path.join(DATA, "anthropic-traffic.csv")
SEEN_PATH = os.path.join(DATA, "anthropic-traffic-seen.json")
SALT_PATH = os.path.join(DATA, ".anthropic-traffic-salt")
OWNER_PATH = os.path.join(DATA, "owner-ips.txt")
NGINX_CONTAINER = "agentgraph-nginx-1"
BACKEND_CONTAINER = "agentgraph-backend-1"
SELF_IPS = {"98.94.217.37"}  # the prod host probing itself (catalog self-scan, evals)
SEEN_WINDOW_DAYS = 30
SURFACES = ("claude", "claude-code", "chatgpt", "other", "total")

COLUMNS = [
    "day", "cc_machines", "cc_new_machines_30d", "cc_reqs", "cc_sessions",
    "claudeai_reqs", "claudeai_ips", "hook_machines_nginx", "hook_reqs", "hook_top_version",
    "gate_machines", "preinstall_machines", "scans_200", "badges_200",
    "calls_claude", "callers_claude", "calls_claude_code", "callers_claude_code",
    "calls_chatgpt", "callers_chatgpt", "calls_other", "callers_other", "calls_total",
    "hook_machines_hll",
    "owner_cc_reqs", "owner_cc_sessions", "owner_hook_reqs", "owner_scans_200",
    "cc_machines_excl_owner", "hook_machines_excl_owner", "log_complete",
]

REDIS_PROGRAM = r"""
import asyncio, json, sys
from src.redis_client import get_redis
day = sys.argv[1]
async def main():
    r = get_redis()
    out = {}
    for s in ("claude", "claude-code", "chatgpt", "other", "total"):
        v = await r.get(f"ag:metrics:mcp:calls:total:{s}:{day}")
        out[f"calls_{s}"] = int(v) if v else 0
        try:
            out[f"callers_{s}"] = await r.pfcount(f"ag:metrics:uniq:mcp:callers:{s}:{day}")
        except Exception:
            out[f"callers_{s}"] = 0
    try:
        out["hook_machines_hll"] = await r.pfcount(f"ag:metrics:uniq:hook:machines:{day}")
    except Exception:
        out["hook_machines_hll"] = 0
    print(json.dumps(out))
asyncio.run(main())
"""


def _nginx_rows(since_hours: int) -> list[dict]:
    proc = subprocess.run(
        ["docker", "logs", NGINX_CONTAINER, "--since", f"{since_hours}h"],
        capture_output=True, timeout=600,
    )
    rows = []
    for raw in (proc.stdout + proc.stderr).splitlines():
        raw = raw.strip()
        if not raw.startswith(b"{"):
            continue
        try:
            rows.append(json.loads(raw))
        except Exception:
            continue
    return rows


def _redis_counts(day: str) -> dict:
    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", "-w", "/app", BACKEND_CONTAINER, "python", "-", day],
            input=REDIS_PROGRAM.encode(), capture_output=True, timeout=120,
        )
        line = proc.stdout.decode().strip().splitlines()[-1]
        return json.loads(line)
    except Exception as exc:  # noqa: BLE001 — the nginx half is still worth writing
        sys.stderr.write(f"redis counts unavailable: {exc}\n")
        return {}


def _salt() -> str:
    os.makedirs(DATA, exist_ok=True)
    if not os.path.exists(SALT_PATH):
        with open(SALT_PATH, "w") as fh:
            fh.write(secrets.token_hex(32))
        os.chmod(SALT_PATH, 0o600)
    with open(SALT_PATH) as fh:
        return fh.read().strip()


def _owner_ips() -> set[str]:
    try:
        with open(OWNER_PATH) as fh:
            return {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}
    except OSError:
        return set()


def _load_seen() -> dict:
    try:
        with open(SEEN_PATH) as fh:
            return json.load(fh)
    except Exception:
        return {}


def snapshot(day: str, since_hours: int) -> dict:
    rows = _nginx_rows(since_hours)
    owner = _owner_ips()
    salt = _salt()
    cc_ips: set[str] = set()
    hook_ips: set[str] = set()
    cai_ips: set[str] = set()
    gate_ips: set[str] = set()
    pre_ips: set[str] = set()
    hook_versions: dict[str, int] = defaultdict(int)
    n = defaultdict(int)
    hours_seen: set[int] = set()
    for r in rows:
        t = r.get("time") or ""
        if t[:10] != day:
            continue
        ip = r.get("remote_addr") or ""
        if ip in SELF_IPS:
            continue
        ua = r.get("http_user_agent") or ""
        req = r.get("request") or ""
        st = r.get("status", 0)
        try:
            hours_seen.add(int(t[11:13]))
        except ValueError:
            pass
        is_owner = ip in owner
        if "POST /mcp" in req and ua.startswith("claude-code/"):
            cc_ips.add(ip)
            n["cc_reqs"] += 1
            if st == 400:
                n["cc_sessions"] += 1
            if is_owner:
                n["owner_cc_reqs"] += 1
                if st == 400:
                    n["owner_cc_sessions"] += 1
        if "Claude-User" in ua:
            n["claudeai_reqs"] += 1
            cai_ips.add(ip)
        if ua.startswith("agentavow-precheck/"):
            hook_ips.add(ip)
            n["hook_reqs"] += 1
            hook_versions[ua.split()[0].split("/", 1)[1]] += 1
            if is_owner:
                n["owner_hook_reqs"] += 1
        if ua.startswith("agentavow-gate/"):
            gate_ips.add(ip)
        if ua.startswith(("agentavow-pre_install/", "agentavow-preinstall/")):
            pre_ips.add(ip)
        if "/api/v1/public/scan" in req and st == 200 and " /api/v1/public/scan/" in req:
            if "/badge" in req:
                n["badges_200"] += 1
            else:
                n["scans_200"] += 1
                if is_owner:
                    n["owner_scans_200"] += 1

    # new machines vs the rolling 30-day hashed set (no raw IPs stored)
    seen = _load_seen()
    cutoff = (datetime.strptime(day, "%Y-%m-%d") - timedelta(days=SEEN_WINDOW_DAYS)).strftime("%Y-%m-%d")
    seen = {h: d for h, d in seen.items() if d >= cutoff}
    new = 0
    for ip in cc_ips:
        h = hashlib.sha256(f"{salt}|{ip}".encode()).hexdigest()[:24]
        if h not in seen or seen[h] < cutoff:
            new += 1
        seen[h] = max(seen.get(h, ""), day)
    os.makedirs(DATA, exist_ok=True)
    with open(SEEN_PATH, "w") as fh:
        json.dump(seen, fh)

    row = {
        "day": day,
        "cc_machines": len(cc_ips), "cc_new_machines_30d": new,
        "cc_reqs": n["cc_reqs"], "cc_sessions": n["cc_sessions"],
        "claudeai_reqs": n["claudeai_reqs"], "claudeai_ips": len(cai_ips),
        "hook_machines_nginx": len(hook_ips), "hook_reqs": n["hook_reqs"],
        "hook_top_version": max(hook_versions, key=hook_versions.get) if hook_versions else "",
        "gate_machines": len(gate_ips), "preinstall_machines": len(pre_ips),
        "scans_200": n["scans_200"], "badges_200": n["badges_200"],
        "owner_cc_reqs": n["owner_cc_reqs"], "owner_cc_sessions": n["owner_cc_sessions"],
        "owner_hook_reqs": n["owner_hook_reqs"], "owner_scans_200": n["owner_scans_200"],
        "cc_machines_excl_owner": len(cc_ips - owner),
        "hook_machines_excl_owner": len(hook_ips - owner),
        "log_complete": int(bool(hours_seen) and min(hours_seen) == 0 and max(hours_seen) == 23),
    }
    # Redis names the surface "claude-code"; the CSV column is calls_claude_code.
    row.update({k.replace("-", "_"): v for k, v in _redis_counts(day).items()
                if k.replace("-", "_") in COLUMNS})
    for c in COLUMNS:
        row.setdefault(c, "")
    return row


def write_row(row: dict, path: str = CSV_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    existing: list[dict] = []
    if os.path.exists(path):
        with open(path, newline="") as fh:
            existing = [r for r in csv.DictReader(fh) if r.get("day") != row["day"]]
    existing.append(row)
    existing.sort(key=lambda r: r["day"])
    tmp = path + ".tmp"
    with open(tmp, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in existing:
            w.writerow({c: r.get(c, "") for c in COLUMNS})
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--day", help="UTC day YYYY-MM-DD (default: yesterday)")
    ap.add_argument("--since-hours", type=int, default=72,
                    help="how far back to read docker logs (default 72; raise to backfill)")
    ap.add_argument("--csv", default=CSV_PATH)
    a = ap.parse_args()
    day = a.day or (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    row = snapshot(day, a.since_hours)
    write_row(row, a.csv)
    print(json.dumps(row, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
