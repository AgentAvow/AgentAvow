"""Discover + scan x402 Bazaar listed endpoints.

x402 is Coinbase's agent-to-agent USDC micropayment protocol on Base.
The Bazaar is the public directory of endpoints that accept x402 payments.

Dry-run (default): fetches the listings and writes target list.
Score mode (--score): scores every listing OFFLINE with src/scanner/x402_scan.py
  (tool-definition checks on the description and schemas, plus payment-term checks;
  nothing is sent to any endpoint) and writes x402-results.json for the catalog.
  Design: docs/internal/x402-scan-design-2026-11-11.md.
Run mode (--run): the old HTTP surface probe. Superseded by phase 2 of the design
  (not built yet); do not use.

Usage:
    python3 scripts/launch_scans/scan_x402.py                       # dry run
    python3 scripts/launch_scans/scan_x402.py --score               # fetch + score
    python3 scripts/launch_scans/scan_x402.py --score --offline     # score the saved
                                                                    # listing only

Memory (run 1 was OOM-killed at 1 GB, 11-11): the listing is streamed to
    data/launch-scans/x402-targets.jsonl one record per line and never held whole; the
    live plan keeps only small stubs; scoring reads the file line by line and writes
    each row as it goes. "[x402 mem] <phase>: peak RSS N MB" lines log the high-water
    mark, and --max-rss-mb stops the run with a message before a container limit
    kills it silently.

Rate-limit posture:
    The Bazaar API has no published limit. We pace 1 req/s and long-pause
    every 25 calls. If Coinbase posts a limit before launch day, update
    _common.py RateLimitPolicy.POLICIES['x402'].
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add package dir so _common is importable regardless of cwd
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))  # src.*

import _common  # noqa: E402

BAZAAR_LISTINGS_URL = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources"
# One raw Bazaar record per line (streamed; never held in memory as a whole). The old
# x402-targets.json (one big JSON document, 320 MB by 11-11) is read only as a fallback
# by --offline and is no longer written.
TARGETS_JSONL = _common.DATA_DIR / "x402-targets.jsonl"
TARGETS_PATH = _common.DATA_DIR / "x402-targets.json"
RESULTS_PATH = _common.DATA_DIR / "x402-results.json"
PROGRESS_PATH = _common.DATA_DIR / "x402-progress.json"


def peak_rss_mb() -> float:
    """This process's peak resident memory so far, in MB (Linux reports KB, macOS bytes)."""
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024, 1)


_MAX_RSS_MB: float | None = None


def rss_checkpoint(phase: str) -> float:
    """Log the peak RSS after ``phase``; stop the run past --max-rss-mb (before the
    container's hard limit kills it with no message)."""
    peak = peak_rss_mb()
    print(f"[x402 mem] {phase}: peak RSS {peak} MB", flush=True)
    if _MAX_RSS_MB is not None and peak > _MAX_RSS_MB:
        raise SystemExit(f"[x402 mem] peak RSS {peak} MB is over --max-rss-mb "
                         f"{_MAX_RSS_MB} after {phase}; stopping")
    return peak


def live_stub(rec: dict) -> dict | None:
    """The few fields the live plan needs (resource, declared method, networks) for an
    eligible listing; None when it is not eligible. Keeps the plan out of the raw
    records, so the live phase holds a few KB per endpoint instead of the listing."""
    from src.scanner import x402_live as xl
    if not xl.eligible(rec):
        return None
    return {"resource": str(rec.get("resource") or rec.get("endpoint_url") or ""),
            "extensions": {"bazaar": {"info": {"input": {
                "method": xl.declared_method(rec)}}}},
            "accepts": [{"network": a.get("network")} for a in rec.get("accepts") or []
                        if isinstance(a, dict)]}


def discover(out_path: Path = TARGETS_JSONL, page_size: int = 1000,
             get=None) -> tuple[int, list[dict]]:
    """Fetch the Bazaar listings via the CDP discovery API (paginated, no auth) and
    stream them to ``out_path``, one raw record per line. Returns (records written,
    live stubs of the eligible ones). Only the URLs seen and the stubs stay in memory;
    each page is dropped before the next is fetched."""
    import json

    import httpx

    seen: set[str] = set()
    stubs: list[dict] = []
    offset = written = 0
    policy = _common.RateLimitPolicy("x402")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")

    with httpx.Client(timeout=30.0) as client, tmp.open("w") as fh:
        fetch = get or (lambda params: client.get(BAZAAR_LISTINGS_URL, params=params))
        while True:
            r = fetch({"type": "http", "limit": page_size, "offset": offset})
            r.raise_for_status()
            data = r.json()
            del r
            items = data.get("items") or []
            total = (data.get("pagination") or {}).get("total")
            del data
            for item in items:
                if not isinstance(item, dict):
                    continue
                endpoint = item.get("resource") or item.get("endpoint") or item.get("url")
                if not endpoint or endpoint in seen:
                    continue
                seen.add(endpoint)
                fh.write(json.dumps(item, separators=(",", ":"), default=str) + "\n")
                written += 1
                stub = live_stub(item)
                if stub:
                    stubs.append(stub)
            n = len(items)
            del items
            offset += n
            if n == 0 or (total is not None and offset >= total):
                break
            if (offset // page_size) % 5 == 0:
                rss_checkpoint(f"fetched {offset} listings")
            policy.wait()
    tmp.replace(out_path)
    return written, stubs


def iter_targets(path: Path = TARGETS_JSONL):
    """The saved listing, one raw record at a time. Falls back to the old single-JSON
    file (memory-heavy: it is parsed whole) when no JSONL exists yet."""
    import json
    if path.exists():
        with path.open() as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
        return
    legacy = (_common.read_json(TARGETS_PATH, default={}) or {}).get("targets") or []
    for t in legacy:
        yield _rec(t)


def _rec(target: dict) -> dict:
    return target.get("raw") if isinstance(target.get("raw"), dict) else target


def score_one(target: dict, live: dict | None = None) -> dict:
    """One catalog row from the listing (src/scanner/x402_scan.py), plus the phase-2
    live reply when one ran. Pure."""
    from src.scanner.verdict import decide
    from src.scanner.x402_scan import scan_result_from_listing

    rec = _rec(target)
    r = scan_result_from_listing(rec, live)
    sev: dict[str, int] = {}
    for f in r.findings:
        if getattr(f, "kind", "defect") != "capability":
            sev[f.severity] = sev.get(f.severity, 0) + 1
    items = [{"category": f.category, "name": f.name, "severity": f.severity,
              "file_path": f.file_path, "line_number": 0,
              "kind": getattr(f, "kind", "defect"), "installed": True, "shipped": True}
             for f in r.findings]
    d = decide({"trust_score": r.trust_score, "findings": {"items": items},
                "metadata": {"files_scanned": r.files_scanned}, "coverage": r.coverage,
                "coverage_gaps": r.coverage_gaps})
    art = r.artifact_scan or {}
    top = sorted(items, key=lambda i: ["critical", "high", "medium", "low", "info"]
                 .index(i["severity"]) if i["severity"] in
                 ("critical", "high", "medium", "low", "info") else 9)[:5]
    return {
        "endpoint_url": art.get("resource") or target.get("endpoint_url"),
        "name": art.get("service_name") or target.get("name"),
        "trust_score": r.trust_score,
        "decision": d.decision,
        "decision_reason": d.reason,
        "critical": sev.get("critical", 0), "high": sev.get("high", 0),
        "medium": sev.get("medium", 0), "low": sev.get("low", 0),
        "top_findings": [{"severity": i["severity"], "name": i["name"]} for i in top],
        "networks": art.get("networks"), "pay_to": art.get("pay_to"),
        "price_usd": art.get("price_usd"), "testnet_only": art.get("testnet_only"),
        "last_updated": art.get("last_updated"),
        "scanned_from": "listing+live" if art.get("live_check") else "listing",
        **({"live_check": art["live_check"]} if art.get("live_check") else {}),
    }


def score_all(targets, live: dict[str, dict] | None = None,
              out_path: Path | None = None) -> dict:
    """Score every target (any iterable of raw records or old-style targets); return the
    summary. With ``out_path`` each row is written as it is scored and only counters
    stay in memory; the file is {"results": [...], "summary": {...}}, written via a
    .tmp file and renamed. Without it, the rows come back in "results" (tests)."""
    import collections
    import json

    live = live or {}
    decisions: collections.Counter = collections.Counter()
    rules: collections.Counter = collections.Counter()
    n = scored = testnet = matches = 0
    keep: list[dict] = []
    fh = None
    tmp = None
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = out_path.with_suffix(out_path.suffix + ".tmp")
        fh = tmp.open("w")
        fh.write('{"results": [\n')
    try:
        for t in targets:
            try:
                url = str(_rec(t).get("resource") or _rec(t).get("endpoint_url") or "")
                row = score_one(t, live.get(url))
            except Exception as exc:  # noqa: BLE001 — one bad record never stops the run
                row = {"endpoint_url": t.get("endpoint_url") or t.get("resource"),
                       "error": f"{type(exc).__name__}"}
            decisions[row.get("decision") or "error"] += 1
            for f in row.get("top_findings") or []:
                if f["severity"] in ("critical", "high", "medium"):
                    rules[f["name"] if "(in the output example)" not in f["name"] else
                          "(output example) " + f["name"].split(
                              " (in the output example)")[0]] += 1
            scored += "trust_score" in row
            testnet += bool(row.get("testnet_only"))
            matches += bool((row.get("live_check") or {}).get("matches"))
            if fh is not None:
                fh.write(("" if n == 0 else ",\n") + json.dumps(row, default=str))
            else:
                keep.append(row)
            n += 1
            if n % 5000 == 0:
                rss_checkpoint(f"scored {n} listings")
        summary = {
            "listing_records": n, "scored": scored,
            "errors": decisions.get("error", 0), "decisions": dict(decisions),
            "testnet_only": testnet,
            "top_rules_medium_plus": rules.most_common(25),
        }
        if live:
            states = collections.Counter(v.get("state") for v in live.values())
            summary["live"] = {"checked": len(live), "states": dict(states),
                               "matches": matches}
        if fh is not None:
            fh.write('\n],\n"summary": ' + json.dumps(summary, indent=1) + "}\n")
            fh.close()
            fh = None
            tmp.replace(out_path)
            return {"summary": summary}
        return {"results": keep, "summary": summary}
    finally:
        if fh is not None:
            fh.close()


def run_live(stubs: list[dict], run_index: int | None) -> dict[str, dict]:
    """Phase 2: the approved live check over eligible listings. Writes a run log next to
    the results (per host: requests sent, why it was skipped)."""
    import asyncio
    import datetime

    from src.scanner import x402_live as xl
    from src.ssrf import ssrf_safe_async_client

    if run_index is None:
        run_index = datetime.date.today().isocalendar()[1]
    the_plan = xl.plan(stubs, run_index)
    n = sum(len(v) for v in the_plan.values())
    print(f"[x402 live] {n} endpoints on {len(the_plan)} hosts (run index {run_index}); "
          f"UA {xl.USER_AGENT!r}")

    async def go():
        async with ssrf_safe_async_client(follow_redirects=False) as client:
            return await xl.run_live_checks(the_plan, xl.make_fetch(client))
    report = asyncio.run(go())
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    for v in report.results.values():
        v["checked_at"] = now
    log = {"checked_at": now, "run_index": run_index, "user_agent": xl.USER_AGENT,
           "hosts": {h: vars(lg) for h, lg in report.hosts.items()}}
    _common.write_json_atomic(RESULTS_PATH.parent / "x402-live-run.json", log)
    print(f"[x402 live] {sum(lg.sent for lg in report.hosts.values())} requests sent")
    return report.results


def scan_one(target: dict) -> dict:
    """Scan a single x402 endpoint via our public scan API.

    Currently a thin wrapper — full scanner integration will land in
    src/scanner/scan_x402.py before we flip this to --run.
    """
    import httpx

    url = target["endpoint_url"]
    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            head = client.head(url)
            probe = client.get(url, headers={"Accept": "application/json"})
        return {
            "endpoint_url": url,
            "http_status": probe.status_code,
            "head_status": head.status_code,
            "has_x402_header": "x-402-payment" in {
                k.lower() for k in probe.headers
            } or "www-authenticate" in {k.lower() for k in probe.headers},
            "content_length": int(probe.headers.get("content-length", 0) or 0),
            "content_type": probe.headers.get("content-type", ""),
        }
    except Exception as exc:  # noqa: BLE001
        return {"endpoint_url": url, "error": str(exc)}


def main() -> int:
    _common.require_py39()
    _common.ensure_data_dir()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="old HTTP probe (superseded; do not use)")
    parser.add_argument("--score", action="store_true",
                        help="score every listing offline and write x402-results.json")
    parser.add_argument("--offline", action="store_true",
                        help="with --score: use the saved listing, fetch nothing")
    parser.add_argument("--out", default=None,
                        help="with --score: write results here instead of the catalog file")
    parser.add_argument("--live", action="store_true",
                        help="with --score: phase 2, one unpaid GET per eligible endpoint "
                             "(src/scanner/x402_live.py limits). Run only as approved: "
                             "weekly, one-off container, nice 19")
    parser.add_argument("--run-index", type=int, default=None,
                        help="with --live: rotation index for hosts over 50 endpoints "
                             "(default: ISO week number)")
    parser.add_argument("--max-rss-mb", type=float, default=None,
                        help="stop with a message once peak RSS passes this (MB), instead "
                             "of being OOM-killed silently; checked between pages/batches")
    args = parser.parse_args()
    if args.live and not args.score:
        parser.error("--live needs --score")
    global _MAX_RSS_MB
    _MAX_RSS_MB = args.max_rss_mb
    rss_checkpoint("start")

    if args.score and args.offline:
        stubs = [st for st in (live_stub(r) for r in iter_targets()) if st] \
            if args.live else []
        count = None
    else:
        print("[x402] fetching Bazaar listings…", flush=True)
        count, stubs = discover()
        print(f"[x402] {count} listings -> {TARGETS_JSONL} "
              f"({len(stubs)} eligible for the live check)", flush=True)
    rss_checkpoint("listing saved")

    if args.score:
        live = None
        if args.live:
            live = run_live(stubs, args.run_index)
            rss_checkpoint("live check done")
        del stubs
        out = Path(args.out) if args.out else RESULTS_PATH
        payload = score_all(iter_targets(), live, out_path=out)
        rss_checkpoint("scored and written")
        import json
        print(json.dumps(payload["summary"], indent=1))
        print(f"[x402] scored {payload['summary']['scored']} listings -> {out}")
        return 0

    if not args.run:
        _common.dry_run_banner("x402", count or 0, TARGETS_JSONL)
        return 0
    targets = [{"endpoint_url": r.get("resource")} for r in iter_targets()]

    _common.run_banner("x402", len(targets))
    policy = _common.RateLimitPolicy("x402")
    results: list[dict] = []
    progress = _common.read_json(PROGRESS_PATH, default={"done": []})
    done = set(progress.get("done", []))

    for i, target in enumerate(targets):
        key = target["endpoint_url"]
        if key in done:
            continue
        print(f"[x402] {i+1}/{len(targets)}: {key}")
        results.append(scan_one(target))
        done.add(key)
        _common.write_json_atomic(PROGRESS_PATH, {"done": sorted(done)})
        _common.write_json_atomic(RESULTS_PATH, {"results": results})
        policy.wait()

    print(f"[x402] complete. {len(results)} scanned -> {RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
