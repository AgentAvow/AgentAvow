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
TARGETS_PATH = _common.DATA_DIR / "x402-targets.json"
RESULTS_PATH = _common.DATA_DIR / "x402-results.json"
PROGRESS_PATH = _common.DATA_DIR / "x402-progress.json"


def discover() -> list[dict]:
    """Fetch the Bazaar listings via CDP discovery API. Paginated, no auth."""
    import httpx

    targets: list[dict] = []
    offset = 0
    page_size = 1000  # max per CDP docs
    seen: set[str] = set()
    policy = _common.RateLimitPolicy("x402")

    with httpx.Client(timeout=30.0) as client:
        while True:
            r = client.get(
                BAZAAR_LISTINGS_URL,
                params={"type": "http", "limit": page_size, "offset": offset},
            )
            r.raise_for_status()
            data = r.json()
            items = data.get("items") or []
            for item in items:
                endpoint = item.get("resource") or item.get("endpoint") or item.get("url")
                if not endpoint or endpoint in seen:
                    continue
                seen.add(endpoint)
                meta = item.get("metadata") or {}
                accepts = item.get("accepts") or []
                # Operator: closest signal is the payTo wallet on the first accept option
                pay_to = None
                if accepts and isinstance(accepts[0], dict):
                    pay_to = accepts[0].get("payTo") or accepts[0].get("pay_to")
                targets.append({
                    # The whole record: the scorer reads extensions.bazaar (schemas,
                    # output example) and accepts[]. The fields below stay for the
                    # older readers.
                    "raw": item,
                    "name": meta.get("description", endpoint).split(".")[0][:80] or endpoint,
                    "endpoint_url": endpoint,
                    "description": meta.get("description", ""),
                    "input_schema": meta.get("input"),
                    "output_schema": meta.get("output"),
                    "accepts": accepts,
                    "pay_to": pay_to,
                    "last_updated": item.get("lastUpdated"),
                    "x402_version": item.get("x402Version"),
                })
            pagination = data.get("pagination") or {}
            total = pagination.get("total")
            offset += len(items)
            if not items or (total is not None and offset >= total):
                break
            policy.wait()
    return targets


def score_one(target: dict) -> dict:
    """One catalog row from the listing alone (src/scanner/x402_scan.py). Pure."""
    from src.scanner.verdict import decide
    from src.scanner.x402_scan import scan_result_from_listing

    rec = target.get("raw") if isinstance(target.get("raw"), dict) else target
    r = scan_result_from_listing(rec)
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
        "scanned_from": "listing",
    }


def score_all(targets: list[dict]) -> dict:
    """Score every target; return the results file payload with a summary."""
    import collections

    results = []
    for t in targets:
        try:
            results.append(score_one(t))
        except Exception as exc:  # noqa: BLE001 — one bad record never stops the run
            results.append({"endpoint_url": t.get("endpoint_url"),
                            "error": f"{type(exc).__name__}"})
    decisions = collections.Counter(r.get("decision") or "error" for r in results)
    rules = collections.Counter(
        f["name"] if "(in the output example)" not in f["name"] else
        "(output example) " + f["name"].split(" (in the output example)")[0]
        for r in results for f in r.get("top_findings") or []
        if f["severity"] in ("critical", "high", "medium"))
    summary = {
        "listing_records": len(targets), "scored": sum(1 for r in results
                                                       if "trust_score" in r),
        "errors": decisions.get("error", 0), "decisions": dict(decisions),
        "testnet_only": sum(1 for r in results if r.get("testnet_only")),
        "top_rules_medium_plus": rules.most_common(25),
    }
    return {"results": results, "summary": summary}


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
    args = parser.parse_args()

    if args.score and args.offline:
        targets = (_common.read_json(TARGETS_PATH, default={}) or {}).get("targets") or []
    else:
        print("[x402] fetching Bazaar listings…")
        targets = discover()
        _common.write_json_atomic(TARGETS_PATH, {"targets": targets, "count": len(targets)})

    if args.score:
        payload = score_all(targets)
        out = Path(args.out) if args.out else RESULTS_PATH
        _common.write_json_atomic(out, payload)
        import json
        print(json.dumps(payload["summary"], indent=1))
        print(f"[x402] scored {payload['summary']['scored']} listings -> {out}")
        return 0

    if not args.run:
        _common.dry_run_banner("x402", len(targets), TARGETS_PATH)
        return 0

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
