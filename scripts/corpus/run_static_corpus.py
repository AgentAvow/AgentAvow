"""Static known-good corpus gate (precision PR 2).

Scans every pinned package in ``tests/corpus/static/manifest.json`` through the SAME
code production runs for a package scan (``npm_result_from_tarball`` /
``pypi_result_from_archive`` with the wheel member list → ``installed``,
``apply_artifact_scan`` → ``scan_artifact_files``, then ``_calculate_trust_score``),
labels each with the real three-phrase ``src.scanner.verdict.decide()`` over the public
API dict, and fails when:

* a known-good package is labelled ``do_not_connect``;
* a ``review`` rests only on capability findings or files the consumer never installs;
* a package with a human-recorded ``expect`` lands on a different label;

Thin coverage (nothing found in fewer than 8 files) reads ``safe`` with the reason
"nothing found; little code to inspect" (decided 2026-10-08, follow-up #19); the
report lists those packages separately.

A package whose manifest entry carries a reviewed ``known_fp`` (an open false-positive
class left for a later decision, with its label) is reported under "Known false
positives" instead of failing — only while it keeps exactly that label.
* (``--fail-on-diff``) any score / label / count differs from the committed
  ``tests/corpus/static/expected.json`` — update the snapshot in the same PR
  (``--write-expected``) so the drift is reviewed.

Network-free parts are deterministic: OSV advisories and build provenance (time-varying,
networked) are NOT applied, so corpus scores can differ from live scores by those deltas.

Archives are untrusted data: cached by sha256, never executed or installed. Run with
``python -I`` so nothing in the cwd/cache can shadow a module:

    python -I scripts/corpus/run_static_corpus.py --cache DIR [--workers 4]
        [--only pypi/mcp,npm/chalk] [--subset] [--offline]
        [--report report.md] [--write-expected] [--fail-on-diff]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.corpus.corpus_lib import (  # noqa: E402
    EXPECTED_PATH,
    MANIFEST_PATH,
    SUBSET_PATH,
    default_cache_dir,
    ensure_cached,
    load_manifest,
    read_cached,
)

LABELS = ("safe", "review", "do_not_connect")
SEVERITIES = ("critical", "high", "medium", "low", "info")


# ---------------------------------------------------------------------------
# Decision: the REAL three-phrase rule, ``src.scanner.verdict.decide()``, fed the same
# dict the public API builds (``_scan_result_to_dict`` over a fully scored result), so a
# corpus label is exactly what a user would read for this archive (minus the networked
# OSV / provenance deltas noted above).
# ---------------------------------------------------------------------------

# decide()'s thin-coverage reason: nothing found in fewer than 8 files. Since
# 2026-10-08 (#19) it reads safe; the report lists these packages separately.
THIN_COVERAGE_REASON = "nothing found; little code to inspect"


@dataclass
class Decision:
    label: str                                   # safe | review | do_not_connect
    reasons: list[str] = field(default_factory=list)
    reason_findings: list = field(default_factory=list)   # Finding objects behind it
    reason: str = ""                             # decide()'s one-line decision_reason


def api_dict(result) -> dict:
    """The dict the public API hands ``decide()`` for this result."""
    from src.api.public_scan_router import _scan_result_to_dict

    return _scan_result_to_dict(result)


def real_decide(result) -> Decision:
    """Label via ``verdict.decide()``; the listed reasons/findings explain it for the
    report and for the gate's "review must rest on an installed defect" check."""
    from src.scanner.scan import _finding_is_blocking, _is_defect
    from src.scanner.verdict import decide

    d = decide(api_dict(result))
    blocking = [f for f in result.findings if _finding_is_blocking(f)]
    if d.decision == "do_not_connect":
        why = [f for f in blocking if f.severity == "critical"]
    elif d.decision == "review":
        why = [f for f in blocking if f.severity == "high"]
        if not why and result.deprecation:
            why = [f for f in result.findings if f.category == "maintenance"]
        if not why and d.reason.startswith("trust score"):
            why = [f for f in result.findings if _is_defect(f)
                   and getattr(f, "installed", True)
                   and f.severity in ("critical", "high", "medium")][:5]
    else:
        why = []
    return Decision(d.decision, [d.reason] + [_reason(f) for f in why], why, d.reason)


DECIDE = real_decide


def _reason(f) -> str:
    return f"{f.severity} {f.name} @ {f.file_path}:{f.line_number}"


# ---------------------------------------------------------------------------
# Scan one package (runs in a worker process)
# ---------------------------------------------------------------------------

def scan_entry(entry: dict, cache_dir: str, offline: bool) -> dict:
    from src.scanner.artifact_fetch import (
        MAX_DOWNLOAD_BYTES,
        ArtifactFetchError,
        npm_result_from_tarball,
        pypi_result_from_archive,
        wheel_installed_paths_from_bytes,
    )
    from src.scanner.scan import (
        ScanResult,
        _calculate_category_scores,
        _calculate_trust_score,
        _certified_status,
        apply_artifact_scan,
    )

    cache = Path(cache_dir)
    eco, name, version = entry["ecosystem"], entry["name"], entry["version"]
    arc = entry["archive"]

    def _get(url: str, sha: str) -> bytes | None:
        if offline:
            return read_cached(cache, sha)
        return ensure_cached(cache, url, sha, max_bytes=MAX_DOWNLOAD_BYTES)[0]

    out: dict = {"id": entry["id"], "version": version}
    try:
        raw = _get(arc["url"], arc["sha256"])
        if raw is None:
            out["label"] = "missing"
            return out
        if eco == "npm":
            fetched = npm_result_from_tarball(name, version, raw, tarball_url=arc["url"])
        else:
            installed = None
            w = entry.get("wheel")
            # Production downloads the wheel only for its member list; an oversize wheel
            # trips the download cap there → installed_paths None (everything installed).
            if arc["kind"] == "sdist" and w and int(w.get("size") or 0) <= MAX_DOWNLOAD_BYTES:
                wraw = _get(w["url"], w["sha256"])
                if wraw is None:
                    out["label"] = "missing"
                    return out
                try:
                    installed = wheel_installed_paths_from_bytes(wraw)
                except Exception:  # noqa: BLE001 — production fails open the same way
                    installed = None
            fetched = pypi_result_from_archive(name, version, arc["kind"], arc["url"], raw,
                                               installed_paths=installed)
        fetched.deprecation = entry.get("deprecation")
    except ArtifactFetchError as exc:
        out.update(label="unscannable", error=str(exc)[:200])
        return out

    result = ScanResult(repo=f"{eco}:{name}", stars=0, description="", framework="")
    apply_artifact_scan(result, eco, fetched)
    # Same scoring tail as production scan_package (minus networked OSV / provenance).
    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    decision = DECIDE(result)
    return summarize(entry, result, decision)


def summarize(entry: dict, result, decision: Decision) -> dict:
    from src.scanner.scan import _is_defect

    sev: Counter = Counter()
    rules: Counter = Counter()
    caps = 0
    not_installed = 0
    findings = []
    for f in result.findings:
        defect = _is_defect(f)
        installed = getattr(f, "installed", True)
        if not defect:
            caps += 1
        elif not installed:
            not_installed += 1
        else:
            sev[f.severity] += 1
            if f.severity != "info":
                rules[f"{f.severity}: {f.name}"] += 1
        if f.severity in ("critical", "high", "medium") or not defect:
            findings.append({
                "sev": f.severity, "name": f.name, "kind": "defect" if defect else "capability",
                "installed": installed, "path": f.file_path, "line": f.line_number,
                "snippet": (f.snippet or "")[:160], "why": (f.remediation or "")[:160],
            })
    reason_ok = all(_is_defect(f) and getattr(f, "installed", True)
                    for f in decision.reason_findings)
    return {
        "id": entry["id"],
        "version": entry["version"],
        "score": result.trust_score,
        "label": decision.label,
        "reason": decision.reason,
        "files_scanned": result.files_scanned,
        "severity": {s: sev.get(s, 0) for s in SEVERITIES},
        "capabilities": caps,
        "not_installed": not_installed,
        "rules": dict(sorted(rules.items())),
        "_reasons": decision.reasons,
        "_reason_ok": (bool(decision.reason_findings) and reason_ok)
                      if decision.label == "review" else True,
        "_findings": findings,
    }


# ---------------------------------------------------------------------------
# Gate, diff, report
# ---------------------------------------------------------------------------

def gate(manifest: dict, results: dict[str, dict]) -> list[str]:
    failures: list[str] = []
    for e in manifest["packages"]:
        r = results.get(e["id"])
        if r is None or r["label"] not in LABELS:
            continue
        if (e.get("known_fp") or {}).get("label") == r["label"]:
            continue  # reviewed, open false-positive class (reported separately)
        if r["label"] == "do_not_connect":
            failures.append(f"{e['id']}: known-good package labelled do_not_connect "
                            f"({'; '.join(r['_reasons'][:3])})")
        if r["label"] == "review" and not r["_reason_ok"]:
            failures.append(f"{e['id']}: review rests only on capability / not-installed "
                            f"findings ({'; '.join(r['_reasons'][:3])})")
        exp = e.get("expect")
        if exp and exp != r["label"]:
            failures.append(f"{e['id']}: expected {exp}, got {r['label']} "
                            f"({'; '.join(r['_reasons'][:2])})")
    return failures


def _is_thin(r: dict) -> bool:
    """Safe on thin coverage: nothing found, little code to inspect."""
    return r.get("label") == "safe" and r.get("reason") == THIN_COVERAGE_REASON


def public(r: dict) -> dict:
    return {k: v for k, v in r.items() if not k.startswith("_") and k != "id"}


def diff(expected: dict, results: dict[str, dict]) -> list[str]:
    lines: list[str] = []
    old = expected.get("packages") or {}
    for pid in sorted(set(old) | set(results)):
        a, b = old.get(pid), (public(results[pid]) if pid in results else None)
        if a == b:
            continue
        if a is None:
            lines.append(f"+ {pid}: {b.get('label')} {b.get('score')}")
        elif b is None:
            lines.append(f"- {pid}: (not run)")
        else:
            changes = []
            for k in ("version", "label", "reason", "score", "files_scanned", "capabilities",
                      "not_installed"):
                if a.get(k) != b.get(k):
                    changes.append(f"{k} {a.get(k)} → {b.get(k)}")
            if a.get("severity") != b.get("severity"):
                changes.append(f"severity {_sev_short(a.get('severity'))} → "
                               f"{_sev_short(b.get('severity'))}")
            ra, rb = Counter(a.get("rules") or {}), Counter(b.get("rules") or {})
            for rule in sorted(set(ra) | set(rb)):
                if ra[rule] != rb[rule]:
                    changes.append(f"[{rule}] {ra[rule]} → {rb[rule]}")
            lines.append(f"~ {pid}: " + "; ".join(changes))
    return lines


def _sev_short(s: dict | None) -> str:
    s = s or {}
    return "/".join(str(s.get(k, 0)) for k in ("critical", "high", "medium", "low"))


def medium_histogram(results: dict[str, dict]) -> dict[str, list[tuple[str, int]]]:
    """Known-good packages with NO critical/high defect on the installed surface,
    bucketed by how many medium defects they carry (the input for the graduated
    score-curve decision, tracked follow-up #4)."""
    buckets: dict[str, list[tuple[str, int]]] = {"0": [], "1": [], "2": [], "3+": []}
    for pid, r in results.items():
        if r.get("label") not in LABELS:
            continue
        s = r["severity"]
        if s["critical"] or s["high"]:
            continue
        m = s["medium"]
        buckets["3+" if m >= 3 else str(m)].append((pid, r["score"]))
    return buckets


def report(manifest: dict, results: dict[str, dict], failures: list[str],
           diff_lines: list[str]) -> str:
    rs = [results[e["id"]] for e in manifest["packages"] if e["id"] in results]
    by_label = Counter(r["label"] for r in rs)
    out = ["# Static corpus report", ""]
    out.append(f"Packages: {len(rs)} · " + " · ".join(
        f"{k}: {by_label.get(k, 0)}" for k in (*LABELS, "unscannable", "missing")))
    out.append("")
    out.append("## Gate failures" if failures else "## Gate: pass")
    out += [f"- {f}" for f in failures]
    thin = sorted((r for r in rs if _is_thin(r)), key=lambda r: r["id"])
    if thin:
        out += ["", f"## Safe on thin coverage ({len(thin)}; nothing found, fewer than 8 "
                "files)", "", "| Package | Files scanned | Score |", "|---|---|---|"]
        out += [f"| {r['id']} | {r['files_scanned']} | {r['score']} |" for r in thin]
    known = [(e, results[e["id"]]) for e in manifest["packages"]
             if e.get("known_fp") and e["id"] in results]
    if known:
        out += ["", "## Known false positives (reviewed, open)", "",
                "| Package | Score | Label | Class | Detail |", "|---|---|---|---|---|"]
        for e, r in known:
            k = e["known_fp"]
            held = "" if k["label"] == r["label"] else f" (manifest says {k['label']})"
            out.append(f"| {e['id']} | {r.get('score')} | {r['label']}{held} | {k['class']} "
                       f"| {k['detail'].replace('|', '/')} |")
    out += ["", "## Do not connect and Review", "",
            "| Package | Score | Label | Reason |", "|---|---|---|---|"]
    for r in sorted(rs, key=lambda r: (LABELS.index(r["label"]) * -1
                                       if r["label"] in LABELS else 9, r.get("score", 0))):
        if r["label"] in ("review", "do_not_connect"):
            out.append(f"| {r['id']} | {r['score']} | {r['label']} | "
                       f"{'<br>'.join(x.replace('|', '/') for x in r['_reasons'][:4])} |")
    out += ["", "## Lowest scores", "", "| Package | Score | Label | crit/high/med/low |",
            "|---|---|---|---|"]
    for r in sorted((r for r in rs if r["label"] in LABELS), key=lambda r: r["score"])[:25]:
        out.append(f"| {r['id']} | {r['score']} | {r['label']} | {_sev_short(r['severity'])} |")
    out += ["", "## Medium-only histogram (no critical/high on the installed surface)", "",
            "| Mediums | Packages | Score min / median / max |", "|---|---|---|"]
    for k, v in medium_histogram(results).items():
        sc = [s for _p, s in v]
        stat = f"{min(sc)} / {median(sc):g} / {max(sc)}" if sc else "-"
        out.append(f"| {k} | {len(v)} | {stat} |")
    rule_tot: Counter = Counter()
    for r in rs:
        for k, v in (r.get("rules") or {}).items():
            if not k.startswith(("low", "info")):
                rule_tot[k] += v
    out += ["", "## Top scored rules (installed defects, medium+)", "",
            "| Rule | Findings |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in rule_tot.most_common(25)]
    others = [r for r in rs if r["label"] not in LABELS]
    if others:
        out += ["", "## Not scanned", ""]
        out += [f"- {r['id']}: {r['label']} {r.get('error', '')}" for r in others]
    out += ["", "## Diff vs expected.json", "", "```"] + (diff_lines or ["(no changes)"]) + ["```"]
    out += ["", "## Review / do-not-connect detail", ""]
    for r in rs:
        if r["label"] in ("review", "do_not_connect"):
            out.append(f"### {r['id']} {r['version']} — {r['score']} {r['label']}")
            for f in r["_findings"]:
                if f["kind"] == "defect" and f["installed"] and f["sev"] in ("critical", "high"):
                    out.append(f"- {f['sev']} {f['name']} `{f['path']}:{f['line']}` "
                               f"`{f['snippet'][:120]}` — {f['why'][:120]}")
            out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Static known-good corpus gate")
    ap.add_argument("--cache", type=Path, default=default_cache_dir())
    ap.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    ap.add_argument("--expected", type=Path, default=EXPECTED_PATH)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--only", default="", help="comma-separated package ids")
    ap.add_argument("--subset", action="store_true",
                    help="only the ids in tests/corpus/static/subset.json")
    ap.add_argument("--offline", action="store_true",
                    help="never download; a package absent from the cache is 'missing'")
    ap.add_argument("--report", type=Path, help="write a markdown report here")
    ap.add_argument("--json-out", type=Path, help="write full per-package results here")
    ap.add_argument("--write-expected", action="store_true")
    ap.add_argument("--fail-on-diff", action="store_true")
    args = ap.parse_args()

    manifest = load_manifest(args.manifest)
    entries = manifest["packages"]
    if args.only:
        want = set(args.only.split(","))
        entries = [e for e in entries if e["id"] in want]
    if args.subset:
        want = set(json.loads(SUBSET_PATH.read_text())["ids"])
        entries = [e for e in entries if e["id"] in want]
    manifest = {**manifest, "packages": entries}
    args.cache.mkdir(parents=True, exist_ok=True)

    results: dict[str, dict] = {}
    with ProcessPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {e["id"]: ex.submit(scan_entry, e, str(args.cache), args.offline)
                for e in entries}
        for pid, fut in futs.items():
            try:
                results[pid] = fut.result()
            except Exception as exc:  # noqa: BLE001 — report per package
                results[pid] = {"id": pid, "label": "error", "error": repr(exc)[:200]}

    expected = json.loads(args.expected.read_text()) if args.expected.exists() else {}
    scope = {pid: r for pid, r in results.items()}
    exp_scope = {**expected, "packages": {k: v for k, v in (expected.get("packages") or {}).items()
                                          if k in scope}}
    diff_lines = diff(exp_scope, scope)
    failures = gate(manifest, results)
    errors = [r for r in results.values() if r["label"] in ("error", "missing")]

    by_label = Counter(r["label"] for r in results.values())
    print(f"static corpus: {len(results)} packages · "
          + " · ".join(f"{k} {v}" for k, v in sorted(by_label.items())))
    print(f"diff vs {args.expected.name}: {len(diff_lines)} changed")
    for line in diff_lines[:200]:
        print("  " + line)
    for e in manifest["packages"]:
        k = e.get("known_fp")
        if k and results.get(e["id"], {}).get("label") == k["label"]:
            print(f"KNOWN {e['id']}: {k['label']} — {k['class']}")
    for f in failures:
        print("FAIL " + f)
    for r in errors:
        print(f"ERROR {r['id']}: {r['label']} {r.get('error', '')}")

    if args.report:
        args.report.write_text(report(manifest, results, failures, diff_lines))
        print(f"report: {args.report}")
    if args.json_out:
        args.json_out.write_text(json.dumps(results, indent=1, sort_keys=True))
    if args.write_expected:
        merged = dict(expected.get("packages") or {})
        merged.update({pid: public(r) for pid, r in results.items()
                       if r["label"] not in ("error", "missing")})
        args.expected.write_text(json.dumps({
            "_doc": "Committed snapshot of the static corpus gate (score, label and "
                    "reason from verdict.decide(), defect counts per severity on the installed surface, rule "
                    "counts). Regenerate with run_static_corpus.py --write-expected and "
                    "review the diff in the same PR.",
            "packages": dict(sorted(merged.items())),
        }, indent=1, sort_keys=False) + "\n")
        print(f"wrote {args.expected}")

    if failures or errors:
        return 1
    if args.fail_on_diff and diff_lines:
        print("FAIL: results differ from expected.json (re-run with --write-expected and "
              "commit the snapshot if the change is intended)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
