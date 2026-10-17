"""Install-check corpus (nightly label gate).

A second pinned 400-package corpus, ``tests/corpus/install_check/manifest.json``: the
top 200 npm + top 200 PyPI packages by AgentAvow adoption (what people actually ask
the install check about), pinned 2026-10-16 with the ``build_manifest`` resolvers. It
overlaps the download-ranked static corpus (``tests/corpus/static``) on 129 packages.

How it differs from ``run_static_corpus.py`` (which this reuses for scanning):

* the static corpus runs on scanner PRs (path-filtered) and fails on ANY drift in score,
  reason or counts; this one runs nightly over all of main, whatever path changed, and
  fails only when a package's three-phrase LABEL moves (or a package cannot be
  scanned). Score-only drift is printed but does not fail;
* downloads are sequential and spaced (``--delay``) before scanning, instead of every
  worker fetching in parallel; scanning then runs offline from the cache.

Each package is scored by ``run_static_corpus.scan_entry`` — the same production path
(``npm_result_from_tarball`` / ``pypi_result_from_archive`` -> ``apply_artifact_scan``
-> trust score -> ``verdict.decide()``), minus networked OSV / provenance. Archives are
untrusted data: verified against the pinned sha256, never executed or installed. Run
with ``python -I``:

    python -I scripts/corpus/run_install_check_corpus.py [--cache DIR] [--workers 4]
        [--delay 0.25] [--only npm/react,pypi/flask] [--report report.md]
        [--json-out results.json] [--write-expected]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.corpus import run_static_corpus as rsc  # noqa: E402
from scripts.corpus.corpus_lib import (  # noqa: E402
    REPO_ROOT,
    USER_AGENT,
    ensure_cached,
    load_manifest,
    read_cached,
)

CORPUS_DIR = REPO_ROOT / "tests" / "corpus" / "install_check"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
EXPECTED_PATH = CORPUS_DIR / "expected.json"


def default_cache_dir() -> Path:
    env = os.environ.get("AGENTAVOW_INSTALL_CHECK_CACHE")
    if env:
        return Path(env)
    return Path.home() / ".cache" / "agentavow-install-check-corpus"


def prefetch(entries: list[dict], cache: Path, delay: float) -> dict[str, str]:
    """Download every archive not yet cached, one at a time, ``delay`` seconds apart
    (registry-polite). Returns ``{id: error}`` for packages that could not be fetched."""
    import httpx

    from src.scanner.artifact_fetch import MAX_DOWNLOAD_BYTES

    errors: dict[str, str] = {}
    urls: list[tuple[str, str, str]] = []
    for e in entries:
        arc = e["archive"]
        urls.append((e["id"], arc["url"], arc["sha256"]))
        w = e.get("wheel")
        if arc["kind"] == "sdist" and w and int(w.get("size") or 0) <= MAX_DOWNLOAD_BYTES:
            urls.append((e["id"], w["url"], w["sha256"]))
    fetched = 0
    with httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=60) as client:
        for pid, url, sha in urls:
            if not sha:
                errors[pid] = f"no sha256 pin for {url}"
                continue
            if read_cached(cache, sha) is not None:
                continue
            try:
                ensure_cached(cache, url, sha, max_bytes=MAX_DOWNLOAD_BYTES, client=client)
                fetched += 1
            except Exception as exc:  # noqa: BLE001 — reported per package
                errors[pid] = f"{type(exc).__name__}: {str(exc)[:160]}"
            time.sleep(delay)
    print(f"prefetch: {fetched} downloaded, {len(urls) - fetched - len(errors)} cached, "
          f"{len(errors)} failed")
    return errors


def compare(expected: dict, results: dict[str, dict]) -> tuple[list[str], list[str]]:
    """``(label_moves, score_only)`` between the snapshot and this run."""
    old = expected.get("packages") or {}
    moves: list[str] = []
    score_only: list[str] = []
    for pid in sorted(set(old) | set(results)):
        a, b = old.get(pid), results.get(pid)
        if a is None:
            moves.append(f"{pid}: new package, now {b.get('label')} {b.get('score')} "
                         "(add it to expected.json with --write-expected)")
        elif b is None:
            moves.append(f"{pid}: in expected.json ({a.get('label')}) but not run")
        elif a.get("label") != b.get("label"):
            moves.append(f"{pid}: {a.get('label')} ({a.get('score')}) -> {b.get('label')} "
                         f"({b.get('score')}) | {b.get('reason') or b.get('error') or ''}")
        elif a.get("score") != b.get("score"):
            score_only.append(f"{pid}: {b.get('label')} {a.get('score')} -> {b.get('score')}")
    return moves, score_only


def main() -> int:
    ap = argparse.ArgumentParser(description="Install-check corpus label gate")
    ap.add_argument("--cache", type=Path, default=default_cache_dir())
    ap.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    ap.add_argument("--expected", type=Path, default=EXPECTED_PATH)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.25,
                    help="seconds between archive downloads (default 0.25)")
    ap.add_argument("--only", default="", help="comma-separated package ids")
    ap.add_argument("--report", type=Path, help="write a markdown report here")
    ap.add_argument("--json-out", type=Path, help="write full per-package results here")
    ap.add_argument("--write-expected", action="store_true",
                    help="rewrite the snapshot from this run (review the diff)")
    args = ap.parse_args()

    manifest = load_manifest(args.manifest)
    entries = manifest["packages"]
    if args.only:
        want = set(args.only.split(","))
        entries = [e for e in entries if e["id"] in want]
    args.cache.mkdir(parents=True, exist_ok=True)

    fetch_errors = prefetch(entries, args.cache, args.delay)

    results: dict[str, dict] = {}
    with ProcessPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {e["id"]: ex.submit(rsc.scan_entry, e, str(args.cache), True)
                for e in entries if e["id"] not in fetch_errors}
        for pid, fut in futs.items():
            try:
                results[pid] = fut.result()
            except Exception as exc:  # noqa: BLE001 — report per package
                results[pid] = {"id": pid, "label": "error", "error": repr(exc)[:200]}
    for pid, err in fetch_errors.items():
        results[pid] = {"id": pid, "label": "missing", "error": err}

    pub = {pid: {"id": pid, **rsc.public(r)} for pid, r in results.items()}
    expected = json.loads(args.expected.read_text()) if args.expected.exists() else {}
    exp_scope = {**expected, "packages": {k: v for k, v in (expected.get("packages") or {})
                                          .items() if k in pub}}
    moves, score_only = compare(exp_scope, pub)
    detail = rsc.diff(exp_scope, results)
    errors = [r for r in results.values() if r["label"] not in rsc.LABELS]

    by_label = Counter(r["label"] for r in results.values())
    print(f"install-check corpus: {len(results)} packages · "
          + " · ".join(f"{k} {v}" for k, v in sorted(by_label.items())))
    print(f"label moves vs {args.expected.name}: {len(moves)}; score-only changes: "
          f"{len(score_only)}")
    for line in moves:
        print("MOVED " + line)
    for line in score_only:
        print("score " + line)
    for r in errors:
        print(f"ERROR {r['id']}: {r['label']} {r.get('error', '')}")

    if args.report:
        lines = ["# Install-check corpus (nightly)", "",
                 f"Packages: {len(results)} · " + " · ".join(
                     f"{k}: {by_label.get(k, 0)}" for k in (*rsc.LABELS, "unscannable",
                                                            "missing", "error")),
                 "", f"## Label moves ({len(moves)})", ""]
        lines += [f"- {m}" for m in moves] or ["(none)"]
        lines += ["", f"## Score-only changes ({len(score_only)}, not a failure)", ""]
        lines += [f"- {s}" for s in score_only] or ["(none)"]
        if errors:
            lines += ["", "## Not scanned", ""]
            lines += [f"- {r['id']}: {r['label']} {r.get('error', '')}" for r in errors]
        lines += ["", "## Full diff vs expected.json", "", "```"]
        lines += detail or ["(no changes)"]
        lines += ["```", ""]
        args.report.write_text("\n".join(lines))
        print(f"report: {args.report}")
    if args.json_out:
        args.json_out.write_text(json.dumps(results, indent=1, sort_keys=True))
    if args.write_expected:
        merged = dict(expected.get("packages") or {})
        merged.update({pid: rsc.public(r) for pid, r in results.items()
                       if r["label"] in rsc.LABELS})
        args.expected.write_text(json.dumps({
            "_doc": "Committed snapshot of the install-check corpus (label, score and "
                    "reason from verdict.decide(), defect counts). The nightly gate fails "
                    "when a label moves. Regenerate with run_install_check_corpus.py "
                    "--write-expected and review the diff in the same PR.",
            "packages": dict(sorted(merged.items())),
        }, indent=1) + "\n")
        print(f"wrote {args.expected}")

    if errors:
        return 1
    if moves and not args.write_expected:
        print("FAIL: labels moved vs expected.json (if intended, re-run with "
              "--write-expected and commit the snapshot)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
