"""Local, offline scan — the same 12-category static engine and scoring the hosted
service runs, but over a checked-out working tree instead of the GitHub API.

This is the engine behind ``agentavow scan <path>``, the in-runner GitHub Action
(local-scan-action/), the GitLab CI component (gitlab/), and the slim scanner image
(docker/scanner.Dockerfile): a developer (or a private repo's CI) gets the identical
trust score + findings WITHOUT sending any code to AgentAvow. The score is
recomputable and matches a hosted scan of the same tree for the static portion.

What's identical to a hosted scan: file selection, the 12 detection categories,
suppression/allowlist, MCP/media context discounting, dependency findings, and
the trust-score / certified computation — all imported from ``scan.py``, not
re-implemented, so scores can't drift. What's absent (hosted-only, network
signals): OSV supply-chain enrichment, published-artifact diffing, and maintainer
metadata. Those are additive; their absence leaves the base static grade intact.

Signing is deliberately NOT done here — a verifiable attestation requires
AgentAvow's private key. A local scan proves the findings; the hosted service
(or its CI action) mints the signed, third-party-verifiable attestation on top.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from src.scanner.scan import (
    _DEP_FILES,
    ScanResult,
    _calculate_category_scores,
    _calculate_trust_score,
    _canonical_tool_digest,
    _certified_status,
    _compute_manifest_digest,
    _dedupe_findings,
    _detect_language,
    _finding_is_blocking,
    _is_nonshipped_path,
    _is_test_or_doc_file,
    _load_allowlist,
    _scan_content,
    _scan_dependencies,
    _select_scan_files,
    _should_skip_path,
)
from src.scanner.verdict import Decision, decide
from src.trust_tiers import trust_word, verdict_phrase

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _is_shipped(path: str) -> bool:
    """False for test/doc/example paths — those score at a fraction, so the output
    leads with the shipped surface an agent actually runs."""
    return not (_is_nonshipped_path(path) or _is_test_or_doc_file(path))

# Skip files larger than ~1MB — matches the practical hosted fetch cap and keeps
# a huge generated/vendored file from dominating the scan.
_MAX_FILE_BYTES = 1_000_000

# Directory names pruned at walk time (never scanned, never counted). Mirrors what
# _should_skip_path already rejects, but pruning here avoids walking huge trees.
_PRUNE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".next", ".turbo", ".nuxt", "target", ".mypy_cache", ".pytest_cache", ".tox",
    ".gradle", ".idea", ".vscode", "vendor", "coverage", ".cache",
}


def _read_text(p: Path) -> str | None:
    try:
        if p.stat().st_size > _MAX_FILE_BYTES:
            return None
        return p.read_text(encoding="utf-8", errors="ignore")
    except (OSError, ValueError):
        return None


def _git_tracked_files(root: Path) -> list[str] | None:
    """Files git tracks under ``root`` (posix paths), or None if not a git repo.

    Using git's own file list is what makes a local scan match a hosted scan:
    the hosted scanner reads the committed GitHub tree, so it never sees gitignored
    build output, data dumps, local caches, or vendored trees. Walking the raw
    filesystem would scan all of that and wildly diverge (a repo's `data/` corpus
    alone dwarfed the real source and dragged the score to 0). git-tracked ==
    same surface the hosted grade is computed over.
    """
    import subprocess
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--exclude-standard"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    files = [ln for ln in out.stdout.splitlines() if ln.strip()]
    return files or None


def _walk_tree(root: Path) -> list[dict]:
    """Build a GitHub-tree-shaped file list ([{"path": <relative posix>}]).

    Prefers git-tracked files (parity with the hosted GitHub-tree scan); falls back
    to a filesystem walk (pruning noise dirs) for a non-git directory.
    """
    tracked = _git_tracked_files(root)
    if tracked is not None:
        return [{"path": p, "type": "blob"} for p in tracked]
    out: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS]
        for fn in filenames:
            rel = (Path(dirpath) / fn).relative_to(root).as_posix()
            out.append({"path": rel, "type": "blob"})
    return out


def scan_local(root: str | Path, *, name: str | None = None) -> ScanResult:
    """Scan a local directory and return a fully-scored ScanResult.

    Mirrors the ordering of ``scan_repo`` (language → declared scope → hygiene →
    MCP/media context → file selection → per-file scan → deps → score), but every
    file read is from disk and every scoring call is the shared helper from
    ``scan.py`` so the grade equals a hosted static scan of the same tree.
    """
    root = Path(root).resolve()
    display = name or root.name
    result = ScanResult(repo=display, stars=0, description="", framework="")

    if not root.is_dir():
        result.error = f"Not a directory: {root}"
        return result

    tree = _walk_tree(root)
    if not tree:
        result.error = "Empty directory — nothing to scan"
        return result

    def read(rel: str) -> str | None:
        return _read_text(root / rel)

    # --- language ---
    result.primary_language = _detect_language(tree)

    # --- declared scope (.agentavow.yml) ---
    _mpath = next(
        (it["path"] for it in tree
         if it["path"].lower() in (".agentavow.yml", ".agentavow.yaml")),
        None,
    )
    if _mpath:
        try:
            from src.scanner.behavioral.manifest import parse_manifest
            _scope = parse_manifest(read(_mpath) or "")
            if _scope.present:
                result.declared_scope = {
                    "present": True, "egress": _scope.egress,
                    "capabilities": _scope.capabilities, "note": _scope.note,
                }
        except Exception:
            pass

    # --- README / LICENSE / tests hygiene ---
    for it in tree:
        pl = it["path"].lower()
        if pl.startswith("readme"):
            result.has_readme = True
        if pl.startswith("license") or pl.startswith("licence"):
            result.has_license = True
        if "test" in pl or "spec" in pl:
            result.has_tests = True

    # --- MCP-server detection (expected fs_access/unsafe_exec get discounted) ---
    mcp_indicators = {"server.json", "mcp.json", ".mcp.json"}
    mcp_dep_files = {"package.json", "pyproject.toml", "setup.py"}
    for it in tree:
        if Path(it["path"]).name.lower() in mcp_indicators:
            result.is_mcp_server = True
            break
    if not result.is_mcp_server:
        for it in tree:
            if Path(it["path"]).name.lower() in mcp_dep_files:
                low = (read(it["path"]) or "").lower()
                if ("mcp" in low or "modelcontextprotocol" in low
                        or "model-context-protocol" in low):
                    result.is_mcp_server = True
                    break

    # --- media/TTS tool detection (fs access expected) ---
    media_kw = {"tts", "text-to-speech", "speech", "audio", "voice", "whisper",
                "synthesize", "synthesizer", "vocoder", "video", "ffmpeg", "media",
                "sound", "wav", "mp3", "transcribe", "transcription"}
    if any(kw in display.lower() for kw in media_kw):
        result.is_media_tool = True
    if not result.is_media_tool:
        media_patterns = {".wav", ".mp3", ".ogg", ".flac", ".m4a", ".mp4", ".avi",
                          ".mkv", ".webm", "audio", "voice", "tts", "speech"}
        if sum(1 for it in tree
               if any(p in it["path"].lower() for p in media_patterns)) >= 3:
            result.is_media_tool = True

    # --- dependency-pinning positive (lock files) ---
    lock_files = {"requirements.txt", "poetry.lock", "package-lock.json",
                  "pipfile.lock", "cargo.lock", "yarn.lock", "pnpm-lock.yaml"}
    if any(Path(it["path"]).name.lower() in lock_files for it in tree):
        result.positive_signals.append("Dependency pinning")

    # --- user excludes (.agentgraph-scan.yml) ---
    user_excludes: set[str] = set()
    _cfg = next(
        (it["path"] for it in tree
         if it["path"] in (".agentgraph-scan.yml", ".agentgraph-scan.yaml")),
        None,
    )
    if _cfg:
        try:
            import yaml
            cfg = yaml.safe_load(read(_cfg) or "") or {}
            for pattern in cfg.get("exclude", []):
                user_excludes.add(str(pattern).lower())
        except Exception:
            pass

    # --- select scannable files (shared with the hosted path — can't drift) ---
    scan_files, result.total_scannable_files, result.sampled = _select_scan_files(
        tree, user_excludes,
    )

    # --- per-file static analysis (the 12 categories) ---
    allowlist = _load_allowlist()
    for it in scan_files:
        content = read(it["path"])
        if not content:
            continue
        findings, positives, suppressed = _scan_content(content, it["path"], allowlist)
        result.findings.extend(findings)
        result.positive_signals.extend(positives)
        result.suppressed_count += suppressed
        result.files_scanned += 1
        digest = _canonical_tool_digest(content, it["path"])
        if digest:
            result.tool_digests[it["path"]] = digest
    result.tool_manifest_digest = _compute_manifest_digest(result.tool_digests)

    # --- dependency findings (offline regex over manifests/lockfiles) ---
    dep_names = {f.lower() for f in _DEP_FILES}
    dep_files = [
        it for it in tree
        if Path(it["path"]).name.lower() in dep_names
        and not _should_skip_path(it["path"])
    ]
    for dep_item in dep_files[:10]:
        dep_content = read(dep_item["path"])
        if dep_content:
            result.findings.extend(_scan_dependencies(dep_content, dep_item["path"]))

    # --- score (identical helpers to the hosted path) ---
    result.findings = _dedupe_findings(result.findings)
    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    return result


# --------------------------------------------------------------------------- #
# Output + CLI
# --------------------------------------------------------------------------- #

def _tier(score: int) -> str:
    """Score → trust tier word (the six API tiers, src/trust_tiers.py)."""
    return trust_word(score)


def decision_for_result(result: ScanResult) -> Decision:
    """The three-phrase decision (``src.scanner.verdict.decide``) for a local result.
    Items carry the scanner's own blocking call as ``shipped`` and the headline counts
    are the blocking counts, so the CLI and the hosted API decide alike. There is no
    sandbox run locally, so the decision is always final."""
    items = [
        {"category": f.category, "name": f.name, "severity": f.severity,
         "shipped": _finding_is_blocking(f), "kind": f.kind, "installed": f.installed}
        for f in sorted(result.findings, key=lambda x: _SEV_RANK.get(x.severity, 5))
    ]
    return decide({
        "trust_score": result.trust_score,
        "findings": {"critical": result.shipped_critical_count,
                     "high": result.shipped_high_count, "items": items},
        "metadata": {"files_scanned": result.files_scanned},
        "deprecation": getattr(result, "deprecation", None),
        "incident_history": getattr(result, "incident_history", None) or {},
        "supply_chain": getattr(result, "supply_chain", None) or {},
    })


def verdict_for(result: ScanResult) -> tuple[str, str]:
    """``(phrase, value)`` for a scored result: the headline phrase ("Safe to connect"
    / "Review before you connect" / "Do not connect") and its machine value
    (``safe`` / ``review`` / ``do_not_connect``). The ONE place the local CLI derives
    a verdict: ``decide()`` via :func:`decision_for_result`."""
    d = decision_for_result(result)
    return verdict_phrase(d), d.decision


def result_to_dict(result: ScanResult) -> dict:
    """Compact JSON view for CI / inner-loop consumption."""
    sev_counts: dict[str, int] = {}
    for f in result.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    dec = decision_for_result(result)
    return {
        "tool": result.repo,
        "verdict": dec.decision,
        "verdict_phrase": verdict_phrase(dec),
        "decision": dec.decision,
        "decision_reason": dec.reason,
        "trust_score": result.trust_score,
        "tier": _tier(result.trust_score),
        "certified": bool((result.certified or {}).get("eligible")),
        "files_scanned": result.files_scanned,
        "total_scannable_files": result.total_scannable_files,
        "sampled": result.sampled,
        "primary_language": result.primary_language,
        "is_mcp_server": result.is_mcp_server,
        "declared_scope": result.declared_scope or {},
        "suppressed": result.suppressed_count,
        "counts": {
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
            "total": len(result.findings),
        },
        "category_scores": result.category_scores,
        "capabilities": result.capabilities,
        "findings": [
            {
                "category": f.category,
                "name": f.name,
                "severity": f.severity,
                "file": f.file_path,
                "line": f.line_number,
                "remediation": f.remediation,
                "shipped": _is_shipped(f.file_path),
                "kind": f.kind,
                "capability": f.capability,
                "installed": f.installed,
            }
            # shipped findings first, then by severity — lead with what an agent runs
            for f in sorted(
                result.findings,
                key=lambda x: (not _is_shipped(x.file_path),
                               _SEV_RANK.get(x.severity, 5)),
            )
        ],
    }


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def result_to_sarif(result: ScanResult) -> dict:
    """SARIF 2.1.0 — so findings show up inline in GitHub code scanning / PR annotations."""
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        rule_id = f"agentavow/{f.category}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f.category,
            "shortDescription": {"text": f.name},
        })
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.name}"
                                + (f" — {f.remediation}" if f.remediation else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": max(1, f.line_number)},
                }
            }],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "AgentAvow",
                "informationUri": "https://agentavow.com",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


# GitLab Code Quality (CodeClimate subset) severities: info < minor < major < critical
# < blocker. A shipped critical is the thing that floors the score, so it is the
# one that blocks.
_CODE_QUALITY_SEVERITY = {"critical": "blocker", "high": "critical", "medium": "major",
                          "low": "minor", "info": "info"}


def _code_quality_fingerprint(path: str, category: str, name: str, ordinal: int) -> str:
    """Stable id for one finding. GitLab diffs fingerprints between the target and
    source branch to decide what is new vs. fixed, so the line number stays out:
    an unrelated edit above the finding must not re-report it. The ordinal (n-th
    identical finding in the file, by line order) keeps two hits of the same rule
    in one file distinct."""
    key = f"{path}\0{category}\0{name}\0{ordinal}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def result_to_code_quality(result: ScanResult, path_prefix: str = "") -> list[dict]:
    """GitLab Code Quality report (``gl-code-quality-report.json``) so findings show
    in the merge-request widget on every GitLab tier. Format:
    https://docs.gitlab.com/ci/testing/code_quality/#code-quality-report-format

    ``path_prefix`` is the scanned directory relative to the repository root, for
    scans of a subdirectory; GitLab resolves ``location.path`` from the repo root.
    """
    prefix = path_prefix.strip("/")
    seen: dict[tuple[str, str, str], int] = {}
    report: list[dict] = []
    ordered = sorted(result.findings, key=lambda f: (f.file_path, f.line_number))
    for f in ordered:
        path = f"{prefix}/{f.file_path}" if prefix else f.file_path
        key = (path, f.category, f.name)
        ordinal = seen.get(key, 0)
        seen[key] = ordinal + 1
        description = f.name + (f". {f.remediation}" if f.remediation else "")
        report.append({
            "type": "issue",
            "check_name": f"agentavow/{f.category}",
            "description": description,
            "categories": ["Security"],
            "severity": _CODE_QUALITY_SEVERITY.get(f.severity, "major"),
            "fingerprint": _code_quality_fingerprint(path, f.category, f.name, ordinal),
            "location": {"path": path, "lines": {"begin": max(1, f.line_number)}},
        })
    return report


def _scan_path_prefix(root: Path) -> str:
    """The scanned directory relative to the CI project root, when it is inside
    one (``CI_PROJECT_DIR`` is what GitLab exports). Empty when they coincide or the
    scan is outside the checkout, so report paths stay repo-relative either way."""
    project_dir = os.environ.get("CI_PROJECT_DIR")
    if not project_dir:
        return ""
    try:
        rel = Path(root).resolve().relative_to(Path(project_dir).resolve())
    except ValueError:
        return ""
    return "" if rel == Path(".") else rel.as_posix()


def _print_human(result: ScanResult, stream=sys.stderr) -> None:
    d = result_to_dict(result)
    c = d["counts"]
    print(f"\nAgentAvow — {d['tool']}", file=stream)
    print(f"  Verdict     : {d['verdict_phrase']}"
          + (" · Certified" if d["certified"] else "")
          + f" — {d['decision_reason']}", file=stream)
    print(f"  Trust score : {d['trust_score']}/100  (tier: {d['tier']})"
          + ("  ✓ Certified-eligible" if d["certified"] else ""), file=stream)
    print(f"  Files       : {d['files_scanned']} scanned"
          + (f" of {d['total_scannable_files']} (sampled)" if d["sampled"] else ""),
          file=stream)
    print(f"  Findings    : {c['critical']} critical · {c['high']} high · "
          f"{c['medium']} medium · {c['low']} low", file=stream)
    if result.is_mcp_server:
        print("  Context     : MCP server (fs_access/unsafe_exec discounted)", file=stream)
    top = sorted(
        [f for f in result.findings if f.severity in ("critical", "high")],
        key=lambda x: (not _is_shipped(x.file_path), _SEV_RANK.get(x.severity, 5)),
    )[:15]
    if top:
        print("\n  Top findings:", file=stream)
        for f in top:
            print(f"    [{f.severity:<8}] {f.category:<16} {f.file_path}:{f.line_number}"
                  f"  {f.name}", file=stream)
            if f.remediation:
                print(f"               ↳ {f.remediation}", file=stream)
    print("", file=stream)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="agentavow",
        description="Scan a local directory for tool-safety findings — the same "
                    "engine AgentAvow runs, offline. No code leaves your machine.",
    )
    sub = p.add_subparsers(dest="cmd")
    sc = sub.add_parser("scan", help="scan a local path")
    sc.add_argument("path", nargs="?", default=".", help="directory to scan (default: .)")
    sc.add_argument("--json", metavar="FILE", nargs="?", const="-",
                    help="write findings JSON (to FILE, or stdout if no FILE)")
    sc.add_argument("--sarif", metavar="FILE",
                    help="write SARIF 2.1.0 to FILE (for GitHub code scanning)")
    sc.add_argument("--gitlab-code-quality", metavar="FILE",
                    help="write a GitLab Code Quality report to FILE "
                         "(artifacts:reports:codequality, shows in the MR widget)")
    sc.add_argument("--min-score", type=int, default=None,
                    help="exit non-zero if the trust score is below this (CI gate)")
    sc.add_argument("--fail-on",
                    choices=["do_not_connect", "review", "critical", "high", "medium"],
                    action="append", default=None,
                    help="exit non-zero on this answer or worse (do_not_connect | "
                         "review), or if any finding at/above this severity is present "
                         "(critical | high | medium). Repeat to combine an answer gate "
                         "with a severity gate.")
    sc.add_argument("--quiet", action="store_true", help="suppress the human summary")
    # allow bare `agentavow <path>` as shorthand for `agentavow scan <path>`
    args, _ = p.parse_known_args(argv)
    if args.cmd != "scan":
        # Support `agentavow scan` only; print help otherwise.
        p.print_help(sys.stderr)
        return 2

    result = scan_local(args.path)
    if result.error:
        print(f"agentavow: {result.error}", file=sys.stderr)
        return 2

    if not args.quiet:
        _print_human(result)

    if args.json is not None:
        payload = json.dumps(result_to_dict(result), indent=2)
        if args.json == "-":
            print(payload)
        else:
            Path(args.json).write_text(payload, encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(result_to_sarif(result), indent=2),
                                    encoding="utf-8")
    if args.gitlab_code_quality:
        report = result_to_code_quality(result, _scan_path_prefix(Path(args.path)))
        Path(args.gitlab_code_quality).write_text(json.dumps(report, indent=2),
                                                  encoding="utf-8")

    # --- CI gating ---
    if args.min_score is not None and result.trust_score < args.min_score:
        print(f"agentavow: FAIL — score {result.trust_score} < min {args.min_score}",
              file=sys.stderr)
        return 1
    for fail_on in args.fail_on or ():
        if fail_on in ("do_not_connect", "review"):
            dec = decision_for_result(result)
            failing = ("do_not_connect",) if fail_on == "do_not_connect" \
                else ("do_not_connect", "review")
            if dec.decision in failing:
                print(f"agentavow: FAIL — {verdict_phrase(dec)}: {dec.reason}",
                      file=sys.stderr)
                return 1
        else:
            order = {"critical": 3, "high": 2, "medium": 1}
            thresh = order[fail_on]
            if any(order.get(f.severity, 0) >= thresh for f in result.findings):
                print(f"agentavow: FAIL — findings at/above '{fail_on}' present",
                      file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
