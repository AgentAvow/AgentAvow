"""Phase 2 — scan the PUBLISHED artifact + detect repo↔artifact drift.

Runs the SAME 12-category static engine (:func:`src.scanner.scan._scan_content`)
over the unpacked artifact tree, adds the artifact-only attack surface that
repo-only scanning is structurally blind to:

  * **Install/build-time exec** — npm ``scripts.preinstall/install/postinstall``
    in the PACKAGED ``package.json`` (reuses ``_scan_install_hooks``); PyPI
    ``setup.py`` code that runs at ``pip install`` time from an sdist, detected by
    **AST** (``os.system`` / ``subprocess`` / ``eval`` / ``exec`` / network / a
    custom ``cmdclass``) — never executed.
  * **Repo↔artifact drift** — files present in the artifact but absent from the
    repo (``added_files``), or present with different content (``modified_files``),
    plus ``has_install_hook``. Suspicious added *source* files raise findings — the
    exact "clean repo, poisoned tarball" tell (event-stream, ctx, xz-utils).

Everything here is **static** (no execution), **feature-flagged**
(``settings.scanner_scan_artifact``, default False), and **fail-open**: any
fetch/unpack error returns ``ok=False`` and the caller keeps the repo-only grade.
"""
from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from src.scanner.artifact_fetch import (
    ArtifactFetchError,
    ArtifactFetchResult,
    fetch_npm_artifact,
    fetch_pypi_artifact,
)

logger = logging.getLogger(__name__)

# Registry snapshot date pinned into coverage.db_snapshots (recompute discipline).
from datetime import datetime, timezone  # noqa: E402


def _registry_snapshot() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


@dataclass
class ArtifactScanResult:
    """Outcome of an artifact fetch+scan+drift pass (fail-open)."""

    ok: bool = False
    ecosystem: str = ""
    name: str = ""
    version: str = ""
    kind: str = ""
    digest: str | None = None            # "sha256:..." of the artifact bytes
    download_url: str | None = None
    findings: list = field(default_factory=list)   # list[scan.Finding]
    files_scanned: int = 0
    unpacked_size: int = 0
    file_count: int = 0
    drift: dict = field(default_factory=dict)
    registry_snapshot: str | None = None
    error: str | None = None


# Files whose presence-only in the artifact (not the repo) is a strong injection
# tell: real executable/source code, not generated metadata/build noise.
_DRIFT_SOURCE_EXTS = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".sh", ".bash", ".rb", ".go", ".rs", ".php", ".pl", ".ps1",
})
# Never treat these as suspicious "added" files — they are normally generated at
# pack time and legitimately absent from the repo.
_DRIFT_IGNORE_NAMES = frozenset({
    "package.json", "package-lock.json", "npm-shrinkwrap.json",
    "pkg-info", "metadata", "record", "wheel", "top_level.txt",
    "setup.cfg", "requires.txt", "sources.txt", "entry_points.txt",
})
_DRIFT_IGNORE_DIR_MARKERS = ("dist-info", "egg-info")

# Directories/files a BUILD STEP normally emits — compiled/bundled output that is
# expected to be present in the published package but absent from (or different in)
# the git source. A TS package ships dist/*.js built from src/*.ts; that path-level
# difference is NOT a poisoned-tarball signal. The CONTENT of these files is still
# scanned for malware by scan_artifact_files — this only suppresses the path-drift
# FINDING, so a compiled package doesn't get a spurious HIGH "ships N files" drift.
_BUILD_OUTPUT_DIR_SEGMENTS = frozenset({
    "dist", "build", "_build", "es", "esm", "cjs", "umd", "out",
    "target", "bundle", "bundles", ".next", "__generated__", "generated",
})
_BUILD_OUTPUT_SUFFIXES = (
    ".min.js", ".min.css", ".map", ".js.map", ".css.map",
    ".d.ts", ".d.mts", ".d.cts",
)


def _is_expected_build_output(path: str) -> bool:
    """True for a file a build step normally produces (compiled/bundled/generated),
    so its path-level difference from the git source is expected, not injection."""
    low = path.lower()
    if low.endswith(_BUILD_OUTPUT_SUFFIXES):
        return True
    return any(seg in _BUILD_OUTPUT_DIR_SEGMENTS for seg in Path(low).parts)


# ---------------------------------------------------------------------------
# PyPI setup.py install-time exec detection (AST — never executed)
# ---------------------------------------------------------------------------

# Callables that, unguarded at sdist install time, run a SHELL or fetch the
# network — the real install-time RCE / download-and-run patterns. Deliberately
# EXCLUDES the eval-family (``exec``/``eval``/``compile``/``__import__``): the
# ubiquitous ``exec(open('_version.py').read())`` metadata-read pattern is benign,
# and generic net names (``get``/``post``/``request``/``connect``) collide with
# ``dict.get``/attribute calls, so they're excluded to keep precision high.
_AST_EXEC_CALLS = frozenset({
    "system", "popen", "run", "call", "check_output", "check_call", "Popen",
    "urlopen", "urlretrieve",
})
_AST_NET_CALLS = frozenset({"urlopen", "urlretrieve"})
# setuptools commands that run at install/build time. A ``cmdclass`` override of
# one of these injects code into ``pip install``; overriding only ``test`` or
# another custom command (common — e.g. requests' ``cmdclass={'test': PyTest}``)
# is a dev convenience, not an install hook.
_INSTALL_BUILD_COMMANDS = frozenset({
    "install", "develop", "build", "build_py", "build_ext", "build_clib",
    "bdist", "bdist_egg", "bdist_wheel", "egg_info",
    "install_lib", "install_scripts", "install_data", "install_headers",
})


def _call_name(node: ast.Call) -> str:
    """Best-effort dotted-tail name of a call target (``a.b.c`` → ``c``)."""
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _is_cli_publish_guard(test: ast.AST) -> bool:
    """True if an ``if`` test gates code on a manual CLI subcommand rather than
    install time — i.e. it inspects ``sys.argv`` or ``__name__`` (``== '__main__'``).

    ``if sys.argv[-1] == 'publish':`` / ``if __name__ == '__main__':`` wrap
    maintainer helpers (publish/upload/tag) that run when the author types
    ``python setup.py publish`` — NOT when a consumer runs ``pip install``. Code
    reachable only under such a guard is not an install hook.
    """
    for node in ast.walk(test):
        if isinstance(node, ast.Attribute) and node.attr == "argv":
            return True
        if isinstance(node, ast.Name) and node.id in ("argv", "__name__"):
            return True
    return False


class _InstallExecVisitor(ast.NodeVisitor):
    """Collect dangerous calls, tracking whether each is reachable only under a
    publish/CLI guard (``sys.argv`` / ``__name__``). Guarded calls are maintainer
    helpers, not install-time code, so they don't count as an install hook."""

    def __init__(self) -> None:
        self.unguarded: list[tuple[str, int]] = []
        self.guarded: list[tuple[str, int]] = []
        self.has_net_unguarded = False
        self.cmdclass = False
        self._guard_depth = 0

    def visit_If(self, node: ast.If) -> None:
        if _is_cli_publish_guard(node.test):
            # The body runs only under the guard → guarded. The else-branch is the
            # normal (install) path → visited unguarded.
            self._guard_depth += 1
            for child in node.body:
                self.visit(child)
            self._guard_depth -= 1
            for child in node.orelse:
                self.visit(child)
        else:
            self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        fname = _call_name(node)
        if fname in _AST_EXEC_CALLS:
            if self._guard_depth > 0:
                self.guarded.append((fname, getattr(node, "lineno", 1)))
            else:
                self.unguarded.append((fname, getattr(node, "lineno", 1)))
                if fname in _AST_NET_CALLS:
                    self.has_net_unguarded = True
        if fname == "setup":
            for kw in node.keywords:
                if kw.arg == "cmdclass" and isinstance(kw.value, ast.Dict):
                    # Flag only if the override targets a real install/build command.
                    for key in kw.value.keys:
                        if (
                            isinstance(key, ast.Constant)
                            and isinstance(key.value, str)
                            and key.value in _INSTALL_BUILD_COMMANDS
                        ):
                            self.cmdclass = True
        self.generic_visit(node)


def detect_pypi_install_exec(source: str, file_path: str) -> list:
    """AST-scan a ``setup.py`` for code that executes at ``pip install`` time.

    An sdist install runs ``setup.py`` in-process — so any module-level
    ``os.system``/``subprocess``/``eval``/network call, or a custom ``cmdclass``
    override, is auto-run-on-install. **Guard-aware**: dangerous calls reachable
    only under a ``sys.argv``/``__name__`` publish guard (a maintainer helper) are
    NOT install hooks and are ignored. Returns ``install_hook`` findings. Never
    executes the file. AST parse failure ⇒ ``[]`` (fail-open; regex engine still runs).
    """
    from src.scanner.scan import _REMEDIATION_HINTS, Finding

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    visitor = _InstallExecVisitor()
    visitor.visit(tree)

    findings: list = []
    if visitor.unguarded:
        # network + exec at install time is the pip-install download-and-run pattern.
        severity = "critical" if visitor.has_net_unguarded else "high"
        name, line = visitor.unguarded[0]
        findings.append(Finding(
            category="install_hook",
            name=f"setup.py executes code at install time ({name}...)",
            severity=severity,
            file_path=file_path,
            line_number=line,
            snippet=f"install-time exec via {name}(...) in setup.py",
            remediation=_REMEDIATION_HINTS.get("install_hook", "Audit install-time code"),
        ))
    elif visitor.cmdclass:
        findings.append(Finding(
            category="install_hook",
            name="setup.py overrides install/build commands (cmdclass)",
            severity="medium",
            file_path=file_path,
            line_number=1,
            snippet="custom cmdclass runs at build/install time",
            remediation=_REMEDIATION_HINTS.get("install_hook", "Audit install-time code"),
        ))
    return findings


# ---------------------------------------------------------------------------
# Scan the unpacked tree with the existing 12-category engine
# ---------------------------------------------------------------------------

def scan_artifact_files(fetched: ArtifactFetchResult) -> tuple[list, int, bool]:
    """Run the 12-category engine + install-hook detectors over the unpacked tree.

    Returns ``(findings, files_scanned, has_install_hook)``. Reuses the repo
    scanner's ``_scan_content`` / ``_scan_dependencies`` verbatim, so every current
    detector gains artifact-truth for free.
    """
    from src.scanner.scan import (
        _is_source_file,
        _is_test_or_doc_file,
        _load_allowlist,
        _scan_content,
        _scan_dependencies,
        _should_skip_path,
    )

    findings: list = []
    files_scanned = 0
    has_install_hook = False
    allowlist = _load_allowlist()

    for path, af in fetched.files.items():
        # Dependency manifests (package.json / setup.py / requirements.txt ...) →
        # dependency + install-hook detectors (npm lifecycle hooks live here).
        name_lower = Path(path).name.lower()
        if name_lower in {"package.json", "setup.py", "setup.cfg", "pyproject.toml",
                          "requirements.txt", "pipfile"}:
            if af.text:
                dep_findings = _scan_dependencies(af.text, path)
                findings.extend(dep_findings)
                if any(f.category == "install_hook" for f in dep_findings):
                    has_install_hook = True

        # PyPI setup.py — analyzed ONLY by the guard-aware install-exec detector,
        # NOT the general regex engine below: setup.py legitimately contains
        # publish/CLI helper code (os.system behind `if sys.argv[-1]=='publish'`)
        # that the guard-unaware regex engine would false-flag as unsafe_exec. The
        # dedicated detector understands install-time vs maintainer-only reachability.
        if name_lower == "setup.py":
            if af.text:
                ast_findings = detect_pypi_install_exec(af.text, path)
                if ast_findings:
                    findings.extend(ast_findings)
                    if any(f.category == "install_hook" for f in ast_findings):
                        has_install_hook = True
            continue

        # The 12-category static engine over every scannable source file. Test /
        # doc / example code shipped in an sdist is skipped — it isn't the runtime
        # or install surface an agent executes, and penalizing it would grade a
        # package on its test suite (the repo scanner downgrades these; for
        # artifact-truth we skip them, since install hooks + drift are detected
        # separately above).
        if (
            af.text
            and _is_source_file(path)
            and not _should_skip_path(path)
            and not _is_test_or_doc_file(path)
        ):
            f, _positives, _suppressed = _scan_content(af.text, path, allowlist)
            findings.extend(f)
            files_scanned += 1

    return findings, files_scanned, has_install_hook


def huggingface_weight_findings(fetched: ArtifactFetchResult) -> list:
    """HF-specific detector: grade the LOAD-TIME code surface a repo scan can't see.

    A model whose weights are pickle-backed (``.bin``/``.pt``/``.ckpt``…) runs
    arbitrary Python the moment it's loaded (``torch.load`` unpickles). That is the
    load-time analogue of an npm install hook — invisible to any source scan of the
    ``.py`` files. ``.safetensors`` (and friends) have no code path, so a repo that
    ALSO ships a safe copy earns a lighter finding (the caller can opt into it)."""
    from src.scanner.scan import _REMEDIATION_HINTS, Finding

    manifest = fetched.packaged_manifest or {}
    hf = manifest.get("hf") if isinstance(manifest, dict) else None
    if not isinstance(hf, dict):
        return []

    findings: list = []
    unsafe = hf.get("unsafe_weights") or []
    safe = hf.get("safe_weights") or []
    if unsafe:
        has_safe_alt = bool(safe)
        severity = "medium" if has_safe_alt else "high"
        detail = (
            "a safetensors copy is also published, so this can be loaded safely"
            if has_safe_alt
            else "no safetensors alternative is published"
        )
        findings.append(Finding(
            category="insecure_deserialization",
            name=(
                f"Model ships pickle-format weights ({unsafe[0]}) — "
                "arbitrary code executes on load"
            ),
            severity=severity,
            file_path=unsafe[0],
            line_number=1,
            snippet=(
                f"{len(unsafe)} pickle-backed weight file(s); loading with "
                f"torch.load / pickle.load deserializes arbitrary code — {detail}"
            ),
            remediation=_REMEDIATION_HINTS.get(
                "insecure_deserialization",
                "Prefer .safetensors; load pickle weights only from trusted publishers "
                "or with a restricted unpickler.",
            ),
        ))
    return findings


_DOCKER_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:PASS(?:WORD)?|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|"
    r"CLIENT_SECRET|AUTH|CREDENTIAL|PWD)(?:$|_)",
    re.IGNORECASE,
)
# Placeholder-ish values that aren't real leaked secrets (build args / templates).
_DOCKER_ENV_PLACEHOLDER = re.compile(
    r"^(?:|\$\{.*\}|<.*>|changeme|example|your[_-].*|xxx+|none|null|true|false|\d{1,4})$",
    re.IGNORECASE,
)


def _docker_stale_months(created: str | None) -> int | None:
    """Whole months since the image was built, from the config's ISO ``created``.
    Best-effort — returns None if unparseable."""
    if not created or not isinstance(created, str):
        return None
    try:
        from datetime import datetime, timezone
        ts = created.replace("Z", "+00:00")
        # Trim over-precise fractional seconds (docker emits 9 digits; fromisoformat wants ≤6).
        if "." in ts:
            head, _, tail = ts.partition(".")
            frac = "".join(ch for ch in tail if ch.isdigit())[:6]
            off = tail[len(frac):] if len(tail) > len(frac) else ""
            # keep any timezone offset that followed the fraction
            import re as _re
            moff = _re.search(r"[+-]\d\d:\d\d$", tail)
            ts = f"{head}.{frac}{moff.group(0) if moff else off}"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        return max(0, int(delta.days / 30))
    except (ValueError, TypeError):
        return None


def docker_config_findings(fetched: ArtifactFetchResult) -> list:
    """Config-level container grade (no layer scan): the OCI image config carries
    the highest-density security signal without pulling layers.

    Detects: runs-as-root (no/root ``USER``), secrets baked into ``Env``/``Labels``,
    a stale base (not rebuilt in a long time → unpatched CVEs), and SSH exposed. Fails
    open on a missing manifest."""
    from src.scanner.scan import _REMEDIATION_HINTS, Finding

    manifest = fetched.packaged_manifest or {}
    d = manifest.get("docker") if isinstance(manifest, dict) else None
    if not isinstance(d, dict):
        return []
    cfg = d.get("config") or {}
    findings: list = []

    # 1) Runs as root — no USER, or an explicit root/0. The default, and a real
    #    privilege-escalation surface if the container is breached.
    user = str(cfg.get("User") or "").strip()
    if user in ("", "root", "0", "0:0", "root:root"):
        findings.append(Finding(
            category="fs_access",
            name="Container runs as root (no non-root USER set)",
            severity="medium",
            file_path="image config",
            line_number=1,
            snippet="config.User is unset/root — a breach runs with full container-root privileges",
            remediation="Add a non-root USER in the Dockerfile and drop Linux capabilities.",
        ))

    # 2) Secrets baked into ENV / Labels — the config ships to every puller.
    env_list = cfg.get("Env") or []
    labels = cfg.get("Labels") or {}
    pairs = [(e.split("=", 1)[0], e.split("=", 1)[1] if "=" in e else "")
             for e in env_list if isinstance(e, str)]
    pairs += [(str(k), str(v)) for k, v in (labels.items() if isinstance(labels, dict) else [])]
    for key, val in pairs:
        if (_DOCKER_SECRET_KEY_RE.search(key) and val
                and not _DOCKER_ENV_PLACEHOLDER.match(val.strip())
                and len(val.strip()) >= 6):
            findings.append(Finding(
                category="secret",
                name=f"Credential baked into image config ({key})",
                severity="high",
                file_path="image config",
                line_number=1,
                snippet=f"{key}=<redacted> ships in the image ENV/labels to everyone who pulls it",
                remediation=_REMEDIATION_HINTS.get(
                    "secret", "Never bake secrets into an image; inject at runtime."),
            ))
            break  # one finding is enough to fail the axis; avoid leaking every key

    # 3) SSH exposed — a container is not a VM; an sshd surface is an anti-pattern.
    ports = cfg.get("ExposedPorts") or {}
    if isinstance(ports, dict) and any(str(p).startswith(("22/", "2222/")) for p in ports):
        findings.append(Finding(
            category="fs_access",
            name="Image exposes an SSH port (22)",
            severity="low",
            file_path="image config",
            line_number=1,
            snippet="ExposedPorts includes SSH — containers should not run sshd",
            remediation="Remove sshd from the image; use `docker exec` / a sidecar for access.",
        ))

    # 4) Stale base — not rebuilt in a long time means unpatched OS/base CVEs.
    months = _docker_stale_months(d.get("created"))
    if months is not None and months >= 18:
        findings.append(Finding(
            category="dependency",
            name=f"Image not rebuilt in ~{months} months (stale base — unpatched CVEs)",
            severity="low" if months < 36 else "medium",
            file_path="image config",
            line_number=1,
            snippet=(
                f"config.created is ~{months} months old; "
                "the base layer likely ships known CVEs"
            ),
            remediation="Rebuild on a current base image on a regular cadence.",
        ))
    return findings


# ---------------------------------------------------------------------------
# Repo ↔ artifact drift
# ---------------------------------------------------------------------------

def _is_drift_ignorable(path: str) -> bool:
    name = Path(path).name.lower()
    if name in _DRIFT_IGNORE_NAMES:
        return True
    low = path.lower()
    return any(marker in low for marker in _DRIFT_IGNORE_DIR_MARKERS)


def compute_drift(
    fetched: ArtifactFetchResult,
    repo_paths: set[str] | None,
    repo_text_hashes: dict[str, str] | None,
    *,
    has_install_hook: bool,
    release_blob_shas: dict[str, str] | None = None,
) -> tuple[dict, list]:
    """Diff the artifact tree against the repo. Returns ``(drift_summary, findings)``.

    * ``added_files``    — in the artifact, absent from the repo.
    * ``modified_files`` — in both, but content sha differs (only when we have a
      repo text hash for that path — otherwise not asserted, to avoid false drift).
    * ``has_install_hook`` — carried through so the summary is self-describing.

    Suspicious *added source* files (real code the repo never committed) raise
    ``artifact_drift`` findings — the core poisoned-tarball signal.

    ``release_blob_shas`` ({path: git-blob-sha} of the repo AT THE RELEASE TAG the
    artifact was built from) is the accurate comparison basis: the published package
    should equal its own tagged source. When provided, the diff runs against it via
    git blob SHAs (no content fetch needed). Without it we fall back to the repo's
    DEFAULT BRANCH, which for an active repo has moved past the release — producing
    spurious "modifies/ships N files" drift that is really just release-vs-main skew.
    """
    from src.scanner.scan import Finding

    repo_paths = repo_paths or set()
    repo_text_hashes = repo_text_hashes or {}

    added: list[str] = []
    modified: list[str] = []
    if release_blob_shas is not None:
        # Accurate basis: compare the artifact against its own release tag by git blob SHA.
        for path, af in fetched.files.items():
            if _is_drift_ignorable(path):
                continue
            tag_sha = release_blob_shas.get(path)
            if tag_sha is None:
                added.append(path)
            elif af.git_blob_sha and af.git_blob_sha != tag_sha:
                modified.append(path)
        have_repo_view = bool(release_blob_shas)
    else:
        # Fallback: default-branch view (path set + decoded-text hashes).
        for path, af in fetched.files.items():
            if _is_drift_ignorable(path):
                continue
            if path not in repo_paths and path not in repo_text_hashes:
                added.append(path)
            else:
                repo_hash = repo_text_hashes.get(path)
                if repo_hash and af.text_sha256 and repo_hash != af.text_sha256:
                    modified.append(path)
        have_repo_view = bool(repo_paths or repo_text_hashes)

    added.sort()
    modified.sort()

    # If NONE of the artifact's non-ignorable files line up with a repo path, the
    # two trees don't correspond (e.g. a monorepo subdir package, or a repo whose
    # tree we couldn't fully fetch). Treating every artifact file as "added" there
    # would be a false-positive storm — so we mark the comparison inconclusive and
    # raise no drift findings.
    considered = [p for p in fetched.files if not _is_drift_ignorable(p)]
    matched = len(considered) - len(added)
    comparable = have_repo_view and (matched > 0 or not considered)

    drift = {
        "compared": comparable,
        "added_files": added if comparable else [],
        "modified_files": modified,
        "has_install_hook": bool(has_install_hook),
        "added_count": len(added) if comparable else 0,
        "modified_count": len(modified),
    }

    findings: list = []
    if not comparable:
        # No repo comparison → no drift assertions. A genuine install hook is
        # already reported as an ``install_hook`` finding by the artifact scan;
        # emitting an ``artifact_drift`` "hook" finding here would double-count and,
        # with no repo to diff against, isn't drift at all.
        return drift, findings

    added = drift["added_files"]

    # Added SOURCE files that the repo never committed = injected-code drift —
    # EXCEPT expected build output (dist/*.js compiled from src/*.ts, *.min.js,
    # *.d.ts, …), which every compiled package ships and whose content is scanned
    # separately. Without this, every TS/JS package with a build step got a spurious
    # HIGH "ships N source files not in the repo" drift.
    suspicious_added = [
        p for p in added
        if Path(p).suffix.lower() in _DRIFT_SOURCE_EXTS
        and not _is_expected_build_output(p)
    ]
    if suspicious_added:
        preview = ", ".join(suspicious_added[:5])
        findings.append(Finding(
            category="artifact_drift",
            name=(
                f"Published artifact ships {len(suspicious_added)} source file(s) "
                "not in the repo"
            ),
            severity="high",
            file_path=suspicious_added[0],
            line_number=1,
            snippet=f"artifact-only source: {preview}"[:120],
            remediation=(
                "The published package contains code absent from the git source "
                "(clean-repo / poisoned-tarball pattern). Verify the tarball was "
                "built from the tagged commit; treat unexplained additions as malicious."
            ),
        ))
    # Modified files that are expected build transforms (a rebuilt dist/, a stamped
    # version file, a regenerated .d.ts) aren't tampering — only assert drift on
    # SOURCE files whose committed content the artifact changed.
    suspicious_modified = [p for p in modified if not _is_expected_build_output(p)]
    if suspicious_modified:
        modified = suspicious_modified
        preview = ", ".join(modified[:5])
        findings.append(Finding(
            category="artifact_drift",
            name=f"Published artifact modifies {len(modified)} file(s) vs the repo",
            severity="medium",
            file_path=modified[0],
            line_number=1,
            snippet=f"content differs from repo: {preview}"[:120],
            remediation=(
                "Artifact file content differs from the repo source — confirm the "
                "difference is an expected build transform, not an injected change."
            ),
        ))
    if has_install_hook:
        findings.append(_install_hook_drift_finding())
    return drift, findings


def _install_hook_drift_finding():
    from src.scanner.scan import Finding

    return Finding(
        category="artifact_drift",
        name="Published artifact contains an install/build-time hook",
        severity="high",
        file_path="",
        line_number=1,
        snippet="artifact runs code on install (npm lifecycle / setup.py)",
        remediation=(
            "Install-time code is the top supply-chain vector — audit it and "
            "prefer packages with no install hooks."
        ),
    )


# ---------------------------------------------------------------------------
# Orchestrator (fail-open)
# ---------------------------------------------------------------------------

async def scan_published_artifact(
    ecosystem: str,
    name: str,
    version: str | None = None,
    *,
    repo_paths: set[str] | None = None,
    repo_text_hashes: dict[str, str] | None = None,
    release_shas_resolver=None,
    client: httpx.AsyncClient | None = None,
) -> ArtifactScanResult:
    """Fetch → verify → unpack → scan → drift the published artifact. **Fail-open.**

    ``ecosystem`` is ``"npm"`` or ``"pypi"``. On ANY error returns
    ``ArtifactScanResult(ok=False, error=...)`` so the caller keeps the repo-only
    grade — an artifact lookup must never break a scan.
    """
    eco = (ecosystem or "").lower()
    result = ArtifactScanResult(ecosystem=eco, name=name, version=version or "")
    try:
        if eco == "npm":
            fetched = await fetch_npm_artifact(name, version, client=client)
        elif eco in ("pypi", "python"):
            fetched = await fetch_pypi_artifact(name, version, client=client)
        else:
            result.error = f"unsupported artifact ecosystem: {ecosystem!r}"
            return result

        if not fetched.ok:
            result.error = fetched.error or "artifact fetch failed"
            return result

        findings, files_scanned, has_hook = scan_artifact_files(fetched)
        # Prefer comparing the artifact against the RELEASE TAG it was built from
        # (accurate); the resolver returns {path: git-blob-sha} for that tag, or None
        # when no matching tag exists — then compute_drift falls back to the branch view.
        release_blob_shas = None
        if release_shas_resolver is not None and fetched.version:
            try:
                release_blob_shas = await release_shas_resolver(fetched.version)
            except Exception:  # noqa: BLE001 — never let tag resolution break a scan
                release_blob_shas = None
        drift, drift_findings = compute_drift(
            fetched, repo_paths, repo_text_hashes, has_install_hook=has_hook,
            release_blob_shas=release_blob_shas,
        )
        findings.extend(drift_findings)

        result.ok = True
        result.ecosystem = fetched.ecosystem
        result.version = fetched.version
        result.kind = fetched.kind
        result.digest = fetched.digest
        result.download_url = fetched.download_url
        result.findings = findings
        result.files_scanned = files_scanned
        result.unpacked_size = fetched.unpacked_size
        result.file_count = fetched.file_count
        result.drift = drift
        result.registry_snapshot = _registry_snapshot()
        return result
    except ArtifactFetchError as exc:
        result.error = str(exc)
        logger.warning("Artifact scan guard/fetch failed for %s:%s — repo-only fallback: %s",
                       eco, name, exc)
        return result
    except Exception as exc:  # noqa: BLE001 — fail-open is mandatory
        result.error = str(exc)
        logger.warning("Artifact scan errored for %s:%s — repo-only fallback",
                       eco, name, exc_info=True)
        return result
