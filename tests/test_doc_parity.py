"""Doc parity: what AGENTS.md tells people to run or open has to exist.

Checks, against the repo as it is checked out:
- every `make <target>` names a target in the Makefile;
- every `npm run <script>` names a script in web/package.json;
- every backticked repo path exists (globs and `{a,b}` lists must match something);
- every `tests/x.py::test_name` names a test function in that file.

No database, network or app import: `make doc-parity` runs it with `--noconftest`.
When a check fails, fix AGENTS.md or the file it points at, in the same PR.
"""

from __future__ import annotations

import json
import re
import subprocess
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTS_MD = ROOT / "AGENTS.md"

# Backticked tokens with a slash that are not repo paths.
NOT_PATHS = {
    "feat/", "fix/", "chore/", "docs/",  # branch-name prefixes
    "ghcr.io/agentavow/scanner",  # container image
    "/mcp",  # HTTP route
    "postgresql+asyncpg://",  # URL scheme
}
# Backticked bare names that are deliberately untracked (gitignored local files).
UNTRACKED_OK = {".env", ".venv"}
_PATH_CHARS = re.compile(r"^[\w.\-*/{},\[\]]+$")
_FILE_EXT = re.compile(r"\.(py|md|json|ya?ml|toml|ini|sh|mjs|js|ts|tsx|template|example)$")


def _text() -> str:
    return AGENTS_MD.read_text(encoding="utf-8")


def _backticked() -> set[str]:
    return {t.strip() for t in re.findall(r"`([^`\n]+)`", _text()) if t.strip()}


@lru_cache(maxsize=1)
def _repo_paths() -> tuple[frozenset[str], frozenset[str]]:
    """Tracked files and every folder that holds one, as POSIX paths relative to ROOT."""
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout
        files = {line for line in out.splitlines() if line}
    except (OSError, subprocess.CalledProcessError):
        skip = {".git", "node_modules", ".venv", ".venv312", ".claude"}
        files = {
            p.relative_to(ROOT).as_posix()
            for p in ROOT.rglob("*")
            if p.is_file() and not skip.intersection(p.relative_to(ROOT).parts)
        }
    dirs = {"/".join(f.split("/")[:i]) for f in files for i in range(1, f.count("/") + 1)}
    return frozenset(files), frozenset(dirs)


def _expand_braces(token: str) -> list[str]:
    m = re.search(r"\{([^{}]+)\}", token)
    if not m:
        return [token]
    out: list[str] = []
    for part in m.group(1).split(","):
        out.extend(_expand_braces(token[: m.start()] + part + token[m.end() :]))
    return out


def _exists(token: str) -> bool:
    """True if token names a tracked file or folder, at the root or nested.

    AGENTS.md often names a path relative to the folder it is describing (`js/` under
    `sdk/`, `ci.yml` under `.github/workflows/`), so a suffix match counts.
    """
    files, dirs = _repo_paths()
    want = token.rstrip("/")
    if "*" in want:
        pattern = re.compile(
            "(^|/)" + re.escape(want).replace(r"\*\*", ".*").replace(r"\*", "[^/]*") + "(/|$)"
        )
        return any(pattern.search(f) for f in files)
    if want in files or want in dirs:
        return True
    suffix = "/" + want
    return any(p.endswith(suffix) for p in files | dirs)


def _path_tokens() -> list[str]:
    tokens = []
    for tok in _backticked():
        tok = tok.split("::")[0]
        if tok in NOT_PATHS or tok in UNTRACKED_OK or not _PATH_CHARS.match(tok):
            continue
        if "[" in tok or "<" in tok:  # JSON pointers like plugins[0].version, placeholders
            continue
        if "/" in tok or _FILE_EXT.search(tok) or tok in {"Dockerfile", "Makefile"}:
            tokens.append(tok)
    return sorted(tokens)


def _make_targets() -> set[str]:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"^([A-Za-z0-9_.\-]+):(?!=)", text, flags=re.M))


def test_agents_md_exists():
    assert AGENTS_MD.is_file()


def test_make_targets_exist():
    named = set(re.findall(r"\bmake ([a-z][\w\-]*)", _text()))
    assert named, "expected AGENTS.md to name at least one make target"
    missing = sorted(named - _make_targets())
    assert not missing, f"AGENTS.md names make targets the Makefile lacks: {missing}"


def test_npm_scripts_exist():
    scripts = json.loads((ROOT / "web" / "package.json").read_text(encoding="utf-8"))["scripts"]
    named = set(re.findall(r"\bnpm run ([\w:\-]+)", _text()))
    missing = sorted(named - set(scripts))
    assert not missing, f"AGENTS.md names npm scripts web/package.json lacks: {missing}"


def test_repo_paths_exist():
    tokens = _path_tokens()
    assert len(tokens) > 20, f"path extraction looks broken: only {tokens}"
    missing = [
        tok for tok in tokens if not all(_exists(t) for t in _expand_braces(tok))
    ]
    assert not missing, f"AGENTS.md names paths that don't exist: {missing}"


def test_pytest_node_ids_exist():
    missing = []
    for file, name in re.findall(r"`(tests/[\w/]+\.py)::(\w+)`", _text()):
        path = ROOT / file
        if not path.is_file() or not re.search(
            rf"^\s*(async\s+)?def {re.escape(name)}\b", path.read_text(encoding="utf-8"), re.M
        ):
            missing.append(f"{file}::{name}")
    assert not missing, f"AGENTS.md names tests that don't exist: {missing}"


def test_checker_catches_a_missing_path():
    assert not _exists("src/definitely_not_a_real_module_402.py")
    assert _exists("src/scanner/verdict.py")
    assert _exists("ci.yml")
    assert _exists("scripts/corpus/**")
    assert all(_exists(t) for t in _expand_braces("src/scanner/{verdict,categories}.py"))
