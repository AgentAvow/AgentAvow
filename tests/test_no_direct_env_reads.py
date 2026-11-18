"""Settings come from src/config.py, not from os.environ (#403).

An AST check, not a text search: the scanner's pattern files and fixtures contain
``os.environ`` as detection data, and those strings must not trip it. It counts real
uses of ``os.environ`` / ``os.getenv`` (and putenv/unsetenv, ``import os as x``
aliases, and ``from os import environ``) in every module under ``src/``.

``BASELINE`` holds the reads that existed when the rule landed. A file may not go
above its baseline count, and a file not in the baseline may have none. To add a
setting, add a field to ``Settings`` in src/config.py (and a line to .env.example)
and read ``settings.<field>``. When you remove a baselined read, lower its count.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# The settings module itself is allowed to read the environment.
ALLOWED_FILES = {"src/config.py"}

_ENV_NAMES = {"environ", "environb", "getenv", "getenvb", "putenv", "unsetenv"}

# Direct reads that existed when the rule landed (2026-11-16). Counts per file.
BASELINE: dict[str, int] = {
    # Separate package with its own env-driven config (ERC-8004 bridge).
    "src/agentgraph_bridge_erc8004/abi/__init__.py": 1,
    "src/agentgraph_bridge_erc8004/config.py": 7,
    "src/agentgraph_bridge_erc8004/tests/test_registry_reader.py": 1,
    "src/api/erc8004_router.py": 2,
    "src/bridges/mcp_streamable.py": 2,
    "src/jobs/erc8004_self_watch.py": 1,
    # Writes BLUESKY_* into os.environ for the marketing job.
    "src/jobs/scheduler.py": 8,
    "src/marketing/reply_guy/monitor.py": 1,
    # CI-side scanner entry points: run in the slim scanner image, read CI variables.
    "src/scanner/ci_bitbucket.py": 1,
    "src/scanner/local_scan.py": 2,
}


def find_env_reads(source: str, filename: str = "<string>") -> list[int]:
    """Line numbers of direct environment access in ``source``."""
    tree = ast.parse(source, filename)
    os_aliases = {"os"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    os_aliases.add(alias.asname or "os")
    lines: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in os_aliases
            and node.attr in _ENV_NAMES
        ):
            lines.append(node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            lines.extend(node.lineno for a in node.names if a.name in _ENV_NAMES)
    return sorted(lines)


def _scan_src() -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if rel in ALLOWED_FILES:
            continue
        hits = find_env_reads(path.read_text(encoding="utf-8"), rel)
        if hits:
            found[rel] = hits
    return found


def test_no_new_direct_env_reads_in_src():
    over = []
    for rel, hits in _scan_src().items():
        allowed = BASELINE.get(rel, 0)
        if len(hits) > allowed:
            over.append(f"{rel}: {len(hits)} direct env reads (allowed {allowed}), "
                        f"lines {hits}")
    assert not over, (
        "Read settings from src/config.py instead of os.environ / os.getenv:\n  "
        + "\n  ".join(over)
    )


def test_baseline_has_no_stale_entries():
    """A baselined file that no longer exists, or has fewer reads, must be lowered
    so the allowance can't be reused by a new read."""
    found = _scan_src()
    stale = [
        f"{rel}: baseline {n}, now {len(found.get(rel, []))}"
        for rel, n in BASELINE.items()
        if len(found.get(rel, [])) < n
    ]
    assert not stale, "Lower these BASELINE counts:\n  " + "\n  ".join(stale)


# --- The rule itself ---------------------------------------------------------

def test_rule_catches_planted_reads():
    planted = (
        "import os\n"
        "import os as _os\n"
        "from os import getenv\n"
        "a = os.environ['X']\n"
        "b = os.getenv('Y')\n"
        "c = _os.environ.get('Z')\n"
        "os.environ['W'] = '1'\n"
    )
    assert find_env_reads(planted) == [3, 4, 5, 6, 7]


def test_rule_ignores_strings_and_comments():
    # Scanner pattern files carry these as detection data.
    source = (
        "PATTERNS = ['os.environ', r'os\\.getenv\\(']\n"
        "# os.environ['SECRET'] in a comment\n"
        "doc = 'call os.getenv(\"TOKEN\")'\n"
        "settings_environ = 1\n"
    )
    assert find_env_reads(source) == []


def test_planted_read_in_src_file_fails(tmp_path, monkeypatch):
    """End to end: a new module under src/ with an env read fails the check."""
    fake_root = tmp_path
    (fake_root / "src").mkdir()
    (fake_root / "src" / "new_module.py").write_text(
        "import os\nTOKEN = os.getenv('TOKEN')\n", encoding="utf-8"
    )
    mod = sys.modules[__name__]
    monkeypatch.setattr(mod, "ROOT", fake_root)
    monkeypatch.setattr(mod, "SRC", fake_root / "src")
    try:
        test_no_new_direct_env_reads_in_src()
    except AssertionError as exc:
        assert "src/new_module.py" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("planted os.getenv read was not caught")
