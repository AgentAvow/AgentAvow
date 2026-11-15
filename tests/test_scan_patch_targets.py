"""Guard for the scan.py split (#415): no test patch on ``src.scanner.scan`` may go silent.

Tests patch scanner internals through ``src.scanner.scan`` (for example
``monkeypatch.setattr("src.scanner.scan._fetch_file_content", fake)``). While the
patched function and every caller of it live in ``scan.py``, that works. Once code
moves into ``src/scanner/static/``, a caller that now lives next to the real function
looks the name up in its own module, so a patch on ``scan`` no longer reaches it: the
test still passes but tests nothing.

This test lists every patch target on ``src.scanner.scan`` in ``tests/`` and fails when
a target is defined outside ``scan.py`` while some module under ``src/scanner/static/``
still reads that name directly. The fix is to point those tests at the module that
now defines the name, in the same step that moved it.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
STATIC = ROOT / "src" / "scanner" / "static"
SCAN_MODULE = "src.scanner.scan"

# Dotted-string targets: monkeypatch.setattr("src.scanner.scan.X", ...), patch("...X").
_STRING_TARGET = re.compile(r"""["']src\.scanner\.scan\.([A-Za-z_][A-Za-z0-9_]*)["']""")
# Names a test binds to the scan module.
_ALIAS_PATTERNS = (
    re.compile(r"^\s*import\s+src\.scanner\.scan\s+as\s+(\w+)", re.M),
    re.compile(r"^\s*from\s+src\.scanner\s+import\s+scan(?:\s+as\s+(\w+))?\s*$", re.M),
    re.compile(
        r"""^\s*(\w+)\s*=\s*importlib\.import_module\(\s*["']src\.scanner\.scan["']\s*\)""",
        re.M,
    ),
)


def _object_targets(text: str) -> set[str]:
    """Names patched via setattr(<scan alias>, "X") or patch.object(<scan alias>, "X")."""
    aliases: set[str] = set()
    for pattern in _ALIAS_PATTERNS:
        for match in pattern.finditer(text):
            aliases.add(match.group(1) or "scan")
    found: set[str] = set()
    for alias in aliases:
        call = re.compile(
            r"(?:setattr|patch\.object)\(\s*" + re.escape(alias) + r"""\s*,\s*["'](\w+)["']"""
        )
        found.update(call.findall(text))
    return found


def collect_patch_targets(tests_dir: Path = TESTS) -> dict[str, set[str]]:
    """Map each patched name on src.scanner.scan to the test files that patch it."""
    targets: dict[str, set[str]] = {}
    for path in sorted(tests_dir.rglob("*.py")):
        if path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        names = set(_STRING_TARGET.findall(text)) | _object_targets(text)
        for name in names:
            targets.setdefault(name, set()).add(str(path.relative_to(tests_dir.parent)))
    return targets


def static_readers(name: str, static_dir: Path = STATIC) -> list[str]:
    """Modules under src/scanner/static that read ``name`` as a plain name."""
    readers: list[str] = []
    if not static_dir.is_dir():
        return readers
    for path in sorted(static_dir.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(
            isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)
            for node in ast.walk(tree)
        ):
            readers.append(str(path.relative_to(static_dir.parents[2])))
    return readers


def silent_patches(scan_module, targets: dict[str, set[str]], static_dir: Path = STATIC):
    """Return (name, defining module, readers, test files) for each patch that would go silent."""
    problems = []
    for name in sorted(targets):
        obj = getattr(scan_module, name, None)
        home = getattr(obj, "__module__", None)
        if home is None or home == SCAN_MODULE:
            continue
        readers = static_readers(name, static_dir)
        if readers:
            problems.append((name, home, readers, sorted(targets[name])))
    return problems


def test_patch_targets_found():
    """The scan finds today's known patch targets, so a broken regex can't pass silently."""
    targets = collect_patch_targets()
    for expected in ("_fetch_file_content", "_fetch_repo_tree", "scan_package"):
        assert expected in targets, f"patch target {expected!r} no longer detected"


# Already patched with raising=False on a name scan.py never defined at module level
# (scan imports it inside functions), so these patches do nothing on main today. Fix them
# in their own PR; listed here so the guard starts green.
KNOWN_ABSENT = {"get_github_token"}


def test_patch_targets_exist_on_scan():
    from src.scanner import scan

    missing = sorted(
        name
        for name in collect_patch_targets()
        if not hasattr(scan, name) and name not in KNOWN_ABSENT
    )
    assert not missing, (
        f"tests patch names that src.scanner.scan no longer exposes: {missing}. "
        "Re-export them from scan.py or point the tests at the new module."
    )


def test_no_silent_patches():
    from src.scanner import scan

    problems = silent_patches(scan, collect_patch_targets())
    assert not problems, "\n".join(
        f"{name} now lives in {home} and is read by {', '.join(readers)}; "
        f"patching src.scanner.scan.{name} no longer reaches those callers. "
        f"Point these tests at {home}: {', '.join(files)}"
        for name, home, readers, files in problems
    )


@pytest.fixture
def planted(tmp_path):
    """A fake static package where a moved function and its caller sit together."""
    static = tmp_path / "src" / "scanner" / "static"
    static.mkdir(parents=True)
    (static / "__init__.py").write_text("")
    (static / "fetch.py").write_text(
        "def _fetch_file_content():\n    return 'real'\n\n"
        "def caller():\n    return _fetch_file_content()\n"
    )
    return static


def test_guard_fires_on_planted_violation(planted):
    """Self-check: a patched name defined and read inside static/ is reported."""

    def _fetch_file_content():
        return "real"

    _fetch_file_content.__module__ = "src.scanner.static.fetch"

    class FakeScan:
        pass

    FakeScan._fetch_file_content = staticmethod(_fetch_file_content)
    targets = {"_fetch_file_content": {"tests/test_example.py"}}
    problems = silent_patches(FakeScan, targets, planted)
    assert problems and problems[0][0] == "_fetch_file_content"


def test_guard_quiet_when_callers_stay_in_scan(planted):
    """A name still defined in scan.py is never reported, even if static/ reads it."""

    def _fetch_file_content():
        return "real"

    _fetch_file_content.__module__ = SCAN_MODULE

    class FakeScan:
        pass

    FakeScan._fetch_file_content = staticmethod(_fetch_file_content)
    targets = {"_fetch_file_content": {"tests/test_example.py"}}
    assert silent_patches(FakeScan, targets, planted) == []
