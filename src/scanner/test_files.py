"""Is a test-named file in a repository really test code?

A file named ``test_*.py`` / ``*_test.py`` or sitting under ``tests/`` is graded like
test code: its findings drop to medium and never decide the answer. The name is the
author's choice, so in a repository (or local-tree) scan the exemption now holds only
when the file is test code by content or location AND nothing that runs uses it:

* test code: it lives under a ``test/`` / ``tests/`` / ``__tests__/`` directory, or it is
  a test module (Python: imports ``pytest`` / ``unittest``, defines ``test_``
  functions or ``TestCase`` classes; JS / TS: ``describe`` / ``it`` / ``test`` calls or
  a test-runner import);
* not used: no non-test code file of the tree imports it (Python ``import`` / ``from …
  import`` / ``importlib.import_module``, resolved by module path; JS / TS relative
  ``require`` / ``import``) or names it as a file to run, and no ``package.json``
  entry point or non-test script, ``setup.py`` / ``setup.cfg`` / ``pyproject.toml``
  entry, ``Procfile`` line or ``Dockerfile`` ``CMD`` / ``ENTRYPOINT`` names it.

Only files exempt for being tests are judged (not docs / examples / fixtures /
benchmarks, co-located ``.test.`` / ``.spec.`` files or ``conftest.py``). Package
scans are unchanged: there the installed-file check decides. Pure text analysis over
the texts the scan already read; bounded by the number of files.
"""
from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Callable
from pathlib import PurePosixPath

_TEST_DIRS = frozenset({"test", "tests", "__tests__"})
# Other directories that exempt a file on their own (see scan._BLOCKING_EXEMPT_DIRS):
# a file there is not judged here.
_OTHER_EXEMPT_DIRS = frozenset({
    "example", "examples", "sample", "samples", "e2e", "integration", "fixture",
    "fixtures", "spec", "benchmark", "benchmarks", "bench", "benches", "docs", "doc",
})
_PY_EXTS = frozenset({".py"})
_JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"})
_CODE_EXTS = _PY_EXTS | _JS_EXTS

_PY_TEST_RE = re.compile(
    r"^\s*(?:import\s+(?:pytest|unittest)\b|from\s+(?:pytest|unittest)\b)"
    r"|^\s*(?:async\s+)?def\s+test(?:_\w*)?\s*\(|^\s*class\s+\w+\s*\([^)]*TestCase\b",
    re.MULTILINE)
_JS_TEST_RE = re.compile(
    r"^\s*(?:describe|it|test)(?:\.(?:each|only|skip)\b[^(]*)?\s*\("
    r"|(?:require\s*\(\s*|from\s+)['\"](?:node:test|vitest|mocha|ava|tap|@jest/globals|"
    r"chai|uvu)['\"]", re.MULTILINE)

_PY_IMPORT_RE = re.compile(
    r"^[ \t]*import[ \t]+([\w.]+(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[\w.]+"
    r"(?:[ \t]+as[ \t]+\w+)?)*)", re.MULTILINE)
_PY_FROM_RE = re.compile(
    r"^[ \t]*from[ \t]+(\.*)([\w.]*)[ \t]+import[ \t]+(?:\(([^)]*)\)|([^\n]+))",
    re.MULTILINE)
_PY_DYN_RE = re.compile(r"""(?:import_module|__import__)\s*\(\s*['"]([\w.]+)['"]""")
_JS_SPEC_RE = re.compile(
    r"""(?:\brequire\s*\(\s*|\bfrom\s+|\bimport\s*\(\s*|^\s*import\s+)['"]([^'"\n]+)['"]""",
    re.MULTILINE)

# Lines of a Python packaging file that configure the test run, not an entry point.
_TEST_CONFIG_LINE_RE = re.compile(
    r"test_suite|tests_require|testpaths|pytest|python_files|addopts|norecursedirs|"
    r"\[tool\.(?:coverage|tox|nox)|tox|coverage", re.IGNORECASE)
_NPM_TEST_SCRIPT_RE = re.compile(r"^(?:pre|post)?(?:test|lint|coverage|ci|check|e2e)\b")
_PY_PACKAGING = frozenset({"setup.py", "setup.cfg", "pyproject.toml"})


def _parts(path: str) -> list[str]:
    return [p.lower() for p in PurePosixPath(path).parts[:-1]]


def _suffix(path: str) -> str:
    return PurePosixPath(path.lower()).suffix


def _stem(path: str) -> str:
    return PurePosixPath(path).stem


def _in_test_dir(path: str) -> bool:
    return any(p in _TEST_DIRS for p in _parts(path))


def judged(path: str) -> bool:
    """A code file exempt only for being a test (by directory or by name)."""
    if _suffix(path) not in _CODE_EXTS:
        return False
    name = PurePosixPath(path).name.lower()
    stem = _stem(path).lower()
    if any(p in _OTHER_EXEMPT_DIRS for p in _parts(path)):
        return False
    if ".test." in name or ".spec." in name or stem.endswith("_spec") or stem == "conftest":
        return False
    return _in_test_dir(path) or stem.startswith("test_") or stem.endswith("_test")


def is_test_code(path: str, text: str) -> bool:
    if _in_test_dir(path):
        return True
    rx = _PY_TEST_RE if _suffix(path) in _PY_EXTS else _JS_TEST_RE
    return bool(rx.search(text or ""))


def _module_names(path: str) -> list[str]:
    """Dotted names the file can be imported by, longest first (``a.tests.util``,
    ``tests.util``, ``util``); a package ``__init__`` is its directory."""
    p = PurePosixPath(path)
    parts = list(p.parts[:-1]) + ([] if p.stem == "__init__" else [p.stem])
    return [".".join(parts[i:]) for i in range(len(parts)) if parts[i:]]


def _py_imports(path: str, text: str) -> tuple[set[str], set[str]]:
    """(absolute dotted names, repo-relative module paths of relative imports)."""
    names: set[str] = set()
    rel: set[str] = set()
    for m in _PY_IMPORT_RE.finditer(text):
        for part in m.group(1).split(","):
            names.add(part.split(" as ")[0].strip())
    for m in _PY_FROM_RE.finditer(text):
        dots, mod, items = m.group(1), m.group(2), m.group(3) or m.group(4) or ""
        items = items.split("#")[0] if m.group(4) else items
        subs = [s.split(" as ")[0].strip() for s in items.replace("\n", " ").split(",")]
        subs = [s for s in subs if re.fullmatch(r"\w+", s or "")]
        if dots:
            base = PurePosixPath(path).parent
            for _ in range(len(dots) - 1):
                base = base.parent
            target = posixpath.normpath(posixpath.join(str(base), *mod.split("."))) \
                if mod else posixpath.normpath(str(base))
            rel.add(target)
            rel.update(posixpath.normpath(posixpath.join(target, s)) for s in subs)
        elif mod:
            names.add(mod)
            names.update(f"{mod}.{s}" for s in subs)
    names.update(m.group(1) for m in _PY_DYN_RE.finditer(text))
    return names, rel


def _py_imported(path: str, users: dict[str, str]) -> bool:
    mods = _module_names(path)
    own = posixpath.normpath(str(PurePosixPath(path).with_suffix("")))
    if PurePosixPath(path).stem == "__init__":
        own = posixpath.normpath(str(PurePosixPath(path).parent))
    stem = mods[-1] if mods else ""
    for q, text in users.items():
        if _suffix(q) not in _PY_EXTS:
            continue
        names, rel = _py_imports(q, text)
        if own in rel:
            return True
        for n in names:
            if n in mods[:-1]:            # a dotted path of two or more parts
                return True
            if n == stem and (posixpath.dirname(q) == posixpath.dirname(path)
                              or not posixpath.dirname(path)):
                return True               # a sibling / top-level module by bare name
    return False


def _js_imported(path: str, users: dict[str, str]) -> bool:
    own = posixpath.normpath(path)
    no_ext = posixpath.splitext(own)[0]
    for q, text in users.items():
        if _suffix(q) not in _JS_EXTS:
            continue
        for m in _JS_SPEC_RE.finditer(text):
            spec = m.group(1)
            if not spec.startswith("."):
                continue
            t = posixpath.normpath(posixpath.join(posixpath.dirname(q), spec))
            if t in (own, no_ext) or posixpath.join(t, "index") == no_ext:
                return True
    return False


def _named_re(path: str) -> re.Pattern[str]:
    """How a file to run is named: by its tree path (``tests/run.py``) when it sits in
    a test directory (a generic basename there names nothing in particular), else by
    its basename (``test_x.py``)."""
    if _in_test_dir(path):
        target = re.escape(path)
    else:
        target = re.escape(PurePosixPath(path).name)
    return re.compile(r"(?<![\w.\-])" + target + r"(?![\w\-])")


def _manifest_names(path: str, texts: dict[str, str]) -> bool:
    named = _named_re(path)
    stem = _stem(path)
    mods = [n for n in _module_names(path) if "." in n] + (
        [] if _in_test_dir(path) else [stem])
    mod_re = re.compile(r"(?<![\w.])(?:" + "|".join(re.escape(m) for m in mods) + r")(?![\w])") \
        if mods else None
    for q, text in texts.items():
        name = PurePosixPath(q).name
        low = name.lower()
        if low == "package.json":
            if _package_json_names(path, q, text):
                return True
        elif low in _PY_PACKAGING:
            for ln in text.split("\n"):
                if _TEST_CONFIG_LINE_RE.search(ln):
                    continue
                if named.search(ln) or (mod_re is not None and mod_re.search(ln)):
                    return True
        elif name == "Procfile":
            if named.search(text):
                return True
        elif name == "Dockerfile" or name.startswith("Dockerfile.") \
                or low.endswith(".dockerfile"):
            for ln in text.split("\n"):
                if re.match(r"\s*(?:CMD|ENTRYPOINT)\b", ln) and named.search(ln):
                    return True
    return False


def _package_json_names(path: str, manifest: str, text: str) -> bool:
    try:
        data = json.loads(text)
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    root = posixpath.dirname(manifest)
    rel = posixpath.relpath(path, root) if root else path
    if rel.startswith(".."):
        return False
    strings: list[str] = []

    def walk(v) -> None:
        if isinstance(v, str):
            strings.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    for key in ("main", "module", "bin", "exports", "browser"):
        walk(data.get(key))
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for k, v in scripts.items():
            if isinstance(k, str) and not _NPM_TEST_SCRIPT_RE.match(k):
                walk(v)
    rel_no_ext = posixpath.splitext(rel)[0]
    named = _named_re(rel)
    for s in strings:
        n = posixpath.normpath(s.split("?")[0]) if s.startswith(".") else s
        if n in (rel, rel_no_ext) or named.search(s):
            return True
    return False


def not_really_tests(texts: dict[str, str], *, runs_for_consumer: Callable[[str], bool]
                     ) -> set[str]:
    """Paths of judged (test-exempt) files that are not test code, or that non-test
    code imports or runs. ``runs_for_consumer(path)``: the scanner's own rule for a
    file that is shipped code (not test / doc / example / CI / build tooling)."""
    judged_paths = [p for p in texts if judged(p)]
    if not judged_paths:
        return set()
    users = {q: t for q, t in texts.items()
             if _suffix(q) in _CODE_EXTS and not judged(q) and runs_for_consumer(q)}
    out: set[str] = set()
    for p in judged_paths:
        text = texts.get(p) or ""
        if not is_test_code(p, text):
            out.add(p)
            continue
        others = {q: t for q, t in users.items() if q != p}
        used = (_py_imported(p, others) if _suffix(p) in _PY_EXTS
                else _js_imported(p, others))
        if used or any(_named_re(p).search(t) for t in others.values()) \
                or _manifest_names(p, texts):
            out.add(p)
    return out
