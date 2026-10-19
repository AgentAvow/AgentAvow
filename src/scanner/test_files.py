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

Also named: a wheel's ``*.dist-info/entry_points.txt`` (``pytest11``,
``console_scripts`` ...), ``package.json`` ``files``, and an MCP / server config's
``command`` / ``args`` (any JSON / YAML / TOML config with those keys that is not
CI or test-runner configuration).

Two location rules on top (review of #199):

* ``conftest.py`` is pytest's own: exempt in a test directory or at the top of a
  repository, never inside an importable package directory (one with
  ``__init__.py``) or anywhere else in a published package, where it runs in the
  consumer's pytest.
* a top-level ``tests/`` / ``test/`` package (with ``__init__.py``) that is itself
  an import name is shipped code: a wheel's top-level directory, a name in
  ``packages=[...]``, ``find_packages()`` / ``packages = find:`` with no ``exclude``,
  a ``[tool.setuptools.packages.find]`` with no ``exclude``, or the project's name.

Judged: files exempt for being tests (test directories, ``test_*`` / ``*_test`` /
``*_spec`` names, co-located ``.test.`` / ``.spec.`` files, ``conftest.py``), not docs
/ examples / fixtures / benchmarks. Applied to repository, local-tree and package
scans (``scan_artifact_files``; there an uninstalled file stays informational).
Pure text analysis over the texts the scan already read; bounded by the number of
files.
"""
from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Callable, Iterable
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
# Calls of a test runner's globals, also compiled (`(0, vitest_1.describe)(...`).
_JS_TEST_RE = re.compile(
    r"(?<![\w$])(?:describe|it|test|suite|beforeEach|beforeAll|afterEach|afterAll)"
    r"(?:\.(?:each|only|skip|todo|concurrent)\b[^(]*)?\s*\)?\s*\("
    r"|(?:require\s*\(\s*|from\s+)['\"](?:node:test|vitest|mocha|ava|tap|@jest/globals|"
    r"chai|uvu|jest|sinon|supertest|@testing-library/[\w-]+)['\"]", re.MULTILINE)

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

# Lines of a Python packaging file that configure the test run, not an entry point
# (a `pytest11` entry point is NOT one: it loads the module into every pytest run).
_TEST_CONFIG_LINE_RE = re.compile(
    r"testpaths|python_files|addopts|norecursedirs|\[tool[.:](?:pytest|coverage|tox|nox)|"
    r"\btox\b|\bcoverage\b", re.IGNORECASE)
# `test_suite='tests'` / `tests_require=[...]` inside an otherwise meaningful line.
_TEST_CONFIG_KV_RE = re.compile(
    r"""\b(?:test_suite|tests_require)\s*[=:]\s*(?:\[[^\]]*\]|['"][^'"]*['"])""")
_NPM_TEST_SCRIPT_RE = re.compile(
    r"^(?:pre|post)?(?:tests?|lint|coverage|cover|ci|check|e2e|unit|integration|bench\w*|"
    r"typecheck|tsd)\b|[:_-](?:tests?|unit|e2e|integration|coverage)\b")
# A script that runs a test runner (`tape test/*.js`, `nyc mocha`) runs the test suite.
_TEST_RUNNER_RE = re.compile(
    r"\b(?:tape|jest|mocha|vitest|ava|nyc|c8|tap|tsd|karma|jasmine|uvu|playwright|cypress|"
    r"borp|lab|pytest|tox|nox)\b|\bnode\s+--test\b")
# Scripts that run for whoever installs or starts the package.
_NPM_RUN_SCRIPTS = frozenset({"preinstall", "install", "postinstall", "prepare", "start"})
# Packaging sections that name what is installed or run (not tool configuration such as
# `[tool.ruff.per-file-ignores]`, which names test files to lint them).
_ENTRY_SECTION_RE = re.compile(
    r"^(?:project\.(?:scripts|gui-scripts|entry-points(?:\..+)?)|tool\.poetry\."
    r"(?:scripts|plugins(?:\..+)?|packages)|tool\.setuptools(?:\..+)?|options(?:\..+)?|"
    r"entry_points|metadata)$")
_PY_PACKAGING = frozenset({"setup.py", "setup.cfg", "pyproject.toml", "entry_points.txt"})
_CONFIG_EXTS = frozenset({".json", ".yaml", ".yml", ".toml"})
_CMD_KEY_RE = re.compile(r"""['"]?\b(?:command|args|cmd|entrypoint)\b['"]?\s*[:=]""",
                         re.IGNORECASE)


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
    return (_in_test_dir(path) or stem.startswith("test_") or stem.endswith(("_test", "_spec"))
            or stem == "conftest" or ".test." in name or ".spec." in name)


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


def _named_re(path: str) -> re.Pattern[str]:
    """How a file to run is named: by its tree path (``tests/run.py``) when it sits in
    a test directory (a generic basename there names nothing in particular), else by
    its basename (``test_x.py``)."""
    if _in_test_dir(path):
        target = re.escape(path)
    else:
        target = re.escape(PurePosixPath(path).name)
    return re.compile(r"(?<![\w.\-])" + target + r"(?![\w\-])")


def runs_test_tooling(path: str) -> bool:
    """CI and test-runner configs: what they run is the maintainer's test suite."""
    parts = [p.lower() for p in PurePosixPath(path).parts]
    name = parts[-1] if parts else ""
    return (any(p in (".github", ".gitlab", ".circleci", ".buildkite", "workflows")
                for p in parts)
            or name in (".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml",
                        "codecov.yml", ".codecov.yml", "package.json",
                        ".pre-commit-config.yaml", "docker-compose.test.yml")
            or name.startswith(("jest.", "vitest.", ".mocharc", "karma.", "cypress.",
                                "playwright.", "tsconfig.", "tox.", "pytest.")))


# A file path as a whole string literal in code (`'tests/run.py'`, `"./test_x.js"`):
# what the code names to run. Prose and URLs in docstrings are not.
_FILE_TOKEN_RE = re.compile(
    r"""['"`](?:\./)?((?:\.\./)*[\w\-][\w.\-/]*\.(?:py|[cm]?[jt]sx?))['"`]""")


def _package_json_strings(text: str) -> list[str] | None:
    """Strings of a package.json that name what runs or ships: main / module / bin /
    exports / browser / files and every script that is not a test / lint script."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
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

    for key in ("main", "module", "bin", "exports", "browser", "files"):
        walk(data.get(key))
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for k, v in scripts.items():
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            if k in _NPM_RUN_SCRIPTS or not (
                    _NPM_TEST_SCRIPT_RE.search(k) or _TEST_RUNNER_RE.search(v)):
                walk(v)
    return strings


def _entry_lines(name: str, text: str) -> list[str]:
    """The lines of a Python packaging file that can name a module to install or run:
    all of ``setup.py`` and ``entry_points.txt``; only entry-point / package sections
    of ``setup.cfg`` and ``pyproject.toml``. Test-run configuration is dropped."""
    out: list[str] = []
    keep = name in ("setup.py", "entry_points.txt")
    for ln in text.split("\n"):
        if name not in ("setup.py", "entry_points.txt"):
            m = re.match(r"\s*\[+\s*([^\]]+?)\s*\]+\s*$", ln)
            if m:
                keep = bool(_ENTRY_SECTION_RE.match(m.group(1).strip().strip('"')))
                continue
        if not keep:
            continue
        ln = _TEST_CONFIG_KV_RE.sub(" ", ln)
        if ln.strip() and not _TEST_CONFIG_LINE_RE.search(ln):
            out.append(ln)
    return out


class _Index:
    """What the runtime code and manifests of one tree import, run and name, read once
    (a large package has thousands of test files and hundreds of runtime modules)."""

    def __init__(self, texts: dict[str, str], users: dict[str, str]) -> None:
        self.py_names: set[str] = set()
        self.py_bare_by_dir: dict[str, set[str]] = {}
        self.py_rel: set[str] = set()
        self.js_targets: set[str] = set()
        self.tokens: set[str] = set()
        for q, text in users.items():
            for m in _FILE_TOKEN_RE.finditer(text):
                self.tokens.add(m.group(1))
            if _suffix(q) in _PY_EXTS:
                names, rel = _py_imports(q, text)
                self.py_names |= names
                self.py_rel |= rel
                self.py_bare_by_dir.setdefault(posixpath.dirname(q), set()).update(
                    n for n in names if "." not in n)
            else:
                for m in _JS_SPEC_RE.finditer(text):
                    spec = m.group(1)
                    if spec.startswith("."):
                        self.js_targets.add(
                            posixpath.normpath(posixpath.join(posixpath.dirname(q), spec)))
        # Manifests: (kind, path, payload) read once.
        self.pkg_json: list[tuple[str, list[str]]] = []
        self.packaging: list[str] = []            # meaningful lines, test config removed
        self.texts_named: list[str] = []          # configs / Procfiles: whole text
        self.docker_lines: list[str] = []
        for q, text in texts.items():
            if any(d in _TEST_DIRS or d in _OTHER_EXEMPT_DIRS for d in _parts(q)):
                continue                  # a fixture package's manifest, not this one's
            name = PurePosixPath(q).name
            low = name.lower()
            if low == "package.json":
                strings = _package_json_strings(text)
                if strings:
                    self.pkg_json.append((q, strings))
            elif low in _PY_PACKAGING:
                self.packaging += _entry_lines(low, text)
            elif (_suffix(q) in _CONFIG_EXTS and not runs_test_tooling(q)
                  and _CMD_KEY_RE.search(text)):
                self.texts_named.append(text)      # an MCP / server config
            elif name == "Procfile":
                self.texts_named.append(text)
            elif name == "Dockerfile" or name.startswith("Dockerfile.") \
                    or low.endswith(".dockerfile"):
                self.docker_lines += [ln for ln in text.split("\n")
                                      if re.match(r"\s*(?:CMD|ENTRYPOINT)\b", ln)]
        self.packaging_text = "\n".join(self.packaging)

    def imported(self, path: str) -> bool:
        if _suffix(path) in _PY_EXTS:
            mods = _module_names(path)
            own = posixpath.normpath(str(PurePosixPath(path).with_suffix("")))
            if PurePosixPath(path).stem == "__init__":
                own = posixpath.normpath(str(PurePosixPath(path).parent))
            if own in self.py_rel or any(m in self.py_names for m in mods[:-1]):
                return True
            stem = mods[-1] if mods else ""
            d = posixpath.dirname(path)
            # a sibling / top-level module imported by bare name
            if stem in self.py_bare_by_dir.get(d, ()):
                return True
            return not d and stem in self.py_names
        own = posixpath.normpath(path)
        no_ext = posixpath.splitext(own)[0]
        cands = {own, no_ext}
        if PurePosixPath(no_ext).name == "index":
            cands.add(posixpath.dirname(no_ext))   # `require('./tests')` -> tests/index
        return bool(cands & self.js_targets)

    def code_names(self, path: str) -> bool:
        """Runtime code names the file as one to run (``runpy.run_path('test_x.py')``,
        ``spawn('node', ['tests/run.js'])``)."""
        target = path if _in_test_dir(path) else PurePosixPath(path).name
        return any(t == target or t.endswith("/" + target) for t in self.tokens)

    def manifests_name(self, path: str) -> bool:
        named = _named_re(path)
        stem = _stem(path)
        mods = [n for n in _module_names(path) if "." in n] + (
            [] if _in_test_dir(path) else [stem])
        if self.packaging_text:
            if named.search(self.packaging_text):
                return True
            if mods and re.search(r"(?<![\w.])(?:" + "|".join(re.escape(m) for m in mods)
                                  + r")(?![\w])", self.packaging_text):
                return True
        if any(named.search(t) for t in self.texts_named):
            return True
        if any(named.search(ln) for ln in self.docker_lines):
            return True
        for manifest, strings in self.pkg_json:
            root = posixpath.dirname(manifest)
            rel = posixpath.relpath(path, root) if root else path
            if rel.startswith(".."):
                continue
            rel_no_ext = posixpath.splitext(rel)[0]
            rel_named = _named_re(rel)
            for sv in strings:
                n = posixpath.normpath(sv.split("?")[0]) if sv.startswith(".") else sv
                if n in (rel, rel_no_ext) or rel_named.search(sv):
                    return True
        return False


_FIND_PKGS_RE = re.compile(r"\bfind_(?:namespace_)?packages\s*\(([^)]*)\)")
_CFG_FIND_RE = re.compile(r"^\s*packages\s*=\s*find(?:_namespace)?:", re.MULTILINE)
_CFG_FIND_SECTION_RE = re.compile(r"^\s*\[options\.packages\.find\]([^\[]*)", re.MULTILINE)
_TOML_FIND_RE = re.compile(r"^\s*\[tool\.setuptools\.packages\.find\]([^\[]*)",
                           re.MULTILINE)
_NARROWS_RE = re.compile(r"^\s*(?:exclude|where|include)\s*=", re.MULTILINE)
_NAME_RE = re.compile(r"""\bname\s*=\s*['"]?([\w.-]+)""")


def _find_all(args: str) -> bool:
    """A ``find_packages(...)`` call that lists the root's top-level packages with no
    exclude: no arguments, or only ``where='.'`` / ``'.'``."""
    a = args.strip()
    if not a:
        return True
    if "exclude" in a or "include" in a:
        return False
    return bool(re.fullmatch(r"""(?:where\s*=\s*)?['"]\.?/?['"]""", a))


def import_name_test_dirs(texts: dict[str, str], *, wheel: bool = False,
                          paths: set[str] | None = None) -> set[str]:
    """Top-level ``tests`` / ``test`` packages (with ``__init__.py``) that are import
    names: a wheel's top-level directory, or one the root packaging lists
    (``packages=[...]``, ``find_packages()`` / ``packages = find:`` with no exclude, a
    ``[tool.setuptools.packages.find]`` with no exclude, the project's own name)."""
    out: set[str] = set()
    for d in ("tests", "test"):
        if f"{d}/__init__.py" not in (paths if paths is not None else texts):
            continue
        if wheel:
            out.add(d)
            continue
        setup_py = texts.get("setup.py", "")
        cfg = texts.get("setup.cfg", "")
        toml = texts.get("pyproject.toml", "")
        listed = re.compile(r"""\bpackages\s*=\s*\[[^\]]*['"]""" + d + r"""['"]""")
        names = {m.group(1) for t in (setup_py, cfg, toml) for m in _NAME_RE.finditer(t)}
        cfg_find = _CFG_FIND_RE.search(cfg) and not any(
            _NARROWS_RE.search(m.group(1)) for m in _CFG_FIND_SECTION_RE.finditer(cfg))
        if (listed.search(setup_py) or listed.search(toml) or cfg_find
                or any(_find_all(m.group(1)) for m in _FIND_PKGS_RE.finditer(setup_py))
                or any(not _NARROWS_RE.search(m.group(1))
                       for m in _TOML_FIND_RE.finditer(toml))
                or d in names):
            out.add(d)
    return out


def _conftest_shipped(path: str, paths: set[str], wheel: bool) -> bool:
    """A ``conftest.py`` outside a test directory inside an importable package (its
    directory has ``__init__.py``), or anywhere in a wheel (installed as is)."""
    if _in_test_dir(path):
        return False
    if wheel:
        return True
    parent = posixpath.dirname(path)
    return bool(parent) and posixpath.join(parent, "__init__.py") in paths


def not_really_tests(texts: dict[str, str], *, runs_for_consumer: Callable[[str], bool],
                     wheel: bool = False, paths: Iterable[str] | None = None
                     ) -> set[str]:
    """Paths of judged (test-exempt) files that are not test code, or that non-test
    code imports or runs. ``runs_for_consumer(path)``: the scanner's own rule for a
    file that is shipped code (not test / doc / example / CI / build tooling).
    ``wheel``: the tree is a PyPI wheel (installed as is). ``paths``: every path in
    the tree, empty files included (an empty ``__init__.py`` has no text)."""
    judged_paths = [p for p in texts if judged(p)]
    if not judged_paths:
        return set()
    users = {q: t for q, t in texts.items()
             if _suffix(q) in _CODE_EXTS and not judged(q) and runs_for_consumer(q)}
    existing = set(texts) | set(paths or ())
    import_dirs = import_name_test_dirs(texts, wheel=wheel, paths=existing)
    index: _Index | None = None
    out: set[str] = set()
    for p in judged_paths:
        text = texts.get(p) or ""
        parts = PurePosixPath(p).parts
        if len(parts) > 1 and parts[0] in import_dirs:
            out.add(p)                    # the tests package is an import name
            continue
        if _stem(p) == "conftest":
            if _conftest_shipped(p, existing, wheel):
                out.add(p)
            continue                      # pytest loads it; nothing else imports it
        if not is_test_code(p, text):
            out.add(p)
            continue
        if index is None:
            index = _Index(texts, users)
        if index.imported(p) or index.code_names(p) or index.manifests_name(p):
            out.add(p)
    return out
