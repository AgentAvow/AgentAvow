"""Shipped Python bytecode, by target type (the PyCache trap, arXiv 2610.10612).

A skill or repo ships a clean ``.py`` and a swapped ``.pyc`` that Python runs instead
(an unchecked-hash ``__pycache__`` entry is loaded without looking at the source; a
sourceless ``.pyc`` in a package directory is imported when no ``.py`` is there). The
paper reports 94-100% success against seven scanners. The engine never reads bytecode
(``SKIP_EXTENSIONS``, ``SKIP_DIRS``, the artifact unpack's bulk tier), so a swapped file
was simply unread, and unread read as clean.

Nothing here decompiles or compares bytecode with its source. The finding is the
shipped bytecode itself, graded by what the target is:

* **skill**: any ``.pyc`` / ``.pyo`` or ``__pycache__`` entry in the skill's tree is
  HIGH (Review). A skill is a folder of text an agent reads and scripts it runs; it has
  no reason to ship compiled code.
* **GitHub repo** (only tracked files: the GitHub tree lists what is committed, never a
  local untracked build dir): HIGH when the bytecode has no ``.py`` with the same module
  name anywhere in the repo (sourceless) or sits next to one (the shadowing shape:
  ``d/__pycache__/m.*.pyc`` or ``d/m.pyc`` beside ``d/m.py``). A legacy-location
  ``d/m.pyc`` with no ``d/m.py`` is HIGH even when an ``m.py`` exists elsewhere, since
  Python imports it as is. Other tracked bytecode (a ``__pycache__`` entry whose source
  is in another directory: committed ``build/`` output, a vendored copy) is MEDIUM.
* **sdist**: MEDIUM. pip builds the wheel from the sources, so bytecode in an sdist is
  usually packaging debris, but it is still code nobody read.
* **wheel, container image layer**: not reported. Bytecode is normal there.

Every reported file is also a coverage gap (``bytecode_unread``): it is never silent.
Category ``obfuscation`` (code a reviewer cannot read), never ``secret``.

A ``.pyc`` renamed to another extension is recognised by its header (a CPython magic
number followed by ``\\r\\n``) where the bytes are in hand (a package archive); a repo
or skill scan never downloads files it does not read, so there the name decides.
"""
from __future__ import annotations

import posixpath

BYTECODE_EXTS = (".pyc", ".pyo")
GAP_KEY = "bytecode_unread"
CATEGORY = "obfuscation"
_MAX_EXAMPLES = 3


def is_bytecode_path(path: str) -> bool:
    """A ``.pyc`` / ``.pyo`` file, or anything inside a ``__pycache__`` directory."""
    p = path.replace("\\", "/")
    return p.lower().endswith(BYTECODE_EXTS) or "__pycache__" in p.split("/")[:-1]


def looks_like_pyc(head: bytes) -> bool:
    """A CPython bytecode header: a 2-byte little-endian magic number, then ``\\r\\n``.
    Python 3 magic numbers are 3000-3999; Python 2 used 20121-62211."""
    if len(head) < 8 or head[2:4] != b"\r\n":
        return False
    magic = int.from_bytes(head[:2], "little")
    return 3000 <= magic <= 3999 or 20121 <= magic <= 62211


def _module_of(path: str) -> tuple[str, str]:
    """``(source_dir, module_name)`` a bytecode path stands for:
    ``d/__pycache__/m.cpython-312.pyc`` -> ``(d, m)``; ``d/m.pyc`` -> ``(d, m)``."""
    p = path.replace("\\", "/")
    d, base = posixpath.split(p)
    if posixpath.basename(d) == "__pycache__":
        d = posixpath.dirname(d)
    return d, base.split(".", 1)[0]


def classify_repo(paths: list[str], extra_bytecode: set[str] | None = None,
                  ) -> list[tuple[str, str]]:
    """``(path, kind)`` for every bytecode file among ``paths`` (tracked files), with
    ``kind`` one of ``shadow`` (a same-name ``.py`` next to it), ``sourceless`` (a
    legacy-location ``.pyc`` with no ``.py`` beside it: imported as is),
    ``orphan_cache`` (a ``__pycache__`` entry with no same-name ``.py`` anywhere) or
    ``elsewhere`` (a ``__pycache__`` entry whose same-name ``.py`` is in another
    directory). ``extra_bytecode``: paths known to be bytecode by content."""
    extra = extra_bytecode or set()
    sources: dict[str, set[str]] = {}
    for p in paths:
        q = p.replace("\\", "/")
        if q.endswith(".py") and "__pycache__" not in q.split("/"):
            d, base = posixpath.split(q)
            sources.setdefault(base[:-3], set()).add(d)
    out: list[tuple[str, str]] = []
    for p in paths:
        if not (is_bytecode_path(p) or p in extra):
            continue
        d, mod = _module_of(p)
        dirs = sources.get(mod, set())
        in_cache = "__pycache__" in p.replace("\\", "/").split("/")[:-1]
        if d in dirs:
            kind = "shadow"
        elif in_cache:
            # Python ignores a __pycache__ entry with no source beside it: build output
            # or a vendored copy of a module whose source is elsewhere in the repo, or
            # (no source anywhere) code that only a loader in the repo could run.
            kind = "elsewhere" if dirs else "orphan_cache"
        else:
            # No source at all, or a legacy-location .pyc with none beside it: Python
            # imports that file as is.
            kind = "sourceless"
        out.append((p, kind))
    return out


_WHY = {
    "skill": ("Skill ships Python bytecode ({what})",
              "A skill has no reason to ship compiled Python. Python can run the bytecode "
              "instead of the readable .py beside it (the PyCache trap), so what the "
              "agent runs may not be what you read. Delete the bytecode from the skill."),
    "shadow": ("Python bytecode committed beside its own source ({what})",
               "Python can load this bytecode instead of the .py next to it (an "
               "unchecked-hash .pyc is never compared with the source), so the code that "
               "runs may not be the code you read. Remove it and add __pycache__/ and "
               "*.pyc to .gitignore."),
    "sourceless": ("Python bytecode committed with no source ({what})",
                   "A .pyc with no .py beside it is imported as is, and nobody can read "
                   "it. Ship the source instead."),
    "orphan_cache": ("Python bytecode committed with no source ({what})",
                     "Compiled Python with no source anywhere in the repo: nobody can read "
                     "it. Remove it, or ship the source."),
    "elsewhere": ("Python bytecode committed in the repo ({what})",
                  "The scan does not read bytecode, so this code was not checked. Remove "
                  "it, or confirm it is build output from the source in this repo."),
    "sdist": ("Source distribution ships Python bytecode ({what})",
              "The scan does not read bytecode, so this code was not checked. An sdist "
              "should ship only sources; rebuild it without __pycache__ / *.pyc."),
}
_SEVERITY = {"skill": "high", "shadow": "high", "sourceless": "high",
             "orphan_cache": "high", "elsewhere": "medium", "sdist": "medium"}
# Graded as shipped wherever it sits (``Finding.payload``): bytecode Python runs in
# place of readable source, or imports as is. A clean ``tests/conftest.py`` with a
# swapped ``tests/__pycache__/conftest.*.pyc`` runs on every ``pytest``. An orphan
# ``__pycache__`` entry (never imported by itself) keeps the usual test / docs /
# fixture location rule, which is what keeps a decompiler's fixtures from blocking.
_PAYLOAD = frozenset({"skill", "shadow", "sourceless"})


def findings_for(groups: list[tuple[str, str]]) -> list:
    """One finding per (kind, directory): ``groups`` is ``(path, kind)``."""
    from src.scanner.scan import Finding

    by: dict[tuple[str, str], list[str]] = {}
    for path, kind in groups:
        d, _m = _module_of(path)
        by.setdefault((kind, d), []).append(path)
    out = []
    for (kind, d), paths in sorted(by.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        paths = sorted(paths)
        names = ", ".join(posixpath.basename(p) for p in paths[:_MAX_EXAMPLES])
        more = len(paths) - _MAX_EXAMPLES
        what = f"{len(paths)} file{'' if len(paths) == 1 else 's'} in {d or '.'}/"
        title, remediation = _WHY[kind]
        out.append(Finding(
            category=CATEGORY,
            name=title.format(what=what),
            severity=_SEVERITY[kind],
            file_path=paths[0],
            line_number=0,
            snippet=names + (f" and {more} more" if more > 0 else "") + " (not read)",
            remediation=remediation,
            payload=kind in _PAYLOAD,
        ))
    return out


def repo_bytecode(paths: list[str]) -> tuple[list, dict]:
    """Findings + coverage gap for a GitHub repo's tracked files."""
    groups = classify_repo(paths)
    if not groups:
        return [], {}
    return findings_for(groups), {GAP_KEY: len(groups)}


def skill_bytecode(paths: list[str], skill_dir: str) -> tuple[list, dict]:
    """Findings + coverage gap for the bytecode inside one skill's tree."""
    inside = [p for p in paths if is_bytecode_path(p)
              and (not skill_dir or p.startswith(skill_dir.rstrip("/") + "/"))]
    if not inside:
        return [], {}
    return findings_for([(p, "skill") for p in inside]), {GAP_KEY: len(inside)}


def artifact_bytecode(fetched) -> tuple[list, dict]:
    """Findings + coverage gap for a package archive. Only a PyPI sdist is graded;
    wheels, npm tarballs and container layers are not (bytecode is normal in a wheel or
    an image; an npm package is not a Python target)."""
    eco = (getattr(fetched, "ecosystem", "") or "").lower()
    kind = (getattr(fetched, "kind", "") or "").lower()
    if eco not in ("pypi", "python") or kind != "sdist":
        return [], {}
    hits = [p for p, af in (getattr(fetched, "files", None) or {}).items()
            if is_bytecode_path(p) or getattr(af, "pyc_header", False)]
    skipped = getattr(fetched, "skipped", None)
    for ex in (getattr(skipped, "examples", None) or []):
        p = str(ex.get("path") or "") if isinstance(ex, dict) else ""
        if p and is_bytecode_path(p) and p not in hits:
            hits.append(p)
    if not hits:
        return [], {}
    return findings_for([(p, "sdist") for p in hits]), {GAP_KEY: len(hits)}
