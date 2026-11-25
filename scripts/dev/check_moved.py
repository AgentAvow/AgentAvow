#!/usr/bin/env python3
"""Prove that a scan.py split step moved code without changing it.

Usage:
    python3 scripts/dev/check_moved.py OLD NEW [--allow-changed NAME ...]

OLD and NEW are each a git ref (``origin/main``, ``HEAD``, a SHA) or a path to a
checkout directory (use ``.`` for the working tree).

For OLD the script reads ``src/scanner/scan.py``. For NEW it reads
``src/scanner/scan.py`` plus every ``.py`` file under ``src/scanner/static/``.
It then checks, using the parsed syntax tree (comments and formatting are ignored):

* every top-level function and class in OLD ``scan.py`` is defined exactly once in
  NEW, with an identical tree (body, signature, decorators and docstring);
* every top-level constant (a plain ``NAME = value`` or ``NAME: T = value``) in OLD
  ``scan.py`` is assigned once in NEW with an identical value expression;
* NEW defines no top-level function, class or constant that OLD did not have.

A name listed with ``--allow-changed`` may differ (for example a path built from
``__file__`` that has to change when its module moves). Exit status is 0 when the
move is clean and 1 when anything differs; every problem is printed.
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

SCAN = "src/scanner/scan.py"
STATIC = "src/scanner/static"


def _read(source: str, path: str) -> str | None:
    """Return the text of ``path`` at ``source`` (a ref or a directory), or None."""
    base = Path(source)
    if base.is_dir():
        f = base / path
        return f.read_text(encoding="utf-8") if f.is_file() else None
    proc = subprocess.run(
        ["git", "show", f"{source}:{path}"], capture_output=True, text=True
    )
    return proc.stdout if proc.returncode == 0 else None


def _list_static(source: str) -> list[str]:
    base = Path(source)
    if base.is_dir():
        root = base / STATIC
        if not root.is_dir():
            return []
        return sorted(str(p.relative_to(base)) for p in root.rglob("*.py"))
    proc = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", source, STATIC + "/"],
        capture_output=True,
        text=True,
    )
    return sorted(p for p in proc.stdout.splitlines() if p.endswith(".py"))


def _top_level(text: str, label: str) -> tuple[dict, dict]:
    """Map name -> [(label, dump)] for top-level defs and for constants."""
    tree = ast.parse(text)
    defs: dict[str, list] = defaultdict(list)
    consts: dict[str, list] = defaultdict(list)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defs[node.name].append((label, ast.dump(node)))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    consts[target.id].append((label, ast.dump(node.value)))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            value = ast.dump(node.value) if node.value is not None else ""
            consts[node.target.id].append((label, ast.dump(node.annotation) + "|" + value))
    return defs, consts


def _merge(into: dict, more: dict) -> None:
    for name, entries in more.items():
        into[name].extend(entries)


def compare(old: str, new: str, allow_changed: set[str]) -> list[str]:
    old_text = _read(old, SCAN)
    if old_text is None:
        return [f"cannot read {SCAN} at {old}"]
    old_defs, old_consts = _top_level(old_text, SCAN)

    new_defs: dict[str, list] = defaultdict(list)
    new_consts: dict[str, list] = defaultdict(list)
    for path in [SCAN, *_list_static(new)]:
        text = _read(new, path)
        if text is None:
            continue
        d, c = _top_level(text, path)
        _merge(new_defs, d)
        _merge(new_consts, c)

    problems: list[str] = []
    for kind, old_map, new_map in (
        ("def", old_defs, new_defs),
        ("constant", old_consts, new_consts),
    ):
        for name in sorted(old_map):
            if name in allow_changed:
                continue
            want = sorted(d for _, d in old_map[name])
            got = new_map.get(name, [])
            if not got:
                problems.append(f"{kind} {name}: missing in NEW")
                continue
            if sorted(d for _, d in got) != want:
                where = ", ".join(sorted({p for p, _ in got}))
                if len(got) != len(want):
                    problems.append(
                        f"{kind} {name}: defined {len(got)}x in NEW ({where}), "
                        f"{len(want)}x in OLD"
                    )
                else:
                    problems.append(f"{kind} {name}: changed (now in {where})")
        for name in sorted(set(new_map) - set(old_map)):
            if name in allow_changed:
                continue
            where = ", ".join(sorted({p for p, _ in new_map[name]}))
            problems.append(f"{kind} {name}: new in NEW ({where}); a move adds no code")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("old", help="git ref or directory before the step")
    parser.add_argument("new", help="git ref or directory after the step")
    parser.add_argument(
        "--allow-changed",
        action="append",
        default=[],
        metavar="NAME",
        help="a name allowed to differ (repeatable)",
    )
    args = parser.parse_args(argv)
    problems = compare(args.old, args.new, set(args.allow_changed))
    if problems:
        print(f"check_moved: {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("check_moved: OK (every def and constant from scan.py is unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
