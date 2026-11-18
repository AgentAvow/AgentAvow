"""Parse every .py file under the given folders and fail if any of them doesn't parse.

Used by `make ast-verify` (and so `make check`). One process for the whole tree, and a
non-zero exit on the first bad file set, unlike a `find -exec` loop, which always exits 0.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def main(roots: list[str]) -> int:
    failures: list[str] = []
    count = 0
    for root in roots or ["src", "tests"]:
        for path in sorted(Path(root).rglob("*.py")):
            count += 1
            try:
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
                failures.append(f"{path}: {exc}")
    for line in failures:
        print(f"AST FAIL: {line}", file=sys.stderr)
    print(f"ast-verify: {count - len(failures)}/{count} files parse")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
