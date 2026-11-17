"""Write the committed OpenAPI document, or check that it is current.

    python scripts/openapi/generate.py            # rewrite docs/api/openapi.json
    python scripts/openapi/generate.py --check    # exit 1 if the committed file is stale

`make openapi` runs the first form. CI and tests/test_openapi_contract.py run the second.

The app is imported in a child process with a fixed environment and an empty working
directory, so a developer's shell variables or untracked `.env` cannot change which
routes are registered or how they are described. Output is JSON with sorted keys,
two-space indent and a trailing newline, so the same code always gives the same bytes.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "docs" / "api" / "openapi.json"

# The only environment the app sees while the document is generated. Values are fixed
# placeholders: importing the app connects to nothing.
FIXED_ENV = {
    "DEBUG": "true",
    "DATABASE_URL": "postgresql+asyncpg://openapi:openapi@localhost:5432/openapi",
    "REDIS_URL": "redis://localhost:6379/0",
    "LOG_FORMAT": "text",
}
# Passed through so the interpreter itself can start; none of these reach settings.
PASS_THROUGH = ("PATH", "HOME", "TMPDIR", "SYSTEMROOT", "LANG", "LC_ALL")
_CHILD_FLAG = "_AGENTAVOW_OPENAPI_CHILD"


def serialize(spec: dict) -> str:
    """The one serialization the committed file uses."""
    return json.dumps(spec, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _child() -> None:
    sys.path.insert(0, str(ROOT))
    from src.main import app

    sys.stdout.write(serialize(app.openapi()))


def generate() -> str:
    """Build the document in a clean child process and return its text."""
    env = {k: os.environ[k] for k in PASS_THROUGH if k in os.environ}
    env.update(FIXED_ENV)
    env[_CHILD_FLAG] = "1"
    with tempfile.TemporaryDirectory() as cwd:
        proc = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).resolve())],
            cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8",
        )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"OpenAPI generation failed (exit {proc.returncode})")
    json.loads(proc.stdout)  # fail loudly on anything but one JSON document
    return proc.stdout


def check(path: Path, fresh: str | None = None) -> tuple[bool, str]:
    """(is_current, message) for the committed file at ``path``."""
    fresh = generate() if fresh is None else fresh
    rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
    if not path.exists():
        return False, f"{rel} is missing. Run `make openapi` and commit it."
    committed = path.read_text(encoding="utf-8")
    if committed == fresh:
        return True, f"{rel} is current."
    diff = "".join(
        list(difflib.unified_diff(
            committed.splitlines(keepends=True), fresh.splitlines(keepends=True),
            fromfile=f"{rel} (committed)", tofile=f"{rel} (from the code)", n=2,
        ))[:80]
    )
    return False, (
        f"{rel} is stale: the API routes or models changed but the committed OpenAPI "
        f"document was not regenerated.\nRun `make openapi` and commit the result.\n\n"
        f"First lines of the difference:\n{diff}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the file is stale")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    path = args.output.resolve()
    if args.check:
        ok, message = check(path)
        print(message, file=sys.stdout if ok else sys.stderr)
        return 0 if ok else 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate(), encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")
    return 0


if __name__ == "__main__":
    if os.environ.get(_CHILD_FLAG) == "1":
        _child()
    else:
        raise SystemExit(main())
