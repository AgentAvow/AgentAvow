"""env_names_from_files: static collection of the env var names a package reads."""
from __future__ import annotations

from dataclasses import dataclass

from src.scanner.behavioral.env_reads import MAX_ENV_NAMES, env_names_from_files


@dataclass
class _File:
    path: str
    text: str | None = None


JS = """
const token = process.env.GITHUB_TOKEN;
const key = process.env["OPENAI_API_KEY"];
const other = process.env['SLACK_WEBHOOK'];
const home = process.env.HOME; const env = process.env.NODE_ENV; const ci = process.env.CI;
const lower = process.env.notUpper;
"""
PY = """
import os
a = os.environ["DATABASE_URL"]
b = os.environ.get("AWS_SECRET_ACCESS_KEY")
c = os.getenv('STRIPE_KEY', None)
d = os.environ.get("PATH")
e = os.getenv("PYTHONPATH")
"""


def test_collects_all_five_forms_and_drops_noise():
    files = {"index.js": _File("index.js", JS), "app.py": _File("app.py", PY)}
    assert env_names_from_files(files) == [
        "AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "GITHUB_TOKEN", "OPENAI_API_KEY",
        "SLACK_WEBHOOK", "STRIPE_KEY",
    ]


def test_skips_binary_non_source_and_vendored_files():
    files = {
        "README.md": _File("README.md", "process.env.FROM_DOCS"),
        "bin.wasm": _File("bin.wasm", None),
        "node_modules/dep/index.js": _File("node_modules/dep/index.js", "process.env.VENDORED"),
        "src/x.ts": _File("src/x.ts", "process.env.REAL_ONE"),
    }
    assert env_names_from_files(files) == ["REAL_ONE"]


def test_sorted_unique_and_capped():
    text = "\n".join(f"process.env.VAR_{i:03d}" for i in range(60)) + "\nprocess.env.VAR_001"
    out = env_names_from_files({"a.js": _File("a.js", text)})
    assert len(out) == MAX_ENV_NAMES
    assert out == sorted(set(out)) and out[0] == "VAR_000"


def test_tolerates_garbage_input():
    assert env_names_from_files(None) == []
    assert env_names_from_files({}) == []
    assert env_names_from_files({"a.js": object()}) == []
    assert env_names_from_files({"a.js": _File("a.js", "")}) == []


def test_accepts_iterable_of_pairs():
    assert env_names_from_files([("a.py", _File("a.py", 'os.getenv("X_KEY")'))]) == ["X_KEY"]
