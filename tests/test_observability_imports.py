"""Logging setup and tracing libraries live in src/observability only (#405).

Code elsewhere logs with ``logging.getLogger(__name__)`` as usual. What it must not do
is configure logging itself (``logging.basicConfig``, ``logging.config``, a root
formatter) or import a tracing / structured-logging library: those bypass the
redaction and the request ids. Call ``src.observability.setup_logging()`` from a CLI
entry point instead.

An AST check, so detection patterns in the scanner that mention these names as
strings don't trip it.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
ALLOWED_DIR = SRC / "observability"

BANNED_MODULES = (
    "opentelemetry",
    "structlog",
    "pythonjsonlogger",
    "json_log_formatter",
    "loguru",
    "ddtrace",
    "logging.config",
)
BANNED_LOGGING_CALLS = {"basicConfig", "dictConfig", "fileConfig"}


def _banned(module: str) -> bool:
    return any(module == b or module.startswith(b + ".") for b in BANNED_MODULES)


def violations(tree: ast.AST) -> list[str]:
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _banned(alias.name):
                    found.append(f"line {node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            if _banned(node.module):
                found.append(f"line {node.lineno}: from {node.module} import ...")
            elif node.module == "logging":
                for alias in node.names:
                    if alias.name in ("config", *BANNED_LOGGING_CALLS):
                        found.append(f"line {node.lineno}: from logging import {alias.name}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in BANNED_LOGGING_CALLS:
                found.append(f"line {node.lineno}: {node.func.attr}()")
    return found


def test_no_logging_setup_or_tracing_imports_outside_observability():
    bad: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if ALLOWED_DIR in path.parents:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        bad += [f"{path.relative_to(ROOT)} {v}" for v in violations(tree)]
    assert not bad, (
        "Configure logging and tracing only in src/observability "
        "(call src.observability.setup_logging() from an entry point):\n  "
        + "\n  ".join(bad)
    )


def test_check_catches_each_banned_form():
    src = (
        "import logging\n"
        "import opentelemetry.trace\n"
        "from structlog import get_logger\n"
        "import logging.config\n"
        "from logging import config\n"
        "logging.basicConfig(level=logging.INFO)\n"
    )
    assert len(violations(ast.parse(src))) == 5


def test_plain_get_logger_is_fine():
    src = "import logging\nlogger = logging.getLogger(__name__)\nlogger.info('x')\n"
    assert violations(ast.parse(src)) == []
