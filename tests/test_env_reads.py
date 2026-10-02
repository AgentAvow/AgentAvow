"""env_names_from_files: static collection of the env var names a package reads;
env_names_from_text: credential-looking names mined from prose (README, server errors)."""
from __future__ import annotations

from dataclasses import dataclass

from src.scanner.behavioral.env_reads import (
    MAX_ENV_NAMES,
    env_names_from_files,
    env_names_from_text,
    looks_like_credential,
)


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


# ── env_names_from_text (prose) ───────────────────────────────────────────────

SUPABASE = ("Please provide a personal access token (PAT) with the --access-token flag or "
            "set the SUPABASE_ACCESS_TOKEN environment variable")
BRAVE = ("A Brave API key is required via --brave-api-key, BRAVE_API_KEY, "
         "--brave-api-key-file, or BRAVE_API_KEY_FILE")
GIT = ("be included in your $PATH - be set via $GIT_PYTHON_GIT_EXECUTABLE ... "
       "$GIT_PYTHON_REFRESH environment variable")
README = """
## Setup
```bash
export OPENAI_API_KEY=sk-...
MCP_SERVER_PORT=3000 LOG_LEVEL=debug npx demo
```
Also honours `GITHUB_PAT` and process.env.PLAIN_SETTING. HTTP_200 is not a variable.
"""


def test_mines_credential_names_from_server_errors_and_readmes():
    assert env_names_from_text(SUPABASE) == ["SUPABASE_ACCESS_TOKEN"]
    assert env_names_from_text(BRAVE) == ["BRAVE_API_KEY", "BRAVE_API_KEY_FILE"]
    assert env_names_from_text(GIT) == []  # PATH / GIT_PYTHON_* are not credentials
    # code-read names are kept whatever they look like; prose names must look secret
    assert env_names_from_text(README) == ["GITHUB_PAT", "OPENAI_API_KEY", "PLAIN_SETTING"]


def test_prose_miner_noise_filter_cap_and_garbage():
    assert env_names_from_text("PATH HOME NODE_OPTIONS PYTHONPATH TOKEN KEYS") == []
    many = " ".join(f"ACME_KEY_{i:03d}" for i in range(60))
    out = env_names_from_text(many)
    assert len(out) == MAX_ENV_NAMES and out == sorted(out)
    assert env_names_from_text("") == [] and env_names_from_text(None) == []
    assert env_names_from_text(123) == []
    # boundaries: not inside a longer identifier / camelCase
    assert env_names_from_text("myAPI_KEYS_X") == []


def test_looks_like_credential():
    yes = ["BRAVE_API_KEY", "GITHUB_PAT", "SUPABASE_ACCESS_TOKEN", "AWS_REGION", "APIKEY",
           "DB_PASSWORD", "AUTH_HEADER", "SLACK_WEBHOOK", "SECRET_X", "CLIENT_CREDENTIALS"]
    no = ["PATH", "PATTERN_X", "CAPITAL_CITY", "API", "LOG_LEVEL", "MCP_SERVER_PORT",
          "NODE_TLS_REJECT", "TOKEN", ""]
    assert all(looks_like_credential(n) for n in yes), [n for n in yes if not looks_like_credential(n)]
    assert not any(looks_like_credential(n) for n in no), [n for n in no if looks_like_credential(n)]
