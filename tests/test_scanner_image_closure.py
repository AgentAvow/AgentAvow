"""The slim scanner image (docker/scanner.Dockerfile) ships only src/scanner/,
src/trust_tiers.py and two third-party packages (httpx, pyyaml). This test runs a
full ``agentavow scan`` in a subprocess with the web stack blocked at import time
and asserts that every ``src.*`` module the scan touched is one the Dockerfile
copies. A new module-level import of FastAPI / SQLAlchemy / src.config anywhere on
the scan path fails here before it breaks the image.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.filterwarnings("ignore")

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "docker" / "scanner.Dockerfile"

# Everything pyproject.toml installs for the backend that the slim image must not need.
BLOCKED_TOP_LEVEL = [
    "fastapi", "starlette", "uvicorn", "sqlalchemy", "asyncpg", "alembic", "redis",
    "pydantic", "pydantic_settings", "jwt", "pwdlib", "stripe", "networkx", "community",
    "nh3", "aiosmtplib", "pythonjsonlogger", "rfc8785", "agentgraph_trust", "mcp",
    "PIL", "boto3", "botocore", "email_validator", "multipart",
]

_RUNNER = r"""
import json, sys
BLOCKED = set(json.loads(sys.argv[1]))
ALLOWED_SRC_PREFIXES = json.loads(sys.argv[2])
repo, out_json, out_cq = sys.argv[3], sys.argv[4], sys.argv[5]

class _Block:
    def find_spec(self, name, path=None, target=None):
        top = name.split(".")[0]
        if top in BLOCKED:
            raise ImportError(f"slim image: {name} is not installed")
        if top == "src" and name != "src" and not any(
            name == p or name.startswith(p + ".") for p in ALLOWED_SRC_PREFIXES
        ):
            raise ImportError(f"slim image: {name} is not copied into the image")
        return None

sys.meta_path.insert(0, _Block())
from src.scanner.local_scan import main
rc = main(["scan", repo, "--quiet", "--json", out_json, "--gitlab-code-quality", out_cq])
loaded = sorted(m for m in sys.modules if m == "src" or m.startswith("src."))
print(json.dumps({"rc": rc, "src_modules": loaded,
                  "third_party": sorted({m.split(".")[0] for m in sys.modules
                                         if "." not in m and m not in sys.stdlib_module_names
                                         and not m.startswith("_")})}))
"""


def _dockerfile_src_copies() -> list[str]:
    """Module prefixes for every ``COPY src/...`` line in the Dockerfile."""
    prefixes = []
    for line in DOCKERFILE.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "COPY" and parts[1].startswith("src/"):
            rel = parts[1].rstrip("/")
            if rel.endswith(".py"):
                rel = rel[:-3]
            prefixes.append(rel.replace("/", "."))
    return prefixes


def test_dockerfile_copies_the_scanner_and_tiers():
    prefixes = _dockerfile_src_copies()
    assert "src.scanner" in prefixes
    assert "src.trust_tiers" in prefixes
    text = DOCKERFILE.read_text()
    assert "fastapi" not in text.lower() or "no FastAPI" in text
    assert "ENTRYPOINT" not in [ln.split()[0] for ln in text.splitlines() if ln.split()]


def test_scan_runs_with_web_stack_blocked(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.co"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    # exercise the lazy paths too: a manifest (yaml + behavioral.manifest), a user
    # exclude file (yaml), a dependency manifest, an MCP indicator, and a finding
    (repo / "app.py").write_text("import os\ndef run(c):\n    os.system(c)\n")
    (repo / "server.json").write_text('{"name": "demo"}\n')
    (repo / "requirements.txt").write_text("requests==2.31.0\n")
    (repo / ".agentavow.yml").write_text(
        "version: agentavow-manifest-v0\negress: [api.example.com]\n"
        "capabilities: [network:egress]\n"
    )
    (repo / ".agentgraph-scan.yml").write_text("exclude: [vendor/]\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=repo, check=True)

    allowed = _dockerfile_src_copies()
    out_json, out_cq = tmp_path / "scan.json", tmp_path / "cq.json"
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    proc = subprocess.run(
        [sys.executable, "-c", _RUNNER, json.dumps(BLOCKED_TOP_LEVEL), json.dumps(allowed),
         str(repo), str(out_json), str(out_cq)],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout.strip().splitlines()[-1])
    assert report["rc"] == 0
    assert json.loads(out_json.read_text())["findings"]
    assert json.loads(out_cq.read_text())

    for m in report["src_modules"]:
        assert m == "src" or any(m == p or m.startswith(p + ".") for p in allowed), (
            f"{m} is on the scan path but docker/scanner.Dockerfile does not copy it"
        )
    assert "src.config" not in report["src_modules"]
    assert not set(report["third_party"]) & set(BLOCKED_TOP_LEVEL)
