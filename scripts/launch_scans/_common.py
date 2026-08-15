"""Shared helpers for launch-scan discovery/scan scripts.

Keep this file thin — anything that belongs in the scanner itself should live
in src/scanner. These helpers exist only to run the scripts in a consistent way:

  * load secrets from .env.secrets
  * write targets/progress JSON atomically
  * pace requests against a named rate-limit policy
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "launch-scans"


def ensure_data_dir() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR


def load_secret(key: str, default: str | None = None) -> str | None:
    """Load a secret from env or .env.secrets (never from argv or code)."""
    value = os.environ.get(key)
    if value:
        return value
    secrets = PROJECT_ROOT / ".env.secrets"
    if secrets.exists():
        for line in secrets.read_text().splitlines():
            if line.startswith(f"{key}="):
                candidate = line.split("=", 1)[1].strip().strip("'\"")
                if candidate:
                    return candidate
    return default


def write_json_atomic(path: Path, payload: Any) -> None:
    """Write JSON via tmp-rename so partial runs don't corrupt the file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str))
    tmp.replace(path)


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


class RateLimitPolicy:
    """Named pacing policy so we don't scatter magic numbers.

    Not a formal limiter — just "sleep this much between requests".
    For budget-aware scanning we rely on the registry's server-side 429s.
    """

    POLICIES = {
        # registry -> (seconds_between_requests, long_pause_every_n, long_pause_s)
        "x402":  (1.0, 25, 15.0),    # unknown public limits, be very polite
        "mcp":   (0.75, 40, 10.0),   # registry is fast but community-run
        "npm":   (0.8, 50, 10.0),    # 5000/hr — could push harder
        "pypi":  (1.0, 30, 15.0),    # no hard limit, but be courteous
        "github": (1.2, 30, 20.0),   # 5000/hr authenticated
    }

    def __init__(self, name: str) -> None:
        if name not in self.POLICIES:
            raise ValueError(f"unknown policy: {name}")
        self._pause, self._every, self._long = self.POLICIES[name]
        self._count = 0

    def wait(self) -> None:
        self._count += 1
        if self._count % self._every == 0:
            time.sleep(self._long)
        else:
            time.sleep(self._pause)


def dry_run_banner(name: str, count: int, output_path: Path) -> None:
    print("─" * 70)
    print(f"[{name}] DRY RUN — discovery only")
    print(f"[{name}] Targets found: {count}")
    print(f"[{name}] Written to:    {output_path}")
    print(f"[{name}] To scan:       re-run with --run")
    print("─" * 70)


def run_banner(name: str, target_count: int) -> None:
    print("═" * 70)
    print(f"[{name}] SCAN RUN — hitting real endpoints against {target_count} targets")
    print(f"[{name}] Rate limit policy: {name}")
    print(f"[{name}] Starting in 5s — Ctrl-C now to abort")
    print("═" * 70)
    time.sleep(5)


def require_py39() -> None:
    """The build machine is Python 3.9.6 — bail on older."""
    if sys.version_info < (3, 9):  # noqa: UP036
        raise RuntimeError("scripts require Python 3.9+")


def extract_owner_repo(url: str | None) -> str | None:
    """Extract 'owner/repo' from any GitHub URL flavor (https, git+, ssh)."""
    if not url:
        return None
    import re
    m = re.search(r"github\.com[:/]+([^/]+)/([^/.\s]+)", url)
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}"


def summarize_scan_result(result: Any) -> dict:
    """Convert a ScanResult to a JSON-serializable summary."""
    _err = getattr(result, "error", None)
    return {
        # A fetch failure is UNSCANNABLE, not a 0 — null the score so the catalog
        # reads "fetch error", never "Blocked". (Previously defaulted to 0 on error.)
        "trust_score": None if _err else getattr(result, "trust_score", 0),
        "findings_count": len(getattr(result, "findings", []) or []),
        "critical": getattr(result, "critical_count", 0),
        "high": getattr(result, "high_count", 0),
        "files_scanned": getattr(result, "files_scanned", 0),
        "primary_language": getattr(result, "primary_language", ""),
        "has_readme": getattr(result, "has_readme", False),
        "has_license": getattr(result, "has_license", False),
        "has_tests": getattr(result, "has_tests", False),
        "is_mcp_server": getattr(result, "is_mcp_server", False),
        "scan_error": getattr(result, "error", None),
    }
