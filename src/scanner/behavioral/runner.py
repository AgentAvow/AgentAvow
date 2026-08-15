"""Behavioral scan orchestration: materialize an artifact, run it in the sandbox, and map
the observed behavior to findings.

Flow:
  run_behavioral(surface, coordinate)
    → pick a base image + a run command for the surface (npm install+require, pip
      install+import, MCP stdio + list-tools)
    → invoke scripts/sandbox/behavioral_run.sh (gVisor container behind a transparent
      egress logger; returns JSON: egress_hosts, fs_writes, exit_code, timed_out)
    → parse into a BehavioralResult, diffing observed egress against an allowlist / the
      tool's declared hosts
  behavioral_findings(result) → list[Finding] a scan can fold in as a signed BEHAVIORAL axis

The sandbox call is guarded by a feature flag and fails OPEN (never blocks a static scan):
if the runner or a sandbox host is unavailable, run_behavioral returns ran=False.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path

from src.scanner.scan import Finding

_RUNNER = Path(__file__).resolve().parents[3] / "scripts" / "sandbox" / "behavioral_run.sh"

# Base image + how to exercise a target per surface. The command installs/loads the target
# so its install hook + import-time code actually execute inside the sandbox.
_NPM_CMD = "npm install --no-audit --no-fund {name} && node -e 'require(\"{name}\")'"
_PIP_CMD = "pip install --no-input {name} && python -c 'import {import_name}'"
_SURFACE_PLAN: dict[str, tuple[str, str]] = {
    "npm": ("node:20-alpine", _NPM_CMD),
    "pypi": ("python:3.12-alpine", _PIP_CMD),
}

# Hosts a benign install legitimately reaches. Egress OUTSIDE this set (and outside any
# host the tool declares) is the signal we care about.
_REGISTRY_ALLOW = {
    "registry.npmjs.org", "registry.yarnpkg.com",
    "pypi.org", "files.pythonhosted.org",
    "github.com", "codeload.github.com", "objects.githubusercontent.com",
}


@dataclass
class BehavioralResult:
    """What the sandbox observed. ``ran`` False = we couldn't run it (fail-open)."""
    ran: bool
    surface: str
    coordinate: str
    timed_out: bool = False
    exit_code: int | None = None
    egress_hosts: list[str] = field(default_factory=list)
    unexpected_egress: list[str] = field(default_factory=list)
    fs_writes: list[str] = field(default_factory=list)
    error: str | None = None

    def to_public_dict(self) -> dict:
        return {
            "ran": self.ran,
            "timed_out": self.timed_out,
            "egress_hosts": self.egress_hosts,
            "unexpected_egress": self.unexpected_egress,
            "fs_writes_sample": self.fs_writes[:20],
            "error": self.error,
        }


def _import_name(coordinate: str) -> str:
    """Best-effort python import name from a pip coordinate (dashes → underscores, drop extras)."""
    base = coordinate.split("[")[0].split("==")[0].split(">")[0].split("<")[0].strip()
    return base.replace("-", "_")


def _classify_egress(hosts: list[str], expected: set[str]) -> list[str]:
    """Hosts reached that are neither a package registry nor a declared/expected host."""
    allow = _REGISTRY_ALLOW | {h.lower() for h in expected}
    out: list[str] = []
    for h in hosts:
        hl = (h or "").strip().lower()
        if not hl:
            continue
        # allow exact + subdomain matches of an allowed host
        if any(hl == a or hl.endswith("." + a) for a in allow):
            continue
        out.append(hl)
    return sorted(set(out))


async def run_behavioral(
    surface: str,
    coordinate: str,
    *,
    expected_hosts: set[str] | None = None,
    timeout: int = 45,
) -> BehavioralResult:
    """Run the target in the sandbox and return observed behavior. Fails OPEN."""
    surface = (surface or "").lower()
    plan = _SURFACE_PLAN.get(surface)
    if not plan or not _RUNNER.exists():
        return BehavioralResult(ran=False, surface=surface, coordinate=coordinate,
                                error="unsupported_surface_or_runner_missing")
    image, cmd_tmpl = plan
    cmd = cmd_tmpl.format(name=coordinate, import_name=_import_name(coordinate))
    try:
        proc = await asyncio.create_subprocess_exec(
            "bash", str(_RUNNER), image, cmd, str(timeout),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        # generous outer timeout — the runner has its own wall-clock kill.
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 60)
    except (FileNotFoundError, asyncio.TimeoutError, OSError) as exc:
        return BehavioralResult(ran=False, surface=surface, coordinate=coordinate,
                                error=f"runner_unavailable:{type(exc).__name__}")
    try:
        data = json.loads(stdout.decode("utf-8", "replace") or "{}")
    except json.JSONDecodeError:
        return BehavioralResult(ran=False, surface=surface, coordinate=coordinate,
                                error="runner_bad_output")
    if data.get("error"):
        return BehavioralResult(ran=False, surface=surface, coordinate=coordinate,
                                error=str(data["error"]))
    hosts = [str(h) for h in (data.get("egress_hosts") or [])]
    unexpected = _classify_egress(hosts, expected_hosts or set())
    return BehavioralResult(
        ran=True, surface=surface, coordinate=coordinate,
        timed_out=bool(data.get("timed_out")),
        exit_code=data.get("exit_code"),
        egress_hosts=hosts,
        unexpected_egress=unexpected,
        fs_writes=[str(f) for f in (data.get("fs_writes") or [])],
    )


def behavioral_findings(result: BehavioralResult) -> list[Finding]:
    """Map observed behavior to findings for the BEHAVIORAL axis. Empty if it didn't run."""
    findings: list[Finding] = []
    if not result.ran:
        return findings
    if result.unexpected_egress:
        hosts = ", ".join(result.unexpected_egress[:8])
        findings.append(Finding(
            category="exfiltration",
            name="Unexpected network egress during install/run",
            severity="high" if len(result.unexpected_egress) < 3 else "critical",
            file_path="<behavioral>",
            line_number=0,
            snippet=f"egress to {hosts}",
            remediation=(
                "The tool contacted host(s) outside the package registry and its declared "
                "endpoints while installing/running in isolation. Review why it phones home; "
                "unexpected egress at install time is a common exfiltration pattern."
            ),
            reachability="direct",
        ))
    return findings
