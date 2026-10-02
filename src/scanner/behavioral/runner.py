"""Behavioral scan orchestration: materialize an artifact, run it in the sandbox, and map
the observed behavior to findings.

Flow:
  run_behavioral(surface, coordinate, plan=...)
    → pick a PLAN: a base image + a run command (npm install+require, pip install+import,
      an MCP exerciser plan that installs the package then launches its server over stdio
      and calls every tool, or a docker image run with the image's own entrypoint)
    → invoke the sandbox runner script (gVisor container behind a passive egress capture;
      returns JSON: egress_hosts, fs_writes, exit_code, timed_out, and — v2 only —
      exercise (the exerciser transcript) + canary_exfil)
    → parse into a BehavioralResult, diffing observed egress against an allowlist / the
      tool's declared hosts
  behavioral_findings(result) → list[Finding] (thin wrapper over graders.grade)

Runner versions. v1 (``scripts/sandbox/behavioral_run.sh``, LIVE on the sandbox box) takes
``<image> '<cmd>' [timeout]``. v2 (``behavioral_run_v2.sh``) adds ``--mode exec|mcp|image``,
``--files-b64`` (the exerciser sources shipped per run — the sandbox host never needs files
from us), ``--canary``, and ``--memory-mb`` / ``--pids`` (container caps from
``scanner_behavioral_memory_mb`` / ``scanner_behavioral_pids``). v2 is selected ONLY by the
``scanner_behavioral_sandbox_runner_v2``
setting; while it is empty the v1 script is called with exactly the old command line and
MCP/docker plans degrade (mcp → the plain exec plan, docker → not run).

The sandbox call is guarded by a feature flag and fails OPEN (never blocks a static scan):
if the runner or a sandbox host is unavailable, run_behavioral returns ran=False.
"""
from __future__ import annotations

import asyncio
import base64
import gzip
import json
import re
import secrets
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from src.scanner.behavioral.env_reads import MAX_ENV_NAMES, env_names_from_text
from src.scanner.behavioral.transcript import CANARY_PREFIX, ExerciseTranscript, parse_transcript
from src.scanner.scan import Finding

_SANDBOX_DIR = Path(__file__).resolve().parents[3] / "scripts" / "sandbox"
_RUNNER = _SANDBOX_DIR / "behavioral_run.sh"
_RUNNER_V2 = _SANDBOX_DIR / "behavioral_run_v2.sh"
_SSM_STDOUT_CAP = 24000  # AWS SSM GetCommandInvocation StandardOutputContent limit (chars)

# The sandbox container's root filesystem is READ-ONLY; only /tmp, /run and /work (the
# working dir) are writable tmpfs. npm and pip both write under $HOME by default
# (/root/.npm, /root/.local), so without this prefix `npm install` could not write its
# cache and `pip install` failed outright with EROFS — the run still "ran" and showed
# registry egress, but nothing was actually installed or imported. Every plan's command
# starts with this: a writable HOME under /work, caches under /tmp, and the pip user site
# (where `--user` installs land, console scripts in /work/.local/bin) on PATH.
_SANDBOX_ENV = (
    "export HOME=/work npm_config_cache=/tmp/npm-cache PIP_CACHE_DIR=/tmp/pip-cache "
    "PYTHONUSERBASE=/work/.local PATH=/work/.local/bin:$PATH && "
)
# Base image + how to exercise a target per plan. The command installs/loads the target
# so its install hook + import-time code actually execute inside the sandbox.
_NPM_CMD = (
    _SANDBOX_ENV
    + "npm install --no-audit --no-fund {name} && node -e 'require(\"{name}\")'"
)
_PIP_CMD = (
    _SANDBOX_ENV
    + "pip install --no-input --user {name} && python -c 'import {import_name}'"
)
# MCP plans: install, then the shipped launcher discovers the package's bin(s) and runs
# the shipped exerciser against the candidates (first that initializes wins; at most 4
# launches). The launcher gets the canary value as ``--canary-value V`` BEFORE its ``--``
# so it can retry a key-gated server with the credential names / flags the server's own
# error names (see mcp_launch.sh) — the exerciser still receives the same value after
# ``--``; the two are always identical.
_NPM_MCP_CMD = (
    _SANDBOX_ENV
    + "npm install --no-audit --no-fund {name} && "
    "sh /work/mcp_launch.sh npm {dist} --canary-value {canary} -- "
    "node /work/mcp_exercise.js {exerciser_args}"
)
# python:3.12-alpine has no git; mcp-server-git (GitPython) cannot even initialize
# without the binary. The root filesystem is READ-ONLY, so a plain ``apk add git`` fails
# (EROFS on /usr) — instead apk installs git + its libraries into an alternate root under
# the writable /work (``-p``, ``--initdb``, the image's own keys + repositories copied in,
# ``--no-scripts`` so apk never chroots) and a tiny wrapper on PATH points git at those
# libraries. Every step is ``|| true``: if the mirror or apk misbehaves the run proceeds
# exactly as before and the launch is classified ``missing_binary`` honestly. Costs ~5 s
# and egress to dl-cdn.alpinelinux.org (allow-listed). Build deps for pip (gcc, musl-dev)
# are deliberately NOT installed: that is 150 MB+ per run; a package that needs them
# records ``install_failed``.
_ALPINE_GIT_PREFIX = (
    "(mkdir -p /work/.apk/etc/apk /work/.local/bin && "
    "cp -r /etc/apk/keys /etc/apk/repositories /work/.apk/etc/apk/ && "
    "apk add --no-cache --no-scripts --initdb -p /work/.apk git && "
    "printf '#!/bin/sh\\nexport LD_LIBRARY_PATH=/work/.apk/usr/lib:/work/.apk/lib "
    "GIT_EXEC_PATH=/work/.apk/usr/libexec/git-core "
    "GIT_TEMPLATE_DIR=/work/.apk/usr/share/git-core/templates\\n"
    "exec /work/.apk/usr/bin/git \"$@\"\\n' > /work/.local/bin/git && "
    "chmod +x /work/.local/bin/git) >/dev/null 2>&1 || true; "
)
_PIP_MCP_CMD = (
    _SANDBOX_ENV
    + _ALPINE_GIT_PREFIX
    + "pip install --no-input --user {name} && "
    "sh /work/mcp_launch.sh pypi {dist} --canary-value {canary} -- "
    "python /work/mcp_exercise.py {exerciser_args}"
)
# plan → (image, command template, runner mode). "{name}" in the image = the coordinate.
# Repos with NO published package: install straight from GitHub. The installed package's
# real name is resolved inside the container (`npm view … name` / pip's install report)
# and handed to the launcher, so a repo-hosted MCP server gets the full exercise.
# {name} = "github:owner/repo" (npm) or "git+https://github.com/owner/repo" (pip).
_NPM_GIT_NAME = 'NAME=$(npm view {name} name 2>/dev/null) && [ -n "$NAME" ] && '
_NPM_GIT_CMD = (
    _SANDBOX_ENV + _NPM_GIT_NAME
    + "npm install --no-audit --no-fund {name} && node -e 'require(process.env.NAME)'"
)
_NPM_GIT_MCP_CMD = (
    _SANDBOX_ENV + _NPM_GIT_NAME
    + "npm install --no-audit --no-fund {name} && "
    'sh /work/mcp_launch.sh npm "$NAME" --canary-value {canary} -- '
    "node /work/mcp_exercise.js {exerciser_args}"
)
_PIP_GIT_NAME = (
    "pip install --no-input --user --report /work/pipreport.json {name} && "
    "NAME=$(python3 -c \"import json;r=json.load(open('/work/pipreport.json'));"
    "print(next((i['metadata']['name'] for i in r.get('install',[]) if i.get('requested')),''))\")"
    ' && [ -n "$NAME" ] && '
)
_PIP_GIT_CMD = (
    _SANDBOX_ENV + _ALPINE_GIT_PREFIX + _PIP_GIT_NAME
    + "python -c 'import importlib,os; importlib.import_module(os.environ[\"NAME\"].replace(\"-\",\"_\"))'"
)
_PIP_GIT_MCP_CMD = (
    _SANDBOX_ENV + _ALPINE_GIT_PREFIX + _PIP_GIT_NAME
    + 'sh /work/mcp_launch.sh pypi "$NAME" --canary-value {canary} -- '
    "python /work/mcp_exercise.py {exerciser_args}"
)
_SURFACE_PLAN: dict[str, tuple[str, str, str]] = {
    "npm": ("node:20-alpine", _NPM_CMD, "exec"),
    "pypi": ("python:3.12-alpine", _PIP_CMD, "exec"),
    "npm-mcp": ("node:20-alpine", _NPM_MCP_CMD, "mcp"),
    "pypi-mcp": ("python:3.12-alpine", _PIP_MCP_CMD, "mcp"),
    "npm-git": ("node:20-alpine", _NPM_GIT_CMD, "exec"),
    "pypi-git": ("python:3.12-alpine", _PIP_GIT_CMD, "exec"),
    "npm-git-mcp": ("node:20-alpine", _NPM_GIT_MCP_CMD, "mcp"),
    "pypi-git-mcp": ("python:3.12-alpine", _PIP_GIT_MCP_CMD, "mcp"),
    "docker": ("{name}", "", "image"),
}


def _git_spec(plan: str, coordinate: str) -> str:
    """The install spec for a git plan: 'owner/repo' → github:owner/repo (npm) or
    git+https://github.com/owner/repo (pip). A 'github:' / URL prefix is tolerated."""
    repo = coordinate.strip()
    for prefix in ("github:", "https://github.com/", "http://github.com/", "git+https://github.com/"):
        if repo.lower().startswith(prefix):
            repo = repo[len(prefix):]
    repo = repo.strip("/").removesuffix(".git")
    return f"github:{repo}" if plan.startswith("npm") else f"git+https://github.com/{repo}"
# Files from scripts/sandbox/ shipped into /work for a plan (via --files-b64).
# Where each shipped file lives in the repo. The argument generator is a real module under
# src/ (unit-tested, importable by the app) and is copied into the container next to the
# exerciser, which imports it by bare name from its own directory.
_SHIPPED_SOURCES: dict[str, Path] = {
    "synthetic_args.py": Path(__file__).resolve().parent / "synthetic_args.py",
}
_PLAN_FILES: dict[str, tuple[str, ...]] = {
    "npm-mcp": ("mcp_launch.sh", "mcp_exercise.js"),
    "pypi-mcp": ("mcp_launch.sh", "mcp_exercise.py", "synthetic_args.py"),
    "npm-git-mcp": ("mcp_launch.sh", "mcp_exercise.js"),
    "pypi-git-mcp": ("mcp_launch.sh", "mcp_exercise.py", "synthetic_args.py"),
}
# What an MCP plan degrades to when the exerciser can't be shipped / v2 is off.
_EXEC_FALLBACK = {"npm-mcp": "npm", "pypi-mcp": "pypi",
                  "npm-git-mcp": "npm-git", "pypi-git-mcp": "pypi-git"}
_README_LIMIT = 64_000

# Hosts a benign install legitimately reaches. Egress OUTSIDE this set (and outside any
# host the tool declares) is the signal we care about.
_REGISTRY_ALLOW = {
    "registry.npmjs.org", "registry.yarnpkg.com",
    "pypi.org", "files.pythonhosted.org",
    "github.com", "codeload.github.com", "objects.githubusercontent.com",
    "dl-cdn.alpinelinux.org",  # apk mirror: the pypi-mcp plan installs git (see above)
}
# A container that exits 137 was SIGKILLed by its cgroup (memory / pids cap), not by the
# target: recorded as the ``killed_resource_limit`` note → start_reason ``resource_limit``.
_RESOURCE_LIMIT_EXIT = 137
# Image mode pulls from a registry too.
_IMAGE_ALLOW = {
    "registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com",
    "index.docker.io", "ghcr.io", "pkg-containers.githubusercontent.com",
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
    # v2: which plan ran, the exerciser transcript (MCP plans), canary hits, and notes
    # about degradations (e.g. "exerciser_missing" → fell back to the exec plan).
    plan: str = ""
    transcript: ExerciseTranscript | None = None
    canary_exfil: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Hosts reached that belong to the tool's own vendor by name (observed, not a finding).
    vendor_egress: list[str] = field(default_factory=list)

    def to_public_dict(self) -> dict:
        return {
            "ran": self.ran,
            "timed_out": self.timed_out,
            "egress_hosts": self.egress_hosts,
            "unexpected_egress": self.unexpected_egress,
            "fs_writes_sample": self.fs_writes[:20],
            "error": self.error,
            "plan": self.plan,
            "canary_exfil": self.canary_exfil,
            "exercise": self.transcript.to_public_dict() if self.transcript else None,
            "notes": self.notes,
            "vendor_egress": self.vendor_egress,
            # the container command's exit status: for install plans a non-zero value
            # means the install/import step itself failed (the MCP launcher always exits 0)
            "exit_code": self.exit_code,
        }


def _import_name(coordinate: str) -> str:
    """Best-effort python import name from a pip coordinate (dashes → underscores, drop extras)."""
    base = coordinate.split("[")[0].split("==")[0].split(">")[0].split("<")[0].strip()
    return base.replace("-", "_")


def _dist_name(coordinate: str) -> str:
    """The bare distribution/package name: npm ``@scope/name@1.2`` → ``@scope/name``,
    pip ``name[extra]==1.0`` → ``name``."""
    c = (coordinate or "").strip()
    scoped = c.startswith("@")
    body = (c[1:] if scoped else c).split("@", 1)[0]
    for sep in ("[", "==", ">", "<", "~", "!"):
        body = body.split(sep)[0]
    return ("@" if scoped else "") + body.strip()


# Hosts our OWN synthetic arguments point a tool at (synthetic_args.SAMPLE_URL etc.).
# A fetch tool contacting example.com did exactly what we asked; never a finding.
_SYNTHETIC_HOSTS = {"example.com"}

# Name tokens too generic to identify a vendor: "mcp-server" must not vouch for mcp.io.
_GENERIC_TOKENS = {
    "mcp", "server", "servers", "modelcontextprotocol", "api", "www", "com", "io", "dev",
    "ai", "app", "cli", "sdk", "tool", "tools", "plugin", "plugins", "agent", "agents",
    "node", "python", "py", "js", "ts", "lib", "core", "client", "service", "the", "for",
}


_SECOND_LEVEL_SUFFIXES = {"co", "com", "org", "net", "ac", "gov", "edu", "ne", "or"}


def _name_tokens(coordinate: str) -> set[str]:
    """Identifying tokens of a package coordinate: '@upstash/context7-mcp@1.2' →
    {'upstash', 'context7'}; 'tavily-mcp' → {'tavily'}; 'exa-mcp-server' → {'exa'}."""
    base = coordinate.split("==")[0].split("[")[0].strip().lower()
    if base.startswith("@"):
        base = base[1:]
    elif "@" in base:
        base = base.split("@", 1)[0]
    toks = {t for t in re.split(r"[^a-z0-9]+", base) if len(t) >= 3}
    return {t for t in toks if t not in _GENERIC_TOKENS}


def _vendor_hosts(coordinate: str, hosts: list[str]) -> list[str]:
    """Hosts that belong to the tool's own vendor by name: a label of the host's
    registrable domain equals an identifying token of the package name. tavily-mcp →
    api.tavily.com is expected; the same host from a package named 'leftpad-helper' is
    not. Deterministic, no network."""
    toks = _name_tokens(coordinate)
    if not toks:
        return []
    out = []
    for h in hosts:
        labels = [x for x in (h or "").lower().rstrip(".").split(".") if x]
        if len(labels) < 2:
            continue
        # The registrable label is the one just before the public suffix; a subdomain
        # (fetch.evil.net) must never vouch. Handle two-part suffixes like co.uk / com.au.
        registrable = labels[-2]
        if registrable in _SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
            registrable = labels[-3]
        if registrable in toks:
            out.append(h)
    return out


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


def _run_via_ssm(instance_id: str, region: str, command: str, timeout: int) -> str | None:
    """Run ``command`` on the sandbox via SSM Send-Command; return its stdout.

    The no-key path: prod's IAM role is allowed to send AWS-RunShellScript to the
    one sandbox instance, so nothing SSHes and no private key sits on prod. SSM
    runs the command as root on the target. Synchronous (boto3) — call through
    ``asyncio.to_thread``. Returns None on any failure (missing boto3, API error,
    or the command not finishing in time); the caller treats None as fail-open."""
    try:
        import boto3
    except ImportError:
        return None
    import time
    try:
        ssm = boto3.client("ssm", region_name=region)
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command], "executionTimeout": [str(timeout + 120)]},
            TimeoutSeconds=60,
        )
    except Exception:
        return None
    command_id = (resp.get("Command") or {}).get("CommandId")
    if not command_id:
        return None
    deadline = time.time() + timeout + 90
    while time.time() < deadline:
        time.sleep(2)
        try:
            inv = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except Exception:
            # InvocationDoesNotExist is expected in the moment right after send — keep polling.
            continue
        status = inv.get("Status")
        if status == "Success":
            return inv.get("StandardOutputContent", "") or ""
        if status in ("Failed", "Cancelled", "TimedOut", "Undeliverable", "Terminated"):
            return None
    return None


async def _execute(runner_args: list[str], timeout: int, *, v2: bool = False,
                   ) -> tuple[str | None, str | None]:
    """Run the sandbox runner script with ``runner_args`` and return (stdout, error).

    The single seam between orchestration and execution (tests monkeypatch this). A
    behavioral scan runs UNTRUSTED code, so it must never run on the app/prod host.
    Three exec paths, in priority order:
      - SSM  (mode="ssm" + instance_id): prod sends the runner to the sandbox via AWS
        Systems Manager — NO SSH key on prod. Preferred.
      - SSH  (sandbox_host set): SSH the runner to the sandbox box.
      - local: run the runner here (dev/test on a machine that IS the sandbox).
    ``v2`` picks the v2 script path (setting / bundled file) over the v1 one."""
    from src.config import settings
    if v2:
        remote_runner = ((getattr(settings, "scanner_behavioral_sandbox_runner_v2", "") or "")
                         .strip() or "/home/ec2-user/behavioral_run_v2.sh")
        local_runner = _RUNNER_V2
    else:
        remote_runner = (getattr(settings, "scanner_behavioral_sandbox_runner", "")
                         or "/home/ec2-user/behavioral_run.sh")
        local_runner = _RUNNER
    mode = (getattr(settings, "scanner_behavioral_sandbox_mode", "") or "").strip().lower()
    instance_id = (getattr(settings, "scanner_behavioral_sandbox_instance_id", "") or "").strip()
    host = (getattr(settings, "scanner_behavioral_sandbox_host", "") or "").strip()
    quoted = " ".join(shlex.quote(a) for a in runner_args)

    if mode == "ssm" and instance_id:
        region = (getattr(settings, "scanner_behavioral_sandbox_region", "")
                  or "us-east-1").strip()
        # SSM runs the command as root on the target, so no sudo wrapper is needed.
        command = f"bash {shlex.quote(remote_runner)} {quoted}"
        out = await asyncio.to_thread(_run_via_ssm, instance_id, region, command, timeout)
        return (out, None) if out is not None else (None, "ssm_unavailable")

    if host:
        user = getattr(settings, "scanner_behavioral_sandbox_user", "ec2-user") or "ec2-user"
        key = (getattr(settings, "scanner_behavioral_sandbox_key", "") or "").strip()
        remote = f"sudo {shlex.quote(remote_runner)} {quoted}"
        argv = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15",
                "-o", "BatchMode=yes"]
        if key:
            argv += ["-i", key]
        argv += [f"{user}@{host}", remote]
    else:
        # Local exec needs the bundled runner script present (dev/test only);
        # the SSM/SSH paths use the runner that lives on the remote sandbox.
        if not local_runner.exists():
            return None, "local_runner_missing"
        argv = ["bash", str(local_runner), *runner_args]

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        # generous outer timeout — the runner has its own wall-clock kill.
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 60)
    except (FileNotFoundError, asyncio.TimeoutError, OSError) as exc:
        return None, f"runner_unavailable:{type(exc).__name__}"
    return stdout.decode("utf-8", "replace"), None


def _new_canary() -> str:
    return CANARY_PREFIX + secrets.token_hex(6)


def _files_payload(plan: str, readme_text: str | None) -> str | None:
    """``--files-b64`` payload for a plan: base64(gzip(JSON {name: base64(bytes)})) of the
    exerciser sources read from scripts/sandbox/ at call time (+ README.md when given).
    None when a required source file is missing (→ the caller falls back to exec)."""
    names = _PLAN_FILES.get(plan)
    if not names:
        return None
    files: dict[str, str] = {}
    for name in names:
        path = _SHIPPED_SOURCES.get(name, _SANDBOX_DIR / name)
        try:
            files[name] = base64.b64encode(path.read_bytes()).decode("ascii")
        except OSError:
            return None
    if readme_text:
        files["README.md"] = base64.b64encode(
            readme_text[:_README_LIMIT].encode("utf-8", "replace")).decode("ascii")
    raw = json.dumps(files, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(gzip.compress(raw, compresslevel=6)).decode("ascii")


_SECRET_PARTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASS", "PAT",
                 "CREDENTIAL", "CREDENTIALS", "AUTH", "COOKIE", "SESSION", "PRIVATE",
                 "BEARER", "JWT", "SIGNATURE")
# Config that is NOT a secret even when it sits next to one (AWS_REGION, API_BASE_URL…):
# a canary here becomes part of a hostname/URL the tool legitimately contacts and would
# read as exfiltration. Seen 2026-10-02: AWS_REGION=canary → DNS for
# bedrock-agent-runtime.<canary>.amazonaws.com flagged as a credential leak.
_NOT_SECRET_PARTS = ("REGION", "ENDPOINT", "URL", "URI", "HOST", "HOSTNAME", "PORT", "BASE",
                     "DOMAIN", "PATH", "DIR", "FILE", "MODEL", "VERSION", "ENV", "LEVEL",
                     "MODE", "NAME", "ID", "TIMEOUT", "PROFILE", "BUCKET", "ZONE")


def is_secret_name(name: str) -> bool:
    """Does an env var NAME denote a secret (gets a canary) rather than configuration?
    Word-based on '_'-separated parts: AWS_SECRET_ACCESS_KEY / GITHUB_TOKEN → yes;
    AWS_REGION / API_BASE_URL / KB_ID / SESSION_ID → no."""
    parts = [p for p in str(name).upper().split("_") if p]
    if not parts:
        return False
    if parts[-1] in _NOT_SECRET_PARTS:
        return False
    return any(p in _SECRET_PARTS or p.endswith(("KEY", "TOKEN", "SECRET")) for p in parts)


def _exerciser_args(*, timeout: int, max_tools: int, canary: str, env_names: list[str],
                    readme: bool) -> str:
    args = ["--timeout", str(timeout), "--per-call-timeout", "10", "--max-tools",
            str(max_tools), "--canary-value", canary]
    names = [n for n in env_names if n and n.replace("_", "").isalnum() and is_secret_name(n)]
    if names:
        args += ["--canary-env", ",".join(names[:32])]
    if readme:
        args += ["--readme", "/work/README.md"]
    return " ".join(shlex.quote(a) for a in args)


def _default_plan(surface: str) -> str | None:
    return surface if surface in ("npm", "pypi", "docker") else None


def _merge_env_names(static: list[str] | None, readme_text: str | None) -> list[str]:
    """Static env reads first (exact), then credential-looking names mined from the README
    (``BRAVE_API_KEY`` in an install snippet) — a key-gated server gets its canary even
    when the static pass missed the read. De-duplicated, capped like the static list."""
    out: list[str] = []
    for name in list(static or []) + env_names_from_text(readme_text or ""):
        if name and name not in out:
            out.append(name)
    return out[:MAX_ENV_NAMES]


def _resource_args() -> list[str]:
    """``--memory-mb`` / ``--pids`` for the v2 runner from settings (v2 only: the v1
    script does not know the flags). Non-positive / unset → the runner's own defaults."""
    from src.config import settings
    out: list[str] = []
    try:
        mem = int(getattr(settings, "scanner_behavioral_memory_mb", 0) or 0)
    except (TypeError, ValueError):
        mem = 0
    try:
        pids = int(getattr(settings, "scanner_behavioral_pids", 0) or 0)
    except (TypeError, ValueError):
        pids = 0
    if mem > 0:
        out += ["--memory-mb", str(mem)]
    if pids > 0:
        out += ["--pids", str(pids)]
    return out


async def run_behavioral(
    surface: str,
    coordinate: str,
    *,
    expected_hosts: set[str] | None = None,
    manifest: str | None = None,
    timeout: int = 45,
    env_names: list[str] | None = None,
    readme_text: str | None = None,
    plan: str | None = None,
) -> BehavioralResult:
    """Run the target in the sandbox and return observed behavior. Fails OPEN.

    ``manifest`` is the tool's optional ``.agentavow.yml`` text; its declared egress hosts
    are added to ``expected_hosts`` so a tool is judged against what its author declared.
    ``plan`` overrides the surface→plan choice ("npm-mcp" / "pypi-mcp" when the package
    looks like an MCP server, "docker" for an image). ``env_names`` are the env vars the
    package reads (canary targets); ``readme_text`` helps the exerciser pick arguments."""
    from src.config import settings
    from src.scanner.behavioral.manifest import parse_manifest
    expected = set(expected_hosts or set()) | parse_manifest(manifest).egress_set()
    surface = (surface or "").lower()
    plan = (plan or "").strip().lower() or _default_plan(surface) or ""
    notes: list[str] = []

    def _fail(error: str) -> BehavioralResult:
        return BehavioralResult(ran=False, surface=surface, coordinate=coordinate,
                                error=error, plan=plan, notes=notes)

    if plan not in _SURFACE_PLAN:
        return _fail("unsupported_surface")

    v2 = bool((getattr(settings, "scanner_behavioral_sandbox_runner_v2", "") or "").strip())
    if not v2 and plan in _EXEC_FALLBACK:
        notes.append("v2_runner_off")
        plan = _EXEC_FALLBACK[plan]
    if not v2 and plan == "docker":
        return _fail("v2_runner_off")

    canary = _new_canary()
    files_b64: str | None = None
    if plan in _PLAN_FILES:
        files_b64 = _files_payload(plan, readme_text)
        if files_b64 is None:
            notes.append("exerciser_missing")
            plan = _EXEC_FALLBACK[plan]

    image_tmpl, cmd_tmpl, mode = _SURFACE_PLAN[plan]
    image = image_tmpl.format(name=coordinate)
    if mode == "mcp":
        mcp_timeout = int(getattr(settings, "scanner_behavioral_mcp_timeout", 90) or 90)
        max_tools = int(getattr(settings, "scanner_behavioral_max_tools", 25) or 25)
        timeout = max(int(timeout), mcp_timeout + 45)  # install + exercise budget
        spec = _git_spec(plan, coordinate) if "-git" in plan else coordinate
        cmd = cmd_tmpl.format(
            name=shlex.quote(spec), dist=shlex.quote(_dist_name(coordinate)),
            canary=shlex.quote(canary),
            exerciser_args=_exerciser_args(
                timeout=mcp_timeout, max_tools=max_tools, canary=canary,
                env_names=_merge_env_names(env_names, readme_text), readme=bool(readme_text)),
        )
    else:
        spec = _git_spec(plan, coordinate) if "-git" in plan else coordinate
        cmd = cmd_tmpl.format(name=shlex.quote(spec) if "-git" in plan else coordinate,
                              import_name=_import_name(coordinate))

    runner_args: list[str] = []
    if v2:
        runner_args += ["--mode", mode, "--canary", canary, *_resource_args()]
        if files_b64:
            runner_args += ["--files-b64", files_b64]
    runner_args += [image, cmd, str(timeout)]

    stdout_text, exec_error = await _execute(runner_args, timeout, v2=v2)
    if exec_error or stdout_text is None:
        return _fail(exec_error or "runner_unavailable")

    try:
        data = json.loads(stdout_text or "{}")
    except json.JSONDecodeError:
        notes.append(f"runner_output_len={len(stdout_text)}")
        # SSM caps a command's stdout at 24,000 chars; a cut-off JSON is this, not junk.
        return _fail("runner_output_truncated" if len(stdout_text) >= _SSM_STDOUT_CAP - 200
                     else "runner_bad_output")
    if isinstance(data, dict) and isinstance(data.get("gz"), str):
        try:
            data = json.loads(gzip.decompress(base64.b64decode(data["gz"])).decode("utf-8"))
        except Exception:  # noqa: BLE001
            return _fail("runner_bad_output")
    if not isinstance(data, dict):
        return _fail("runner_bad_output")
    if data.get("error"):
        return _fail(str(data["error"]))
    if data.get("exit_code") == _RESOURCE_LIMIT_EXIT:
        notes.append("killed_resource_limit")
    hosts = [str(h) for h in (data.get("egress_hosts") or [])]
    allow = expected | _SYNTHETIC_HOSTS | (_IMAGE_ALLOW if mode == "image" else set())
    vendor = _vendor_hosts(coordinate, hosts)
    unexpected = [h for h in _classify_egress(hosts, allow) if h not in vendor]
    exercise = data.get("exercise")
    transcript = parse_transcript(exercise) if isinstance(exercise, (dict, str)) else None
    canary_exfil = [
        {"via": str(h.get("via") or ""), "host": str(h.get("host") or "")}
        for h in (data.get("canary_exfil") or []) if isinstance(h, dict)
    ][:32]
    return BehavioralResult(
        ran=True, surface=surface, coordinate=coordinate,
        timed_out=bool(data.get("timed_out")),
        exit_code=data.get("exit_code"),
        egress_hosts=hosts,
        unexpected_egress=unexpected,
        fs_writes=[str(f) for f in (data.get("fs_writes") or [])],
        plan=plan, transcript=transcript, canary_exfil=canary_exfil, notes=notes,
        vendor_egress=[h for h in vendor if h not in allow],
    )


def behavioral_findings(result: BehavioralResult) -> list[Finding]:
    """Map observed behavior to findings for the BEHAVIORAL axis. Empty if it didn't run.
    Thin compatibility wrapper over :func:`graders.grade`."""
    from src.scanner.behavioral.graders import grade
    return list(grade(result))
