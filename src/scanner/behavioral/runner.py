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
# OpenClaw / Agent Skill: a repo, not a package. The skill is cloned (shallow) and the
# shipped exerciser runs its lifecycle hooks, .mcp.json servers and bundled scripts with
# canary credentials (see scripts/sandbox/skill_exercise.sh for the exact rules). Scripts
# may be bash / node, so the alt-root apk install also brings nodejs, npm and bash — each
# a separate, optional step so a mirror hiccup on one never costs the clone. The git
# wrapper is the pypi-mcp one plus the CA bundle for an https clone.
_ALPINE_SKILL_PREFIX = (
    "(mkdir -p /work/.apk/etc/apk /work/.local/bin && "
    "cp -r /etc/apk/keys /etc/apk/repositories /work/.apk/etc/apk/ && "
    "apk add --no-cache --no-scripts --initdb -p /work/.apk git && "
    "printf '#!/bin/sh\\nexport LD_LIBRARY_PATH=/work/.apk/usr/lib:/work/.apk/lib "
    "GIT_EXEC_PATH=/work/.apk/usr/libexec/git-core "
    "GIT_TEMPLATE_DIR=/work/.apk/usr/share/git-core/templates "
    "GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt\\n"
    "exec /work/.apk/usr/bin/git \"$@\"\\n' > /work/.local/bin/git && "
    "chmod +x /work/.local/bin/git && "
    "(apk add --no-cache --no-scripts -p /work/.apk nodejs npm bash && "
    "printf '#!/bin/sh\\nexport LD_LIBRARY_PATH=/work/.apk/usr/lib:/work/.apk/lib\\n"
    "exec /work/.apk/usr/bin/node \"$@\"\\n' > /work/.local/bin/node && "
    "printf '#!/bin/sh\\nexec /work/.local/bin/node /work/.apk/usr/bin/npm \"$@\"\\n' "
    "> /work/.local/bin/npm && "
    "printf '#!/bin/sh\\nexport LD_LIBRARY_PATH=/work/.apk/usr/lib:/work/.apk/lib\\n"
    "exec /work/.apk/bin/bash \"$@\"\\n' > /work/.local/bin/bash && "
    "chmod +x /work/.local/bin/node /work/.local/bin/npm /work/.local/bin/bash || true)"
    ") >/dev/null 2>&1 || true; "
)
# {repo} = "owner/repo" (GitHub only; validated + shell-quoted by the runner).
_SKILL_CMD = (
    _SANDBOX_ENV + _ALPINE_SKILL_PREFIX
    + "git clone --depth 1 https://github.com/{repo} /work/skill && cd /work/skill && "
    "sh /work/skill_exercise.sh {exerciser_args}"
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
    "skill": ("python:3.12-alpine", _SKILL_CMD, "exec"),
}
_SKILL_REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def _git_spec(plan: str, coordinate: str) -> str:
    """The install spec for a git plan: 'owner/repo' → github:owner/repo (npm) or
    git+https://github.com/owner/repo (pip). A 'github:' / URL prefix is tolerated."""
    repo = coordinate.strip()
    for prefix in ("github:", "https://github.com/", "http://github.com/", "git+https://github.com/"):
        if repo.lower().startswith(prefix):
            repo = repo[len(prefix):]
    repo = repo.strip("/").removesuffix(".git")
    if plan == "skill":
        return repo  # the skill plan clones https://github.com/{repo} itself
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
    "skill": ("skill_exercise.sh",),
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
    # GitHub release downloads (install-time prebuilt binaries) moved here in 2025.
    "release-assets.githubusercontent.com",
    # Well-known library data fetched at import, not by the tool's own logic:
    # tiktoken's tokenizer files (any Python package using OpenAI tokenizers).
    "openaipublic.blob.core.windows.net",
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

# SSRF probe sentinel. A URL-taking tool is handed this link-local address; if the server
# actually connects to it, the host-side capture sees a packet to the sentinel IP and the
# ``ssrf_internal_fetch`` grader fires — the tool follows a caller-supplied URL to an
# internal target without validating it (CVE-2026-14540 and the JPMorgan/DINUM class).
# 169.254.254.254 is link-local (RFC 3927): routers never forward it, so the packet dies
# at the sandbox host and can reach no real system — and it is NOT 169.254.169.254, so it
# never collides with a cloud SDK's own metadata probe. The matching dst-IP grep lives in
# scripts/sandbox/behavioral_run_v2.sh; keep the two in sync.
SSRF_SENTINEL_IP = "169.254.254.254"
SSRF_SENTINEL_URL = "http://169.254.254.254/agentavow-ssrf"


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
    # SSRF sentinel targets the server actually connected to (see SSRF_SENTINEL_IP). A
    # non-empty list means a tool followed a caller-supplied URL to a link-local address.
    ssrf_hits: list[str] = field(default_factory=list)

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
            "ssrf_hits": self.ssrf_hits,
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
        if _vendor_label_matches(registrable, toks):
            out.append(h)
    return out


# A vendor's API often lives on a domain that is not its bare name.
_VENDOR_ALIASES = {
    "google": {"googleapis", "google", "gstatic", "googleusercontent"},
    "gmail": {"googleapis", "google"}, "gdrive": {"googleapis", "google"},
    "gcp": {"googleapis", "google"}, "gemini": {"googleapis", "google"},
    "aws": {"amazonaws"}, "amazon": {"amazonaws", "amazon"},
    "azure": {"azure", "windows", "microsoft"}, "microsoft": {"microsoft", "windows", "azure"},
    "github": {"github", "githubusercontent"}, "slack": {"slack"},
}
# Common product-domain affixes: trynia.ai / getnia.com / niaapp.io → vendor 'nia'.
_VENDOR_AFFIXES = ("try", "get", "use", "go", "my", "hq", "app", "api", "io")


def _vendor_label_matches(label: str, toks: set[str]) -> bool:
    if label in toks:
        return True
    for t in toks:
        if label in _VENDOR_ALIASES.get(t, ()):
            return True
        if any(label in (a + t, t + a) for a in _VENDOR_AFFIXES):
            return True
    return False


# The sandbox host's resolver appends its search domain to non-FQDN lookups, so a lookup
# of github.com can also appear as github.com.ec2.internal. Those are not destinations.
_SEARCH_DOMAIN_SUFFIXES = (".ec2.internal", ".internal", ".local", ".localdomain",
                           ".home.arpa", ".lan", ".compute.internal")


def _is_search_domain_artifact(host: str) -> bool:
    return (host or "").lower().rstrip(".").endswith(_SEARCH_DOMAIN_SUFFIXES)


def _classify_egress(hosts: list[str], expected: set[str]) -> list[str]:
    """Hosts reached that are neither a package registry nor a declared/expected host."""
    allow = _REGISTRY_ALLOW | {h.lower() for h in expected}
    out: list[str] = []
    for h in hosts:
        hl = (h or "").strip().lower()
        if not hl or _is_search_domain_artifact(hl):
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


def _canary_env_names(env_names: list[str]) -> list[str]:
    """The env names that get a canary: well-formed and secret-looking (≤32)."""
    return [n for n in env_names
            if n and n.replace("_", "").isalnum() and is_secret_name(n)][:32]


def _exerciser_args(*, timeout: int, max_tools: int, canary: str, env_names: list[str],
                    readme: bool) -> str:
    args = ["--timeout", str(timeout), "--per-call-timeout", "10", "--max-tools",
            str(max_tools), "--canary-value", canary, "--ssrf-url", SSRF_SENTINEL_URL]
    names = _canary_env_names(env_names)
    if names:
        args += ["--canary-env", ",".join(names)]
    if readme:
        args += ["--readme", "/work/README.md"]
    return " ".join(shlex.quote(a) for a in args)


_SKILL_SCRIPT_TIMEOUT = 20  # seconds per hook / bundled script inside the sandbox


def _skill_exerciser_args(*, timeout: int, max_scripts: int, canary: str,
                          env_names: list[str]) -> str:
    """Arguments for scripts/sandbox/skill_exercise.sh: the overall budget, the per-script
    timeout, the script cap, and the canary value + the secret-named env vars the static
    scan saw the skill read (exported with that value for every hook and script)."""
    args = ["--timeout", str(timeout), "--per-script-timeout", str(_SKILL_SCRIPT_TIMEOUT),
            "--max-scripts", str(max_scripts), "--canary-value", canary]
    names = _canary_env_names(env_names)
    if names:
        args += ["--canary-env", ",".join(names)]
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


def _retry_memory_mb(resource: list[str]) -> int:
    """The retry cap when it is above the cap the run used; 0 = no retry."""
    from src.config import settings
    try:
        retry = int(getattr(settings, "scanner_behavioral_memory_retry_mb", 0) or 0)
    except (TypeError, ValueError):
        return 0
    try:
        current = int(resource[resource.index("--memory-mb") + 1])
    except (ValueError, IndexError):
        current = 0
    return retry if retry > current else 0


def _with_memory(resource: list[str], mem_mb: int) -> list[str]:
    out = list(resource)
    if "--memory-mb" in out:
        out[out.index("--memory-mb") + 1] = str(mem_mb)
    else:
        out += ["--memory-mb", str(mem_mb)]
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
    looks like an MCP server, "docker" for an image, "skill" for an OpenClaw / Agent Skill
    repo — coordinate "owner/repo" — whose hooks and scripts are run). ``env_names`` are the env vars the
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
    if not v2 and plan in ("docker", "skill"):
        return _fail("v2_runner_off")
    if plan == "skill" and not _SKILL_REPO_RE.fullmatch(_git_spec(plan, coordinate)):
        return _fail("bad_coordinate")

    canary = _new_canary()
    files_b64: str | None = None
    if plan in _PLAN_FILES:
        files_b64 = _files_payload(plan, readme_text)
        if files_b64 is None:
            notes.append("exerciser_missing")
            if plan not in _EXEC_FALLBACK:
                return _fail("exerciser_missing")  # a skill has no install-only fallback
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
    elif plan == "skill":
        # apk + clone, then every hook/script with its own timeout inside one budget: the
        # exerciser gets the MCP budget, the container the budget plus install headroom.
        budget = int(getattr(settings, "scanner_behavioral_mcp_timeout", 90) or 90)
        max_scripts = int(getattr(settings, "scanner_behavioral_max_tools", 25) or 25)
        timeout = max(int(timeout), budget + 60)
        cmd = cmd_tmpl.format(
            repo=shlex.quote(_git_spec(plan, coordinate)),
            exerciser_args=_skill_exerciser_args(
                timeout=budget, max_scripts=max_scripts, canary=canary,
                env_names=list(env_names or [])),
        )
    else:
        spec = _git_spec(plan, coordinate) if "-git" in plan else coordinate
        cmd = cmd_tmpl.format(name=shlex.quote(spec) if "-git" in plan else coordinate,
                              import_name=_import_name(coordinate))

    def _args(resource: list[str]) -> list[str]:
        out: list[str] = []
        if v2:
            out += ["--mode", mode, "--canary", canary, *resource]
            if files_b64:
                out += ["--files-b64", files_b64]
        out += [image, cmd, str(timeout)]
        return out

    async def _run_once(runner_args: list[str]) -> tuple[dict | None, str | None]:
        """Execute and parse one runner invocation → (data, None) or (None, error)."""
        stdout_text, exec_error = await _execute(runner_args, timeout, v2=v2)
        if exec_error or stdout_text is None:
            return None, exec_error or "runner_unavailable"
        try:
            parsed = json.loads(stdout_text or "{}")
        except json.JSONDecodeError:
            notes.append(f"runner_output_len={len(stdout_text)}")
            # SSM caps a command's stdout at 24,000 chars; a cut-off JSON is this, not junk.
            return None, ("runner_output_truncated"
                          if len(stdout_text) >= _SSM_STDOUT_CAP - 200 else "runner_bad_output")
        if isinstance(parsed, dict) and isinstance(parsed.get("gz"), str):
            try:
                parsed = json.loads(
                    gzip.decompress(base64.b64decode(parsed["gz"])).decode("utf-8"))
            except Exception:  # noqa: BLE001
                return None, "runner_bad_output"
        if not isinstance(parsed, dict):
            return None, "runner_bad_output"
        if parsed.get("error"):
            return None, str(parsed["error"])
        return parsed, None

    resource = _resource_args()
    data, err = await _run_once(_args(resource))
    if err or data is None:
        return _fail(err or "runner_unavailable")
    if data.get("exit_code") == _RESOURCE_LIMIT_EXIT:
        notes.append("killed_resource_limit")
        # The container was SIGKILLed by its memory / pids cap before the tool could be
        # observed. Heavy-but-legitimate servers (task-master, anything that bundles a
        # browser) do this at the default cap; give them ONE more run at the retry cap so
        # the grade rests on an observation, not on static analysis alone.
        retry_mb = _retry_memory_mb(resource)
        if v2 and retry_mb:
            notes.append(f"retried_at_{retry_mb}mb")
            data2, err2 = await _run_once(_args(_with_memory(resource, retry_mb)))
            if data2 is not None and not err2:
                data = data2
                if data.get("exit_code") != _RESOURCE_LIMIT_EXIT:
                    notes.remove("killed_resource_limit")
            # else: keep the first run's result (fail-open; the retry never makes it worse)
    hosts = [str(h) for h in (data.get("egress_hosts") or [])
             if not _is_search_domain_artifact(str(h))]
    allow = expected | _SYNTHETIC_HOSTS | (_IMAGE_ALLOW if mode == "image" else set())
    vendor = _vendor_hosts(coordinate, hosts)
    unexpected = [h for h in _classify_egress(hosts, allow) if h not in vendor]
    exercise = data.get("exercise")
    transcript = parse_transcript(exercise) if isinstance(exercise, (dict, str)) else None
    canary_exfil = [
        {"via": str(h.get("via") or ""), "host": str(h.get("host") or "")}
        for h in (data.get("canary_exfil") or []) if isinstance(h, dict)
    ][:32]
    ssrf_hits = [str(h) for h in (data.get("ssrf_hits") or []) if h][:8]
    return BehavioralResult(
        ran=True, surface=surface, coordinate=coordinate,
        timed_out=bool(data.get("timed_out")),
        exit_code=data.get("exit_code"),
        egress_hosts=hosts,
        unexpected_egress=unexpected,
        fs_writes=[str(f) for f in (data.get("fs_writes") or [])],
        plan=plan, transcript=transcript, canary_exfil=canary_exfil, notes=notes,
        vendor_egress=[h for h in vendor if h not in allow],
        ssrf_hits=ssrf_hits,
    )


def behavioral_findings(result: BehavioralResult) -> list[Finding]:
    """Map observed behavior to findings for the BEHAVIORAL axis. Empty if it didn't run.
    Thin compatibility wrapper over :func:`graders.grade`."""
    from src.scanner.behavioral.graders import grade
    return list(grade(result))
