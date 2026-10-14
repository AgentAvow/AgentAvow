"""Where a finding sits inside a published npm / PyPI package, and what that means.

The 12-category engine matches text. Inside a published package three kinds of file
carry text that matches a code-execution or prompt-injection pattern without the
package running it or aiming it at an agent:

* **Detection data** — a guardrail's signature list (litellm's
  ``prompt_injection_malicious_code.yaml`` lists ``curl | bash`` so it can BLOCK it),
  a policy template, a jailbreak corpus. A ``.yaml`` / ``.json`` / ``.txt`` the package
  reads as data describes the attack; it does not run it.
* **A prebuilt web bundle** — ``_next/static`` chunks, ``*.min.js``, minified
  ``static/`` / ``assets/`` files a server hands to a browser. A browser cannot pipe
  anything to a shell, and a UI that shows a guardrail's rules carries their strings.
* **The package's own code that is not a tool surface** — a library's prompt template
  (langchain's summarization prompt), a log message about "the system prompt".

Prompt-injection phrases exist to catch injection in text an AGENT reads: MCP tool
descriptions, skill instructions, README / agent instructions. Those surfaces keep full
severity here: a file an agent is given as instructions (``SKILL.md``, ``AGENTS.md``,
``mcp.json``, ``skills/``, ``prompts/``, …), and code that declares agent tools. So does
anything a package or its tooling executes: shell scripts, lifecycle scripts
(``package.json``), CI workflows, Dockerfiles, compose files, ``.py`` / ``.js`` code.

``calibrate_package_findings`` lowers the matched findings to ``low`` (reported, never
scored, never blocking) with a remediation line that says why. Pure; applied to npm and
PyPI artifacts only — repository, MCP-server, skill, image and model scans are
unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path

# Formats a package reads as data. Not executed by the package manager or the runtime.
DATA_FILE_EXTS = frozenset({
    ".yaml", ".yml", ".json", ".jsonl", ".toml", ".xml", ".txt", ".csv", ".tsv", ".md",
})

# Data-format files that ARE executed by a tool: lifecycle / task scripts, CI, compose,
# GitHub Action definitions, build hooks. Never data.
EXECUTED_CONFIG_NAMES = frozenset({
    "package.json", "composer.json", "deno.json", "deno.jsonc", "pyproject.toml",
    "setup.cfg", "tox.ini", "turbo.json", "nx.json", "lerna.json", "vercel.json",
    "netlify.toml", "action.yml", "action.yaml", "taskfile.yml", "taskfile.yaml",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    ".pre-commit-config.yaml", ".pre-commit-hooks.yaml", "bitbucket-pipelines.yml",
    "buildspec.yml", "buildspec.yaml", "appveyor.yml", "codecov.yml", ".gitlab-ci.yml",
    ".travis.yml", "azure-pipelines.yml", "cloudbuild.yaml", "cloudbuild.yml",
    "makefile.toml", "justfile", "procfile",
})

# Files an agent is handed as instructions or tool definitions. Keep full severity.
AGENT_INSTRUCTION_NAMES = frozenset({
    "skill.md", "agents.md", "agent.md", "claude.md", "gemini.md", "copilot-instructions.md",
    ".cursorrules", ".windsurfrules", ".clinerules", "llms.txt", "llms-full.txt",
    "mcp.json", ".mcp.json", "server.json", "ai-plugin.json", "manifest.json",
    "plugin.json", "marketplace.json", "tools.json", "smithery.yaml", "smithery.yml",
    "openapi.json", "openapi.yaml", "openapi.yml",
    # crewAI-style agent / task definitions: role, goal and steps an agent follows.
    "agents.yaml", "agents.yml", "tasks.yaml", "tasks.yml",
})
AGENT_INSTRUCTION_DIRS = frozenset({
    "skills", "skill", ".claude", ".claude-plugin", ".cursor", ".windsurf", ".agents",
    ".codex", ".gemini", ".github", "agents", "prompts", "instructions", "commands",
})
# A data file named for agent instructions (`system_prompt.yaml`, `tool_defs.json`) is
# an instruction surface…
_INSTRUCTION_STEM_RE = re.compile(
    r"(?:^|[._-])(?:tools?|tool[_-]?defs?|mcp|skills?|prompts?|instructions?|system)"
    r"(?:[._-]|$)",
)
# …unless the path says it is detection data (`prompt_injection.yaml`,
# `content_filter_data/…`, `jailbreak_signatures.json`): a list of attacks to block.
_DETECTION_DATA_RE = re.compile(
    r"inject|jailbreak|malicious|attack|guardrail|blocklist|blacklist|denylist|"
    r"signature|detect|filter|moderation|red[_-]?team|threat|harmful|unsafe|abuse",
)

# Web bundles a server hands to a browser.
_BUNDLE_EXTS = frozenset({".js", ".mjs", ".cjs"})
_BUNDLE_DIRS = frozenset({"static", "assets", "public"})
_MINIFIED_LINE_CHARS = 1000  # same bar as scan._MINIFIED_LINE_CHARS (bidi rule)

# Finding categories that are text matches of code / attack shapes. Secrets (a leaked
# key in a config file is still leaked), invisible Unicode, dependency advisories and
# install hooks are never lowered here.
_DATA_TEXT_CATEGORIES = frozenset({
    "prompt_injection", "dynamic_remote_load", "unsafe_exec", "obfuscation",
    "insecure_deserialization", "fs_access", "exfiltration", "toxic_flow", "ssrf",
})
# In a browser bundle: shell-pipe strings, prompt phrases, and the whole-file heuristics
# (trifecta co-occurrence, MCP-tool SSRF shape) that a minified line satisfies by size.
# eval / Function / decoded exec / child_process / exfil keep their severity.
_BUNDLE_REMOTE_LOAD_NAMES = frozenset({"curl/wget piped to shell"})
_BUNDLE_CATEGORIES = frozenset({"prompt_injection", "toxic_flow", "ssrf"})
# Text that describes an exfiltration to an agent stays serious in code.
_CODE_INJECTION_KEEP = frozenset({"Exfiltration directive in description"})

# Code that declares agent tools: its strings ARE tool descriptions.
_TOOL_DECL_EXTRA_RE = re.compile(
    r"registerTool|addTool|ListToolsRequest|tools/list|@tool\b|StructuredTool|BaseTool|"
    r"FunctionTool|function_declarations",
)

WHY_DATA = ("Matched text in a data file the package reads, not code it runs or "
            "instructions it gives an agent (e.g. a guardrail's list of attacks to block). "
            "Reported for visibility; not scored.")
WHY_BUNDLE = ("Matched text in a prebuilt web bundle served to a browser; a browser does "
              "not run shell commands or read it as agent instructions. Reported for "
              "visibility; not scored.")
WHY_CODE_TEXT = ("Prompt text in the package's own code (a prompt template or log "
                 "message), not a tool description or instructions an agent is given. "
                 "Reported for visibility; not scored.")
WHY_CODE_PHRASE = ("Instruction-override text in the package's code, in a file that "
                   "declares no agent tool. Check whether the package returns this text "
                   "to an agent.")
_ROLE_DIRECTIVE = "Injected system/role directive"
# The role-override forms of that rule ("you are now DAN", "your new role is"): a
# jailbreak phrase, not template structure; in code they stay a medium.
_JAILBREAK_ROLE_RE = re.compile(r"you\s+are\s+now\b|your\s+(?:new|real|actual)\s+",
                                re.IGNORECASE)

PACKAGE_ECOSYSTEMS = frozenset({"npm", "pypi", "python"})
_CODE_EXTS = frozenset({".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"})


def _parts(path: str) -> list[str]:
    return [p.lower() for p in Path(path).parts]


def is_agent_instruction_file(path: str) -> bool:
    """A file an agent is given as instructions or tool definitions."""
    parts = _parts(path)
    if not parts:
        return False
    name = parts[-1]
    if name in AGENT_INSTRUCTION_NAMES or name.startswith("readme") or name.endswith(".mdc"):
        return True
    if any(p in AGENT_INSTRUCTION_DIRS for p in parts[:-1]):
        return True
    stem = Path(name).stem
    return bool(_INSTRUCTION_STEM_RE.search(stem)) and not _DETECTION_DATA_RE.search(
        "/".join(parts))


def is_package_data_file(path: str) -> bool:
    """A non-executed data file shipped in a package (see module docstring)."""
    from src.scanner.scan import _is_infra_file

    name = Path(path).name.lower()
    if Path(name).suffix not in DATA_FILE_EXTS:
        return False
    if name in EXECUTED_CONFIG_NAMES or is_agent_instruction_file(path):
        return False
    return not _is_infra_file(path)


def is_browser_bundle(path: str, text: str | None) -> bool:
    """A prebuilt web bundle: a Next.js static chunk, a ``*.min.js``, or a minified
    file under ``static/`` / ``assets/`` / ``public/``."""
    low = "/" + path.lower().lstrip("/")
    if Path(low).suffix not in _BUNDLE_EXTS:
        return False
    if "/_next/static/" in low or "/.next/static/" in low or low.endswith(".min.js"):
        return True
    if not any(p in _BUNDLE_DIRS for p in _parts(path)[:-1]):
        return False
    return bool(text) and any(len(ln) > _MINIFIED_LINE_CHARS for ln in text.split("\n"))


def _declares_tools(text: str | None) -> bool:
    from src.scanner.patterns import SSRF_TOOL_SURFACE_RE

    if not text:
        return False
    return bool(SSRF_TOOL_SURFACE_RE.search(text) or _TOOL_DECL_EXTRA_RE.search(text))


def _lower(f, why: str) -> None:
    f.severity = "low"
    f.remediation = why
    if hasattr(f, "payload"):
        f.payload = False


def calibrate_package_findings(findings: list, fetched) -> list:
    """Lower text-match findings in detection data, web bundles and non-tool code of an
    npm / PyPI artifact (module docstring). Mutates and returns ``findings``."""
    eco = (getattr(fetched, "ecosystem", "") or "").lower()
    if eco not in PACKAGE_ECOSYSTEMS:
        return findings
    files = getattr(fetched, "files", None) or {}
    cache: dict[str, tuple[str, bool]] = {}

    def context(path: str) -> tuple[str, bool]:
        """(``data`` | ``bundle`` | ``instructions`` | ``code`` | ``other``,
        declares_tools)."""
        if path not in cache:
            af = files.get(path)
            text = getattr(af, "text", None) if af is not None else None
            # Bundle before code (a chunk is .js); code before the instruction-path
            # check (a `.py` under `agents/` is code — whether its strings are tool
            # descriptions is the declares-tools test).
            if is_browser_bundle(path, text):
                ctx = "bundle"
            elif Path(path).suffix.lower() in _CODE_EXTS:
                ctx = "code"
            elif is_agent_instruction_file(path):
                ctx = "instructions"
            elif is_package_data_file(path):
                ctx = "data"
            else:
                ctx = "other"
            cache[path] = (ctx, ctx == "code" and _declares_tools(text))
        return cache[path]

    for f in findings:
        if getattr(f, "kind", "defect") == "capability":
            continue
        if f.severity not in ("critical", "high", "medium"):
            continue
        cat = getattr(f, "category", "")
        ctx, tools = context(getattr(f, "file_path", "") or "")
        if ctx == "data" and cat in _DATA_TEXT_CATEGORIES:
            _lower(f, WHY_DATA)
        elif ctx == "bundle" and (cat in _BUNDLE_CATEGORIES
                                  or f.name in _BUNDLE_REMOTE_LOAD_NAMES):
            _lower(f, WHY_BUNDLE)
        elif (ctx == "code" and cat == "prompt_injection" and not tools
              and f.name not in _CODE_INJECTION_KEEP):
            if f.name == _ROLE_DIRECTIVE and not _JAILBREAK_ROLE_RE.search(f.snippet or ""):
                # `<instructions>` / "System prompt:" structuring the package's own
                # model call: prompt-template text.
                _lower(f, WHY_CODE_TEXT)
            elif f.severity in ("critical", "high"):
                # An override / hide-from-user phrase in code that declares no tool may
                # still be text the package returns to an agent: kept, not blocking.
                f.severity = "medium"
                f.remediation = WHY_CODE_PHRASE
    return findings
