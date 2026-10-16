"""Detection data and prebuilt web bundles inside a published npm / PyPI package.

The 12-category engine matches text. Two kinds of file in a published package carry
text that matches a code-execution or prompt-injection pattern without the package
running it or aiming it at an agent:

* **Detection data**: a guardrail's signature list. litellm's
  ``content_filter_data/categories/prompt_injection_malicious_code.yaml`` lists
  ``curl | bash`` so it can BLOCK it.
* **A prebuilt web bundle**: a Next.js ``_next/static`` chunk or a minified asset a
  server hands to a browser. A browser cannot pipe anything to a shell, and a UI that
  shows a guardrail's rules carries their strings.

Data files are NEVER lowered by default (an MCP server's ``descriptions.json`` or
``locales/en.json`` is where its tool text lives; a ``cfg.yaml`` can be what the code
``exec``s). A finding in a data file drops to ``low`` only when ALL of these hold:

1. the file's stem or its immediate parent directory names detection data
   (``prompt_injection``, ``guardrail``, ``jailbreak``, ``blocklist``, ``policy`` …), and
   the stem is not instruction-ish (``tool``, ``system``, ``instructions``,
   ``description``, ``prompts``, ``skill``, ``mcp``, ``agent``), except after a leading
   ``prompt_injection_`` prefix, where the rest names the attack's sub-category
   (``prompt_injection_system_prompt``);
2. the content has the shape of a detection list: at least two detection keys
   (``keyword``, ``patterns``, ``always_block_keywords``, ``utterances``, ``severity``,
   ``default_action`` …) and the matched line is a short list entry
   (``- "curl | bash"``, ``- keyword: "…"``, a JSON array string), not a free-text value;
3. no code file in the package that could reach it (names its basename or its directory,
   or enumerates files of its extension) has an exec / eval / system / subprocess /
   spawn / ``new Function`` / pickle sink;
4. it is not an agent-instruction surface, a lifecycle / CI / compose file, or infra.

A web bundle (``_next/static`` / ``.next/static``, ``*.min.js``, or a minified file
under ``static/`` / ``assets/`` / ``public/``) has pipe-to-shell strings, prompt phrases
and the whole-file trifecta / SSRF heuristics lowered, unless the file can act as Node
code: it ``require``s or imports a Node core module, touches ``process.env`` /
``stdin`` / ``argv`` outside a string, declares MCP tools, or is named by
``package.json`` (``main`` / ``bin`` / ``exports``) or by any non-bundle code file. In
such a bundle the zero-width-character rule is lowered too (minified UI libraries carry
ZWJ / ZWSP in string tables); the Tags-block rule never is.

The role-directive rule ("Injected system/role directive") in package CODE is lowered
when the package declares no agent tool at all, or, in a package that does, when the
finding is already a medium (scan.py demoted it: a bare tag in a file that declares no
tool, or a "system prompt:" label) AND its own file defines no tool (MCP decorators,
FastMCP ``add_tool``, LangChain, OpenAI function schemas, Vercel ``tool({…})``, WebMCP)
AND the line is either a "system prompt:" label followed only by a placeholder or a
tag that is the whole of a one-line string literal used as an element (no
concatenation / join / formatting / f-string / ``${}`` on the line, and the file never
holds the same tag as both an opening and a closing literal) AND no file that registers
tools names the module, directly or through a package ``__init__`` / ``index`` it
names (a constant the tool code imports can become a tool description). A tag inside a
longer string, a role-override phrase, and anything in a metadata / instruction file
keep their severity. Each condition is pinned by a recall-review fixture.

Minified (``.min.``) files are skipped by the engine, except the ones the package runs:
named by package.json ``main`` / ``bin`` / ``exports`` / ``scripts`` (with or without the
extension), ``require``d / imported / run with ``node`` by code, transitively. Those are
read as code and are never treated as browser bundles.

A ``curl … | bash`` string in JS / TS / Python code is lowered when its value reaches
only human-facing output in every file of the package that reads it (a printed install
hint: ``src.scanner.printed_hint``).

Applied to npm and PyPI artifacts only; repository, MCP-server, skill, image and model
scans are unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path

from src.scanner.printed_hint import WHY as WHY_HINT
from src.scanner.printed_hint import Hints, is_supported

PACKAGE_ECOSYSTEMS = frozenset({"npm", "pypi", "python"})

# Formats a package reads as data. Not executed by the package manager or the runtime.
DATA_FILE_EXTS = frozenset({
    ".yaml", ".yml", ".json", ".jsonl", ".toml", ".xml", ".txt", ".csv", ".tsv", ".md",
})
# Data-format files that ARE executed by a tool. Never data.
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
# Files an agent is handed as instructions or tool definitions. Never data.
AGENT_INSTRUCTION_NAMES = frozenset({
    "skill.md", "agents.md", "agent.md", "claude.md", "gemini.md", "copilot-instructions.md",
    ".cursorrules", ".windsurfrules", ".clinerules", "llms.txt", "llms-full.txt",
    "mcp.json", ".mcp.json", "server.json", "ai-plugin.json", "manifest.json",
    "plugin.json", "marketplace.json", "tools.json", "smithery.yaml", "smithery.yml",
    "openapi.json", "openapi.yaml", "openapi.yml",
    "agents.yaml", "agents.yml", "tasks.yaml", "tasks.yml",
})
AGENT_INSTRUCTION_DIRS = frozenset({
    "skills", "skill", ".claude", ".claude-plugin", ".cursor", ".windsurf", ".agents",
    ".codex", ".gemini", ".github", "agents", "prompts", "instructions", "commands",
})

# (1) Name evidence, read from the stem and the immediate parent only.
_DETECTION_WORD_RE = re.compile(
    r"inject|jailbreak|malicious|attack|guardrail|blocklist|blacklist|denylist|"
    r"signature|detect|moderation|red[_-]?team|threat|harmful|abuse|policy|policies",
)
# A compound that NAMES the attack ("prompt_injection") is removed before looking for
# instruction-ish tokens, so `prompt_injection_malicious_code` is not "a prompt file".
_ATTACK_COMPOUND_RE = re.compile(r"prompt[_-]?injections?")
_ATTACK_PREFIX_RE = re.compile(r"prompt[_-]?injections?[_-]")
_INSTRUCTION_TOKENS = frozenset({
    "tool", "tools", "tooldefs", "tool_defs", "defs", "system", "instruction",
    "instructions", "description", "descriptions", "prompt", "prompts", "skill", "skills",
    "mcp", "agent", "agents", "persona", "personas", "role", "roles",
})
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

# (2) Content shape of a detection list.
_DETECTION_KEY_RE = re.compile(
    r"""(?m)^\s*-?\s*["']?(keywords?|patterns?|regex(?:es|ps)?|always_block\w*|"""
    r"""block(?:ed)?_\w+|additional_block_words|identifier_words|exceptions?|"""
    r"""utterances|example_sentences|examples|category(?:_name)?|categories|severity|"""
    r"""default_action|action|match_type|similarity_threshold|guardrails?|"""
    r"""denied_\w+|route_name)["']?\s*:""",
)
_MIN_DETECTION_KEYS = 2
# The matched line is a short list entry, not a free-text value.
_LIST_ENTRY_RE = re.compile(
    r"""^\s*-\s+(?:(?:keyword|pattern|regex|utterance|example)\s*:\s*)?"""
    r"""(?:"[^"\n]{1,200}"|'[^'\n]{1,200}'|[^\s"'#:][^:#\n]{0,199})\s*$"""
    r"""|^\s*"[^"\n]{1,200}"\s*,?\s*$"""
    r"""|^\s*"(?:keyword|pattern|regex|utterance|example)"\s*:\s*"[^"\n]{1,200}"\s*,?\s*$""",
)

# (3) A code file that could load the data file and run it.
_EXEC_SINK_RE = re.compile(
    r"""\bexec\s*\(|\beval\s*\(|os\.system|\bpopen\s*\(|\bsubprocess\b|child_process|"""
    r"""\bexecSync\b|\bexecFile(?:Sync)?\b|\bspawn(?:Sync)?\s*\(|\bnew\s+Function\b|"""
    r"""\bFunction\s*\(|\bpickle\.|\bmarshal\.|\bdill\.|\brunpy\b|\bvm\.run\w*|"""
    r"""shell\s*=\s*True|\bcompile\s*\([^)]*['"]exec['"]""",
)
_REF_WINDOW = 40  # lines between a directory / extension reference and the sink
_ENUMERATE_RE = re.compile(r"\bglob\b|listdir|iterdir|readdirSync|readdir\b|os\.walk|scandir")
_REFERENCER_EXTS = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts",
    ".sh", ".bash", ".zsh", ".rb", ".pl", ".php", ".ps1", ".bat", ".cmd",
})

# Web bundles.
_BUNDLE_EXTS = frozenset({".js", ".mjs", ".cjs"})
_BUNDLE_DIRS = frozenset({"static", "assets", "public"})
_MINIFIED_LINE_CHARS = 1000  # same bar as scan._MINIFIED_LINE_CHARS (bidi rule)
# Node capability anywhere in the file (a string-hidden `require('child_process')` is
# still a disqualifier: these are never in a browser bundle's code).
_NODE_MODULE_RE = re.compile(
    r"""require\s*\(\s*['"`](?:node:)?(?:child_process|fs|fs/promises|net|http|https|"""
    r"""http2|os|tls|dgram|worker_threads|cluster|vm|module|process|readline)['"`]\s*\)|"""
    r"""\bfrom\s*['"`]node:|\bimport\s*\(\s*['"`]node:|"""
    r"""\bfrom\s*['"`](?:child_process|fs|net|https?|os|vm|worker_threads)['"`]""",
)
# Node globals, counted only outside string literals (a guardrail test-suite string such
# as "Use `Function('return process.env')()`" is UI text).
_NODE_GLOBAL_RE = re.compile(r"\bprocess\.(?:env|stdin|argv|binding|mainModule)\b")
_TOOL_DECL_RE = re.compile(
    r"""@(?:\w+\.)?tool\b|\.tool\s*\(|registerTool|addTool|CallToolRequest|"""
    r"""ListToolsRequest|tools/(?:call|list)|list_tools|inputSchema|input_schema""",
)
# Bundle disqualifier. Same as above, except a QUOTED `"mcp_list_tools"` (the OpenAI
# Responses output item type a browser UI compares against, litellm's chunk) is not a
# declaration; an unquoted `mcp_list_tools` (a handler, a key) still is. WebMCP
# (`navigator.modelContext.registerTool / provideContext`) declares agent tools in a
# browser, so `modelContext` / `provideContext` disqualify too (recall review).
_BUNDLE_TOOL_DECL_RE = re.compile(
    r"""@(?:\w+\.)?tool\b|\.tool\s*\(|registerTool|addTool|CallToolRequest|"""
    r"""ListToolsRequest|tools/(?:call|list)|(?<!["'`]mcp_)list_tools|inputSchema|"""
    r"""input_schema|modelContext|provideContext""",
)
# Other ways a FILE defines an agent tool that _TOOL_DECL_RE misses (recall review):
# FastMCP `add_tool`, LangChain `StructuredTool.from_function` / `Tool(name=…)`, OpenAI
# function schemas, Vercel AI `tool({…})`, WebMCP, OpenAI Agents `@function_tool`.
_TOOL_DEF_EXTRA_RE = re.compile(
    r"""\badd_tool\s*\(|\bStructuredTool\b|\bfrom_function\s*\(|\b\w*Tool\s*\(\s*name\s*=|"""
    r"""["']type["']\s*:\s*["']function["']|\btool\s*\(\s*\{|modelContext|provideContext|"""
    r"""function_tool|\bFastMCP\s*\(|\bMcpServer\s*\(|\bBaseTool\b""",
)


def _defines_tools(text: str) -> bool:
    return bool(_TOOL_DECL_RE.search(text) or _TOOL_DEF_EXTRA_RE.search(text))


# A file that REGISTERS / serves tools (not one that merely mentions `tools/list` in a
# docstring or reads an `input_schema` as a gateway): the files whose imports decide
# whether a prompt constant can end up in a tool description.
_TOOL_REGISTER_RE = re.compile(
    r"""@(?:\w+\.)*tool\b|\.tool\s*\(|registerTool|addTool|CallToolRequest|"""
    r"""ListToolsRequest|@(?:\w+\.)+(?:list_tools|call_tool)\b|\bdef\s+\w*list_tools\b|"""
    r"""\b\w*list_tools\s*[:=]""",
)

# Findings lowered.
_DATA_TEXT_CATEGORIES = frozenset({
    "prompt_injection", "dynamic_remote_load", "unsafe_exec", "obfuscation",
    "insecure_deserialization", "fs_access", "exfiltration",
})
_BUNDLE_REMOTE_LOAD_NAMES = frozenset({"curl/wget piped to shell"})
_BUNDLE_CATEGORIES = frozenset({"prompt_injection", "toxic_flow", "ssrf"})
# Minifiers and UI libraries carry zero-width joiners / spaces in string tables (text
# segmentation, emoji ZWJ sequences). The Tags-block and bidi rules are NOT in this set:
# a Tags-block run is smuggled text wherever it is, and bidi already has its own rule.
_BUNDLE_UNICODE_NAMES = frozenset({"Zero-width / invisible character"})

WHY_DATA = ("Matched text is an entry in a detection list the package ships (a "
            "guardrail's list of attacks to block); no code in the package that could "
            "load the file executes anything. Reported for visibility; not scored.")
WHY_BUNDLE = ("Matched text in a prebuilt web bundle served to a browser (no Node "
              "modules, no process access, not loaded by the package's code). Reported "
              "for visibility; not scored.")

WHY_CODE_TEXT = ("Prompt-template text (a tag or a \"System prompt:\" label) in the code of "
                 "a package that declares no agent tool. Reported for visibility; not "
                 "scored.")
_ROLE_DIRECTIVE = "Injected system/role directive"
# The role-override forms of that rule ("you are now DAN", "your new role is") are a
# jailbreak phrase, not template structure: never lowered.
_JAILBREAK_ROLE_RE = re.compile(r"you\s+are\s+now\b|your\s+(?:new|real|actual)\s+",
                                re.IGNORECASE)
_CODE_EXTS = frozenset({".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"})

WHY_PROMPT_STRUCTURE = ("A prompt label or a tag used as a delimiter (a \"System prompt:\" "
                        "label followed only by a placeholder, or a string that is only "
                        "`</instructions>`) in the code of a file that declares no agent "
                        "tool. It carries no instruction text. Reported for visibility; "
                        "not scored.")
# A tag that is the WHOLE content of a one-line string literal, as an element of a tuple,
# list, call or assignment: `("# agents.md instructions for ", "</instructions>")`.
# A tag inside a longer string (a multi-line template that wraps text between
# `<important>` and `</important>`, Invariant Labs' tool-poisoning shape) does not match.
_TAG_NAMES = r"(?:system|important|instructions?|SYSTEM|IMPORTANT|INSTRUCTIONS?)"
_DELIM_LITERAL_RE = re.compile(
    r"""(?:^|[\s(\[{,=:])(["'`])\s*<\s*(/?)\s*(""" + _TAG_NAMES + r""")\s*>\s*\1"""
    r"""(?=\s*[,)\]};])""")  # an element; a literal ending the line may be implicit concat
_ANY_TAG_RE = re.compile(r"<\s*/?\s*" + _TAG_NAMES + r"\s*>")
# Building text on the line (concatenation, join, formatting, interpolation) disqualifies
# the delimiter reading: `"<important>" + DIRECTIVE`, `"".join(("<important>", …))`,
# `f"{OPEN} …"`, `` `${OPEN} …` `` assemble a description.
_STRING_BUILD_RE = re.compile(
    r"""\+|\bjoin\s*\(|\.format\s*\(|\bconcat\s*\(|%\s*[(\w]|\$\{|"""
    r"""(?<![\w])[rRbB]?[fF][rRbB]?["']""")
# A Python / JS module reference, for "does tool code import this file".
_WORD_RE = re.compile(r"[A-Za-z_$][\w$]*")
_INDEX_STEMS = frozenset({"__init__", "index"})


def delimiter_tags_only(line: str, file_text: str = "") -> bool:
    """Every role-directive tag on ``line`` is a whole one-line string literal used as a
    delimiter, nothing on the line builds a string from it, and the file never holds the
    same tag as BOTH an opening and a closing delimiter literal (a pair wraps text)."""
    tags = list(_ANY_TAG_RE.finditer(line))
    delims = list(_DELIM_LITERAL_RE.finditer(line))
    if not tags or len(delims) != len(tags) or _STRING_BUILD_RE.search(line):
        return False
    for m in delims:
        other = "" if m.group(2) else "/"
        pair = re.compile(r"""["'`]\s*<\s*""" + other + r"\s*" + re.escape(m.group(3))
                          + r"""\s*>\s*["'`]""", re.IGNORECASE)
        if pair.search(file_text or ""):
            return False
    return True


def system_prompt_label_only(line: str) -> bool:
    """The role-directive hits on ``line`` are "system prompt:" labels followed only by a
    format placeholder (``"failed to prepend system prompt: %s"``)."""
    from src.scanner.patterns import PROMPT_INJECTION_PATTERNS
    from src.scanner.scan import _system_prompt_label_only
    pattern = next(p for n, p, _s in PROMPT_INJECTION_PATTERNS if n == _ROLE_DIRECTIVE)
    return _system_prompt_label_only(line, pattern)


def _parts(path: str) -> list[str]:
    return [p.lower() for p in Path(path).parts]


def is_agent_instruction_file(path: str) -> bool:
    """A file an agent is given as instructions or tool definitions (by name / dir)."""
    parts = _parts(path)
    if not parts:
        return False
    name = parts[-1]
    if name in AGENT_INSTRUCTION_NAMES or name.startswith("readme") or name.endswith(".mdc"):
        return True
    return any(p in AGENT_INSTRUCTION_DIRS for p in parts[:-1])


def _stem_tokens(stem: str) -> set[str]:
    return {t for t in _TOKEN_SPLIT_RE.split(_ATTACK_COMPOUND_RE.sub(" ", stem)) if t}


def detection_name_evidence(path: str) -> bool:
    """(1): the stem or the immediate parent names detection data, and the stem is not
    instruction-ish."""
    parts = _parts(path)
    if not parts:
        return False
    stem = Path(parts[-1]).stem
    parent = parts[-2] if len(parts) > 1 else ""
    # A stem that STARTS with the attack name (`prompt_injection_system_prompt`): the
    # rest is the attack's sub-category, so an instruction-ish word after the prefix
    # does not block (shape, list entry and reachability are still required).
    if _ATTACK_PREFIX_RE.match(stem):
        return True
    if _stem_tokens(stem) & _INSTRUCTION_TOKENS:
        return False
    return bool(_DETECTION_WORD_RE.search(stem) or _DETECTION_WORD_RE.search(parent))


def detection_shape(text: str | None) -> bool:
    """(2, file part): at least two distinct detection-list keys."""
    if not text:
        return False
    keys = {m.group(1).lower() for m in _DETECTION_KEY_RE.finditer(text)}
    return len(keys) >= _MIN_DETECTION_KEYS


def is_list_entry(line: str) -> bool:
    """(2, line part): the matched line is a short list entry."""
    return bool(_LIST_ENTRY_RE.match(line))


def _outside_strings(text: str, pos: int, starts: list[int], ends: list[int]) -> bool:
    import bisect
    i = bisect.bisect_right(starts, pos) - 1
    return i < 0 or pos >= ends[i]


def _string_spans(text: str) -> tuple[list[int], list[int]]:
    """Quote-delimited spans (', ", `) with backslash escapes. Approximate (regex
    literals are not modelled); used only to IGNORE a Node global inside UI text."""
    starts: list[int] = []
    ends: list[int] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"`":
            j = i + 1
            while j < n and text[j] != c:
                if text[j] == "\\":
                    j += 1
                elif c != "`" and text[j] == "\n":
                    break
                j += 1
            starts.append(i)
            ends.append(j + 1)
            i = j + 1
        else:
            i += 1
    return starts, ends


def node_capable(text: str | None) -> bool:
    """Bundle disqualifier: the file can act as Node code or declares MCP tools."""
    if not text:
        return False
    if _NODE_MODULE_RE.search(text) or _BUNDLE_TOOL_DECL_RE.search(text):
        return True
    hits = list(_NODE_GLOBAL_RE.finditer(text))
    if not hits:
        return False
    starts, ends = _string_spans(text)
    return any(_outside_strings(text, m.start(), starts, ends) for m in hits)


def bundle_shape(path: str, text: str | None) -> bool:
    """Path / minification shape of a web bundle (before disqualifiers)."""
    low = "/" + path.lower().lstrip("/")
    if Path(low).suffix not in _BUNDLE_EXTS:
        return False
    if "/_next/static/" in low or "/.next/static/" in low or low.endswith(".min.js"):
        return True
    if not any(p in _BUNDLE_DIRS for p in _parts(path)[:-1]):
        return False
    return bool(text) and any(len(ln) > _MINIFIED_LINE_CHARS for ln in text.split("\n"))


class _Package:
    """Package-wide facts, computed once per artifact."""

    def __init__(self, fetched) -> None:
        self.files = getattr(fetched, "files", None) or {}
        self.texts: dict[str, str] = {
            p: af.text for p, af in self.files.items()
            if getattr(af, "text", None)
        }
        self.referencers = {
            p: t for p, t in self.texts.items()
            if Path(p).suffix.lower() in _REFERENCER_EXTS
        }
        self.sink_files = {p: t for p, t in self.referencers.items() if _EXEC_SINK_RE.search(t)}
        self.manifest = self.texts.get("package.json", "")
        # Tool declarations are read package-wide: a description constant in one file
        # is registered from another (`@m.tool(description=DESC)`).
        self.declares_tools = any(
            _defines_tools(t) for p, t in self.referencers.items()
            if not bundle_shape(p, t))
        self._bundle: dict[str, bool] = {}
        self._fetched = fetched
        self._run_min: set[str] | None = None
        self._tool_words: set[str] | None = None
        self._reexport_words: set[str] = set()

    def text(self, path: str) -> str | None:
        return self.texts.get(path)

    def exec_reachable(self, path: str) -> bool:
        """(3): a code file with an exec-type sink names the file, its directory, or
        enumerates files of its extension; or package.json names it (scripts)."""
        p = Path(path)
        base, ext = p.name, p.suffix.lower()
        parent = p.parent.name
        if base in self.manifest:
            return True
        base_re = re.compile(re.escape(base))
        # A file at the top of the package: its "directory" is the import name every
        # module mentions; it is reached by basename or by enumeration instead.
        top_level = len(p.parts) <= 2
        parent_re = re.compile(r"""['"/\\]""" + re.escape(parent) + r"""(?:['"/\\]|$)""") \
            if parent and not top_level else None
        ext_re = re.compile(re.escape(ext) + r"""\b""") if ext else None
        for src, t in self.sink_files.items():
            if src == path or self.is_bundle(src):
                continue
            # The basename anywhere in a file with a sink: the coordinator's floor.
            if base in t:
                return True
            # Loaded by directory or by enumerating files of its extension: only when
            # the sink is near that reference (a 9,000-line server that globs `*.yaml`
            # in one function and runs `subprocess` in another is not a loader).
            lines = t.split("\n")
            sinks = [i for i, ln in enumerate(lines) if _EXEC_SINK_RE.search(ln)]
            refs = [i for i, ln in enumerate(lines)
                    if base_re.search(ln)
                    or (parent_re is not None and parent != Path(src).parent.name
                        and parent_re.search(ln))
                    or (ext_re is not None and ext_re.search(ln) and _ENUMERATE_RE.search(
                        "\n".join(lines[max(0, i - _REF_WINDOW): i + _REF_WINDOW + 1])))]
            if any(abs(r - s) <= _REF_WINDOW for r in refs for s in sinks):
                return True
        return False

    def is_bundle(self, path: str) -> bool:
        if path in self._bundle:
            return self._bundle[path]
        text = self.text(path)
        if self._run_min is None:
            self._run_min = executed_minified_paths(self._fetched)
        # A minified file the package runs is code, not a browser bundle.
        ok = (bundle_shape(path, text) and not node_capable(text)
              and path not in self._run_min)
        if ok:
            base = Path(path).name
            if base in self.manifest:
                ok = False
            else:
                for src, t in self.referencers.items():
                    if src == path or bundle_shape(src, self.text(src)):
                        continue
                    if base in t:
                        ok = False
                        break
        self._bundle[path] = ok
        return ok

    def prompt_structure(self, path: str, line_number: int) -> bool:
        """The role-directive hit at ``path:line_number`` is prompt structure in code: the
        file is code (not a bundle, not an agent-instruction file) that declares no tool
        itself, and the line is a placeholder-only "system prompt:" label or a tag used
        as a delimiter constant. A role-override phrase is never structure."""
        if Path(path).suffix.lower() not in _CODE_EXTS or is_agent_instruction_file(path):
            return False
        text = self.text(path)
        if not text or bundle_shape(path, text) or _defines_tools(text):
            return False
        lines = text.split("\n")
        if not 0 < line_number <= len(lines):
            return False
        line = lines[line_number - 1]
        if _JAILBREAK_ROLE_RE.search(line):
            return False
        if not (system_prompt_label_only(line) or delimiter_tags_only(line, text)):
            return False
        # A constant the package's tool code imports (directly, or re-exported through a
        # package `__init__` / `index`) can become a tool description: never lowered.
        return not self.imported_by_tool_code(path)

    def _module_token(self, path: str) -> str:
        p = Path(path)
        return p.parent.name if p.stem in _INDEX_STEMS else p.stem

    def imported_by_tool_code(self, path: str) -> bool:
        if self._tool_words is None:
            words: set[str] = set()
            for p, t in self.referencers.items():
                if Path(p).suffix.lower() in _CODE_EXTS and not bundle_shape(p, t) \
                        and (_TOOL_REGISTER_RE.search(t) or _TOOL_DEF_EXTRA_RE.search(t)):
                    words |= set(_WORD_RE.findall(t))
            self._tool_words = words
            # Package index files the tool code names: what they re-export counts too.
            self._reexport_words = set()
            for p, t in self.referencers.items():
                if Path(p).stem in _INDEX_STEMS and self._module_token(p) in words:
                    self._reexport_words |= set(_WORD_RE.findall(t))
        tok = self._module_token(path)
        return tok in self._tool_words or tok in self._reexport_words

    def is_detection_data(self, path: str) -> bool:
        name = Path(path).name.lower()
        if Path(name).suffix not in DATA_FILE_EXTS:
            return False
        if name in EXECUTED_CONFIG_NAMES or is_agent_instruction_file(path):
            return False
        from src.scanner.scan import _is_infra_file
        if _is_infra_file(path):
            return False
        return (detection_name_evidence(path) and detection_shape(self.text(path))
                and not self.exec_reachable(path))


def _manifest_entry_strings(manifest_text: str) -> set[str]:
    """Every path string under package.json ``main`` / ``bin`` / ``exports`` (what Node
    runs). ``browser`` / ``unpkg`` / ``jsdelivr`` name browser builds and are left out."""
    import json
    try:
        data = json.loads(manifest_text or "")
    except ValueError:
        return set()
    if not isinstance(data, dict):
        return set()
    out: set[str] = set()

    def walk(v) -> None:
        if isinstance(v, str):
            out.add(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    for key in ("main", "bin", "exports", "scripts"):
        walk(data.get(key))
    return out


_LOAD_REF_RE = r"""(?:require\s*\(\s*|import\s*\(\s*|\bfrom\s+|\bimport\s+)['"`][^'"`\n]*"""


def executed_minified_paths(fetched) -> set[str]:
    """``.min.`` files the package RUNS, though the engine skips minified files by
    default: named by package.json ``main`` / ``bin`` / ``exports``, or ``require``d /
    imported by a non-minified code file. A minified entrypoint is code, not a bundle."""
    files = getattr(fetched, "files", None) or {}
    mins = [p for p in files if ".min." in Path(p).name.lower()]
    if not mins:
        return set()
    manifest_af = files.get("package.json")
    # Manifest strings (entry paths, and `scripts` command lines such as
    # `node setup.min.js` — an install hook running a minified file) split into tokens.
    entry_tokens: set[str] = set()
    for s in _manifest_entry_strings(getattr(manifest_af, "text", "") or ""):
        for tok in re.split(r"""[\s'"`;&|()]+""", s):
            if tok:
                entry_tokens.add(Path(tok).name)
    loaders = [af.text for p, af in files.items()
               if getattr(af, "text", None) and Path(p).suffix.lower() in _REFERENCER_EXTS
               and ".min." not in Path(p).name.lower()]
    out: set[str] = set()
    pending = list(mins)
    changed = True
    while changed:  # a run minified file can itself load another one
        changed = False
        for p in list(pending):
            base = Path(p).name
            stem = base[: -len(Path(base).suffix)] if Path(base).suffix else base
            hit = base in entry_tokens or stem in entry_tokens  # Node adds `.js`
            if not hit:
                ref = re.compile(_LOAD_REF_RE + r"(?:" + re.escape(base) + "|"
                                 + re.escape(stem) + r""")['"`]""")
                # `require` / `import`, or a `node … x.min.js` command line (a bin shell
                # script, a Python `subprocess.run(["node", ".../x.min.js"])`).
                node_cmd = re.compile(r"\bnode\b[^\n]{0,200}" + re.escape(base))
                hit = any(stem in t and (ref.search(t) or node_cmd.search(t))
                          for t in loaders)
            if hit:
                out.add(p)
                pending.remove(p)
                t = getattr(files[p], "text", None)
                if t:
                    loaders.append(t)
                changed = True
    return out


def calibrate_package_findings(findings: list, fetched) -> list:
    """Lower text-match findings in detection data and web bundles of an npm / PyPI
    artifact (module docstring). Mutates and returns ``findings``."""
    eco = (getattr(fetched, "ecosystem", "") or "").lower()
    if eco not in PACKAGE_ECOSYSTEMS:
        return findings
    pkg = _Package(fetched)
    data_ok: dict[str, bool] = {}
    hints = Hints(pkg.texts, package=True)  # lazy: tokenizes only when asked

    for f in findings:
        if getattr(f, "kind", "defect") == "capability":
            continue
        if f.severity not in ("critical", "high", "medium"):
            continue
        path = getattr(f, "file_path", "") or ""
        cat = getattr(f, "category", "")
        if cat in _DATA_TEXT_CATEGORIES and Path(path).suffix.lower() in DATA_FILE_EXTS:
            if path not in data_ok:
                data_ok[path] = pkg.is_detection_data(path)
            text = pkg.text(path)
            if data_ok[path] and text and 0 < f.line_number <= text.count("\n") + 1 \
                    and is_list_entry(text.split("\n")[f.line_number - 1]):
                _lower(f, WHY_DATA)
        elif (Path(path).suffix.lower() in _BUNDLE_EXTS
              and (cat in _BUNDLE_CATEGORIES or f.name in _BUNDLE_REMOTE_LOAD_NAMES
                   or (cat == "hidden_unicode" and f.name in _BUNDLE_UNICODE_NAMES))
              and pkg.is_bundle(path)):
            _lower(f, WHY_BUNDLE)
        elif (f.name == _PIPE_TO_SHELL and is_supported(path)
              and hints.why_not(path, f.line_number, _pipe_to_shell_re()) is None):
            # Printed install hint: the string reaches only print / log / error-message
            # output in every file that reads it (``src.scanner.printed_hint``).
            _lower(f, WHY_HINT)
        elif (cat == "prompt_injection" and Path(path).suffix.lower() in _CODE_EXTS
              and not pkg.declares_tools and f.name == _ROLE_DIRECTIVE
              and not _JAILBREAK_ROLE_RE.search(f.snippet or "")):
            # A package that declares no agent tool anywhere: `<instructions>` /
            # "System prompt:" in its code structures its own model call.
            _lower(f, WHY_CODE_TEXT)
        elif (cat == "prompt_injection" and f.name == _ROLE_DIRECTIVE
              and f.severity == "medium" and pkg.prompt_structure(path, f.line_number)):
            # A package that declares tools somewhere (litellm's MCP gateway), but this
            # file declares none and the line is a bare label or a delimiter constant.
            _lower(f, WHY_PROMPT_STRUCTURE)
    return findings


_PIPE_TO_SHELL = "curl/wget piped to shell"


def _pipe_to_shell_re():
    from src.scanner.patterns import DYNAMIC_REMOTE_LOAD_PATTERNS
    return next(p for n, p, _s in DYNAMIC_REMOTE_LOAD_PATTERNS if n == _PIPE_TO_SHELL)


def _lower(f, why: str) -> None:
    f.severity = "low"
    f.remediation = why
    if hasattr(f, "payload"):
        f.payload = False
