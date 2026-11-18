"""curl / wget piped to a shell in a skill's install prose (#461, owner decision).

A SKILL.md often shows how to install the CLI it drives (``curl -sL cli.genkit.dev |
bash``, next to an npm alternative). That is an instruction for a person, which the
agent may follow when the user asks; it is not code the skill runs. Owner decision: a
pipe-to-shell command shown in a SKILL.md install section is **high** (Review), not
critical. There is no domain allowlist: every host reads the same.

It stays **critical** when:

* the text around it tells the AGENT to run it (``always``, ``automatically``,
  ``without asking``, ``before you start``, ``you must run``, ``step 1``, an
  instruction-override phrase, ...), or it is not in an install section (the nearest
  heading or bold label above it, in the body, is about installing);
* the command hides what it fetches (a variable or command substitution in the
  target, base64 on the line, ``--insecure``), or is not shown as a command (a fenced
  block or an inline code span);
* the file is not a SKILL.md, or the line is in its frontmatter (AGENTS.md, CLAUDE.md
  and other files an agent loads on its own get no relaxation);
* anything else in the tree can run it (:func:`restore_runs`): a script, hook,
  package.json, Makefile, CI file, bin, slash command, agent file or other code that
  names the command's URL, or names the skill's markdown together with a shell or a
  run verb; or such a file is in the tree but was not read.

Pure; never raises on odd input.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from src.scanner.patterns import PROMPT_INJECTION_PATTERNS

WHY_SKILL_INSTALL = (
    "A curl / wget piped to a shell, shown in this skill's install section for a person "
    "to run. Nothing the skill ships runs it, but an agent may run it when you ask it "
    "to set the skill up: check the script it downloads first, or install the tool "
    "another way (a package manager, a pinned release).")

_FENCE_RE = re.compile(r"^\s{0,3}(```|~~~)")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+\S")
# A bold label on a line of its own ("**Installation:**", "__Setup__").
_LABEL_RE = re.compile(r"^\s*(?:\*\*|__)[^*_\n]{1,60}(?:\*\*|__)\s*:?\s*$")
_INSTALL_CUE_RE = re.compile(
    r"(?i)\b(?:install(?:s|ed|ing|ation|er)?|set\s*up|setup|prerequisites?|"
    r"requirements?|getting\s+started|quick\s*start|dependenc(?:y|ies)|download)\b")
# Text that tells the agent itself to run it, now or on its own.
_AGENT_CUE_RE = re.compile(
    r"(?i)\b(?:always|automatically|silently|immediately|unconditionally|yourself)\b"
    r"|\bwithout\s+(?:asking|prompting|confirm\w*|telling|approval|permission|"
    r"(?:the\s+)?user)"
    r"|\b(?:do\s+not|don't|never|no\s+need\s+to)\s+(?:ask|prompt|confirm|check\s+with|"
    r"tell|wait)\b"
    r"|\bbefore\s+(?:you\s+)?(?:do\s+anything|anything|start\w*|begin\w*|answer\w*|"
    r"respond\w*|continu\w*|proceed\w*|reply\w*|using\s+(?:this|the)\s+skill|each|every|"
    r"any)\b"
    r"|\b(?:at\s+the\s+(?:start|beginning)|on\s+(?:every|each|first)|every\s+time|each\s+time|"
    r"whenever|when\s+(?:this|the)\s+skill\s+(?:loads|starts|runs|is\s+(?:loaded|used|"
    r"invoked|triggered|activated)))\b"
    r"|\b(?:you|the\s+agent|claude|the\s+assistant|the\s+model)\s+(?:must|should|need\s+to|"
    r"has\s+to|have\s+to|will|shall)\s+(?:first\s+)?(?:run|execute|install|invoke|call)\b"
    r"|\b(?:must|required\s+to)\s+(?:run|execute)\b"
    r"|\bstep\s+\d|\bfirst\s+step\b"
    r"|\b(?:run|execute)\s+(?:this|it|the\s+(?:following|command|script|installer))\s+"
    r"(?:now|first|immediately|automatically|right\s+away)\b"
    r"|\bfor\s+the\s+user\b|\bon\s+(?:the\s+)?user'?s\s+behalf\b")
_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
_VAR_RE = re.compile(r"""\$\{?\w|\$\(|`[^`]*\$|%\w+%|\{\{""")
_BASE64_RE = re.compile(r"(?i)\bbase64\b|[A-Za-z0-9+/]{40,}={0,2}")
_INSECURE_RE = re.compile(r"(?:^|\s)(?:-k|--insecure|--no-check-certificate)\b")
# What curl / wget fetches: a URL, or a bare host[/path] ("cli.genkit.dev").
_TARGET_RE = re.compile(
    r"(?i)(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/[^\s'\"`|;&)<>]*)?)")
_TOOL_ARGS_RE = re.compile(r"(?i)\b(?:curl|wget)\b([^|\n]*)\|")
_CONTEXT_LINES = 25


def _section(lines: list[str], idx: int) -> tuple[int, str]:
    """``(start, title)``: the nearest heading or bold label above ``idx`` (within
    ``_CONTEXT_LINES``), outside fenced blocks."""
    in_fence = False
    fence_at: list[bool] = []
    for i in range(idx + 1):
        if _FENCE_RE.match(lines[i]):
            in_fence = not in_fence
            fence_at.append(True)
        else:
            fence_at.append(in_fence)
    for j in range(idx - 1, max(-1, idx - _CONTEXT_LINES - 1), -1):
        if fence_at[j] or _FENCE_RE.match(lines[j]):
            continue
        if _HEADING_RE.match(lines[j]) or _LABEL_RE.match(lines[j]):
            return j, lines[j]
    return max(0, idx - _CONTEXT_LINES), ""


def _block_end(lines: list[str], idx: int) -> int:
    """The last line of the fenced block holding ``idx`` (``idx`` if none)."""
    for j in range(idx + 1, min(len(lines), idx + _CONTEXT_LINES)):
        if _FENCE_RE.match(lines[j]):
            return j
    return idx


def _in_fence(lines: list[str], idx: int) -> bool:
    inside = False
    for i in range(idx):
        if _FENCE_RE.match(lines[i]):
            inside = not inside
    return inside


def targets(line: str) -> list[str]:
    """Lower-cased ``host[/path]`` of every curl / wget target on ``line``."""
    out: list[str] = []
    for m in _TOOL_ARGS_RE.finditer(line):
        for t in _TARGET_RE.finditer(m.group(1)):
            out.append(t.group(1).lower().rstrip("/."))
    return out


def human_install_line(lines: list[str], idx: int, body_from: int, path: str) -> bool:
    """The pipe-to-shell on ``lines[idx]`` is a command shown to a person in a SKILL.md
    install section (see the module docstring), not one the agent is told to run."""
    try:
        if PurePosixPath(path).name.lower() != "skill.md" or idx < body_from:
            return False
        line = lines[idx]
        args = " ".join(m.group(1) for m in _TOOL_ARGS_RE.finditer(line))
        if not args or _VAR_RE.search(args) or _BASE64_RE.search(line) \
                or _INSECURE_RE.search(args) or not targets(line):
            return False
        fenced = _in_fence(lines, idx)
        if not fenced and not any("|" in c.group(0) and re.search(r"(?i)curl|wget",
                                                                    c.group(0))
                                  for c in _INLINE_CODE_RE.finditer(line)):
            return False
        start, title = _section(lines, idx)
        end = _block_end(lines, idx) if fenced else idx
        after = lines[end + 1:end + 3]
        context = "\n".join(lines[max(start, body_from):end + 1] + after)
        if _AGENT_CUE_RE.search(context) or any(
                rx.search(context) for _n, rx, _s in PROMPT_INJECTION_PATTERNS):
            return False
        # The section itself is about installing: its heading or bold label says so.
        return start >= body_from and bool(title) and bool(_INSTALL_CUE_RE.search(title))
    except Exception:  # noqa: BLE001 — a rule bug keeps the critical
        return False


def body_offset(lines: list[str]) -> int:
    """0-based index of the first line after a leading ``---`` frontmatter block (0 if
    there is none). A byte-order mark before it is allowed."""
    if not lines or lines[0].lstrip("\ufeff").strip() != "---":
        return 0
    for i in range(1, min(len(lines), 400)):
        if lines[i].strip() == "---":
            return i + 1
    return len(lines)  # never closed: all of it reads as frontmatter (strict)


def lower(finding, line: str) -> None:
    """Lower a critical pipe-to-shell finding in install prose to high, remembering what
    :func:`restore_runs` puts back. (Attributes, not dataclass fields: they never reach
    serialized output.)"""
    finding.skill_install_pre = (finding.severity, finding.remediation)
    finding.skill_install_urls = tuple(targets(line))
    finding.severity = "high"
    finding.remediation = WHY_SKILL_INSTALL


# --- the tree check ---------------------------------------------------------------
_CODE_EXTS = frozenset({
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".py", ".js", ".mjs", ".cjs", ".ts", ".mts",
    ".cts", ".jsx", ".tsx", ".rb", ".pl", ".php", ".ps1", ".psm1", ".bat", ".cmd", ".go",
    ".rs", ".lua", ".mk", ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".nix",
    ".dart", ".java", ".kt", ".swift", ".cs", ".ex", ".exs", ".r", ".jl"})
_RUNNER_NAMES = frozenset({
    "makefile", "gnumakefile", "justfile", "taskfile", "dockerfile", "rakefile",
    "procfile", "claude.md", "agents.md", "gemini.md", ".cursorrules", ".windsurfrules",
    "copilot-instructions.md", ".clinerules", "agent.md"})
# Directories whose files an agent or a harness runs or loads as instructions.
_RUNNER_DIR_RE = re.compile(
    r"(?i)(?:^|/)(?:\.claude|\.claude-plugin|\.codex|\.cursor|\.github|\.gitlab|hooks?|"
    r"commands?|agents?|bin|scripts?|\.husky|\.devcontainer)/")
# A file naming the skill's markdown, then something that runs text: a shell, eval, or
# (in an agent's markdown) a run verb.
_SHELL_SINK_RE = re.compile(
    r"\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:ba|z|da|k)?sh\s+(?:-c\b|<|\$\()|"
    r"\b(?:eval|exec|source)\s*[\"'$(<`.\[/]|\.\s+<\(|child_process|execSync|execFile|"
    r"spawn|subprocess|os\.system|popen|Invoke-Expression|\biex\b|\bsystem\s*\(")
# How far from a mention of the skill's markdown a shell or run verb counts, in a data
# file or an agent's markdown (code files: anywhere in the file).
_NEAR = 300
_RUN_VERB_RE = re.compile(r"(?i)\b(?:run|execute|install|invoke|follow|do)\b")


def _is_prose_doc(path: str) -> bool:
    p = PurePosixPath(path.lower())
    return p.suffix in (".md", ".mdx", ".markdown", ".txt", ".rst", ".adoc") and \
        p.name not in _RUNNER_NAMES and not _RUNNER_DIR_RE.search("/" + path.lower())


def is_runner(path: str) -> bool:
    """A file that can run a command or that an agent loads as instructions: code,
    scripts, manifests, build / CI files, hooks, slash commands, agent files."""
    p = PurePosixPath(path.lower())
    if p.name == "skill.md":
        return False
    if p.name in _RUNNER_NAMES or p.suffix in _CODE_EXTS:
        return True
    return bool(_RUNNER_DIR_RE.search("/" + path.lower()))


# Data formats: a runner only by name or place (package.json, hooks.json, a workflow).
_DATA_EXTS = frozenset({".json", ".yml", ".yaml", ".toml", ".cfg", ".ini"})
_DATA_RUNNER_NAMES = frozenset({"package.json", "hooks.json", "settings.json",
                                "settings.local.json", ".gitlab-ci.yml", "taskfile.yml",
                                "plugin.json", "pyproject.toml", "deno.json"})


def _runner_kind(path: str) -> bool:
    """A file that could run the command (data files only by name / place)."""
    p = PurePosixPath(path.lower())
    if not is_runner(path):
        return False
    if p.suffix in _DATA_EXTS:
        return p.name in _DATA_RUNNER_NAMES or bool(_RUNNER_DIR_RE.search("/" + path.lower()))
    return True


def _skill_mentions(text: str, skill_md: str) -> list[int]:
    """Offsets where ``text`` names the skill's markdown (SKILL.md, a README, or the
    skill's folder)."""
    low = text.lower()
    d = skill_md.rsplit("/", 1)[0].lower() if "/" in skill_md else ""
    keys = ["skill.md", "readme"] + ([d] if d else [])
    return [m.start() for k in keys for m in re.finditer(re.escape(k), low)]


def _runs_skill_text(path: str, text: str, skill_md: str) -> bool:
    """``text`` names the skill's markdown and hands text to a shell / exec (code: in
    the same file; data and markdown: within ``_NEAR`` characters), or, in an agent's
    markdown, names it beside a run verb."""
    hits = _skill_mentions(text, skill_md)
    if not hits:
        return False
    suffix = PurePosixPath(path.lower()).suffix
    md = suffix in (".md", ".mdc", ".mdx", ".markdown", ".txt")
    if suffix not in _DATA_EXTS and not md:
        return bool(_SHELL_SINK_RE.search(text))
    for h in hits:
        window = text[max(0, h - _NEAR):h + _NEAR]
        if _SHELL_SINK_RE.search(window) or (md and _RUN_VERB_RE.search(window)):
            return True
    return False


def _in_scope(path: str, skill_md: str) -> bool:
    """A path inside the skill's folder, or repository-level automation (outside every
    skill folder: root files, hooks, commands, CI)."""
    d = skill_md.rsplit("/", 1)[0] + "/" if "/" in skill_md else ""
    if not d or path.startswith(d):
        return True
    return "/" not in path or bool(_RUNNER_DIR_RE.match(path)) or bool(
        re.match(r"(?i)(?:\.claude|\.github|\.gitlab|hooks?|commands?|agents?|bin|scripts?)/",
                 path))


def runs_it(skill_md: str, urls: list[str], texts: dict[str, str],
            tree_paths: list[str] | None = None) -> str:
    """The path of a file that can run the install command shown in ``skill_md``
    (or that cannot be ruled out because it was not read), or ``""``."""
    for p, t in texts.items():
        if p == skill_md or not t or not _runner_kind(p):
            continue
        low = t.lower()
        if any(u and u in low for u in urls):
            return p
        if _runs_skill_text(p, t, skill_md):
            return p
    for p in tree_paths or ():
        if p not in texts and p != skill_md and _runner_kind(p) and _in_scope(p, skill_md):
            return p
    return ""


def unread_runners(findings: list, texts: dict[str, str],
                   tree_paths: list[str] | None) -> list[str]:
    """Paths the tree check would have to read for the lowered findings: files in scope
    that could run the command and are not in ``texts``. The caller reads them (or
    leaves them unread, which keeps the critical)."""
    lowered = [f.file_path for f in findings if getattr(f, "skill_install_pre", None)]
    if not lowered or not tree_paths:
        return []
    return sorted({p for p in tree_paths for md in lowered
                   if p not in texts and p != md and _runner_kind(p) and _in_scope(p, md)})


# Files the tree check reads on top of the scan's own (a repository scan reads at most
# its file cap). Past this many, the rest stay unread and keep the critical.
MAX_EXTRA_READS = 40


def restore_runs(findings: list, texts: dict[str, str],
                 tree_paths: list[str] | None = None) -> None:
    """Put back the critical on every lowered install-prose finding that something in
    the tree can run (see :func:`runs_it`). ``tree_paths``: every path in the tree,
    read or not (None when ``texts`` holds the whole tree)."""
    for f in findings:
        pre = getattr(f, "skill_install_pre", None)
        if not pre or f.severity != "high":
            continue
        urls = list(getattr(f, "skill_install_urls", ()) or ())
        if runs_it(f.file_path, urls, texts, tree_paths):
            f.severity, f.remediation = pre
            f.skill_install_pre = None
