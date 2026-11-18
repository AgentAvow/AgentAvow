"""A skill that writes a hook into the agent's own settings (issue #460).

Some skills set themselves up by adding a hook to the agent's settings file: a
``PreToolUse`` / ``SessionStart`` entry in ``~/.claude/settings.json`` or
``.claude/settings.json``, a ``[hooks]`` table in Codex's ``~/.codex/config.toml``
(or ``~/.codex/hooks.json``), or an entry in Cursor's ``.cursor/hooks.json``. The skill
may never ship a hook manifest of its own, so the lifecycle-manifest check (``hooks.json``
/ ``plugin.json`` in the skill's tree) does not see it, and ``_TOOL_CONFIG_RE`` in
``skill_scan`` only fires when those files' contents are SENT somewhere.

A hook left in the settings runs its command on every matching agent event (every tool
call, for ``PreToolUse``), outside the skill, until someone removes it. That is worth a
line the user reads before installing, not a defect: this module returns a low
``kind="capability"`` finding, which is never a score input, never blocking and never
moves the answer (``scan._is_defect``, ``verdict.decide``).

The note needs three things in one file (SKILL.md body, another markdown file the
skill ships, or a bundled script):

* an agent settings file that holds hooks (``_SETTINGS_RE``, or the same path built
  from parts on one line, ``Path.home() / ".claude" / "settings.json"``);
* a hook event or hooks table for that agent (``_EVENT_RE`` / ``_TOML_HOOKS_RE``);
* a write to that file. In prose: an install verb (add, merge, write, install, ...),
  not negated, in a sentence that names the settings file or a hook, inside the same
  paragraph or list item as the path (blank lines and headings end it). A fenced block
  in the prose is read like a script. In a script: a write whose target is the settings
  path or a name bound to it on the path's line (``open(p, "w")``, ``p.write_text``,
  ``writeFileSync(p, ...)``, ``>> "$P"``, ``tee``, ``sed -i``, ``mv tmp "$P"``). A write
  to any other file (a report) does not count.

A skill that only reads the settings (an audit skill listing installed hooks) gets
nothing. The command is taken from a ``"command": "..."`` key (or the single-quoted
Python form) or a TOML ``command = "..."`` line a few lines after a hook event.

Pure; never raises on odd input.
"""
from __future__ import annotations

import re

CAPABILITY = "agent:settings_hook"

_PROSE_EXT = (".md", ".markdown", ".mdx", ".txt")
_SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".rb", ".pl", ".ps1")

# Agent settings files that hold hooks. Group 1 is the path as written (with ``~/``,
# ``$HOME/`` or a project-dir variable in front when there is one).
_SETTINGS_RE = re.compile(
    r"((?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\"?\$CLAUDE_PROJECT_DIR\"?|\$\{CLAUDE_PROJECT_DIR\})?"
    r"[/\\]?"
    r"(?:\.claude[/\\]settings(?:\.local)?\.json"
    r"|\.codex[/\\](?:config\.toml|hooks\.json)"
    r"|\.cursor[/\\]hooks\.json))"
)
# Claude Code and Codex hook events, and Cursor's. ``Stop`` / ``stop`` / ``Notification``
# are ordinary words, so they count only as a quoted JSON key.
_EVENT_RE = re.compile(
    r"\b(?:PreToolUse|PostToolUse|SessionStart|SessionEnd|UserPromptSubmit|SubagentStop"
    r"|PreCompact|PermissionRequest"
    r"|beforeShellExecution|beforeMCPExecution|beforeReadFile|afterFileEdit"
    r"|beforeSubmitPrompt|afterAgentResponse|afterAgentThought)\b"
    r"|\"(?:Stop|Notification|stop)\"\s*:"
)
# A ``[hooks]`` / ``[[hooks.PreToolUse]]`` table in a Codex config.toml.
_TOML_HOOKS_RE = re.compile(r"(?m)^\s*\[\[?\s*hooks(?:\.[\w.\"-]+)?\s*\]\]?\s*$")

# A settings path built from parts on one line: ``Path.home() / ".claude" /
# "settings.json"``, ``os.path.join(home, ".codex", "config.toml")``.
_PARTS_RE = re.compile(
    r"""["']\.claude["'][^\n]{0,40}?["']settings(?:\.local)?\.json["']"""
    r"""|["']\.codex["'][^\n]{0,40}?["'](?:config\.toml|hooks\.json)["']"""
    r"""|["']\.cursor["'][^\n]{0,40}?["']hooks\.json["']"""
)
_PART_NAMES_RE = re.compile(
    r"""["'](\.claude|\.codex|\.cursor)["'][^\n]{0,40}?["']([\w.]+\.(?:json|toml))["']""")
_HOME_RE = re.compile(r"(?i)\bhome\b|homedir|expanduser|USERPROFILE|~")

_PROSE_WRITE_RE = re.compile(
    r"(?i)\b(?:add|adds|adding|added|merge|merges|merging|write|writes|writing|append"
    r"|appends|appending|insert|inserts|install|installs|installing|register|registers"
    r"|put|paste|edit|update|create|creates|set\s+up|sets\s+up|configure|configures)\b"
)
_NEGATED_RE = re.compile(
    r"(?i)\b(?:do\s+not|don't|dont|never|not|without|no\s+need\s+to|instead\s+of)\b"
)
# What an install verb's sentence has to be about: the settings file or a hook.
_ABOUT_RE = re.compile(r"(?i)\bhooks?\b|\bsettings\b|\bconfig\.toml\b")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s")
_FENCE_RE = re.compile(r"^\s{0,3}(```|~~~)")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?:])\s+(?=[A-Z*`\[(])")
# A name bound to a settings path on its line (``p = ...``, ``const p = ...``,
# ``P=~/.claude/settings.json``, ``$p = ...``).
_BIND_RE = re.compile(
    r"^\s*(?:(?:export|local|readonly|const|let|var|my|our)\s+)?\$?([A-Za-z_]\w*)\s*:?=(?!=)")
_JSON_CMD_RE = re.compile(r"\"command\"\s*:\s*\"((?:\\.|[^\"\\\n])+)\"")
_PY_CMD_RE = re.compile(r"'command'\s*:\s*'((?:\\.|[^'\\\n])+)'")
_TOML_CMD_RE = re.compile(r"(?m)^\s*command\s*=\s*(?:\[\s*)?([\"'])((?:\\.|(?!\1).)+)\1")
_CMD_MAX = 120
_CMD_WINDOW = 10  # lines after a hook event in which a "command" belongs to it


def _path_hits(line: str) -> list[str]:
    """Settings paths on one line, as shown in the note."""
    out = [_clean_path(m.group(1)) for m in _SETTINGS_RE.finditer(line)]
    for m in _PART_NAMES_RE.finditer(line):
        if _PARTS_RE.search(m.group(0)):
            p = f"{m.group(1)}/{m.group(2)}"
            out.append(("~/" + p) if _HOME_RE.search(line[: m.start()]) else p)
    return out


def _writes_to(line: str, target: str) -> bool:
    """Does this script line write to ``target`` (a regex for the path or its names)?"""
    t = target
    pats = (
        rf"\bopen\s*\(\s*[^,)]*(?:{t})[^,)]*,\s*(?:mode\s*=\s*)?[rbf]?[\"'](?:w|a|r\+|w\+|wb|ab|a\+)",
        rf"(?:{t})[\w\"')\]]*\s*\)?\s*\.(?:write_text|write_bytes)\s*\(",
        rf"(?:{t})[\w\"')\]]*\s*\)?\s*\.open\s*\(\s*[\"'](?:w|a)",
        rf"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|outputJson|outputJSON"
        rf"|writeJson|writeJSON|outputFile)\s*\(\s*[^,)]*(?:{t})",
        rf">>?\s*[\"']?(?:{t})",
        rf"\btee\b(?:\s+-a)?\s+[\"']?(?:{t})",
        rf"\bsed\s+-i\S*\s+[^\n]*(?:{t})",
        rf"\b(?:mv|cp)\s+(?:-\w+\s+)*\S+\s+[\"']?(?:{t})",
        rf"\b(?:Set-Content|Add-Content|Out-File)\b[^\n]*(?:{t})",
        rf"\bFile\.write\s*\(\s*(?:{t})",
    )
    return any(re.search(p, line) for p in pats)


def _clean_path(raw: str) -> str:
    p = raw.replace("\\", "/").replace('"', "")
    if p.startswith("/."):
        p = p[1:]
    return p


def _commands(lines: list[str]) -> list[str]:
    """``command`` values within a few lines after a hook event or hooks table, so a
    sample tool input (``{"tool_input": {"command": "git push"}}``) is not one."""
    seen: list[str] = []
    last_event = -_CMD_WINDOW - 1
    for i, ln in enumerate(lines):
        if _EVENT_RE.search(ln) or _TOML_HOOKS_RE.match(ln):
            last_event = i
        if i - last_event > _CMD_WINDOW or "tool_input" in ln:
            continue
        found = [m.group(1).replace('\\"', '"') for m in _JSON_CMD_RE.finditer(ln)]
        found += [m.group(1) for m in _PY_CMD_RE.finditer(ln)]
        found += [m.group(2) for m in _TOML_CMD_RE.finditer(ln)]
        for cmd in found:
            cmd = cmd.strip()
            if cmd and cmd not in seen:
                seen.append(cmd)
    return seen


def _short(cmd: str) -> str:
    cmd = " ".join(cmd.split())
    return cmd if len(cmd) <= _CMD_MAX else cmd[: _CMD_MAX - 3] + "..."


def _blocks(lines: list[str]) -> list[tuple[str, list[int]]]:
    """Split markdown into paragraphs, list items and fenced blocks: ``(kind, line
    indexes)``. Blank lines, headings and fences end a paragraph; a heading is its own
    block."""
    out: list[tuple[str, list[int]]] = []
    cur: list[int] = []
    fence: list[int] | None = None

    def flush():
        nonlocal cur
        if cur:
            out.append(("prose", cur))
        cur = []

    for i, ln in enumerate(lines):
        if fence is not None:
            if _FENCE_RE.match(ln):
                out.append(("fence", fence))
                fence = None
            else:
                fence.append(i)
            continue
        if _FENCE_RE.match(ln):
            flush()
            fence = []
        elif not ln.strip():
            flush()
        elif _HEADING_RE.match(ln):
            flush()
            out.append(("prose", [i]))
        elif re.match(r"^\s{0,3}(?:[-*+]|\d+[.)])\s", ln):
            flush()
            cur = [i]
        else:
            cur.append(i)
    flush()
    if fence:
        out.append(("fence", fence))
    return out


def _prose_write_line(lines: list[str]) -> int | None:
    """The first settings-path line (0-based) in a paragraph with an install verb whose
    own sentence is about the settings file or a hook, or None. A fenced block is read
    as a script."""
    for kind, idx in _blocks(lines):
        hits = [i for i in idx if _path_hits(lines[i])]
        if not hits:
            continue
        if kind == "fence":
            at = _script_write_line([lines[i] for i in idx])
            if at is not None:
                return idx[at]
            continue
        text = " ".join(lines[i].strip() for i in idx)
        for sent in _SENTENCE_SPLIT_RE.split(text):
            m = _PROSE_WRITE_RE.search(sent)
            if not m or _NEGATED_RE.search(sent[: m.start()]):
                continue
            if _path_hits(sent) or _ABOUT_RE.search(sent) or _EVENT_RE.search(sent):
                return hits[0]
    return None


def _script_write_line(lines: list[str]) -> int | None:
    """The first line (0-based) that writes to a settings path, or to a name bound to
    one, or None. Writes to any other file do not count."""
    lit = _SETTINGS_RE.pattern + "|" + _PARTS_RE.pattern
    names: list[str] = []
    for ln in lines:
        if _path_hits(ln):
            m = _BIND_RE.match(ln)
            if m and m.group(1) not in names:
                names.append(m.group(1))
    target = lit
    if names:
        alts = "|".join(re.escape(n) for n in names)
        target += rf"|\$\{{?(?:{alts})\b\}}?|(?<![\w.$])(?:{alts})\b"
    for i, ln in enumerate(lines):
        if _writes_to(ln, target):
            return i
    return None


def settings_hook_findings(path: str, text: str) -> list:
    """The capability note for one skill file, or []."""
    try:
        return _findings(path, text)
    except Exception:  # noqa: BLE001 - a note is never worth a failed scan
        return []


def _findings(path: str, text: str) -> list:
    if not text:
        return []
    low = path.lower()
    prose, script = low.endswith(_PROSE_EXT), low.endswith(_SCRIPT_EXT)
    if not (prose or script) or not (_SETTINGS_RE.search(text) or _PARTS_RE.search(text)):
        return []
    if not (_EVENT_RE.search(text) or _TOML_HOOKS_RE.search(text)):
        return []
    lines = text.splitlines()
    at = _prose_write_line(lines) if prose else _script_write_line(lines)
    if at is None:
        return []

    targets: list[str] = []
    for ln in lines:
        for p in _path_hits(ln):
            if p not in targets:
                targets.append(p)
    where = " or ".join(targets[:3]) + (" (and others)" if len(targets) > 3 else "")
    cmds = _commands(lines)
    runs = ""
    if cmds:
        runs = ", runs " + _short(cmds[0])
        if len(cmds) > 1:
            runs += f" (+{len(cmds) - 1} more)"
    name = f"Installs a hook into your agent's settings: {where}{runs}"

    from src.scanner.scan import Finding
    return [Finding(
        category="skill_hook", name=name, severity="low", file_path=path,
        line_number=at + 1, snippet=lines[at].strip()[:200],
        remediation=(
            "The skill adds a hook to your agent's settings. The agent then runs that "
            "command on every matching event (every tool call, for PreToolUse), outside "
            "the skill, until you remove it from the settings file. Read the command, and "
            "the script it points at, before you let the skill install it."
        ),
        kind="capability", capability=CAPABILITY,
    )]
