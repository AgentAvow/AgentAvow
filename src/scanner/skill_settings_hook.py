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

* an agent settings file that holds hooks (``_SETTINGS_RE``);
* a hook event or hooks table for that agent (``_EVENT_RE`` / ``_TOML_HOOKS_RE``);
* a write: in prose, an install verb (add, merge, write, append, install, ...) within a
  few lines of the settings path, not negated on its line; in a script, a file write
  (redirect, ``json.dump``, ``writeFile``, ``open(..., "w")``, ``sed -i``, ``tee``).

A skill that only reads the settings (an audit skill listing installed hooks) gets
nothing. The command is taken from a ``"command": "..."`` JSON key or a TOML
``command = "..."`` line in the same file when there is one.

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

_PROSE_WRITE_RE = re.compile(
    r"(?i)\b(?:add|adds|adding|added|merge|merges|merging|write|writes|writing|append"
    r"|appends|appending|insert|inserts|install|installs|installing|register|registers"
    r"|put|paste|edit|update|create|creates|set\s+up|sets\s+up|configure|configures)\b"
)
_NEGATED_RE = re.compile(
    r"(?i)\b(?:do\s+not|don't|dont|never|not|without|no\s+need\s+to|instead\s+of)\b"
)
_SCRIPT_WRITE_RE = re.compile(
    r"(?:>>?\s*[\"']?[\w~$./{}\\-]*(?:settings(?:\.local)?\.json|config\.toml|hooks\.json))"
    r"|\bjson\.dumps?\s*\(|\bwrite_text\s*\(|\.write\s*\(|\bwriteFile(?:Sync)?\s*\("
    r"|\bopen\s*\([^)]*[\"'](?:w|a|r\+|w\+)[\"']|\bsed\s+-i\b|\btee\b|\bSet-Content\b"
    r"|\bOut-File\b|\btomlkit\b|\btoml\.dump|\bjq\b[^\n]*>\s*"
)
_JSON_CMD_RE = re.compile(r"\"command\"\s*:\s*\"((?:\\.|[^\"\\\n])+)\"")
_TOML_CMD_RE = re.compile(r"(?m)^\s*command\s*=\s*(?:\[\s*)?([\"'])((?:\\.|(?!\1).)+)\1")
_PROSE_WINDOW = 12  # lines between the settings path and the install verb
_CMD_MAX = 120
_CMD_WINDOW = 10  # lines after a hook event in which a "command" belongs to it


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
        found += [m.group(2) for m in _TOML_CMD_RE.finditer(ln)]
        for cmd in found:
            cmd = cmd.strip()
            if cmd and cmd not in seen:
                seen.append(cmd)
    return seen


def _short(cmd: str) -> str:
    cmd = " ".join(cmd.split())
    return cmd if len(cmd) <= _CMD_MAX else cmd[: _CMD_MAX - 3] + "..."


def _prose_write_line(lines: list[str], hits: list[int]) -> int | None:
    """The first settings-path line with an install verb near it (0-based), or None."""
    for i in hits:
        lo, hi = max(0, i - _PROSE_WINDOW), min(len(lines), i + _PROSE_WINDOW + 1)
        for j in range(lo, hi):
            m = _PROSE_WRITE_RE.search(lines[j])
            if m and not _NEGATED_RE.search(lines[j][: m.start()]):
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
    if not (prose or script) or not _SETTINGS_RE.search(text):
        return []
    if not (_EVENT_RE.search(text) or _TOML_HOOKS_RE.search(text)):
        return []
    lines = text.splitlines()
    hits = [i for i, ln in enumerate(lines) if _SETTINGS_RE.search(ln)]
    if prose:
        at = _prose_write_line(lines, hits)
    else:
        at = hits[0] if hits and _SCRIPT_WRITE_RE.search(text) else None
    if at is None:
        return []

    targets: list[str] = []
    for ln in lines:
        for m in _SETTINGS_RE.finditer(ln):
            p = _clean_path(m.group(1))
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
