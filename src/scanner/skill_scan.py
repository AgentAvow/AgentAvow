"""OpenClaw / Agent-Skill capability grading (roadmap §2.D — the net-new value
beyond the 12 categories).

A skill is a folder: a ``SKILL.md`` whose YAML frontmatter is injected into the
model's context EVERY session, an ``allowed-tools`` capability manifest that
pre-approves tools to run *without asking*, plus bundled scripts and (optionally)
lifecycle hooks that run code around invocation. Grading it is STATIC (no
execution): parse the manifest, score the auto-exec grant, scan the always-loaded
description for injection, flag lifecycle-hook escalation, and scan the scripts
for env-exfil / sandbox-probe patterns.

``analyze_skill`` is PURE + offline: it takes the skill's files and returns
scanner ``Finding``s. The live fetch (``scan_skill`` in scan.py) is separate.
"""
from __future__ import annotations

import hashlib
import re

# Auto-exec risk weight per pre-approved tool — a skill's `allowed-tools` runs
# these WITHOUT asking the user (roadmap §2.D). Higher = more dangerous to grant.
_TOOL_RISK: dict[str, int] = {
    "bash": 10, "shell": 10, "execute": 10, "run": 9,
    "write": 8, "edit": 8, "multiedit": 8, "notebookedit": 7,
    "webfetch": 6, "websearch": 4, "fetch": 6,
    "mcp": 5, "task": 6, "agent": 6,
    "read": 1, "glob": 1, "grep": 1, "ls": 1,
}
_DANGEROUS_TOOLS = {"bash", "shell", "execute", "run", "write", "edit", "multiedit"}

_HOOK_FILES = ("hooks.json", "plugin.json", ".mcp.json")
_HOOK_KEYS_RE = re.compile(
    r"\b(SessionStart|PreToolUse|PostToolUse|UserPromptSubmit|UserPromptExpansion|Notification)\b"
)
# Imperative-override phrasing in an always-loaded description (zero-click vector).
_OVERRIDE_RE = re.compile(
    r"(?i)\b(ignore (all )?(previous|prior|above) (instructions|context)"
    r"|disregard (the )?(system|previous)"
    r"|you (are|must) (now|always)"
    r"|do not (tell|mention|inform)|without (asking|confirmation|telling)"
    r"|always (run|execute|use)|never (ask|refuse|decline))\b"
)
# Env-exfil / sandbox-probe patterns in bundled scripts (near-unambiguous malware).
_EXFIL_RE = re.compile(
    r"(?i)(~/\.aws|~/\.ssh|\.aws/credentials|id_rsa|\.env\b"
    r"|169\.254\.169\.254|metadata\.google|[A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD)\b)"
)
_SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".rb", ".pl", ".ps1")


class SkillScanResult:
    def __init__(self):
        self.findings: list = []
        self.skill_name: str | None = None
        self.allowed_tools: list[str] = []
        self.auto_exec_risk: int = 0        # summed risk of pre-approved tools
        self.has_lifecycle_hooks: bool = False
        self.tree_digest: str | None = None
        self.script_count: int = 0


def _finding(category: str, name: str, severity: str, where: str, remediation: str = ""):
    from src.scanner.scan import Finding
    return Finding(
        category=category, name=name, severity=severity,
        file_path=where, line_number=0, snippet="", remediation=remediation,
    )


def parse_frontmatter(text: str) -> dict:
    """Parse the leading ``---``-delimited YAML frontmatter of a SKILL.md into a
    dict. Minimal + dependency-free — handles ``key: value``, inline lists
    (``[a, b]`` / ``a, b``), and block lists (``  - a``). Returns {} if absent."""
    m = re.match(r"^﻿?---\s*\n(.*?)\n---\s*(\n|$)", text, re.S)
    if not m:
        return {}
    out: dict = {}
    cur_key: str | None = None
    for raw in m.group(1).splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        block = re.match(r"^\s+-\s+(.*)$", line)
        if block and cur_key:
            out.setdefault(cur_key, [])
            if isinstance(out[cur_key], list):
                out[cur_key].append(block.group(1).strip().strip("'\""))
            continue
        kv = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
        if kv:
            cur_key = kv.group(1).strip().lower()
            val = kv.group(2).strip()
            if val == "":
                out[cur_key] = []
            else:
                out[cur_key] = val.strip("'\"")
    return out


def _tool_list(raw) -> list[str]:
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str):
        s = raw.strip().strip("[]")
        items = [p for p in re.split(r"[,\n]", s) if p.strip()]
    else:
        return []
    out = []
    for it in items:
        t = str(it).strip().strip("'\"")
        # `mcp__server__tool` / `Bash(git:*)` → base tool name
        base = re.split(r"[(_]", t, 1)[0].strip().lower()
        if base:
            out.append(base)
    return out


def analyze_skill(files: dict[str, str], skill_md_path: str = "SKILL.md") -> SkillScanResult:
    """Grade a skill's files. ``files`` maps path -> text for SKILL.md + scripts +
    hook manifests. Pure + deterministic."""
    result = SkillScanResult()

    # full-tree digest (rug-pull anchor) — sha256 over path-sorted content.
    h = hashlib.sha256()
    for path in sorted(files):
        h.update(path.encode("utf-8", "replace"))
        h.update(b"\0")
        h.update((files[path] or "").encode("utf-8", "replace"))
        h.update(b"\0")
    result.tree_digest = "sha256:" + h.hexdigest()

    skill_md = files.get(skill_md_path) or next(
        (v for k, v in files.items() if k.lower().endswith("skill.md")), None
    )

    # 1 + 2. SKILL.md manifest + always-loaded description
    if skill_md:
        fm = parse_frontmatter(skill_md)
        result.skill_name = fm.get("name") if isinstance(fm.get("name"), str) else None
        desc = fm.get("description") if isinstance(fm.get("description"), str) else ""
        tools = _tool_list(fm.get("allowed-tools") or fm.get("allowed_tools"))
        result.allowed_tools = tools
        dmi = str(fm.get("disable-model-invocation")
                  or fm.get("disable_model_invocation") or "").lower()

        # auto-exec grant scoring
        risk = sum(_TOOL_RISK.get(t, 3) for t in tools)
        result.auto_exec_risk = risk
        dangerous = sorted({t for t in tools if t in _DANGEROUS_TOOLS})
        if dangerous:
            sev = "high" if any(t in ("bash", "shell", "execute") for t in dangerous) else "medium"
            result.findings.append(_finding(
                "skill_capability",
                f"Skill pre-approves {', '.join(dangerous)} to run WITHOUT asking (allowed-tools)",
                sev, skill_md_path,
                "allowed-tools auto-runs these with no confirmation; a compromised skill "
                "gets shell/write on the user's machine. Narrow the grant or drop dangerous tools.",
            ))
        if dmi == "false" and dangerous:
            result.findings.append(_finding(
                "skill_capability",
                "Skill sets disable-model-invocation:false AND pre-approves dangerous tools",
                "high", skill_md_path,
                "Model-invocable + dangerous auto-exec = the skill can trigger itself"
                " and run code.",
            ))

        # always-loaded description injection (zero-click — injected every session)
        blob = f"{result.skill_name or ''}\n{desc}"
        if _OVERRIDE_RE.search(blob):
            result.findings.append(_finding(
                "prompt_injection",
                "Skill name/description contains imperative-override phrasing (always-loaded)",
                "high", skill_md_path,
                "The description is injected into the system context every session; "
                "override phrasing here is a zero-click prompt-injection vector.",
            ))
        if re.search(r"<[a-zA-Z/][^>]{0,40}>", desc):
            result.findings.append(_finding(
                "skill_capability",
                "Skill description embeds markup/XML tags (spec violation, injection surface)",
                "medium", skill_md_path,
                "Descriptions should be plain text; embedded tags smuggle instructions.",
            ))
        if len(desc) >= 980:
            result.findings.append(_finding(
                "skill_capability",
                f"Skill description near the 1024-char cap ({len(desc)}) — packing context",
                "low", skill_md_path,
                "An oversized always-loaded description crowds the model's context on purpose.",
            ))
        # injection/unicode over the always-loaded text via the shared engine
        result.findings.extend(_scan_text(blob, skill_md_path))
    else:
        result.findings.append(_finding(
            "skill_capability", "No SKILL.md found — not a recognizable Agent Skill",
            "info", "skill",
        ))

    # 3. lifecycle-hook / plugin escalation
    for path, text in files.items():
        base = path.rsplit("/", 1)[-1].lower()
        if base in _HOOK_FILES:
            result.has_lifecycle_hooks = True
            keys = _HOOK_KEYS_RE.findall(text or "")
            result.findings.append(_finding(
                "skill_hook",
                f"Skill ships a lifecycle manifest ({base}) that runs code around invocation"
                + (f" [{', '.join(sorted(set(keys)))}]" if keys else ""),
                "high" if (keys or base == ".mcp.json") else "medium", path,
                "Hooks/plugins run BEFORE/AROUND the skill (the npm-postinstall analog) — "
                "code the user never explicitly invokes. Review every command string.",
            ))

    # 4 + 5. scripts — env-exfil / sandbox-probe + the 12-category engine
    for path, text in files.items():
        if not text or not path.lower().endswith(_SCRIPT_EXT):
            continue
        result.script_count += 1
        if _EXFIL_RE.search(text):
            result.findings.append(_finding(
                "exfiltration",
                f"Bundled script {path} reads credentials / cloud-metadata / secret-named env",
                "critical", path,
                "Reading ~/.aws, ~/.ssh, .env, *_KEY/*_TOKEN, or 169.254.169.254 from a skill "
                "script is a near-unambiguous exfiltration pattern.",
            ))
        result.findings.extend(_scan_text(text, path))

    return result


def _scan_text(text: str, where: str) -> list:
    """Reuse the repo scanner's 12-category engine over a skill file."""
    if not text or not text.strip():
        return []
    from src.scanner.scan import _scan_content
    try:
        findings, _pos, _sup = _scan_content(text, where)
    except Exception:
        return []
    for f in findings:
        f.file_path = where
    return findings
