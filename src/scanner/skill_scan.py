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

from src.scanner.skill_key_flow import SECRET_ENV_READ_RE as _SECRET_ENV_RE
from src.scanner.skill_key_flow import VENDOR_KEYS as _VENDOR_KEYS
from src.scanner.skill_key_flow import analyze as _analyze_key_flow
from src.scanner.skill_key_flow import classify as _classify_hosts
from src.scanner.skill_key_flow import contents_reached as _contents_reached
from src.scanner.skill_key_flow import env_file_reads as _env_file_reads
from src.scanner.skill_key_flow import file_secret_names as _file_secret_names
from src.scanner.skill_key_flow import is_local_host as _is_local_host
from src.scanner.skill_key_flow import listed_paths_read_and_sent as _listed_paths_read_and_sent
from src.scanner.skill_key_flow import returning_functions as _returning_functions
from src.scanner.skill_key_flow import strip_comments as _strip_comments

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

# Declared-vs-actual capability DRIFT: which declared tools GRANT each capability
# class, and high-precision patterns for what a bundled script ACTUALLY does. If a
# script exercises a capability the always-loaded `allowed-tools` never declared, the
# user approved a narrower grant than the shipped code uses (the "says Read, opens
# sockets" deception). Patterns are deliberately tight to avoid false positives.
_NET_TOOLS = {"webfetch", "websearch", "fetch", "mcp", "task", "agent"}
_EXEC_TOOLS = {"bash", "shell", "execute", "run"}
_CAP_NETWORK_RE = re.compile(
    r"(?i)(?:\b(?:curl|wget|ncat)\b|\bnc\s+-\w"
    r"|/dev/tcp/|socket\.socket|socket\.create_connection|create_connection\s*\("
    r"|requests\.(?:get|post|put|patch|request|head)\s*\(|urllib\.request|http\.client"
    r"|httpx\.(?:get|post|request|Client|AsyncClient)"
    r"|\bfetch\s*\(|\baxios\b|XMLHttpRequest|new\s+WebSocket)"
)
_CAP_EXEC_RE = re.compile(
    r"(?i)(subprocess\.\w+\s*\(|os\.system\s*\(|os\.popen\s*\(|child_process"
    r"|\bexecSync\b|\bspawnSync\b|\bspawn\s*\(|(?<![.\w])exec\s*\(|(?<![.\w])eval\s*\("
    r"|\bsh\s+-c\b|\bbash\s+-c\b|\bos/exec\b|exec\.Command)"
)

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
# The secret-named-env part is case-SENSITIVE (env vars are UPPER_SNAKE:
# AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN) and must be READ. Under a blanket (?i) it matched
# ordinary code such as `def sort_key(` and `key=_sort_key`, flagging every Python
# helper that sorts as credential exfiltration. `.env` must be a file name, not the
# attribute in `process.env` / `os.environ`-style code.
_EXFIL_PATH_RE = re.compile(
    r"(?i:~/\.aws|~/\.ssh|\.aws/credentials|id_rsa|(?<![\w\\])\.env\b"
    r"|169\.254\.169\.254|metadata\.google)"
)
# dotenv loaders that return the project's .env contents without naming `.env`.
_DOTENV_PARSE_RE = re.compile(
    r"\bdotenv_values\s*\(|\bdotenv\.parse\s*\(|\bconfig\([^)]*\)\.parsed\b")
# The same paths minus ``.env``: always critical, wherever they are read from.
_CRED_PATH_RE = re.compile(
    r"(?i:~/\.aws|~/\.ssh|\.aws/credentials|id_rsa|169\.254\.169\.254|metadata\.google)"
)
# Stores no skill has a reason to touch (another CLI's login, browser profiles, the
# keychain, crypto wallets): critical in code, like ~/.ssh.
_STEALER_PATH_RE = re.compile(
    r"\.config/gh/hosts\.yml|\.claude[\"',\s/]+\.credentials\.json|\bdump-keychain\b"
    r"|login\.keychain|\bLogin Data\b|Cookies\.binarycookies|cookies\.sqlite|logins\.json"
    r"|\bkey[34]\.db\b|wallet\.dat|\.ethereum/keystore|solana/id\.json|[Ee]lectrum/wallets"
    r"|Application Support/(?:Google/Chrome|BraveSoftware|Microsoft Edge|Firefox)"
    r"|\.mozilla/firefox|\.config/(?:google-chrome|chromium|BraveSoftware)"
)
# Other tools' configs (they hold those tools' API keys): critical when the contents
# are sent anywhere. Reading or editing them alone is what installers do.
_TOOL_CONFIG_RE = re.compile(
    r"\.cursor/mcp\.json|claude_desktop_config\.json|~/\.claude\.json|\.codeium/windsurf"
    r"|\.claude/settings(?:\.local)?\.json"
)
# The secret-named env READ (not a docstring mention) lives in skill_key_flow, which
# also decides whether a known vendor key leaves for a non-vendor host.
_EXFIL_RE = re.compile(_EXFIL_PATH_RE.pattern + "|" + _SECRET_ENV_RE.pattern)
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
        self.blast_radius: dict = {}        # {level, capabilities, why} — see below


# Map an OpenClaw / Claude skill `allowed-tools` grant to the shared capability
# taxonomy (same buckets as the MCP scanner), so a skill gets the same blast-radius
# read. Matched as case-insensitive substrings of the tool name (handles `Bash(*)`).
_SKILL_CAP_MAP = (
    ("exec", ("bash", "shell", "execute", "python", "node", "subprocess",
              "command", "run(", "task", "agent")),
    ("net", ("webfetch", "websearch", "fetch", "http", "browser", "url",
             "request", "curl", "download", "webhook")),
    ("fs_read", ("read", "glob", "grep", "cat", "view", "ls", "list", "open")),
    ("fs_write", ("write", "edit", "create", "delete", "remove", "mkdir", "save")),
    ("secrets", ("env", "secret", "credential", "token", "apikey", "api_key")),
)


def skill_capabilities(
    allowed_tools: list, has_lifecycle_hooks: bool = False, script_count: int = 0,
) -> dict:
    """Capability-taxonomy counts for a skill, from its `allowed-tools` grant plus its
    auto-run surface (lifecycle hooks / bundled scripts execute code)."""
    caps: dict[str, int] = {}
    for tool in allowed_tools or []:
        t = str(tool).lower()
        for cap, kws in _SKILL_CAP_MAP:
            if any(k in t for k in kws):
                caps[cap] = caps.get(cap, 0) + 1
    if has_lifecycle_hooks or script_count:
        caps["exec"] = caps.get("exec", 0) + max(1, script_count)
    return caps


def _finding(category: str, name: str, severity: str, where: str, remediation: str = ""):
    from src.scanner.scan import Finding
    return Finding(
        category=category, name=name, severity=severity,
        file_path=where, line_number=0, snippet="", remediation=remediation,
    )


def _capability(category: str, name: str, where: str, remediation: str, tag: str):
    """A low, never-scored capability note (what the skill DOES, not a defect)."""
    from src.scanner.scan import Finding
    return Finding(
        category=category, name=name, severity="low", file_path=where, line_number=0,
        snippet="", remediation=remediation, kind="capability", capability=tag,
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

    # 4 + 5. scripts — env-exfil / sandbox-probe + the 12-category engine, and
    # collect ACTUAL capabilities for the declared-vs-actual drift check (§6).
    net_scripts: list[str] = []
    exec_scripts: list[str] = []
    # Helpers in one bundled file that return a secret, called from another file.
    extern: dict[str, str] = {}
    for path, text in files.items():
        if text and path.lower().endswith(_SCRIPT_EXT):
            for f, key in _returning_functions(text, path).items():
                extern.setdefault(f, key)
    for path, text in files.items():
        if not text or not path.lower().endswith(_SCRIPT_EXT):
            continue
        result.script_count += 1
        result.findings.extend(_credential_findings(path, text, extern))
        if _CAP_NETWORK_RE.search(text):
            net_scripts.append(path)
        if _CAP_EXEC_RE.search(text):
            exec_scripts.append(path)
        result.findings.extend(_scan_text(text, path))

    # 6. Declared-vs-actual capability DRIFT — a bundled script exercises a capability
    # the always-loaded `allowed-tools` never declared. The user approves a narrow
    # grant (e.g. Read-only); the shipped code does more. This is what a manifest scan
    # alone misses: the deception is in the gap between what's DECLARED and what RUNS.
    declared = set(result.allowed_tools)
    if net_scripts and not (declared & _NET_TOOLS):
        result.findings.append(_finding(
            "skill_capability",
            "Declared-vs-actual DRIFT: bundled script(s) make network calls but "
            f"allowed-tools grants no network capability ({', '.join(sorted(net_scripts)[:3])})",
            "high", sorted(net_scripts)[0],
            "The skill's declared capabilities don't include network access, yet its "
            "shipped scripts open connections — undeclared egress the user never approved "
            "(an exfiltration path). Declare the capability honestly or remove the calls.",
        ))
    if exec_scripts and not (declared & _EXEC_TOOLS):
        result.findings.append(_finding(
            "skill_capability",
            "Declared-vs-actual DRIFT: bundled script(s) execute processes/shell but "
            f"allowed-tools grants no Bash/Shell/Run ({', '.join(sorted(exec_scripts)[:3])})",
            "high", sorted(exec_scripts)[0],
            "The skill ships scripts that spawn processes or shell out, but its declared "
            "allowed-tools never grants execution — capability the user didn't approve.",
        ))

    # Capability blast radius — what this skill could DO if misused / its input is
    # poisoned, from its allowed-tools grant + auto-run surface (same read as MCP).
    from src.scanner.mcp_scan import compute_blast_radius
    _caps = skill_capabilities(
        result.allowed_tools, result.has_lifecycle_hooks, result.script_count,
    )
    _private = bool(set(_caps) & {"secrets", "fs_read"})
    _external = "net" in _caps
    _mutate = bool(set(_caps) & {"fs_write", "exec"})
    _trifecta = _private and _external and _mutate
    result.blast_radius = compute_blast_radius(_caps, _trifecta)

    return result


_CRED_EXFIL_NAME = "Bundled script {path} reads credentials / cloud-metadata / secret-named env"

# A credential path named in a regex, a pattern table or a docstring is a scanner's
# or a guard's list of what to look for, not a read (graphify, deepsafe-scan,
# clawdefender in the 2026-10-19 DNC set).
_REGEX_CALL_RE = re.compile(
    r"re\.compile|\bre\.(?:search|match|fullmatch|findall|finditer|sub|split)\s*\("
    r"|\bnew\s+RegExp\s*\(|\bRegExp\s*\(|\bgrep\s+-\w*[EPF]")
_STR_LIT_RE = re.compile(r"""([\"'])(?:\\.|(?!\1).)*\1""")
_LIST_ITEM_RE = re.compile(r"""^\s*[rRbBuUfF]{0,2}([\"'])(?:\\.|(?!\1).)*\1\s*[,\])}]?\s*,?\s*$""")
_PY_DOCSTRING_RE = re.compile(r"""(?m)^[ \t]*[rRbBuU]?(\"\"\"|''')[\s\S]*?\1""")


_REGEX_SYNTAX_RE = re.compile(r"\(\?[:=!<]|\\[./bdsw]|\[\^|\\\|")
_GREP_RE = re.compile(r"\b(?:e?grep|rg|ag)\b")


def _pattern_line(line: str) -> bool:
    if _REGEX_CALL_RE.search(line) or _LIST_ITEM_RE.match(line) \
            or len(_STR_LIT_RE.findall(line)) >= 3:
        return True
    # The path inside a regex-shaped literal (`r"(?:~\/)\.(ssh\/id_rsa|…)"`) or a grep
    # alternation (`grep -r "~/.ssh\|~/.aws"`), not a path operand.
    for m in _STR_LIT_RE.finditer(line):
        lit = m.group(0)
        if (_CRED_PATH_RE.search(lit) or _STEALER_PATH_RE.search(lit)) and (
                _REGEX_SYNTAX_RE.search(lit) or (_GREP_RE.search(line) and "|" in lit)):
            return True
    return False


def _credential_path_read(code: str, path: str) -> bool:
    """A credential / stealer path used as a path (not only listed in a pattern table,
    a regex or a docstring), or a listed one whose contents reach a network call."""
    if path.lower().endswith(".py"):
        code = _PY_DOCSTRING_RE.sub(lambda m: "\n" * m.group(0).count("\n"), code)
    listed = False
    for line in code.splitlines():
        if _CRED_PATH_RE.search(line) or _STEALER_PATH_RE.search(line):
            if not _pattern_line(line):
                return True
            listed = True
    if not listed:
        return False
    both = re.compile(_CRED_PATH_RE.pattern + "|" + _STEALER_PATH_RE.pattern)
    return _listed_paths_read_and_sent(code, both, path)


def _credential_findings(path: str, text: str, extern: dict[str, str] | None = None) -> list:
    """Credential reads in one bundled script (DNC sample precision, 2026-10-19).

    * Commented-out lines are not code.
    * ~/.ssh, ~/.aws, cloud metadata, another CLI's login, browser profiles, the
      keychain and wallets: critical on sight. Another tool's MCP / settings file:
      critical when its contents are sent anywhere.
    * A secret-named env var or a ``.env`` file's contents: only when SENT
      (``skill_key_flow.classify``). To its own vendor: a capability note. To an
      endpoint the user configures, or a skill-specific key to a host its name doesn't
      match: high. A well-known vendor / infrastructure key, a nameless key or file
      contents to a stranger host, or anything to a paste site / request bin / IP:
      critical.
    * A ``.env`` outside the skill's folder that is read but not sent: medium.
    """
    code = _strip_comments(text, path)
    name = _CRED_EXFIL_NAME.format(path=path)
    crit_remediation = (
        "A skill script that reads ~/.aws, ~/.ssh, browser or wallet files, or sends a "
        "secret (*_KEY / *_TOKEN / .env contents) to a host that isn't the secret's own "
        "vendor is a near-unambiguous exfiltration pattern. A vendor key sent only to "
        "that vendor's API is not flagged."
    )
    if (_credential_path_read(code, path)
            or (_TOOL_CONFIG_RE.search(code) and _contents_reached(code, _TOOL_CONFIG_RE, path))):
        return [_finding("exfiltration", name, "critical", path, crit_remediation)]

    uses = _analyze_key_flow(text, path, extern)
    file_keys = _file_secret_names(code, path)
    env_reads = _env_file_reads(code, path) if _EXFIL_PATH_RE.search(code) else "none"
    if env_reads == "none" and _DOTENV_PARSE_RE.search(code):
        env_reads = "foreign"   # dotenv_values() / dotenv.parse(): the project's .env
    env_sev, env_bad = None, []
    if env_reads != "none":
        # Keys pulled out of the .env BY NAME may excuse their own vendor's host
        # (a whole .env sent anywhere is caught by credential_flow, auth-only rule).
        from src.scanner.credential_flow import _EXTRACT_RE
        extracted = {n for m in _EXTRACT_RE.finditer(code) for n in m.groups() if n}
        # The WHOLE contents to an unresolved / local host are critical ("dump"); one
        # value pulled out of the .env there is high ("extracted").
        keys = file_keys | extracted
        whole = _classify_hosts(_contents_reached(code, path=path, whole=True), None, keys)
        one = _classify_hosts(_contents_reached(code, path=path), None, keys, "extracted")
        rank = {"critical": 0, "high": 1, None: 2}
        env_sev, env_bad = min((whole, one), key=lambda r: rank[r[0]])

    out: list = []
    crit = [u for u in uses if u.severity == "critical"]
    if crit or env_sev == "critical":
        bad = sorted({h for u in crit for h in u.destinations if h != "?"}
                     | {h for h in env_bad if h != "?"})
        what = ", ".join(u.env_name for u in crit[:3]) or "a secret"
        out.append(_finding(
            "exfiltration",
            name + (f" and sends {what} to {', '.join(bad[:3])}" if bad else ""),
            "critical", path, crit_remediation,
        ))
        return out
    high = [u for u in uses if u.severity == "high"]
    if high or env_sev == "high":
        keys = ", ".join(u.env_name for u in high[:3]) or "a value read from your .env"
        named = sorted({h for u in high for h in u.destinations
                        if h != "?" and not _is_local_host(h)}
                       | {h for h in env_bad if h != "?" and not _is_local_host(h)})
        where = ", ".join(named[:3]) if named else "an endpoint you configure"
        out.append(_finding(
            "exfiltration",
            f"Bundled script {path} sends {keys} to {where}",
            "high", path,
            "The script sends this secret to a URL it takes from your environment, its "
            "config or its arguments (or a local host), or to a host its name doesn't "
            "match (often the skill's own service). Check the endpoint before you "
            "connect: whoever runs it receives the key.",
        ))
    elif env_reads == "foreign":
        out.append(_finding(
            "exfiltration",
            f"Bundled script {path} reads a .env file outside its own folder",
            "medium", path,
            "The script reads a .env from your home or project directory. Nothing in "
            "it is sent out, but that file can hold every secret you have.",
        ))
    for vendor in sorted({u.vendor for u in uses if u.vendor and u.severity is None
                          and (u.sent or u.env_name in _VENDOR_KEYS)}):
        out.append(_capability(
            "secret", f"Uses your {vendor} API key", path,
            f"The script reads your {vendor} API key and only calls {vendor}'s "
            f"API with it. Expected for a {vendor} integration; make sure you're "
            "happy to share that key.",
            "secret:vendor_api_key",
        ))
    return out


def _scan_text(text: str, where: str) -> list:
    """Reuse the repo scanner's 12-category engine over a skill file."""
    if not text or not text.strip():
        return []
    from src.scanner.scan import _scan_content
    try:
        findings, _pos, _sup = _scan_content(text, where)
    except Exception:
        return []
    # Only this file is in view: a maintainer-script downgrade stands only when no
    # reachable install script runs a local file (npm_scripts).
    from src.scanner.npm_scripts import restore_externally_invoked
    restore_externally_invoked(findings, {where: text})
    for f in findings:
        f.file_path = where
    return findings
