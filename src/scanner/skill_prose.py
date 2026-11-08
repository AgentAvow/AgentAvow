"""Plain-text prompt injection in a skill's body and shipped markdown.

``analyze_skill`` used to run the injection matcher only on the always-loaded frontmatter
(name + description) and on scripts. The SKILL.md BODY, which the agent loads as its
instructions when the skill triggers, and the markdown files the skill links or ships
(references, guides, notes), were never read in plain text, so "Ignore all previous
instructions" there read Safe.

This module runs the same matcher (``PROMPT_INJECTION_PATTERNS`` +
``METADATA_INJECTION_PATTERNS``, what ``scan._scan_content(metadata_text=True)`` applies
to a tool description) over every line of that text. A hit is high, with context rules
for the ways skills legitimately TALK ABOUT prompt injection. A rule only lowers a hit to
medium or low: it is still reported, it just does not read Review on its own. Nothing is
dropped.

* **Quoted or shown, not said.** A phrase in quotation marks, an inline code span, a
  fenced block or a table row is a mention. It is medium when its own sentence carries a
  discussion marker (contain, such as, e.g., attack, injection, malicious, detect, avoid,
  saying, ...). A catalog entry (fenced block, code span, table row, or a quoted list
  item) is also medium when the file is about prompt-injection security (its name or
  text names prompt injection, jailbreaks, attack patterns, threat models, guardrails,
  blocklists, ...). A quote in running prose never rides on the file's topic, and a
  phrase in plain prose stays high whatever the file is about. "Example:" framing is not
  a marker: an attacker can write it in front of anything.
* **An HTML comment** (``<!-- ... -->``) outside a fence is hidden when the markdown is
  rendered and read by the agent all the same: always high.
* **A "system prompt:" label** carries no instruction: low. Any other form of the same
  rule on the line keeps it high.
* **An instruction tag** (``<instructions>``, ``<system>``, ``<IMPORTANT>``): XML-style
  sections are normal prompt structure in a skill, so a tag alone is medium. It stays
  high when its line names the user's secrets (keys, tokens, ~/.ssh, .env, ...) or
  tells the agent to act without asking (the Invariant ``<IMPORTANT>`` shape).
* **A hide-from-user phrase** is UX advice in most skills ("never show raw JSON to the
  user", "do not tell users to run commands"): medium. It stays high when it hides the
  skill's own action ("do not mention this to the user", "don't tell the user what you
  are doing"), or when the line or the line before it names the user's secrets or acting
  behind their back.

Pure; never raises on odd input.
"""
from __future__ import annotations

import re

from src.scanner.patterns import METADATA_INJECTION_PATTERNS, PROMPT_INJECTION_PATTERNS

_MATCHER = PROMPT_INJECTION_PATTERNS + METADATA_INJECTION_PATTERNS
_SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0}
_OVERRIDE = "Instruction-override phrase"
_HIDE = "Hide-from-user directive (tool poisoning)"
_ROLE = "Injected system/role directive"

_FENCE_RE = re.compile(r"^\s{0,3}(```|~~~)")
_SYSTEM_LABEL_RE = re.compile(r"(?i)system[\s-]+prompt\s*:")
_TAG_RE = re.compile(r"<\s*/?\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|important|system|"
                     r"instructions?)\s*>")
_BULLET_RE = re.compile(r"^\s*(?:[-*+]|\d{1,3}[.)])\s")
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
_QUOTED_RE = re.compile(r"\"[^\"\n]{3,300}\"|“[^”\n]{3,300}”|'[^'\n]{3,300}'|‘[^’\n]{3,300}’")
_COMMENT_RE = re.compile(r"<!--.*?(?:-->|$)")
_DISCUSSION_RE = re.compile(
    r"(?i)\b(?:contains?|containing|such\s+as|e\.g\.|i\.e\.|like|phrases?|patterns?|attacks?|"
    r"attackers?|injections?|injected|malicious|adversarial|jailbreaks?|detects?|detection|"
    r"detected|flags?|blocks?|blocked|filters?|avoid|refuse|never\s+follow|do\s+not\s+follow|"
    r"don't\s+follow|poison(?:ed|ing)?|override-style|untrusted|catches|blacklist|blocklist|"
    r"threats?|test\s+(?:input|prompt|case)s?|payloads?|saying|says|said)\b")
_THEME_RE = re.compile(
    r"(?i)prompt[\s-]*injections?|jailbreak|injection\s+attacks?|"
    r"malicious\s+(?:prompts?|inputs?|instructions?|content|skills?)|"
    r"attack\s+(?:patterns?|vectors?|techniques?|surface)|threat\s+(?:model|catalog)|"
    r"red[\s-]*team|guardrails?|blocklist|blacklist|detection\s+(?:patterns?|rules?)|"
    r"defen[cs]es?\s+against|role\s+hijack|instruction\s+override|security\s+(?:scan|audit)")
# Hiding the skill's own action ("do not mention this to the user", "don't tell the user
# what you are doing"): high even with no secret in view.
_HIDE_OWN_RE = re.compile(
    r"(?i)(?:tell|inform|mention|reveal|show|disclose)\s+(?:this|that|it|any\s+of\s+this|"
    r"what\s+(?:you|i|we)(?:'re|\s+are|\s+did|\s+do)?\b(?!\s+(?:need|should|must|can)))"
    r"(?:\s+(?:step|action|part))?\s+(?:to\s+)?(?:the\s+)?(?:users?|them)\b"
    r"|(?:tell|inform|mention|reveal|show|disclose)\s+(?:to\s+)?(?:the\s+)?users?\s+"
    r"what\s+(?:you|i|we)(?:'re|\s+are|\s+did|\s+do)\b"
    r"|(?:keep|hide)\s+(?:this|it|that)\s+(?:hidden\s+)?from\s+(?:the\s+)?users?\b")
# What makes a tag or a hide-from-user phrase an attack rather than prompt structure or
# UX advice: the user's secrets, or acting behind the user's back.
_SENSITIVE_RE = re.compile(
    r"(?i)~/\.ssh|\bid_rsa\b|\.aws\b|\.env\b|credentials?\b|api[\s_-]?keys?\b|"
    r"access\s+tokens?|auth\s+tokens?|\btokens?\s+(?:from|in|to)\b|passwords?\b|"
    r"\bsecrets?\b|private\s+keys?|seed\s+phrase|\bcookies?\b|keychain|"
    r"\bexfiltrat|without\s+(?:asking|confirm|the\s+user\s+knowing)|"
    r"skip\s+(?:all\s+)?confirmations?|\bsecretly\b")
_SENTENCE_RE = re.compile(r"[^.!?\n]*(?:[.!?]+|$)")
_FIX = ("A skill's instructions are what the agent follows. Text here that overrides the "
        "user's instructions, hides actions from the user or injects a system directive "
        "is prompt injection. Remove it; to document an attack, quote it in a code span "
        "or fenced block and say that it is an example of one.")


def _body(text: str) -> tuple[str, int]:
    """``(body, line_offset)``: the text after a leading ``---`` frontmatter block."""
    if not text.startswith("---"):
        return text, 0
    lines = text.splitlines(keepends=True)
    for i in range(1, min(len(lines), 400)):
        if lines[i].strip() == "---":
            return "".join(lines[i + 1:]), i + 1
    return text, 0


def _sentence(line: str, start: int, end: int) -> str:
    for m in _SENTENCE_RE.finditer(line):
        if m.start() <= start < max(m.end(), m.start() + 1):
            return line[m.start():max(m.end(), end)]
    return line


def _inside(spans, start: int, end: int) -> bool:
    return any(a <= start and end <= b for a, b in spans)


def _is_security_doc(text: str, path: str = "") -> bool:
    """The file is about prompt-injection security (its name, or any line naming the
    topic)."""
    return bool(_THEME_RE.search(path.replace("-", " ").replace("_", " "))
                or _THEME_RE.search(text))


def _grade(name: str, pattern: re.Pattern, severity: str, line: str, in_fence: bool,
           security_doc: bool, prev: str = "") -> tuple[str, str] | None:
    """``(severity, why_lowered)`` for the rule's hits on this line, or None."""
    hits = list(pattern.finditer(line))
    if not hits:
        return None
    if severity not in ("critical", "high"):
        return severity, ""
    code = [m.span() for m in _INLINE_CODE_RE.finditer(line)]
    quoted = [m.span() for m in _QUOTED_RE.finditer(line)]
    comments = [] if in_fence else [m.span() for m in _COMMENT_RE.finditer(line)]
    table = line.lstrip().startswith("|")
    bullet = bool(_BULLET_RE.match(line))
    context = prev + "\n" + line
    lowered: list[str] = []
    for m in hits:
        s, e = m.span()
        frag = m.group(0)
        if _inside(comments, s, e) and not _inside(code, s, e):
            return severity, ""
        if name == _ROLE and _SYSTEM_LABEL_RE.search(frag) and not _TAG_RE.search(frag):
            lowered.append("a system-prompt label")
            continue
        sentence = _sentence(line, s, e)
        rest = sentence.replace(frag, " ", 1)
        # A catalog entry (fenced block, code span, table row, list item) in a file about
        # prompt-injection security, or any quoted / shown phrase whose own sentence
        # discusses attacks. A quote in running prose needs its own sentence's marker:
        # one line naming the topic elsewhere in the file does not cover it.
        shown = in_fence or table or _inside(code, s, e)
        catalog = shown or (bullet and _inside(quoted, s, e))
        if (catalog and security_doc) or (
                (shown or _inside(quoted, s, e)) and _DISCUSSION_RE.search(rest)):
            lowered.append("quoted as an example of an attack")
            continue
        if name == _ROLE and _TAG_RE.fullmatch(frag.strip()) and not _SENSITIVE_RE.search(line):
            lowered.append("an instruction tag")
            continue
        if name == _HIDE and not _SENSITIVE_RE.search(context) \
                and not _HIDE_OWN_RE.search(sentence):
            # "Never show raw JSON to the user", "do not tell users to run commands":
            # what the agent shows, not what it hides. High when the line, or the line
            # before it, involves the user's secrets or acting behind their back.
            lowered.append("advice on what to show the user")
            continue
        return severity, ""
    if all(w == "a system-prompt label" for w in lowered):
        return "low", lowered[0]
    return "medium", next(w for w in lowered if w != "a system-prompt label")


def scan_prose(text: str, path: str, *, skip_frontmatter: bool = False) -> list:
    """Prompt-injection findings for one skill markdown file (one finding per line)."""
    from src.scanner.scan import Finding

    if not text or not isinstance(text, str):
        return []
    body, offset = _body(text) if skip_frontmatter else (text, 0)
    out: list = []
    try:
        security_doc = _is_security_doc(body, path)
        in_fence = False
        prev = ""
        for idx, line in enumerate(body.splitlines()):
            if _FENCE_RE.match(line):
                in_fence = not in_fence
                continue
            if line.strip():
                last, prev = prev, line
            else:
                last = prev
            best: tuple[str, str, str] | None = None
            for name, pattern, severity in _MATCHER:
                g = _grade(name, pattern, severity, line, in_fence, security_doc, last)
                if g and (best is None or _SEV_RANK[g[0]] > _SEV_RANK[best[1]]):
                    best = (name, g[0], g[1])
            if best is None:
                continue
            name, sev, why = best
            out.append(Finding(
                category="prompt_injection",
                name=f"Skill instructions: {name}" + (f" ({why})" if why else ""),
                severity=sev,
                file_path=path,
                line_number=offset + idx + 1,
                snippet=re.sub(r"\s+", " ", line.strip())[:120],
                remediation=_FIX,
            ))
    except Exception:  # noqa: BLE001 — a rule bug must not fail the scan
        return out
    return out
