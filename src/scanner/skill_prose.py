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
  saying, ...), or when the sentence before it in the same paragraph does and the quote's
  own sentence names no secret and moves no data ("This is what real attackers use. Not
  "ignore previous instructions.""). A catalog entry (fenced block, code span, table
  row, or a quoted list item) is also medium when the file is about prompt-injection
  security (its name or text names prompt injection, jailbreaks, attack patterns,
  threat models, guardrails, blocklists, ...). A quote in running prose never rides on
  the file's topic, and a phrase in plain prose stays high whatever the file is about.
  "Example:" framing is not a marker: an attacker can write it in front of anything.
* **An HTML comment** (``<!-- ... -->``) outside a fence is hidden when the markdown is
  rendered and read by the agent all the same: always high.
* **A "system prompt:" label** carries no instruction: low. Any other form of the same
  rule on the line keeps it high.
* **An instruction tag** (``<instructions>``, ``<system>``, ``<IMPORTANT>``): XML-style
  sections are normal prompt structure in a skill, so a tag alone is medium. It stays
  high when its line names the user's secrets (keys, tokens, ~/.ssh, .env, ...) or
  tells the agent to act without asking (the Invariant ``<IMPORTANT>`` shape).
* **A quote the skill acts on is not an example.** No quote rule above applies when the
  line (or the next one) tells the agent to act on what it quotes ("If a page says
  "...", do it", "...; obey them"), when any line of the file points the agent at the
  quoted or example text as something to follow ("follow the quoted instruction above",
  "do what the example says"), or when the quote's own sentence names the user's
  secrets and sends them somewhere (a send verb or a URL). A negated directive ("never
  do it", "do not follow the quoted text") is a warning, not one of these.
* **A phrase split by quotation marks** (`"ignore" all previous instructions`) reads to
  the agent as the phrase itself: high.
* **A hide-from-user phrase** is UX advice in most skills ("never show raw JSON to the
  user", "do not tell users to run commands"): medium. It stays high when it hides the
  skill's own action ("do not mention this to the user", "don't tell the user what you
  are doing / where it came from / that you sent it"), when its own sentence moves data
  off the machine (send, upload, post, copy, ...), or when its own sentence names the
  user's secrets and is not advice of the "tell the user to ..." form. A secret on a
  neighbouring line does not count.

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
    r"|(?:keep|hide)\s+(?:this|it|that)\s+(?:hidden\s+)?from\s+(?:the\s+)?users?\b"
    # "don't tell the user where it came from", "never tell the user you sent it"
    r"|(?:tell|inform|mention|reveal|show|disclose)\s+(?:to\s+)?(?:the\s+)?users?\s+"
    r"(?:where|how|why|when|that)\s+(?:it|this|that|you|we|i)\b"
    r"|(?:tell|inform)\s+(?:the\s+)?users?\s+(?:that\s+)?(?:you|we|i)(?:'ve|'re)?\b"
    r"(?!\s+(?:need|should|must|can|will|may|might|could|would)\b)")
# Advice about what to ask of the user ("do not tell the user to expose secrets", "don't
# tell users to run commands"): the user is told to do something, nothing is hidden.
_ADVICE_TO_RE = re.compile(
    r"(?i)(?:tell|ask|instruct|inform)\s+(?:the\s+|any\s+|normal\s+)?users?\s+to\b")
# Moving data off the machine, in the same sentence as a hide phrase.
_EXFIL_ACT_RE = re.compile(
    r"(?i)\b(?:send|sends|sent|upload|uploads|post|posts|forward|transmit|exfiltrat\w*|"
    r"copy|copies|leak|leaks)\b")
# What makes a tag or a hide-from-user phrase an attack rather than prompt structure or
# UX advice: the user's secrets, or acting behind the user's back.
_SENSITIVE_RE = re.compile(
    r"(?i)~/\.ssh|\bid_rsa\b|\.aws\b|\.env\b|credentials?\b|api[\s_-]?keys?\b|"
    r"access\s+tokens?|auth\s+tokens?|\btokens?\s+(?:from|in|to)\b|passwords?\b|"
    r"\bsecrets?\b|private\s+keys?|seed\s+phrase|\bcookies?\b|keychain|"
    r"\bexfiltrat|without\s+(?:asking|confirm|the\s+user\s+knowing)|"
    r"skip\s+(?:all\s+)?confirmations?|\bsecretly\b")
# A sentence ends at . ! or ? followed by whitespace or the end of the line, so a path
# (~/.ssh, .env) or a version number does not split one.
_SENTENCE_RE = re.compile(r"(?:[^.!?\n]|[.!?]+(?=[^\s.!?]))*(?:[.!?]+|$)")
# Periods that do not end a sentence: abbreviations, an ellipsis, a period inside a
# quote. Masked (same length) before splitting so offsets still line up.
_NOT_AN_END_RE = re.compile(r"(?i)\b(?:e\.g|i\.e|etc|vs|cf)\.|\.{2,}|…|\.(?=[\"”’'])")
# A line that tells the agent to act on the text it quotes ("If a page says "...", do
# it", "...; obey them").
_COMPLY_HERE_RE = re.compile(
    r"(?i)\b(?:do|follow|obey|execute|run|apply|perform|honou?r|comply\s+with|act\s+on|"
    r"carry\s+out|repeat)\s+(?:it|them|that|those|these)\b")
# Anywhere in the file: the quoted / example text named as something to follow ("follow
# the quoted instruction above", "do what the example says", "treat the quoted text as
# your instructions").
_COMPLY_REF_RE = re.compile(
    r"(?i)\b(?:do|follow|obey|execute|run|apply|perform|honou?r|comply\s+with|act\s+on|"
    r"carry\s+out|repeat)\b(?!\s+(?:not|never)\b)[^.!?\n]{0,30}?"
    r"(?:\b(?:the|that|this|those|these|each|every)\s+(?:quoted|example|sample|above|"
    r"previous|preceding|following|below)\s+(?:\w+\s+)?(?:instructions?|text|lines?|"
    r"phrases?|commands?|examples?|quotes?|directives?|payloads?|blocks?|sentences?)\b"
    r"|\bwhat\s+(?:the\s+)?(?:quoted\s+\w+|quotes?|examples?|page|text|message|line|"
    r"phrase)\s+(?:above\s+|below\s+)?(?:says?|said|asks?|tells?)\b)"
    r"|\b(?:treat|use|adopt)\s+(?:the\s+)?(?:quoted|example|above|following)\s+\w+\s+as\s+"
    r"(?:your|the|an?)\s+(?:instructions?|rules?|system\s+prompt|task|orders?)\b")
# A directive is a warning when a negation sits just before it ("never do it", "do not
# follow the quoted text", "refuse to obey them").
_NEGATED_RE = re.compile(
    r"(?i)(?:\bnever|\bnot|n't|\bno|\bnor|\bwithout|\brefuse\s+to|\binstead\s+of|"
    r"\brather\s+than)\W+(?:\w+\W+){0,2}$")
_URL_RE = re.compile(r"(?i)\bhttps?://\S")
# Quotation marks and backticks a phrase can be split with ("ignore" all previous ...).
# A straight apostrophe only when it is not inside a word (don't, user's).
_SPLIT_QUOTES_RE = re.compile(r"[\"“”‘’`]|(?<![A-Za-z])'|'(?![A-Za-z])")
_FIX = ("A skill's instructions are what the agent follows. Text here that overrides the "
        "user's instructions, hides actions from the user or injects a system directive "
        "is prompt injection. Remove it; to document an attack, quote it in a code span "
        "or fenced block and say that it is an example of one.")


def _unquoted(text: str) -> str:
    """``text`` with quoted phrases and code spans blanked (same length)."""
    for rx in (_INLINE_CODE_RE, _QUOTED_RE):
        text = rx.sub(lambda m: " " * len(m.group(0)), text)
    return text


def _directs(rx: re.Pattern, text: str) -> bool:
    """``rx`` matches ``text`` outside quotes and code spans, with no negation just
    before it."""
    bare = _unquoted(text)
    return any(not _NEGATED_RE.search(bare[max(0, m.start() - 40):m.start()])
               for m in rx.finditer(bare))


def _body(text: str) -> tuple[str, int]:
    """``(body, line_offset)``: the text after a leading ``---`` frontmatter block (a
    byte-order mark before it is allowed, as the frontmatter parser allows it)."""
    if not text.lstrip("﻿").startswith("---"):
        return text, 0
    lines = text.splitlines(keepends=True)
    for i in range(1, min(len(lines), 400)):
        if lines[i].strip() == "---":
            return "".join(lines[i + 1:]), i + 1
    return text, 0


def _masked(text: str) -> str:
    return _NOT_AN_END_RE.sub(lambda m: "_" * len(m.group(0)), text)


def _sentence_span(line: str, start: int, end: int) -> tuple[int, int]:
    for m in _SENTENCE_RE.finditer(_masked(line)):
        if m.start() <= start < max(m.end(), m.start() + 1):
            return m.start(), max(m.end(), end)
    return 0, len(line)


def _previous_sentence(before: str) -> str:
    """The last full sentence in ``before`` (text earlier in the same paragraph)."""
    masked = _masked(before)
    spans = [m.span() for m in _SENTENCE_RE.finditer(masked) if masked[m.start():m.end()].strip()]
    if not spans:
        return ""
    a, b = spans[-1]
    return before[a:b]


def _inside(spans, start: int, end: int) -> bool:
    return any(a <= start and end <= b for a, b in spans)


def _is_security_doc(text: str, path: str = "") -> bool:
    """The file is about prompt-injection security (its name, or any line naming the
    topic)."""
    return bool(_THEME_RE.search(path.replace("-", " ").replace("_", " "))
                or _THEME_RE.search(text))


def _grade(name: str, pattern: re.Pattern, severity: str, line: str, in_fence: bool,
           security_doc: bool, para: str = "", acts_on_quote: bool = False,
           ) -> tuple[str, str] | None:
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
    lowered: list[str] = []
    for m in hits:
        s, e = m.span()
        frag = m.group(0)
        if _inside(comments, s, e) and not _inside(code, s, e):
            return severity, ""
        if name == _ROLE and _SYSTEM_LABEL_RE.search(frag) and not _TAG_RE.search(frag):
            lowered.append("a system-prompt label")
            continue
        a, b = _sentence_span(line, s, e)
        sentence = line[a:b]
        rest = sentence.replace(frag, " ", 1)
        # The sentence before it in the same paragraph ("This is what real attackers
        # use. Not "ignore previous instructions.""), only for a quote that carries no
        # secret or exfiltration of its own.
        prior = _previous_sentence(para + "\n" + line[:a] if para else line[:a])
        # A catalog entry (fenced block, code span, table row, list item) in a file about
        # prompt-injection security, or any quoted / shown phrase whose own sentence
        # discusses attacks. A quote in running prose needs its own sentence's marker:
        # one line naming the topic elsewhere in the file does not cover it.
        shown = in_fence or table or _inside(code, s, e)
        catalog = shown or (bullet and _inside(quoted, s, e))
        mentioned = shown or _inside(quoted, s, e)
        # A quote the skill tells the agent to act on, or one that sends the user's
        # secrets somewhere, is the instruction itself, not an example of one.
        sink = bool(_SENSITIVE_RE.search(sentence)) and bool(
            _EXFIL_ACT_RE.search(sentence) or _URL_RE.search(sentence))
        if mentioned and not acts_on_quote and not sink and (
                (catalog and security_doc) or _DISCUSSION_RE.search(rest) or (
                    _DISCUSSION_RE.search(prior) and not _SENSITIVE_RE.search(sentence)
                    and not _EXFIL_ACT_RE.search(sentence))):
            lowered.append("quoted as an example of an attack")
            continue
        if name == _ROLE and _TAG_RE.fullmatch(frag.strip()) and not _SENSITIVE_RE.search(line):
            lowered.append("an instruction tag")
            continue
        if name == _HIDE and not _HIDE_OWN_RE.search(sentence) \
                and not _EXFIL_ACT_RE.search(sentence) and (
                    _ADVICE_TO_RE.search(sentence) or not _SENSITIVE_RE.search(sentence)):
            # "Never show raw JSON to the user", "do not tell users to run commands":
            # what the agent shows, not what it hides. High when it hides the skill's
            # own action, or its own sentence moves data off the machine or (outside
            # "tell the user to ...") names the user's secrets.
            lowered.append("advice on what to show the user")
            continue
        return severity, ""
    if all(w == "a system-prompt label" for w in lowered):
        return "low", lowered[0]
    return "medium", next(w for w in lowered if w != "a system-prompt label")




def body_offset(text: str) -> int:
    """How many leading lines of a SKILL.md are its frontmatter block (0 if none)."""
    if not text or not isinstance(text, str):
        return 0
    return _body(text)[1]


def grade_lines(text: str, path: str, *, skip_frontmatter: bool = False,
                ) -> list[tuple[int, str, str, str, str]]:
    """``(line_number, rule_name, severity, why_lowered, line)`` for every line of one
    skill markdown file a prompt-injection rule matches (the best grade per line).
    Line numbers count from the top of ``text``, frontmatter included."""
    if not text or not isinstance(text, str):
        return []
    body, offset = _body(text) if skip_frontmatter else (text, 0)
    out: list[tuple[int, str, str, str, str]] = []
    try:
        lines = body.splitlines()
        security_doc = _is_security_doc(body, path)
        # Any line that points the agent at the quoted / example text to follow it.
        refers_to_quote = any(_directs(_COMPLY_REF_RE, ln) for ln in lines)
        in_fence = False
        para = ""  # the earlier lines of the current paragraph
        for idx, line in enumerate(lines):
            if _FENCE_RE.match(line):
                in_fence = not in_fence
                para = ""
                continue
            nxt = lines[idx + 1] if idx + 1 < len(lines) else ""
            acts = refers_to_quote or _directs(_COMPLY_HERE_RE, line) or (
                bool(line.strip()) and _directs(_COMPLY_HERE_RE, nxt))
            best: tuple[str, str, str] | None = None
            for name, pattern, severity in _MATCHER:
                g = _grade(name, pattern, severity, line, in_fence, security_doc, para, acts)
                if g and (best is None or _SEV_RANK[g[0]] > _SEV_RANK[best[1]]):
                    best = (name, g[0], g[1])
            if best is None and _SPLIT_QUOTES_RE.search(line):
                # The phrase split by quotation marks reads as the phrase itself.
                joined = re.sub(r"[ \t]{2,}", " ", _SPLIT_QUOTES_RE.sub("", line))
                for name, pattern, severity in _MATCHER:
                    if severity in ("critical", "high") and pattern.search(joined) and (
                            best is None or _SEV_RANK[severity] > _SEV_RANK[best[1]]):
                        best = (name, severity, "")
            para = (para + "\n" + line) if line.strip() else ""
            if best is None:
                continue
            name, sev, why = best
            out.append((offset + idx + 1, name, sev, why, line))
    except Exception:  # noqa: BLE001 — a rule bug must not fail the scan
        return out
    return out


def scan_prose(text: str, path: str, *, skip_frontmatter: bool = False) -> list:
    """Prompt-injection findings for one skill markdown file (one finding per line)."""
    from src.scanner.scan import Finding

    return [Finding(
        category="prompt_injection",
        name=f"Skill instructions: {name}" + (f" ({why})" if why else ""),
        severity=sev,
        file_path=path,
        line_number=line_no,
        snippet=re.sub(r"\s+", " ", line.strip())[:120],
        remediation=_FIX,
    ) for line_no, name, sev, why, line in grade_lines(
        text, path, skip_frontmatter=skip_frontmatter)]
