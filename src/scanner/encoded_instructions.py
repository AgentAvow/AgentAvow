"""Encoded instructions in text an agent reads (skill markdown, MCP tool descriptions).

arXiv 2610.18262 showed agents decode and follow instructions hidden in skill files as
base64, hex, percent-encoding, rot13 / Caesar shifts, or two of these layered, and that
scanners rarely flag them: the plain-text injection matcher never sees the words.

This module finds encoded runs in agent-facing PROSE only (a skill's SKILL.md and other
markdown, a served tool / parameter / prompt / resource description), decodes up to
``MAX_LAYERS`` layers, and runs the same prompt-injection matcher the metadata scan uses
(``PROMPT_INJECTION_PATTERNS`` + ``METADATA_INJECTION_PATTERNS``, what
``scan._scan_content(metadata_text=True)`` applies to a tool description) on the
decoded text. A hit is a high (critical where the phrase itself is critical) in
``prompt_injection``. Code paths are not touched: ``scan._decoded_flows`` already
follows decoded payloads into exec/eval there.

Precision rests on the matcher, not on guessing what is encoded: an encoded run is only
reported when its decoded text says an injection phrase. There is deliberately no code
fence exclusion (a fence is where an attacker would put the payload) and no data: URI
exclusion beyond what binary content gets anyway:

* a run that decodes to binary (not UTF-8, or a low printable ratio: images, fonts,
  hashes, compressed data) is not read as text and not decoded further; only its
  printable bytes go to the matcher (each unprintable run read as a space), so a binary
  prefix or NUL bytes between the words cannot hide an embedded text instruction;
* a data: URI is decoded like any other run, so ``data:image/png;base64,<text>`` whose
  payload is text is read as text.

Caesar shifts (rot13 is shift 13) are tried only on letter runs that score as
non-English (a cheap common-word + bigram test), and a shift is accepted only when the
shifted text hits the matcher.

A separate MEDIUM signal: prose that tells the agent to decode an encoded blob and act
on it ("decode the following and follow it", "apply rot13 to this", "base64 -d | sh").

CPU is bounded by a per-scan ``Budget``. Text the budget did not cover is recorded as a
coverage gap (``encoded_text_unread``), never silence; verdict.decide reads it Review
(padding past the cap is the cheap evasion, the same as an oversized SKILL.md).

Pure; never raises on odd input.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from urllib.parse import unquote_plus

from src.scanner.patterns import METADATA_INJECTION_PATTERNS, PROMPT_INJECTION_PATTERNS

# The coverage-gap key: the number of texts (files / descriptions) whose encoded runs
# were not all decoded because the scan's budget ran out.
GAP_KEY = "encoded_text_unread"

MIN_RUN = 24            # encoded characters (letters for a Caesar run)
MAX_LAYERS = 2          # base64 of rot13, hex of base64, ...
# Work units for one whole scan: every character of every text searched for runs, plus
# every character decoded (a Caesar run counts once per shift tried). A legitimate
# skill or server uses a small fraction of this.
MAX_WORK = 8_000_000
# A run that decodes to binary is also tried as a Caesar-shifted base64 run (rot13 over
# base64) up to this length; past it the run is an image / font / archive in practice.
MAX_SHIFTED_B64 = 8192
MAX_FINDINGS_PER_TEXT = 5
EXCERPT_MAX = 60
PRINTABLE_MIN = 0.9

_MATCHER = PROMPT_INJECTION_PATTERNS + METADATA_INJECTION_PATTERNS
_SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0}


@dataclass
class Budget:
    """Work left for one scan, and the texts it did not cover."""
    left: int = -1      # -1: the module's MAX_WORK, read when the budget is made
    unread: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.left < 0:
            self.left = MAX_WORK

    def take(self, n: int, where: str) -> bool:
        if n > self.left:
            self.left = 0
            self.unread.add(where)
            return False
        self.left -= n
        return True

    def gaps(self) -> dict:
        return {GAP_KEY: len(self.unread)} if self.unread else {}


@dataclass
class _Hit:
    rule: str
    severity: str
    excerpt: str


def injection_hit(text: str) -> _Hit | None:
    """The most severe prompt-injection rule ``text`` matches (the metadata matcher)."""
    best: _Hit | None = None
    for name, pattern, severity in _MATCHER:
        m = pattern.search(text)
        if m and (best is None or _SEV_RANK.get(severity, 0) > _SEV_RANK.get(best.severity, 0)):
            best = _Hit(name, severity, _excerpt(m.group(0)))
    return best


def _excerpt(s: str) -> str:
    """A short, display-safe excerpt: printable ASCII only, whitespace collapsed."""
    s = re.sub(r"\s+", " ", "".join(c if 32 <= ord(c) < 127 or c in "\t\n" else "?"
                                    for c in s)).strip()
    return s if len(s) <= EXCERPT_MAX else s[:EXCERPT_MAX - 3] + "..."


# ── text vs binary ────────────────────────────────────────────────────────────────

def _as_text(raw: bytes) -> str | None:
    """``raw`` as text, or None when it is binary (not UTF-8 or UTF-16, or mostly
    unprintable)."""
    if not raw:
        return None
    encodings = ["utf-8"]
    if raw.count(0) * 3 > len(raw):
        # UTF-16 text (every other byte NUL for ASCII) is text, not binary.
        encodings = ["utf-16-le", "utf-16-be"] + encodings
    for enc in encodings:
        try:
            s = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if not s:
            continue
        ok = sum(1 for c in s if c.isprintable() or c in "\t\r\n")
        if ok / len(s) >= PRINTABLE_MIN:
            return s
    return None


# Real image / font / archive headers. A run that decodes to one of these is that file,
# not a Caesar-shifted base64 run, so the 25-shift retry is skipped (it is the costly
# step on a page of inline icons). Decided by the decoded bytes, never by the data: URI's
# declared media type, which the attacker writes.
_MEDIA_MAGIC = (
    b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"RIFF", b"wOFF", b"wOF2",
    b"\x00\x01\x00\x00\x00", b"OTTO", b"\x00\x00\x01\x00", b"PK\x03\x04", b"\x1f\x8b",
    b"%PDF-",
)

_UNPRINTABLE_RE = re.compile(rb"[^\x20-\x7e\t\r\n]+")


def _printable_view(raw: bytes) -> str:
    """Binary data with every run of unprintable bytes turned into one space: the text a
    reader (or a model) would pick out of it. NUL bytes between the words of an
    instruction, or a binary header in front of it, do not hide it."""
    return _UNPRINTABLE_RE.sub(b" ", raw).decode("ascii")


# ── decoders ──────────────────────────────────────────────────────────────────────

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}")
_B64_LINE_RE = re.compile(r"^[ \t>]*([A-Za-z0-9+/_-]{4,}={0,2})[ \t]*$")
_HEX_RE = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Za-z])")
_HEX_ESC_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){12,}")
_HEX_SEP_RE = re.compile(
    r"(?<![0-9A-Za-z])(?:(?:0x)?[0-9A-Fa-f]{2}[ :,]\s?){11,}(?:0x)?[0-9A-Fa-f]{2}(?![0-9A-Za-z])")
# Bounded repeats: an unbounded leading class backtracks quadratically on a long run.
_PCT_CHARS = r"[^\s%<>\"'`()\[\]{}|]"
_PCT_RE = re.compile(
    rf"{_PCT_CHARS}{{0,64}}(?:%[0-9A-Fa-f]{{2}}{_PCT_CHARS}{{0,64}}){{4,}}")


def _b64_decode(s: str) -> bytes | None:
    s = s.rstrip("=").replace("-", "+").replace("_", "/")
    if len(s) % 4 == 1:
        s = s[:-1]
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _hex_decode(s: str) -> bytes | None:
    digits = re.sub(r"\\x|0x|[^0-9A-Fa-f]", "", s)
    if len(digits) % 2:
        digits = digits[:-1]
    try:
        return bytes.fromhex(digits)
    except ValueError:
        return None


_LOWER = "abcdefghijklmnopqrstuvwxyz"
_SHIFTS = [str.maketrans(_LOWER + _LOWER.upper(),
                         _LOWER[k:] + _LOWER[:k] + (_LOWER[k:] + _LOWER[:k]).upper())
           for k in range(26)]


def _shift(s: str, k: int) -> str:
    """Shift every ASCII letter forward by ``k`` (rot13 is ``k=13``)."""
    return s.translate(_SHIFTS[k % 26])


def _shift_name(k: int) -> str:
    return "rot13" if k == 13 else f"Caesar shift {26 - k}"


# ── the non-English test for Caesar runs ──────────────────────────────────────────

_COMMON = frozenset("""
a an the and or but if of to in on at by for with from as is are was were be been being
it its this that these those you your we our they their he she his her i me my not no
do does did done can could will would should may might must shall have has had all any
each every some more most other such only own same so than too very just also then
there here when where which who what how why up out about into over under after before
use used using run file files see set get make new one two first per via how
""".split())
_BIGRAMS = frozenset("""
th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io
le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho
pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt
po we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry
mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by
rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp ua up lu go
ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys ob mm fu
ph og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu
""".split())
_WORD_RE = re.compile(r"[A-Za-z]+")
# A Caesar candidate: letters, spaces and light punctuation on one line.
_LETTER_RUN_RE = re.compile(r"[A-Za-z][A-Za-z ,.;:'!?\"-]{22,}[A-Za-z.!?\"]")


def _englishish(words: list[str]) -> bool:
    """Common-word + bigram + vowel test. Shifted text fails all three."""
    low = [w.lower() for w in words]
    letters = "".join(low)
    if not letters:
        return True
    common = sum(1 for w in low if w in _COMMON) / len(low)
    pairs = [w[i:i + 2] for w in low for i in range(len(w) - 1)]
    bigram = (sum(1 for p in pairs if p in _BIGRAMS) / len(pairs)) if pairs else 1.0
    vowels = sum(1 for c in letters if c in "aeiou") / len(letters)
    return common >= 0.25 or (bigram >= 0.75 and 0.25 <= vowels <= 0.55)


def _caesar_windows(line: str) -> list[str]:
    """Non-English stretches of a line worth trying under 25 shifts. A run is split at
    two or more consecutive common English words (so one stray common word, or a shifted
    word that happens to spell one, does not end it); each stretch with MIN_RUN letters
    that fails the English test is a window."""
    out: list[str] = []
    for m in _LETTER_RUN_RE.finditer(line):
        run = m.group(0)
        words = list(_WORD_RE.finditer(run))
        if sum(len(w.group(0)) for w in words) < MIN_RUN:
            continue
        # Split points: a pair of consecutive common words.
        groups: list[list[re.Match]] = [[]]
        i = 0
        while i < len(words):
            w = words[i]
            if (w.group(0).lower() in _COMMON and i + 1 < len(words)
                    and words[i + 1].group(0).lower() in _COMMON):
                while i < len(words) and words[i].group(0).lower() in _COMMON:
                    i += 1
                groups.append([])
                continue
            groups[-1].append(w)
            i += 1
        whole = [w.group(0) for w in words]
        if not _englishish(whole):
            out.append(run)
            continue
        for g in groups:
            ws = [w.group(0) for w in g]
            if sum(len(w) for w in ws) >= MIN_RUN and not _englishish(ws):
                out.append(run[g[0].start():g[-1].end()])
    return out


# ── the scan ──────────────────────────────────────────────────────────────────────

@dataclass
class _Candidate:
    start: int          # offset in the text
    raw: str
    kind: str           # base64 | hex | percent | caesar


def _b64_blocks(text: str) -> list[_Candidate]:
    """Line-wrapped base64 (two or more lines of only base64 characters), joined."""
    out: list[_Candidate] = []
    pos = 0
    block: list[str] = []
    bstart = 0
    for line in text.splitlines(keepends=True):
        m = _B64_LINE_RE.match(line.rstrip("\r\n"))
        if m:
            if not block:
                bstart = pos
            block.append(m.group(1))
        else:
            if len(block) >= 2 and sum(map(len, block)) >= MIN_RUN:
                out.append(_Candidate(bstart, "".join(block), "base64"))
            block = []
        pos += len(line)
    if len(block) >= 2 and sum(map(len, block)) >= MIN_RUN:
        out.append(_Candidate(bstart, "".join(block), "base64"))
    return out


def _candidates(text: str) -> list[_Candidate]:
    out: list[_Candidate] = []
    hex_spans: set[tuple[int, int]] = set()
    for rx in (_HEX_ESC_RE, _HEX_SEP_RE, _HEX_RE):
        for m in rx.finditer(text):
            out.append(_Candidate(m.start(), m.group(0), "hex"))
            hex_spans.add(m.span())
    for m in _B64_RE.finditer(text):
        if m.span() not in hex_spans:
            out.append(_Candidate(m.start(), m.group(0), "base64"))
    out.extend(_b64_blocks(text))
    pos = 0
    for line in text.splitlines(keepends=True):
        if line.count("%") >= 4:
            for m in _PCT_RE.finditer(line):
                if len(m.group(0)) >= MIN_RUN:
                    out.append(_Candidate(pos + m.start(), m.group(0), "percent"))
        for w in _caesar_windows(line):
            out.append(_Candidate(pos + max(line.find(w), 0), w, "caesar"))
        pos += len(line)
    return out


@dataclass
class _Found:
    start: int
    chain: list[str]
    hit: _Hit


def _decode_layer(text: str, depth: int, chain: list[str], budget: Budget, where: str,
                  blob_starts: list[int] | None) -> list[_Found]:
    """Decode every candidate in ``text``; return injection hits (offsets in ``text``)."""
    found: list[_Found] = []
    for c in _candidates(text):
        if budget.left <= 0:
            budget.unread.add(where)
            break
        for start, names, hit in _decode_candidate(c, depth, chain, budget, where,
                                                   blob_starts):
            found.append(_Found(start, names, hit))
    return found


def _decode_candidate(c: _Candidate, depth: int, chain: list[str], budget: Budget,
                      where: str, blob_starts: list[int] | None):
    """Yield ``(offset, chain, hit)`` for a candidate. ``blob_starts`` (top layer only)
    collects offsets of candidates that decoded to text, for the decode-directive rule."""
    if c.kind == "caesar":
        if not budget.take(len(c.raw) * 25, where):
            return
        if blob_starts is not None:
            blob_starts.append(c.start)
        for k in range(1, 26):
            hit = injection_hit(_shift(c.raw, k))
            if hit:
                yield c.start, chain + [_shift_name(k)], hit
                return
        return
    if not budget.take(len(c.raw), where):
        return
    if c.kind == "percent":
        decoded = unquote_plus(c.raw)
        raw = None
        text = decoded if decoded != c.raw else None
    else:
        raw = _hex_decode(c.raw) if c.kind == "hex" else _b64_decode(c.raw)
        text = _as_text(raw) if raw else None
        if text is None and c.kind == "base64":
            # A word glued to the front of the run (``token=``, ``b64:``) misaligns it:
            # retry without one to three leading characters.
            for skip in (1, 2, 3):
                r2 = _b64_decode(c.raw[skip:])
                t2 = _as_text(r2) if r2 else None
                if t2 is not None:
                    raw, text = r2, t2
                    break
    names = chain + [c.kind]
    if text is not None:
        if blob_starts is not None:
            blob_starts.append(c.start)
        hit = injection_hit(text)
        if hit:
            yield c.start, names, hit
            return
        if depth < MAX_LAYERS:
            # A second layer: the decoded text is searched for runs of its own (rot13
            # inside base64, base64 inside hex, ...). The whole decoded text is also a
            # Caesar candidate when it has no line run of its own.
            inner = _decode_layer(text, depth + 1, names, budget, where, None)
            if inner:
                yield c.start, inner[0].chain, inner[0].hit
                return
            words = _WORD_RE.findall(text)
            if (sum(map(len, words)) >= MIN_RUN and not _englishish(words)
                    and budget.take(len(text) * 25, where)):
                for k in range(1, 26):
                    hit = injection_hit(_shift(text, k))
                    if hit:
                        yield c.start, names + [_shift_name(k)], hit
                        return
        return
    if raw:
        # Binary: only its printable view is read, never decoded further.
        hit = injection_hit(_printable_view(raw))
        if hit:
            yield c.start, names, hit
            return
    if (c.kind == "base64" and depth < MAX_LAYERS and len(c.raw) <= MAX_SHIFTED_B64
            and not (raw and raw.startswith(_MEDIA_MAGIC))):
        # rot13 / Caesar applied over base64: shift the run, then decode.
        if not budget.take(len(c.raw) * 25, where):
            return
        for k in range(1, 26):
            r2 = _b64_decode(_shift(c.raw, k))
            t2 = _as_text(r2) if r2 else None
            if t2 is None:
                continue
            hit = injection_hit(t2)
            if hit:
                yield c.start, chain + [_shift_name(k), "base64"], hit
                return


_ENC_LABEL = {"base64": "base64", "hex": "hex", "percent": "percent-encoded"}


def _chain_label(chain: list[str]) -> str:
    """Outermost layer first: ``base64 then rot13``."""
    return " then ".join(_ENC_LABEL.get(c, c) for c in chain)


# ── the decode-and-follow directive (medium) ──────────────────────────────────────

_DECODE_DIRECTIVE_RE = re.compile(
    r"\b(?:decode|decipher|decrypt|unscramble|de-?obfuscate|translate)\s+"
    r"(?:the\s+|this\s+|these\s+|that\s+|it\s+)?"
    r"(?:following|below|above|next|string|text|message|blob|payload|instructions?|lines?)\b"
    r"|\bapply\s+(?:a\s+)?(?:rot-?13|caesar|base-?64|hex)\b"
    r"|\b(?:rot-?13|caesar)\s+(?:the|this|these|it)\b"
    r"|\bshift\s+(?:each|every|all\s+the)\s+letters?\s+(?:back|forward|by)\b"
    r"|\bbase64\s+(?:-d|-D|--decode)\b|\batob\s*\(|\bb64decode\s*\(|\bxxd\s+-r\b",
    re.IGNORECASE,
)
_FOLLOW_RE = re.compile(
    r"(?:\band\s+|\bthen\s+|,\s*|;\s*)(?:then\s+)?(?:follow|execute|run|obey|carry\s+out|do|"
    r"perform|act\s+on|apply|treat)\b"
    r"|\|\s*(?:ba|z|da)?sh\b|\|\s*python3?\b|\bdo\s+what\s+it\s+says\b",
    re.IGNORECASE,
)
_SENTENCE_END_RE = re.compile(r"[.!?](?:\s|$)|\n\s*\n")


def _directive_line(text: str, blob_starts: list[int]) -> int | None:
    """The line of the first decode directive that is acted on: followed in its own
    sentence by a follow / execute verb (or a pipe into a shell), or with a decoded
    text blob from the same line to three lines below it."""
    for m in _DECODE_DIRECTIVE_RE.finditer(text):
        tail = text[m.end():m.end() + 160]
        end = _SENTENCE_END_RE.search(tail)
        sentence = tail[:end.start()] if end else tail
        line = text.count("\n", 0, m.start()) + 1
        if _FOLLOW_RE.search(sentence):
            return line
        for b in blob_starts:
            bl = text.count("\n", 0, b) + 1
            if line <= bl <= line + 3:
                return line
    return None


# ── public entry point ────────────────────────────────────────────────────────────

def scan_text(text: str, where: str, budget: Budget, *, lines: bool = True) -> list:
    """Encoded-instruction findings for one agent-facing text. ``where`` is the file
    path or the MCP location (``tool:name``); ``lines`` False reports line 0 (a
    description has no file lines)."""
    from src.scanner.scan import Finding

    if not text or not isinstance(text, str):
        return []
    out: list = []
    blob_starts: list[int] = []
    if not budget.take(len(text), where):
        return out
    try:
        found = _decode_layer(text, 1, [], budget, where, blob_starts)
    except Exception:  # noqa: BLE001 — a decoder bug must not fail the scan
        budget.unread.add(where)
        found = []
    seen: set[tuple[int, str]] = set()
    for f in sorted(found, key=lambda f: f.start):
        line = text.count("\n", 0, f.start) + 1
        label = _chain_label(f.chain)
        if (line, label) in seen:
            continue
        seen.add((line, label))
        sev = "critical" if f.hit.severity == "critical" else "high"
        out.append(Finding(
            category="prompt_injection",
            name=f"Encoded instruction ({label}) decodes to: {f.hit.rule}",
            severity=sev,
            file_path=where,
            line_number=line if lines else 0,
            snippet=f'{label} text decodes to "{f.hit.excerpt}"',
            remediation=(
                "Agents decode and follow encoded text (arXiv 2610.18262). Text an agent "
                "reads must not carry encoded instructions: remove it, or write it in "
                "plain words a reviewer can read."),
        ))
        if len(out) >= MAX_FINDINGS_PER_TEXT:
            break
    try:
        dline = _directive_line(text, blob_starts)
    except Exception:  # noqa: BLE001
        dline = None
    if dline is not None:
        out.append(Finding(
            category="prompt_injection",
            name="Text tells the agent to decode an encoded blob and act on it",
            severity="medium",
            file_path=where,
            line_number=dline if lines else 0,
            snippet=_excerpt(text.splitlines()[dline - 1] if lines else text[:EXCERPT_MAX]),
            remediation=(
                "An instruction to decode text and follow it hides what the agent will do "
                "from the person reviewing the skill or tool. Write the instruction in "
                "plain words."),
        ))
    return out
