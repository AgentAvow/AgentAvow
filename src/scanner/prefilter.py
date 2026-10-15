"""Literal prefilter for the per-line pattern scan.

``_scan_content`` runs every rule's regex on every line of a file. Almost every rule
needs some literal text to match (``subprocess.``, ``eval``, ``-----BEGIN``), and most
lines carry none of it, so most of those searches are wasted. This module reads each
compiled regex's parse tree once and derives the literal strings any match must
contain; for a file it then finds, with plain substring search, the lines that hold
those literals. A rule's regex runs only on those lines.

The filter only ever skips a line where the regex cannot match, so findings are
unchanged:

* a required literal is derived conservatively: anything the analysis does not
  understand (a backreference, a negated or category class, an optional item) gives
  "no requirement", and the rule then runs on every line;
* a literal from a case-insensitive part of a regex is looked up in a normalized copy
  of the file: the four non-ASCII characters ``re.IGNORECASE`` folds onto ASCII
  letters (KELVIN SIGN, LONG S, the Turkish dotted/dotless I) mapped to that letter,
  then ``str.lower``. Only ASCII literals are used in that mode;
  ``tests/test_scanner_prefilter.py`` checks the fold table against every code point;
* a case-sensitive literal is looked up in the file text as is;
* line numbers come from counting ``\\n``: neither normalization adds or removes one.
"""
from __future__ import annotations

import re
from functools import lru_cache

try:  # Python 3.11+
    from re import _constants as _c  # type: ignore[attr-defined]
    from re import _parser as _p  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - older interpreters
    import sre_constants as _c  # type: ignore[no-redef]
    import sre_parse as _p  # type: ignore[no-redef]

# The non-ASCII characters that ``re.IGNORECASE`` matches to an ASCII letter, mapped to
# that letter BEFORE lowercasing (U+0130 lowers to two characters, which would break a
# literal that spans it).
_IGNORECASE_ASCII_FOLDS = {0x130: "i", 0x131: "i", 0x17F: "s", 0x212A: "k"}

# A character class with more members than this is not worth enumerating.
_MAX_CLASS_CHARS = 256
# At most this many independent required-literal sets per regex (each costs a scan),
# and a set after the first only when its shortest literal is at least this long.
_MAX_SETS = 2
_MIN_EXTRA_LEN = 3

# A literal: (text, case_insensitive). Text is lowercased when case_insensitive.
Lit = tuple[str, bool]


def normalize(text: str) -> str:
    """The haystack that case-insensitive literals are looked up in."""
    if not text.isascii():
        for cp, rep in _IGNORECASE_ASCII_FOLDS.items():
            ch = chr(cp)
            if ch in text:
                text = text.replace(ch, rep)
    return text.lower()


def _class_chars(items, ci: bool) -> frozenset[Lit] | None:
    chars: set[str] = set()
    for op, av in items:
        if op is _c.LITERAL:
            chars.add(chr(av))
        elif op is _c.RANGE:
            lo, hi = av
            if hi - lo + 1 > _MAX_CLASS_CHARS:
                return None
            chars.update(chr(v) for v in range(lo, hi + 1))
        else:  # NEGATE, CATEGORY, anything else: no finite requirement
            return None
        if len(chars) > _MAX_CLASS_CHARS:
            return None
    out: set[Lit] = set()
    for ch in chars:
        lit = _literal(ch, ci)
        if lit is None:
            return None
        out.add(lit)
    return frozenset(out)


def _literal(text: str, ci: bool) -> Lit | None:
    if "\n" in text:
        return None
    if ci:
        if not text.isascii():
            return None
        return (text.lower(), True)
    return (text, False)


def _score(s: frozenset[Lit]) -> tuple[int, int]:
    """Higher is more selective: longest shortest-literal, then fewest literals."""
    return (min(len(t) for t, _ in s), -len(s))


def _seq(items, flags: int) -> list[frozenset[Lit]]:
    """Required-literal sets for a concatenation: a match contains a member of EACH."""
    ci = bool(flags & re.IGNORECASE)
    sets: list[frozenset[Lit]] = []
    run: list[str] = []

    def flush() -> None:
        if run:
            lit = _literal("".join(run), ci)
            if lit is not None:
                sets.append(frozenset({lit}))
            run.clear()

    for op, av in items:
        if op is _c.LITERAL:
            ch = chr(av)
            if ch == "\n" or (ci and not ch.isascii()):
                flush()
                continue
            run.append(ch)
            continue
        flush()
        s = _node(op, av, flags)
        if s is not None:
            sets.append(s)
    flush()
    return sets


def _best(sets: list[frozenset[Lit]]) -> frozenset[Lit] | None:
    return max(sets, key=_score) if sets else None


def _node(op, av, flags: int) -> frozenset[Lit] | None:
    """One required-literal set for a single parse node (None = no requirement)."""
    ci = bool(flags & re.IGNORECASE)
    if op is _c.LITERAL:
        lit = _literal(chr(av), ci)
        return frozenset({lit}) if lit is not None else None
    if op is _c.IN:
        return _class_chars(av, ci)
    if op is _c.SUBPATTERN:
        _group, add_flags, del_flags, sub = av
        return _best(_seq(sub, (flags | add_flags) & ~del_flags))
    if op is getattr(_c, "ATOMIC_GROUP", None):
        return _best(_seq(av, flags))
    if op in (_c.MAX_REPEAT, _c.MIN_REPEAT) or op is getattr(_c, "POSSESSIVE_REPEAT", None):
        lo, _hi, sub = av
        if lo < 1:
            return None
        return _best(_seq(sub, flags))
    if op is _c.BRANCH:
        _none, alts = av
        union: set[Lit] = set()
        for alt in alts:
            s = _best(_seq(alt, flags))
            if s is None:
                return None
            union |= s
        return frozenset(union)
    # AT, ASSERT, ASSERT_NOT, ANY, NOT_LITERAL, GROUPREF, CATEGORY, ...: none.
    return None


@lru_cache(maxsize=4096)
def _required_sets(pattern_src: str, flags: int) -> tuple[frozenset[Lit], ...] | None:
    try:
        parsed = _p.parse(pattern_src, flags)
    except Exception:  # noqa: BLE001 - never let the optimization break a scan
        return None
    sets = _seq(list(parsed), parsed.state.flags)
    if not sets:
        return None
    sets.sort(key=_score, reverse=True)
    # The best set always; another only when it is selective enough to pay for its scan.
    return tuple(s for k, s in enumerate(sets[:_MAX_SETS])
                 if k == 0 or _score(s)[0] >= _MIN_EXTRA_LEN)


def required_literals(pattern: re.Pattern[str]) -> tuple[frozenset[Lit], ...] | None:
    """Sets of literals such that any match of ``pattern`` contains at least one member
    of every set. ``None`` when no requirement could be derived."""
    if not isinstance(pattern.pattern, str):
        return None
    return _required_sets(pattern.pattern, pattern.flags)


_ZERO_WIDTH = (_c.AT, _c.ASSERT, _c.ASSERT_NOT)


def _prefix(items, flags: int) -> frozenset[Lit] | None:
    """Literals one of which every match STARTS with (None = unknown). Zero-width
    assertions before the first character are skipped: they do not move the start."""
    ci = bool(flags & re.IGNORECASE)
    run: list[str] = []
    for op, av in items:
        if op in _ZERO_WIDTH and not run:
            continue
        if op is _c.LITERAL:
            ch = chr(av)
            if ch != "\n" and not (ci and not ch.isascii()):
                run.append(ch)
                continue
        if run:
            break
        if op is _c.SUBPATTERN:
            _group, add_flags, del_flags, sub = av
            return _prefix(sub, (flags | add_flags) & ~del_flags)
        if op is getattr(_c, "ATOMIC_GROUP", None):
            return _prefix(av, flags)
        if op in (_c.MAX_REPEAT, _c.MIN_REPEAT) or op is getattr(_c, "POSSESSIVE_REPEAT", None):
            lo, _hi, sub = av
            return _prefix(sub, flags) if lo >= 1 else None
        if op is _c.BRANCH:
            union: set[Lit] = set()
            for alt in av[1]:
                got = _prefix(alt, flags)
                if got is None:
                    return None
                union |= got
            return frozenset(union)
        if op is _c.IN:
            return _class_chars(av, ci)
        return None
    if not run:
        return None
    lit = _literal("".join(run), ci)
    return frozenset({lit}) if lit is not None else None


@lru_cache(maxsize=4096)
def _prefixes(pattern_src: str, flags: int) -> frozenset[Lit] | None:
    try:
        parsed = _p.parse(pattern_src, flags)
    except Exception:  # noqa: BLE001 - never let the optimization break a scan
        return None
    return _prefix(list(parsed), parsed.state.flags)


def match_prefixes(pattern: re.Pattern[str]) -> frozenset[Lit] | None:
    """Literals such that every match of ``pattern`` begins with one of them."""
    if not isinstance(pattern.pattern, str):
        return None
    return _prefixes(pattern.pattern, pattern.flags)


class AnyOf:
    """A rule that fires when ANY of several regexes matches: its lines are the union.
    ``first`` is the rule's own regex (what the scan loop searches with)."""

    __slots__ = ("first", "patterns")

    def __init__(self, *patterns: re.Pattern[str]) -> None:
        self.first = patterns[0]
        self.patterns = patterns

    def search(self, text: str) -> re.Match[str] | None:
        for p in self.patterns:
            m = p.search(text)
            if m:
                return m
        return None


# Word tokens of the normalized text, for the quick "can this literal be here?" test.
_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_NON_ASCII_RE = re.compile(r"[^\x00-\x7f]")


@lru_cache(maxsize=4096)
def _token_runs(literal: str) -> tuple[tuple[str, bool, bool], ...]:
    """The ``[a-z0-9_]`` runs of a lowercased ASCII literal, each with whether a
    non-token character bounds it inside the literal on the left / right."""
    return tuple((m.group(), m.start() > 0, m.end() < len(literal))
                 for m in _TOKEN_RE.finditer(literal))


class LineFilter:
    """Per-file index: which lines can a given regex match on?"""

    __slots__ = ("_text", "_norm", "_tokens", "_joined", "_runs", "_non_ascii",
                 "_lit_lines", "_pat_lines")

    def __init__(self, text: str) -> None:
        self._text = text
        self._norm: str | None = None
        self._tokens: set[str] | None = None
        self._joined = ""
        self._runs: dict[tuple[str, bool, bool], bool] = {}
        self._non_ascii: set[str] | None = None
        self._lit_lines: dict[Lit, frozenset[int]] = {}
        self._pat_lines: dict[tuple[str, int], frozenset[int] | None] = {}

    def _haystack(self, ci: bool) -> str:
        if not ci:
            return self._text
        if self._norm is None:
            self._norm = normalize(self._text)
        return self._norm

    def _may_contain(self, literal: str) -> bool:
        """False only when an ASCII ``literal`` (lowercased) cannot occur in the
        normalized text. A token-character run of the literal that a non-token
        character bounds on the left must START a token of the text, one bounded on the
        right must END one, one bounded on both sides must BE one, and any run is
        inside some token. Checked against the text's distinct tokens, which is much
        shorter than the text, so most absent literals cost no scan of the file.
        (A case-sensitive literal in the text is also in the normalized text,
        lowercased: the ASCII characters of a match lowercase one for one.)"""
        if self._tokens is None:
            self._tokens = set(_TOKEN_RE.findall(self._haystack(True)))
            self._joined = "\0" + "\0".join(self._tokens) + "\0"
        for key in _token_runs(literal.lower()):
            ok = self._runs.get(key)
            if ok is None:
                run, left, right = key
                if left and right:
                    ok = run in self._tokens
                elif left:
                    ok = "\0" + run in self._joined
                elif right:
                    ok = run + "\0" in self._joined
                else:
                    ok = run in self._joined
                self._runs[key] = ok
            if not ok:
                return False
        return True

    def _may_contain_non_ascii(self, literal: str) -> bool:
        """False when a non-ASCII character of a case-sensitive ``literal`` is absent
        from the text (one pass collects the text's non-ASCII characters)."""
        if self._non_ascii is None:
            text = self._text
            self._non_ascii = set() if text.isascii() else set(_NON_ASCII_RE.findall(text))
        return all(ch in self._non_ascii for ch in literal if not ch.isascii())

    def _lines_with(self, lit: Lit) -> frozenset[int]:
        got = self._lit_lines.get(lit)
        if got is not None:
            return got
        needle, ci = lit
        if not (self._may_contain(needle) if needle.isascii()
                else ci or self._may_contain_non_ascii(needle)):
            got = frozenset()
            self._lit_lines[lit] = got
            return got
        hay = self._haystack(ci)
        found: list[int] = []
        pos = hay.find(needle)
        line = 0
        last = 0
        while pos != -1:
            line += hay.count("\n", last, pos)
            found.append(line)
            nl = hay.find("\n", pos)
            if nl == -1:
                break
            line += 1
            last = nl + 1
            pos = hay.find(needle, last)
        got = frozenset(found)
        self._lit_lines[lit] = got
        return got

    def lines(self, pattern: re.Pattern[str] | AnyOf) -> frozenset[int] | None:
        """0-based indices of the lines (``text.split("\\n")``) where ``pattern`` can
        match, or ``None`` when every line has to be tried."""
        if isinstance(pattern, AnyOf):
            union: set[int] = set()
            for p in pattern.patterns:
                got = self.lines(p)
                if got is None:
                    return None
                union |= got
            return frozenset(union)
        key = (pattern.pattern, pattern.flags)
        if key in self._pat_lines:
            return self._pat_lines[key]
        sets = required_literals(pattern)
        result: frozenset[int] | None
        if sets is None:
            result = None
        else:
            result = None
            for s in sets:
                u: frozenset[int] = frozenset().union(*(self._lines_with(lit) for lit in s))
                result = u if result is None else (result & u)
                if not result:
                    break
        self._pat_lines[key] = result
        return result

    def may_match_a_line(self, pattern: re.Pattern[str]) -> bool:
        """False only when ``pattern.search(line)`` finds nothing on every line."""
        got = self.lines(pattern)
        return got is None or bool(got)

    def lines_containing(self, text: str) -> frozenset[int]:
        """0-based indices of the lines that contain ``text`` (case-sensitive)."""
        return self._lines_with((text, False))

    def may_search(self, pattern: re.Pattern[str]) -> bool:
        """False only when ``pattern.search(text)`` over the WHOLE text cannot match: a
        required literal set has no member anywhere in it. (A whole-text match may
        span lines, so this checks presence, not a common line.)"""
        sets = required_literals(pattern)
        if sets is None:
            return True
        return all(any(self._lines_with(lit) for lit in s) for s in sets)

    def search(self, pattern: re.Pattern[str]) -> re.Match[str] | None:
        """Exactly ``pattern.search(text)``, faster. None at once when a required
        literal is absent. When every match must begin with one of a few literals, the
        regex is tried only where those literals occur, leftmost first: ``search`` tries
        each start left to right and returns the first that matches, and
        ``match(text, pos)`` sees the text before ``pos`` (lookbehind, ``\\b``) and
        anchors ``^`` at the real start, just as ``search`` does at that position."""
        if not self.may_search(pattern):
            return None
        text = self._text
        prefixes = match_prefixes(pattern)
        if prefixes is None or (any(ci for _t, ci in prefixes)
                                and len(self._haystack(True)) != len(text)):
            return pattern.search(text)
        # Positions: every (overlapping) occurrence of a prefix. A case-insensitive
        # prefix is found in the normalized text, which has the same offsets when it has
        # the same length (each character then maps to exactly one).
        limit = len(text) // 64 + 16  # beyond this many starts a plain search is cheaper
        starts: set[int] = set()
        for needle, ci in prefixes:
            hay = self._haystack(ci)
            pos = hay.find(needle)
            while pos != -1:
                starts.add(pos)
                if len(starts) > limit:
                    return pattern.search(text)
                pos = hay.find(needle, pos + 1)
        for pos in sorted(starts):
            m = pattern.match(text, pos)
            if m:
                return m
        return None

    def plan(self, rules, skip=None) -> LinePlan:
        """The ordered sub-list of ``rules`` ((name, pattern, ...) tuples) to try on
        each line: a rule is left out only on lines where its regex cannot match, and
        everywhere when ``skip(rule)`` says so."""
        return LinePlan(self, rules, skip)


class LinePlan:
    """``table.get(idx, default)`` -> the rules (in their original order) whose regex
    can match line ``idx``. Rules with no derivable requirement are on every line
    (``default``); ``always_active`` says whether there are any."""

    __slots__ = ("table", "default", "always_active")

    def __init__(self, lf: LineFilter, rules, skip=None) -> None:
        always: list = []
        by_line: dict[int, list] = {}
        for i, rule in enumerate(rules):
            if skip is not None and skip(rule):
                continue
            cand = lf.lines(rule[1])
            if cand is None:
                always.append((i, rule))
                continue
            for idx in cand:
                by_line.setdefault(idx, []).append((i, rule))
        self.default = tuple(r for _i, r in always)
        self.always_active = bool(always)
        if always:
            self.table = {idx: tuple(r for _i, r in sorted(lst + always, key=_first))
                          for idx, lst in by_line.items()}
        else:
            # Rules were visited in order, so each list is already ordered.
            self.table = {idx: tuple(r for _i, r in lst) for idx, lst in by_line.items()}


def _first(pair: tuple) -> int:
    return pair[0]
