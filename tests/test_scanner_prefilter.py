"""The literal prefilter (src/scanner/prefilter.py) only skips searches that cannot match.

``_scan_content`` tries a rule's regex only on the lines ``LineFilter.lines`` returns,
and runs whole-file checks through ``LineFilter.search``. Findings stay identical only
if both are exact; these tests check that against every rule regex the scanner uses,
on real text (this repo's scanner tests and sources, which are full of attack strings)
and on case-folded / non-ASCII variants of it.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from src.scanner import patterns as pat
from src.scanner import prefilter as pf
from src.scanner import scan as sc
from src.scanner.credential_flow import _CREDENTIAL_HINT_RE
from src.scanner.prefilter import (
    AnyOf,
    LineFilter,
    match_prefixes,
    normalize,
    required_literals,
)

_ROOT = Path(__file__).resolve().parents[1]

_GROUPS = [
    "SECRET_PATTERNS", "UNSAFE_EXEC_PATTERNS", "INSECURE_DESERIALIZATION_PATTERNS",
    "FS_ACCESS_PATTERNS", "EXFILTRATION_PATTERNS", "DYNAMIC_REMOTE_LOAD_PATTERNS",
    "INVISIBLE_UNICODE_PATTERNS", "PROMPT_INJECTION_PATTERNS",
    "METADATA_INJECTION_PATTERNS", "OBFUSCATION_PATTERNS", "AUTH_POSITIVE_PATTERNS",
]
_WHOLE_FILE = [
    pat.NET_READ_RE, pat.EXEC_SINK_RE, pat.DECODE_SINK_RE, pat.SSRF_TOOL_SURFACE_RE,
    pat.SSRF_URL_INPUT_RE, pat.SSRF_DYNAMIC_FETCH_RE, pat.SSRF_GUARD_RE, pat.UNTRUSTED_INPUT_RE,
    pat.OUTBOUND_SEND_RE, pat.SENSITIVE_READ_RE, pat.FILE_READ_RE, sc._CLI_IMPORT_RE,
    sc._EVAL_METHOD_CALL_RE, _CREDENTIAL_HINT_RE,
]


def _rule_patterns() -> list[re.Pattern[str]]:
    out = [rule[1] for g in _GROUPS for rule in getattr(pat, g)]
    return out + _WHOLE_FILE + [sc._js_cp_call_re("const cp = require('child_process')")]


def _variants(text: str) -> list[str]:
    """The text, plus copies with the characters ``re.IGNORECASE`` folds onto ASCII
    letters, swapped case, and non-ASCII / tag / bidi characters mixed in."""
    return [
        text,
        text.swapcase(),
        text.replace("k", "\u212a").replace("s", "\u017f"),
        text.replace("i", "\u0130").replace("I", "\u0131"),
        text.replace(" ", " \u200b").replace("(", "\U000e0041("),
        text.replace("=", "\u202e=").upper(),
    ]


@pytest.fixture(scope="module")
def corpus() -> list[str]:
    paths = sorted((_ROOT / "tests").glob("test_scanner_*.py")) + sorted(
        (_ROOT / "tests").glob("test_precision*.py")) + [
        _ROOT / "src" / "scanner" / "patterns.py",
        _ROOT / "src" / "scanner" / "exec_classify.py",
    ]
    texts = [p.read_text(encoding="utf-8") for p in paths if p.name != Path(__file__).name]
    return [v for t in texts for v in _variants(t)]


def test_fold_table_covers_every_ignorecase_ascii_equivalent():
    """Every character IGNORECASE matches to an ASCII character normalizes to exactly
    that character, lowercased (so a case-insensitive literal keeps its length)."""
    ascii_ci = re.compile(r"(?i)[\x00-\x7f]")
    for cp in range(0x80, 0x110000):
        ch = chr(cp)
        if not ascii_ci.fullmatch(ch):
            continue
        targets = [chr(a) for a in range(128)
                   if re.fullmatch("(?i)" + re.escape(chr(a)), ch)]
        assert targets, hex(cp)
        assert all(normalize(ch) == t.lower() for t in targets), hex(cp)
    for a in range(128):
        assert normalize(chr(a)) == chr(a).lower()


def test_every_rule_regex_has_a_literal_requirement():
    # Not required for correctness (a rule without one runs on every line), but a rule
    # that loses its requirement silently gives back the speed-up.
    missing = [p.pattern for p in _rule_patterns() if required_literals(p) is None]
    assert missing == []


def test_candidate_lines_contain_every_matching_line(corpus):
    for text in corpus:
        lines = text.split("\n")
        lf = LineFilter(text)
        for p in _rule_patterns():
            cand = lf.lines(p)
            if cand is None:
                continue
            for i, ln in enumerate(lines):
                if p.search(ln):
                    assert i in cand, (p.pattern, ln)


def test_whole_text_search_is_identical(corpus):
    for text in corpus:
        lf = LineFilter(text)
        for p in _rule_patterns():
            want = p.search(text)
            got = lf.search(p)
            assert (want is None) == (got is None), p.pattern
            if want is not None:
                assert (got.span(), got.groups()) == (want.span(), want.groups()), p.pattern
            if not lf.may_search(p):
                assert want is None


def test_lines_containing_and_anyof():
    text = "a\nx ag-scan:ignore\nexec(cmd)\nproc.spawn(x)"
    lf = LineFilter(text)
    assert lf.lines_containing("ag-scan:ignore") == {1}
    alias = sc._js_cp_call_re("const proc = require('child_process')")
    rule = AnyOf(re.compile(r"(?<![.\w$])exec\s*\("), alias)
    assert lf.lines(rule) == {2, 3}
    assert rule.search("proc.spawn(x)") is not None
    assert rule.first.pattern == r"(?<![.\w$])exec\s*\("


@pytest.mark.parametrize(("pattern", "expected"), [
    (r"abc", {("abc", False)}),
    (r"(?i)ABC", {("abc", True)}),
    (r"(?:foo|bar)\s*\(", {("foo", False), ("bar", False)}),
    (r"x?y", {("y", False)}),
    (r"(?:foo|)z", {("z", False)}),
    (r"[\u200b\u200c]", {("\u200b", False), ("\u200c", False)}),
])
def test_required_literals(pattern, expected):
    sets = required_literals(re.compile(pattern))
    assert sets is not None and sets[0] == expected


@pytest.mark.parametrize("pattern", [
    r"x?", r"(?:foo|)", r"[^a]", r"\w+", r"(?:a|\d)", r"(?i)\u00e9",
])
def test_no_requirement(pattern):
    assert required_literals(re.compile(pattern)) is None


@pytest.mark.parametrize(("pattern", "expected"), [
    (r"(?<![.\w])eval\s*\(", {("eval", False)}),
    (r"(?:foo|ba(?:r|z))q", {("foo", False), ("ba", False)}),
    (r"(?i)Fetch\s*\(", {("fetch", True)}),
    (r"\bimport\b", {("import", False)}),
])
def test_match_prefixes(pattern, expected):
    assert match_prefixes(re.compile(pattern)) == expected


@pytest.mark.parametrize("pattern", [r"x?y", r"\s*foo", r"(?:a|\w)b", r".foo"])
def test_no_prefix(pattern):
    assert match_prefixes(re.compile(pattern)) is None


def test_token_index_never_hides_a_present_literal():
    # A literal's runs are checked as token prefix / suffix / whole token / substring.
    text = "x = os.environ['K']\nsubprocess.run(a)\nfoo_exec(b)\nA.B\n"
    lf = LineFilter(text)
    for lit, line in [("os.environ", 0), ("subprocess.", 1), ("exec", 2), ("_exec(", 2),
                      ("a.b", 3)]:
        assert line in lf._lines_with((lit, True)), lit
    assert lf._lines_with(("process.env", True)) == frozenset()
    assert lf._lines_with(("xec(b", False)) == {2}


def test_scan_content_skips_nothing_on_a_suppressed_line():
    # A suppression marker is counted even on a line no rule can match.
    content = "x = 1  # ag-scan:ignore\ny = 2\n"
    _findings, _pos, suppressed = sc._scan_content(content, "pkg/a.py")
    assert suppressed == 1


def test_module_constants():
    assert pf._MAX_SETS >= 1 and pf._MIN_EXTRA_LEN >= 1
