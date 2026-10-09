"""Line extents of inline Rust test code (``#[cfg(test)] mod … { }``, ``#[test] fn``).

Rust keeps unit tests in the same file as the code they test, inside a module gated by
``#[cfg(test)]``. That module is compiled only for ``cargo test``: it is never part of
the library or binary a consumer builds. A key fixture or a ``Command::new`` inside it
is test code, the same as a file under ``tests/``.

The extent is found by brace matching on a *masked* copy of the source in which
comments, string literals (including raw strings ``r#"…"#`` and byte strings) and char
literals are blanked out, so a ``{`` inside a PEM fixture or a doc comment never moves
the match. Anything that can't be parsed cleanly (an unbalanced brace, an attribute
that never reaches its item) yields no extent: the findings stay shipped (fail closed).
"""
from __future__ import annotations

import re

# A test-only attribute: ``#[test]``, ``#[tokio::test]``, ``#[tokio::test(flavor = …)]``,
# ``#[cfg(test)]`` and ``#[cfg(all(test, …))]``. ``cfg(any(test, …))`` is NOT test-only
# (it also compiles under the other predicate) and is left alone.
_TEST_ATTR_RE = re.compile(
    r"""^\#\[\s*(?:
        (?:[A-Za-z_][\w]*\s*::\s*)*test\s*(?:\(.*\))?      # #[test], #[tokio::test(...)]
      | cfg\s*\(\s*test\s*\)                                # #[cfg(test)]
      | cfg\s*\(\s*all\s*\(\s*test\s*(?:,.*)?\)\s*\)        # #[cfg(all(test, ...))]
    )\s*\]$""",
    re.VERBOSE | re.DOTALL,
)
_INNER_CFG_TEST_RE = re.compile(r"#!\[\s*cfg\s*\(\s*test\s*\)\s*\]")


def mask_rust(src: str) -> str | None:
    """Return ``src`` with comments, strings and char literals replaced by spaces
    (newlines kept, so offsets and line numbers line up). None if a literal or block
    comment never closes."""
    out = list(src)
    n = len(src)
    i = 0

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
            continue
        if c == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            if depth:
                return None
            blank(i, j)
            i = j
            continue
        prev_ident = i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_")
        # Raw (byte) string: r"…", r#"…"#, br#"…"#
        if not prev_ident and (c == "r" or (c == "b" and nxt == "r")):
            j = i + (2 if c == "b" else 1)
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                close = '"' + "#" * hashes
                end = src.find(close, j + 1)
                if end == -1:
                    return None
                end += len(close)
                blank(i, end)
                i = end
                continue
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                return None
            blank(i, j + 1)
            i = j + 1
            continue
        if c == "'":
            # Char literal ('x', '\n', '\'', '\u{1F600}') vs a lifetime ('a, 'static).
            if nxt == "\\":
                j = src.find("'", i + 2 if src[i + 2:i + 3] != "'" else i + 3)
                if j == -1:
                    return None
                blank(i, j + 1)
                i = j + 1
                continue
            if i + 2 < n and src[i + 2] == "'":
                blank(i, i + 3)
                i += 3
                continue
        i += 1
    return "".join(out)


def _match_close(masked: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index just past the bracket matching ``masked[start]`` (== open_ch); -1 if none."""
    depth = 0
    for k in range(start, len(masked)):
        ch = masked[k]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return k + 1
    return -1


def rust_test_lines(src: str) -> set[int]:
    """0-based line indexes that sit inside test-only Rust code."""
    masked = mask_rust(src)
    if masked is None:
        return set()
    n_lines = src.count("\n") + 1
    if _INNER_CFG_TEST_RE.search(masked):
        return set(range(n_lines))
    spans: list[tuple[int, int]] = []
    pos = 0
    while True:
        a = masked.find("#[", pos)
        if a == -1:
            break
        attr_end = _match_close(masked, a + 1, "[", "]")
        if attr_end == -1:
            break
        pos = attr_end
        attr = masked[a:attr_end]
        if not _TEST_ATTR_RE.match(attr):
            continue
        # Walk to the item the attribute applies to: skip further attributes, then the
        # first `{` (a block item: mod/fn/impl) or `;` (`mod tests;`, a `use`) at
        # bracket depth 0 ends the search.
        k = attr_end
        end = -1
        while k < len(masked):
            ch = masked[k]
            if ch == "#" and masked.startswith("#[", k):
                k2 = _match_close(masked, k + 1, "[", "]")
                if k2 == -1:
                    break
                k = k2
                continue
            if ch in "([":
                k2 = _match_close(masked, k, ch, ")" if ch == "(" else "]")
                if k2 == -1:
                    break
                k = k2
                continue
            if ch == ";":
                end = k + 1
                break
            if ch == "{":
                end = _match_close(masked, k, "{", "}")
                break
            if ch == "}":  # closed the enclosing scope first: malformed, give up
                break
            k += 1
        if end == -1:
            continue
        spans.append((a, end))
        pos = max(pos, end)
    lines: set[int] = set()
    for a, b in spans:
        first = masked.count("\n", 0, a)
        last = masked.count("\n", 0, b)
        lines.update(range(first, last + 1))
    return lines
