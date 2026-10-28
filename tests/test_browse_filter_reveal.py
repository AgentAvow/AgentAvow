"""Regression: Browse filters must always show their results.

A ``RevealStagger`` list used ``whileInView`` with ``once``, so rows mounted after
the first reveal (a filter that returned more rows than the previous view) stayed
at opacity 0 until a full page reload. There is no frontend test runner, so this
pins the two parts of the fix in source.
"""
from __future__ import annotations

import re
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "web" / "src" / "rebrand"


def test_reveal_stagger_children_animate_after_first_reveal():
    src = (WEB / "components" / "motion.tsx").read_text()
    body = src[src.index("export function RevealStagger"):]
    body = body[: body.index("\n}\n")]
    assert "onAnimationComplete={() => setRevealed(true)}" in body
    assert "animate={revealed ? 'show' : undefined}" in body


def test_browse_list_remounts_on_every_filter():
    src = (WEB / "pages" / "Browse.tsx").read_text()
    m = re.search(r"<RevealStagger key=\{\[([^\]]+)\]\.join", src)
    assert m, "Browse's RevealStagger must be keyed on the full filter set"
    keyed = {k.strip() for k in m.group(1).split(",")}
    query = re.search(r"queryKey: \['rebrand-catalog', ([^\]]+)\]", src)
    assert query
    filters = {k.strip() for k in query.group(1).split(",")}
    assert filters <= keyed, f"filters missing from the list key: {filters - keyed}"
