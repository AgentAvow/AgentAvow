#!/usr/bin/env python3
"""Lint the live website copy for AI-slop before deploy.

Extracts user-facing prose (JSX text nodes + prose string literals) from the live
rebrand tree and runs the SAME no-slop detector the marketing bot uses. Static site
copy isn't generated, so nothing gates it at runtime — this is that gate.

Usage:
    python3 scripts/lint_website_copy.py           # warn (exit 0), prints findings
    python3 scripts/lint_website_copy.py --strict  # exit 1 if any slop found (CI gate)

Heuristic extraction — a few false positives are fine (they're for review). Skips
code-y strings (className values, urls, identifiers).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.marketing.content.ai_tells import check as check_ai_tells  # noqa: E402

REBRAND = ROOT / "web" / "src" / "rebrand"

# A "prose" fragment: ≥4 words, has spaces, not obviously code/markup/url/class list.
_CODEY = re.compile(r"(=>|https?://|className|[{}<>]|::|\bimport\b|\breturn\b|_[a-z]+-)")
_JSX_TEXT = re.compile(r">([^<>{}]+)<")
_STR_LIT = re.compile(r"""["'`]([^"'`\n]{16,240})["'`]""")


def _is_prose(s: str) -> bool:
    s = s.strip()
    if len(s.split()) < 4 or "  " in s.replace("\n", " "):
        pass
    if _CODEY.search(s):
        return False
    letters = sum(c.isalpha() for c in s)
    return len(s.split()) >= 4 and letters >= len(s) * 0.5


def _fragments(text: str) -> set[str]:
    out: set[str] = set()
    for m in _JSX_TEXT.finditer(text):
        frag = m.group(1).strip()
        if _is_prose(frag):
            out.add(frag)
    for m in _STR_LIT.finditer(text):
        frag = m.group(1).strip()
        if _is_prose(frag):
            out.add(frag)
    return out


# Whole-post structural metrics that false-positive on single UI sentences — a lone
# UI string with one em-dash isn't "high density." Only phrase/word-level tells count here.
_IGNORE = {"high_em_dash_density", "no_short_sentence", "high_copula_avoidance"}


def main() -> int:
    strict = "--strict" in sys.argv
    findings: list[tuple[str, str, list[str]]] = []
    for path in sorted(REBRAND.rglob("*.tsx")):
        try:
            text = path.read_text()
        except Exception:
            continue
        for frag in _fragments(text):
            r = check_ai_tells(frag, platform="website", strict=True)
            meaningful = [x for x in r.reasons if x not in _IGNORE]
            if meaningful:
                findings.append((str(path.relative_to(ROOT)), frag, meaningful))

    if not findings:
        print("✓ website copy: no AI-slop detected")
        return 0
    print(f"⚠ website copy: {len(findings)} possible slop fragment(s):\n")
    for rel, frag, reasons in findings:
        print(f"  {rel}")
        print(f"    “{frag[:120]}”")
        print(f"    → {', '.join(reasons)}\n")
    if strict:
        print("Failing (--strict). Fix or reword the above before deploy.")
        return 1
    print("(warning only — run with --strict to gate a deploy on this)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
