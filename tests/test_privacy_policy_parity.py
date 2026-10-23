"""The privacy policy exists twice: the no-JavaScript page (src/api/legal_router.py, what
crawlers and OpenAI's automated policy check read) and the in-app page (Legal.tsx). They
must say the same thing, and must keep the commitments the ChatGPT/Claude listings rely on.
"""
from __future__ import annotations

import json
import pathlib
import re

from src.api.legal_router import _PRIVACY_CLAUSES

LEGAL_TSX = pathlib.Path(__file__).resolve().parents[1] / "web/src/rebrand/pages/Legal.tsx"


def _tsx_privacy() -> list[tuple[str, str]]:
    src = LEGAL_TSX.read_text(encoding="utf-8")
    block = src[src.index("const PRIVACY: Clause[] = ["):src.index("const DMCA: Clause[]")]
    return [(json.loads(h), json.loads(b))
            for h, b in re.findall(r'\{ h: ("(?:[^"\\]|\\.)*"), html: ("(?:[^"\\]|\\.)*") \}', block)]


def test_site_and_no_js_page_say_the_same_thing():
    assert _tsx_privacy() == _PRIVACY_CLAUSES


def test_connector_section_and_key_commitments_are_present():
    text = " ".join(b for _, b in _PRIVACY_CLAUSES)
    assert any("connector" in h.lower() for h, _ in _PRIVACY_CLAUSES)
    for phrase in ("do not read or store", "read-only", "less than 30 days",
                   "do not sell personal", "train AI models", "under 16",
                   "privacy@agentavow.com"):
        assert phrase in text, phrase
    assert "—" not in text  # no em dashes in outbound copy
