"""The short adoption-unit table is defined three times (Python, the site's TypeScript,
the MCP trust card's inline JS). These tests keep the three identical and cover every
unit the adoption builders emit."""
from __future__ import annotations

import json
import re
from pathlib import Path

from src.adoption_units import SHORT_UNITS, short_unit

ROOT = Path(__file__).resolve().parents[1]

# Every unit `_surface_adoption_axes` (src/api/public_scan_router.py) can emit.
EMITTED_UNITS = {
    "downloads/wk", "downloads/yr", "downloads/90d", "downloads/mo", "downloads",
    "dependents", "likes", "pulls", "stars", "stars (linked repo)", "installs",
}

EXPECTED = {
    "downloads/wk": "dl/wk",
    "downloads/mo": "dl/mo",
    "downloads/yr": "dl/yr",
    "downloads/90d": "dl/90d",
    "downloads": "dl",
    "stars": "★",
    "stars (linked repo)": "★",
    "pulls": "pulls",
    "dependents": "deps",
    "installs": "installs",
    "likes": "likes",
}


def _ts_table() -> dict[str, str]:
    src = (ROOT / "web/src/rebrand/lib/adoptionUnit.ts").read_text()
    body = src[src.index("SHORT_UNITS"):src.index("}", src.index("SHORT_UNITS"))]
    out = {}
    for m in re.finditer(r"^\s*(?:'([^']+)'|([A-Za-z0-9_]+)):\s*'([^']*)',", body, re.M):
        out[m.group(1) or m.group(2)] = m.group(3)
    return out


def _card_table() -> dict[str, str]:
    from src.bridges.mcp_app_view import TRUST_CARD_HTML
    m = re.search(r"var SHORT_UNITS=(\{.*?\});", TRUST_CARD_HTML)
    assert m, "trust card has no SHORT_UNITS table"
    return json.loads(m.group(1))


def test_python_table_is_the_expected_map():
    assert SHORT_UNITS == EXPECTED


def test_every_emitted_unit_has_a_short_form():
    assert EMITTED_UNITS <= set(SHORT_UNITS)


def test_typescript_twin_matches():
    assert _ts_table() == SHORT_UNITS


def test_trust_card_twin_matches():
    assert _card_table() == SHORT_UNITS


def test_short_unit_fallbacks():
    assert short_unit(None) == ""
    assert short_unit("  ") == ""
    assert short_unit("Downloads/wk") == "dl/wk"
    assert short_unit("downloads/day") == "dl/day"  # unknown unit: generic shortening
    assert short_unit("forks") == "forks"
