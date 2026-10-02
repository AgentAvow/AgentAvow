"""src/trust_tiers.py — the six trust tiers, and every copy of the table that cannot
import it (the GitHub Action's bash, the Claude Code plugin gate, the frontend)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from src.trust_tiers import (
    TIER_FLOORS,
    TIERS,
    TRUST_TIERS,
    recommended_limits,
    tier_for_score,
    tiers_js_table,
    trust_color,
    trust_tier_value,
    trust_word,
)

ROOT = Path(__file__).resolve().parent.parent

# The released plugin keys off these exact values and floors — they must not change.
EXPECTED_FLOORS = {
    "verified": 96, "trusted": 81, "standard": 51, "minimal": 31, "restricted": 11, "blocked": 0,
}
EXPECTED_WORDS = {
    "verified": "Verified", "trusted": "Trusted", "standard": "Standard",
    "minimal": "Minimal", "restricted": "Restricted", "blocked": "Blocked",
}


def test_table_is_the_six_api_tiers_at_the_pinned_floors():
    assert TIER_FLOORS == EXPECTED_FLOORS
    assert {t.value: t.display for t in TIERS} == EXPECTED_WORDS
    # highest first, strictly descending, so the first floor cleared wins
    floors = [t.floor for t in TIERS]
    assert floors == sorted(floors, reverse=True) and len(set(floors)) == 6


def test_legacy_tuple_shape_is_unchanged():
    """public_scan_router.TRUST_TIERS: (min_score, name, rpm, tokens, confirm), -1 = unlimited."""
    assert TRUST_TIERS == [
        (96, "verified", -1, -1, False),
        (81, "trusted", 60, 8192, False),
        (51, "standard", 30, 4096, False),
        (31, "minimal", 15, 2048, True),
        (11, "restricted", 5, 1024, True),
        (0, "blocked", 0, 0, True),
    ]
    from src.api import public_scan_router
    assert public_scan_router.TRUST_TIERS is TRUST_TIERS
    assert public_scan_router._compute_tier(85) == {
        "tier": "trusted",
        "recommended_limits": {
            "requests_per_minute": 60, "max_tokens_per_call": 8192,
            "require_user_confirmation": False,
        },
    }
    assert recommended_limits(100) == {
        "requests_per_minute": None, "max_tokens_per_call": None,
        "require_user_confirmation": False,
    }


@pytest.mark.parametrize("score,value", [
    (100, "verified"), (96, "verified"), (95, "trusted"), (81, "trusted"), (80, "standard"),
    (51, "standard"), (50, "minimal"), (31, "minimal"), (30, "restricted"), (11, "restricted"),
    (10, "blocked"), (0, "blocked"), (-5, "blocked"), (None, "blocked"), ("x", "blocked"),
    (85.9, "trusted"),
])
def test_boundaries(score, value):
    assert trust_tier_value(score) == value
    assert trust_word(score) == EXPECTED_WORDS[value]
    assert tier_for_score(score).value == value


def test_six_distinct_colours_in_both_variants():
    dark = [t.color for t in TIERS]
    light = [t.color_light for t in TIERS]
    assert len(set(dark)) == 6 and len(set(light)) == 6
    assert trust_color(97) == "#16A34A" and trust_color(97, light=True) == "#166534"
    # the previous five-band hues are kept for the tiers they map onto
    assert trust_color(85) == "#22C55E" and trust_color(70) == "#5BBF3A"
    assert trust_color(45) == "#F59E0B" and trust_color(20) == "#F97316"
    assert trust_color(5) == "#EF4444"
    for hexv in dark + light:
        assert re.fullmatch(r"#[0-9A-F]{6}", hexv), hexv


def test_badge_style_reexports_the_helper():
    from src.api import badge_style
    assert badge_style.trust_word is trust_word and badge_style.trust_color is trust_color


def test_js_table_feeds_the_mcp_app_view():
    from src.bridges.mcp_app_view import TRUST_CARD_HTML
    js = tiers_js_table()
    assert js.startswith('[["Verified",96,"#16A34A",')
    assert js in TRUST_CARD_HTML and "__TRUST_TIERS_JS__" not in TRUST_CARD_HTML
    assert "Caution" not in TRUST_CARD_HTML


def test_github_action_bash_thresholds_agree():
    """github-action/scan.sh cannot import Python: parse its `-ge N ... TIER="Word"` chain."""
    sh = (ROOT / "github-action" / "scan.sh").read_text()
    pairs = re.findall(r'\[ "\$\{SCORE\}" -ge (\d+) \]; then TIER="([A-Za-z]+)"', sh)
    assert pairs, "tier chain not found in scan.sh"
    else_word = re.search(r'else TIER="([A-Za-z]+)"; fi', sh).group(1)
    bash_table = [(int(n), w) for n, w in pairs] + [(0, else_word)]
    assert bash_table == [(t.floor, t.display) for t in TIERS]


@pytest.mark.parametrize("path", [
    "plugins/agentavow-trust/scripts/agentavow_pretool_gate.py",
    "integrations/claude-code/agentavow_pretool_gate.py",
])
def test_claude_code_plugin_gate_floors_agree(path):
    src = (ROOT / path).read_text()
    m = re.search(r"TIER_FLOORS\s*=\s*\{([^}]*)\}", src)
    assert m, f"TIER_FLOORS not found in {path}"
    floors = {k: int(v) for k, v in re.findall(r'"([a-z]+)":\s*(\d+)', m.group(1))}
    assert floors == TIER_FLOORS


def test_tool_gate_floors_agree():
    from src.bridges import tool_gate
    assert tool_gate.TIER_FLOORS == TIER_FLOORS


def test_frontend_table_agrees():
    """web/src/components/trust/gradeSystem.ts is the TS twin — same values, floors,
    words, colours (dark + light) and posture, in the same order."""
    ts = (ROOT / "web" / "src" / "components" / "trust" / "gradeSystem.ts").read_text()
    rows = re.findall(
        r"\{ value: '([a-z]+)',\s*name: '([A-Za-z]+)',\s*min: (\d+),\s*color: '(#[0-9A-F]{6})',"
        r"\s*colorText: '(#[0-9A-F]{6})',\s*posture: '([^']+)'", ts)
    assert len(rows) == 6
    assert [(v, n, int(m), c, ct, p) for v, n, m, c, ct, p in rows] == [
        (t.value, t.display, t.floor, t.color, t.color_light, t.posture) for t in TIERS
    ]


def test_no_surface_still_says_caution():
    """The old five-word scheme's 'Caution' must not come back on a display surface."""
    for rel in (
        "src/api/badge_style.py", "src/api/card_svg.py", "src/scanner/local_scan.py",
        "src/bridges/mcp_app_view.py", "github-action/scan.sh", "local-scan-action/README.md",
        "web/src/rebrand/docs/check-guide.md", "web/src/rebrand/docs/how-grading-works.md",
        "web/src/rebrand/docs/gate-on-the-grade.md", "web/src/rebrand/pages/FAQ.tsx",
        "web/src/rebrand/pages/Browse.tsx", "web/src/rebrand/lib/summarize.ts",
    ):
        assert "Caution" not in (ROOT / rel).read_text(), rel
    # gradeSystem.ts keeps the legacy A-F map above the tier table; the tier table itself
    # must be the six words.
    ts = (ROOT / "web/src/components/trust/gradeSystem.ts").read_text()
    tier_block = ts[ts.index("0–100 Trust mark"):]
    assert "Caution" not in tier_block
