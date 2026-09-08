"""Tests for the AI-writing-tell linter (src/marketing/content/ai_tells.py).

Validates that obvious AI-written drafts get flagged and clean human-style
drafts pass cleanly.
"""
from __future__ import annotations

from src.marketing.content.ai_tells import (
    BLOCKLIST_PHRASES,
    BLOCKLIST_WORDS,
    VOICE_PROMPT_FRAGMENT,
    check,
)

# --- Negative cases (should be blocked) ----------------------------------


def test_blocklist_word_blocks_draft():
    """A draft containing 'delve' should be blocked."""
    text = "Let's delve into how agent identity works in production."
    r = check(text, platform="bluesky", strict=True)
    assert not r.passed
    assert "blocklist_word" in r.reasons
    assert "delve" in r.blocked_words


def test_multiple_tell_words_caught():
    """Tapestry + meticulous + crucial — full house."""
    text = (
        "AgentGraph is a tapestry of meticulous trust signals — "
        "a crucial layer for the agent landscape."
    )
    r = check(text, platform="github_discussions", strict=True)
    assert not r.passed
    assert {"tapestry", "meticulous", "crucial", "landscape"}.issubset(
        set(r.blocked_words),
    )


def test_neg_parallelism_its_not_just_blocked():
    """The signature 2025/26 corporate AI tell."""
    text = "It's not just a trust score, it's a verifiable attestation."
    r = check(text, platform="twitter", strict=True)
    assert not r.passed
    assert "neg_parallelism" in r.reasons


def test_neg_parallelism_not_just_but_also_blocked():
    text = "These systems are not just executing tasks, but also adapting."
    r = check(text, platform="linkedin", strict=True)
    assert not r.passed
    assert "neg_parallelism" in r.reasons


def test_blocklist_phrase_in_today_blocked():
    text = (
        "In today's ever-evolving agent ecosystem, identity matters more "
        "than ever before."
    )
    r = check(text, platform="devto", strict=True)
    assert not r.passed
    assert "blocklist_phrase" in r.reasons


def test_blocklist_phrase_in_conclusion_blocked():
    text = (
        "We shipped the gateway and verified end-to-end. The latency held. "
        "Tests passed. In conclusion, the rollout went smoothly."
    )
    r = check(text, platform="devto", strict=True)
    assert not r.passed
    assert "blocklist_phrase" in r.reasons


# --- Positive cases (should pass) ----------------------------------------


def test_clean_draft_passes():
    """A short technical draft with no tells should pass."""
    text = (
        "Shipped /gateway/re-verify today. 30s TTL, no-store, fail-closed "
        "on missing attestation. Smoke-tested in prod, 5.9ms latency."
    )
    r = check(text, platform="bluesky", strict=True)
    assert r.passed, f"reasons: {r.reasons}, blocked: {r.blocked_words}"


def test_short_form_skips_short_sentence_rule():
    """Twitter and Bluesky shouldn't trip 'no_short_sentence'."""
    text = "Trust scoring for AI agents now lives behind a single endpoint."
    r = check(text, platform="twitter", strict=True)
    assert r.passed
    assert "no_short_sentence" not in r.reasons


def test_long_form_with_short_sentence_passes():
    text = (
        "We rebuilt the verify endpoint. It now signs every verdict with "
        "EdDSA. Latency dropped from 40ms to 6ms after we stopped fetching "
        "the cert chain on every call. Worth it."
    )
    r = check(text, platform="github_discussions", strict=True)
    assert r.passed, f"reasons: {r.reasons}"


def test_long_form_without_short_sentence_warns():
    """Long-form draft with all medium-length sentences flags rhythm tell."""
    text = (
        "We have implemented a new verification endpoint for all agents. "
        "The endpoint signs every single verdict using the EdDSA algorithm. "
        "Latency has improved significantly across our entire fleet of services."
    )
    r = check(text, platform="github_discussions", strict=True)
    # Has no blocklist hits, should still warn on rhythm
    assert "no_short_sentence" in r.reasons
    assert r.severity in {"warn", "block"}


def test_empty_text_passes():
    r = check("", platform="twitter", strict=True)
    assert r.passed


def test_hint_includes_specific_words():
    text = "We meticulously delve into the tapestry of trust signals."
    r = check(text, platform="linkedin", strict=True)
    assert not r.passed
    hint = r.hint()
    assert "delve" in hint or "tapestry" in hint or "meticulously" in hint


def test_voice_prompt_fragment_mentions_key_words():
    """Sanity: the prompt fragment names the worst tell-words."""
    assert "delve" in VOICE_PROMPT_FRAGMENT
    assert "tapestry" in VOICE_PROMPT_FRAGMENT
    assert "not just" in VOICE_PROMPT_FRAGMENT


def test_blocklists_are_lowercase():
    """All entries lowercased for case-insensitive matching."""
    assert all(w == w.lower() for w in BLOCKLIST_WORDS)
    assert all(p == p.lower() for p in BLOCKLIST_PHRASES)


def test_em_dash_density_alone_does_not_block():
    """Em-dashes alone — even several — shouldn't block. They're real punctuation."""
    text = "I shipped — finally — the verify endpoint — and it works."
    r = check(text, platform="twitter", strict=True)
    # Should warn maybe, but not block (no other tells present)
    assert r.passed or r.severity == "warn"


def test_em_dash_density_calibrated_per_1000_words():
    """Threshold is 7 per 1,000 words (Freeburg 2026: AI ~10.6, human ~3.2).
    Near-human density passes clean; AI-level density warns; AI-level density
    plus another tell blocks."""
    # ~60 words, 0 dashes + padding: one dash later would be ~16/1000 — but a
    # SINGLE dash never trips the rule (em_count >= 2 guard).
    filler = "The scanner reads the manifest and grades the repo. " * 8
    one_dash = filler + "It works — finally."
    r = check(one_dash, platform="devto", strict=True)
    assert "high_em_dash_density" not in r.reasons

    # Two dashes in ~90 words ≈ 22/1000 → warns, but alone never blocks.
    two_dash = filler + "It works — finally — and ships today."
    r = check(two_dash, platform="devto", strict=True)
    assert "high_em_dash_density" in r.reasons
    assert r.passed

    # Same density + a blocklist word → block.
    r = check(two_dash + " A robust result.", platform="devto", strict=True)
    assert "high_em_dash_density" in r.reasons
    assert not r.passed

    # Human-rate density on long copy stays silent: 2 dashes in ~800 words.
    long_human = "The scanner reads the manifest and grades the repo. " * 89
    long_human += "It works — finally — and ships today."
    r = check(long_human, platform="devto", strict=True)
    assert "high_em_dash_density" not in r.reasons


def test_copula_avoidance_density_warns():
    """Three 'serves as'/'represents'/'stands as' in one draft = AI rhythm."""
    text = (
        "AgentGraph serves as a trust layer. The gateway represents a verifier. "
        "The score serves as the input to enforcement decisions."
    )
    r = check(text, platform="github_discussions", strict=True)
    assert "high_copula_avoidance" in r.reasons


def test_strict_false_warns_instead_of_blocking():
    """Soft mode never blocks, only warns — useful for telemetry phase."""
    text = "Let's delve into the multifaceted tapestry."
    r = check(text, platform="bluesky", strict=False)
    assert r.passed  # soft mode passes
    assert r.severity == "warn"
    assert "blocklist_word" in r.reasons


# --- 2026 structural tells (the "shape, not words" additions) -------------


def test_participial_benefit_tail_blocked():
    """The '..., ensuring X' / '..., making it Y' tail is the top 2026 tell."""
    text = (
        "The platform signs every score, ensuring you can verify it yourself "
        "without trusting our server at all."
    )
    r = check(text, platform="devto", strict=True)
    assert not r.passed
    assert "participial_tail" in r.reasons
    assert "benefit-clause" in r.hint().lower() or "tail" in r.hint().lower()


def test_signpost_transition_blocked():
    """Sentence-opening 'Moreover,' / 'Furthermore,' is an AI signpost tell."""
    text = (
        "The scanner is free to use. Moreover, every result is independently "
        "verifiable against our published keys."
    )
    r = check(text, platform="devto", strict=True)
    assert not r.passed
    assert "signpost_transition" in r.reasons


def test_plays_a_role_blocked():
    """'plays a <adj> role' with any adjective is caught by the regex."""
    text = "Identity plays a central role in how agents trust each other today."
    r = check(text, platform="github_discussions", strict=True)
    assert not r.passed
    assert "plays_a_role" in r.reasons


def test_rhetorical_question_opener_blocked():
    """A 'Ever wondered...?' opener is a classic AI ad lead-in."""
    text = "Ever wondered if that MCP server is safe? We built a scanner for it."
    r = check(text, platform="bluesky", strict=True)
    assert not r.passed
    assert "rhetorical_opener" in r.reasons


def test_new_marketing_verbs_blocked():
    """The 2026 'elevate / streamline / supercharge' cluster is blocked."""
    for word in ("elevate", "streamline", "supercharge", "unlock", "empower"):
        text = f"This will {word} your agent workflow in production."
        r = check(text, platform="bluesky", strict=True)
        assert not r.passed, f"{word!r} should be blocked"
        assert word in r.blocked_words


def test_faux_conversational_signpost_blocked():
    """'Here's the thing' / 'dive into' faux-chat signposts are blocked."""
    text = "Here's the thing about agent trust: nobody actually verifies it."
    r = check(text, platform="bluesky", strict=True)
    assert not r.passed
    assert "blocklist_phrase" in r.reasons


def test_clean_human_draft_still_passes_after_additions():
    """A genuinely human, specific draft must NOT trip the new structural rules."""
    text = (
        "Scanned 950 MCP repos. Most run unsafe exec. We sign every result so "
        "you can check it yourself. Try it on something you actually use."
    )
    r = check(text, platform="devto", strict=True)
    assert r.passed, f"reasons: {r.reasons}, blocked: {r.blocked_words}"


def test_voice_fragment_warns_against_overcorrection():
    """The fragment must tell the model NOT to swing into choppy blandness."""
    assert "overcorrect" in VOICE_PROMPT_FRAGMENT.lower()
    assert "em-dash" in VOICE_PROMPT_FRAGMENT.lower()
