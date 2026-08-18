"""No-slop self-improvement — a growing, admin-approved blocklist.

The rule detector (ai_tells) is the hard gate; this makes it *learn*:

- ``propose_from_edit`` captures phrases a human cut when editing a draft (a labeled
  "the bot wrote slop → you fixed it" signal).
- ``propose_from_llm`` periodically asks the model for emerging AI-tell phrases to avoid
  (no web-search dependency; a true web lane can be added if a search API is wired up).

Proposals queue for one-click admin approval; approved phrases feed the ai_tells dynamic
blocklist. All best-effort — never blocks generation.
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

_PROPOSED = "ag:mktg:slop:proposed"   # hash: phrase -> reason
_APPROVED = "ag:mktg:slop:approved"   # set of approved phrases
_REJECTED = "ag:mktg:slop:rejected"   # set (so we don't re-propose)


async def _r():
    from src.redis_client import get_redis
    return get_redis()


async def refresh_dynamic_blocklist() -> int:
    """Load approved phrases into the ai_tells in-process dynamic blocklist."""
    try:
        r = await _r()
        members = await r.smembers(_APPROVED)
        phrases = {(m.decode() if isinstance(m, bytes) else m) for m in members}
        from src.marketing.content.ai_tells import set_dynamic_blocklist
        set_dynamic_blocklist(phrases)
        return len(phrases)
    except Exception:
        return 0


async def propose(phrase: str, reason: str) -> bool:
    """Queue a candidate slop phrase for admin review (skip if known)."""
    p = (phrase or "").strip().lower()
    if not p or len(p) < 4 or len(p) > 60:
        return False
    try:
        r = await _r()
        if await r.sismember(_APPROVED, p) or await r.sismember(_REJECTED, p):
            return False
        await r.hset(_PROPOSED, p, reason[:120])
        return True
    except Exception:
        return False


async def list_proposals() -> list[dict]:
    try:
        r = await _r()
        h = await r.hgetall(_PROPOSED)
        out = []
        for k, v in h.items():
            out.append({
                "phrase": k.decode() if isinstance(k, bytes) else k,
                "reason": v.decode() if isinstance(v, bytes) else v,
            })
        return out
    except Exception:
        return []


async def act(phrase: str, action: str) -> bool:
    p = (phrase or "").strip().lower()
    try:
        r = await _r()
        await r.hdel(_PROPOSED, p)
        if action == "approve":
            await r.sadd(_APPROVED, p)
            await refresh_dynamic_blocklist()
        else:
            await r.sadd(_REJECTED, p)
        return True
    except Exception:
        return False


def _phrases(text: str) -> set[str]:
    words = re.sub(r"\s+", " ", (text or "").strip().lower()).split()
    grams = set()
    for i in range(len(words) - 2):
        grams.add(" ".join(words[i:i + 3]))
    if len(words) >= 4:
        grams.add(" ".join(words[:4]))  # opener
    return grams


async def propose_from_edit(original: str, edited: str) -> int:
    """Phrases the human REMOVED when editing → candidate slop. Returns # proposed."""
    if not original or not edited or original.strip() == edited.strip():
        return 0
    removed = _phrases(original) - _phrases(edited)
    # Only the notably slop-y ones: skip anything still present as a substring.
    el = edited.lower()
    n = 0
    for g in list(removed)[:8]:
        if g in el or "http" in g:
            continue
        if await propose(g, "you edited this out of a draft"):
            n += 1
    return n


async def propose_from_llm() -> int:
    """Ask the model for emerging AI-tell phrases to avoid; queue them for review."""
    try:
        from src.marketing.llm.router import generate as llm_generate
    except Exception:
        return 0
    prompt = (
        "List 8 short, currently-common AI-writing 'tell' phrases or clichés that make "
        "social copy read as AI-generated (e.g. openers, transitions, filler). Output ONLY "
        "the phrases, one per line, lowercase, no numbering, 2-6 words each."
    )
    try:
        res = await llm_generate(
            prompt, content_type="slop_mining", max_tokens=200, temperature=0.4,
        )
    except Exception:
        return 0
    if getattr(res, "error", None) or not getattr(res, "text", ""):
        return 0
    n = 0
    for line in res.text.splitlines():
        cand = re.sub(r"^[\-\*\d\.\)\s\"']+", "", line).strip().strip('".').lower()
        if 4 <= len(cand) <= 60 and " " in cand:
            if await propose(cand, "model-proposed emerging AI-tell"):
                n += 1
    return n
