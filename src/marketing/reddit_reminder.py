"""Daily Reddit reply reminder.

Finds ONE relevant Reddit thread per day, generates a targeted draft
reply, and emails it to the admin. Skips the day if no good thread
is available.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from src.marketing.config import marketing_settings

logger = logging.getLogger(__name__)


async def _find_best_thread(allow_used: bool = False) -> dict | None:
    """Pick the single best thread to reply to today.

    Sources (in order):
    1. Reddit scout cache (from news-digest on Windows server)
    2. digest_history.json fallback

    With ``allow_used=False`` (default) only fresh, never-drafted threads are
    returned. With ``allow_used=True`` it falls back to re-surfacing the best
    already-used thread when the feed has run dry, so we still have something to
    post. Returned dict carries ``recycled`` to flag that fallback.
    """
    from src.marketing.reddit_scout import get_cached_threads

    threads = await get_cached_threads()

    # Fallback: iterate reddit_thread_details directly from
    # digest_history.json — these have selftext + comments cached
    # and are the only threads we can draft replies for on EC2
    if not threads:
        try:
            import json as _json
            from pathlib import Path

            from src.marketing.reddit_scout import _DIGEST_PATHS
            from src.redis_client import get_redis

            # Load used-threads set so we don't repeat
            used_urls: set[str] = set()
            try:
                _r = get_redis()
                _data = await _r.get("ag:reddit:used_threads")
                if _data:
                    used_urls = set(_json.loads(_data))
            except Exception:
                pass

            # Read reddit_thread_details directly
            for p in _DIGEST_PATHS:
                path = Path(p)
                if not path.exists():
                    continue
                with open(path) as f:
                    data = _json.load(f)
                details = data.get("reddit_thread_details", {})
                recycle = None
                for url, detail in details.items():
                    if not detail.get("title"):
                        continue
                    if url not in used_urls:
                        return {
                            "url": url,
                            "title": detail["title"],
                            "subreddit": detail.get("subreddit", ""),
                            "recycled": False,
                        }
                    if recycle is None:
                        recycle = {
                            "url": url,
                            "title": detail["title"],
                            "subreddit": detail.get("subreddit", ""),
                            "recycled": True,
                        }
                if allow_used and recycle:
                    return recycle
                break  # Only read from the first available path
        except Exception:
            logger.debug("Failed to read digest thread details", exc_info=True)
        return None

    # Score threads: prefer more keywords matched, higher score, some comments
    def _score(t):  # type: ignore[no-untyped-def]
        s = len(t.keywords_matched) * 3
        if t.score > 50:
            s += 2
        if t.score > 200:
            s += 2
        if 3 <= t.num_comments <= 50:
            s += 2  # Active but not overwhelming
        return s

    threads.sort(key=_score, reverse=True)

    # Check Redis for threads we've already drafted replies to
    used_urls: set[str] = set()
    try:
        import json

        from src.redis_client import get_redis

        r = get_redis()
        data = await r.get("ag:reddit:used_threads")
        if data:
            used_urls = set(json.loads(data))
    except Exception:
        pass

    recycle = None
    for t in threads:
        if t.url not in used_urls:
            return {
                "url": t.url,
                "title": t.title,
                "subreddit": t.subreddit,
                "score": t.score,
                "num_comments": t.num_comments,
                "recycled": False,
            }
        if recycle is None:
            recycle = {
                "url": t.url,
                "title": t.title,
                "subreddit": t.subreddit,
                "score": t.score,
                "num_comments": t.num_comments,
                "recycled": True,
            }
    if allow_used and recycle:
        return recycle
    return None


# Subreddits that don't gate low-karma commenters → safe for our account to
# reply in; high-barrier ones often auto-remove new/low-karma accounts.
_LOW_BARRIER_SUBS = {"sideproject", "artificial", "locallama", "langchain"}
_HIGH_BARRIER_SUBS = {"machinelearning", "programming"}


def _karma_friendliness(subreddit: str) -> int:
    """0 = low-karma-friendly (prefer), 2 = high-karma-gated (avoid)."""
    s = (subreddit or "").lower().lstrip("r/").strip("/")
    if s in _LOW_BARRIER_SUBS:
        return 0
    if s in _HIGH_BARRIER_SUBS:
        return 2
    return 1


async def _candidate_threads() -> list[dict]:
    """Reply-candidate threads, karma-friendliest first, fresh (unused) before
    already-used. Each: {url, title, subreddit, used}."""
    import json as _json
    from pathlib import Path

    from src.marketing.reddit_scout import _DIGEST_PATHS, get_cached_threads
    from src.redis_client import get_redis

    used_urls: set[str] = set()
    try:
        r = get_redis()
        data = await r.get("ag:reddit:used_threads")
        if data:
            used_urls = set(_json.loads(data))
    except Exception:
        pass

    cands: list[dict] = []
    seen: set[str] = set()

    # Live source: digest reddit_thread_details
    try:
        for p in _DIGEST_PATHS:
            path = Path(p)
            if not path.exists():
                continue
            with open(path) as f:
                data = _json.load(f)
            for url, detail in data.get("reddit_thread_details", {}).items():
                if not detail.get("title") or url in seen:
                    continue
                seen.add(url)
                cands.append({
                    "url": url,
                    "title": detail["title"],
                    "subreddit": detail.get("subreddit", ""),
                    "used": url in used_urls,
                })
            break  # first available path only
    except Exception:
        logger.debug("Failed to read digest thread details", exc_info=True)

    # Redis scout cache (usually empty now, but include if present)
    try:
        for t in await get_cached_threads():
            if t.url in seen:
                continue
            seen.add(t.url)
            cands.append({
                "url": t.url,
                "title": t.title,
                "subreddit": t.subreddit,
                "used": t.url in used_urls,
            })
    except Exception:
        pass

    cands.sort(key=lambda c: (c["used"], _karma_friendliness(c["subreddit"])))
    return cands


async def _generate_thread_reply(
    thread_url: str,
    db: AsyncSession,
    style: str = "short",
) -> tuple[str | None, str | None, dict | None]:
    """Generate a draft reply for a specific thread.

    style="short" → a 1-2 sentence reply-guy comment.
    style="long"  → a 3-4 paragraph reply to join the thread with.
    Returns (draft_content, llm_model, thread_detail) or (None, None, None).
    """
    from src.marketing.llm.cost_tracker import estimate_cost
    from src.marketing.llm.router import generate as llm_generate
    from src.marketing.reddit_scout import fetch_thread_detail

    detail = await fetch_thread_detail(thread_url)
    if not detail:
        logger.warning("Could not fetch thread detail: %s", thread_url)
        return None, None, None

    thread_title = detail["title"]
    thread_body = detail.get("selftext", "")[:1500]
    subreddit = detail.get("subreddit", "")
    # Pick a specific comment to answer if any exist; with RSS-sourced threads
    # there are no comments, so we reply to the post itself.
    top_comments = detail.get("top_comments", [])
    target = top_comments[0] if top_comments else None
    target_author = target["author"] if target else "OP"
    target_body = (target["body"] if target else thread_body)[:600]
    target_permalink = (target.get("permalink") if target else "") or thread_url
    what = (
        f'u/{target_author} wrote: "{target_body}"'
        if target
        else f'The post says: "{target_body}"'
    )

    # 10% self-promotion rule.
    promo_eligible = False
    try:
        from src.redis_client import get_redis

        redis = get_redis()
        post_number = await redis.incr("ag:reddit:post_count")
        promo_eligible = post_number % 10 == 0
    except Exception:
        pass

    promo_line = (
        "You MAY work in agentavow.com/check ONLY if it's literally the punchline "
        "— never a pitch."
        if promo_eligible
        else "Do NOT mention AgentAvow or any product. Pure community value."
    )

    from src.marketing.content.ai_tells import VOICE_PROMPT_FRAGMENT

    if style == "long":
        prompt = (
            f"You're a real developer in r/{subreddit}. Write a substantive reply to "
            f"this thread that adds something genuine — your take, a relevant "
            f"experience, or a useful pointer.\n\n"
            f'Thread: "{thread_title}"\n{what}\n\n'
            f"Write 3-4 SHORT paragraphs. Conversational and specific, like a human "
            f"who actually knows the topic — not a wall of text, not a listicle, not "
            f"an essay. {promo_line}\n\n"
            f"{VOICE_PROMPT_FRAGMENT}\n"
            "Hard no's: emojis, hashtags, 'Great point/question', em-dash spam, "
            "bullet lists, corporate voice, 'it's worth noting'.\n\n"
            "Reply (just the text):"
        )
        system = (
            "You write Reddit replies that pass for a real, knowledgeable developer "
            "adding genuine value to a thread. You never sound like AI or marketing."
        )
        max_tokens = 420
    else:
        prompt = (
            f"You're a real dev lurking in r/{subreddit}. Reply to THIS like you'd "
            f"thumb it out on your phone:\n\n"
            f'Thread: "{thread_title}"\n{what}\n\n'
            f"Write ONE sentence (two MAX, and keep them short). Fun, a little "
            f"snarky, genuinely on-topic — the kind of reply that gets upvoted for "
            f"being funny and true, not for being a helpful bot. {promo_line}\n\n"
            f"{VOICE_PROMPT_FRAGMENT}\n"
            "Hard no's: emojis, hashtags, 'Great point/question', em-dashes, bullet "
            "lists, corporate voice, 'it's worth noting'. lowercase is fine. It must "
            "read like a human shitposting, not an AI being helpful.\n\n"
            "Reply (just the text):"
        )
        system = (
            "You write Reddit comments that pass for a real, slightly-snarky "
            "developer. Short, specific, funny. You never sound like AI or marketing."
        )
        max_tokens = 120

    result = await llm_generate(
        prompt,
        content_type="reddit_scout_draft",
        system=system,
        max_tokens=max_tokens,
        temperature=0.85,
    )

    if result.error:
        logger.warning("LLM failed for Reddit draft: %s", result.error)
        return None, None, None

    # Flag if it still reads like AI (human reviews + posts Reddit anyway).
    from src.marketing.content.ai_tells import check as check_ai_tells

    tells = check_ai_tells(result.text, platform="reddit", strict=True)
    if not tells.passed:
        logger.warning(
            "Reddit draft tripped AI-tell check (%s): %s",
            tells.reasons, result.text[:120],
        )

    # Save as draft. utm_params carries the REPLY TARGET so review shows exactly
    # which comment this answers, plus a direct permalink to it.
    from src.marketing.draft_queue import enqueue_draft

    cost = estimate_cost(result.model, result.tokens_in, result.tokens_out)
    await enqueue_draft(
        db,
        platform="reddit",
        content=result.text,
        topic=(f"reply-long:{subreddit}" if style == "long" else f"reply:{subreddit}"),
        post_type="reactive",
        llm_model=result.model,
        llm_tokens_in=result.tokens_in,
        llm_tokens_out=result.tokens_out,
        llm_cost_usd=cost,
        utm_params={
            "thread_url": thread_url,
            "thread_title": thread_title,
            "reply_to_author": target_author,
            "reply_to_excerpt": target_body[:280],
            "reply_to_permalink": target_permalink,
            "reply_style": style,
            "ai_tells_ok": tells.passed,
        },
    )
    await db.flush()

    return result.text, result.model, detail


async def _mark_thread_used(thread_url: str) -> None:
    """Track that we've drafted a reply for this thread so we don't repeat."""
    import json

    try:
        from src.redis_client import get_redis

        r = get_redis()
        key = "ag:reddit:used_threads"
        data = await r.get(key)
        used = json.loads(data) if data else []
        used.append(thread_url)
        # Keep last 100 URLs
        await r.set(key, json.dumps(used[-100:]), ex=86400 * 30)
    except Exception:
        pass


async def _send_dry_feed_alert() -> None:
    """Email the admin when the Reddit feed has nothing to draft from.

    Throttled to once every 2 days so it nudges without nagging. Fires when the
    upstream news-digest stops populating ``reddit_thread_details`` — AgentAvow
    is fine, the feed is just dry.
    """
    try:
        from src.redis_client import get_redis

        r = get_redis()
        if await r.get("ag:mktg:reddit_dry_alert"):
            return
        await r.set("ag:mktg:reddit_dry_alert", "1", ex=86400 * 2)
    except Exception:
        pass
    try:
        from src.email import send_email

        html = (
            "<p>No Reddit threads were available to draft a reply from "
            "(fresh or re-surfaced).</p>"
            "<p>AgentAvow is working as intended — the upstream "
            "<b>news-digest</b> isn't populating <code>reddit_thread_details</code>, "
            "so the Reddit feed is dry. Check the news-digest's Reddit capture "
            "(Windows server).</p>"
            "<p>Reply drafts resume automatically once the feed returns.</p>"
        )
        await send_email(
            marketing_settings.marketing_notify_email,
            "Reddit feed is dry — no reply drafts (check the news-digest)",
            html,
        )
        logger.info("Sent Reddit dry-feed alert")
    except Exception:
        logger.debug("Failed to send Reddit dry-feed alert", exc_info=True)


async def _email_reddit_draft(
    thread_info: dict, draft_content: str, detail: dict | None, style: str,
) -> bool:
    """Email one Reddit draft with the thread link in the header."""
    today_date = datetime.now(timezone.utc).strftime("%A, %B %d, %Y")
    thread_title = (detail or {}).get("title", thread_info.get("title", ""))
    subreddit = (detail or {}).get("subreddit", thread_info.get("subreddit", ""))
    thread_url = thread_info["url"]

    from src.email import _load_template, send_email

    html = _load_template(
        "marketing_reddit_reminder.html",
        today_date=today_date,
        subreddit=f"r/{subreddit}" if subreddit else "Reddit",
        thread_title=thread_title,
        thread_url=thread_url,
        draft_content=draft_content,
        fallback=(
            f"Reddit {'post' if style == 'long' else 'reply'}: {thread_title}. "
            f"Review at https://agentavow.com/admin"
        ),
    )
    label = "join-this post" if style == "long" else "reply"
    subject = (
        f"Reddit {label} draft — r/{subreddit}" if subreddit
        else f"Reddit {label} draft"
    )
    return bool(await send_email(
        marketing_settings.marketing_notify_email, subject, html,
    ))


async def send_reddit_reminder(db: AsyncSession) -> bool:
    """Daily Reddit drafts for manual posting: up to two 1-2 sentence reply-guy
    comments + one longer 3-4 paragraph "join this thread" reply, each to a
    distinct karma-friendly thread, with the thread link in the header. Falls back
    to a news-grounded post / dry-feed alert only when there are no threads at all.

    Returns True if at least one draft was sent.
    """
    # Guard against running more than once per day (the batch is per-day).
    try:
        from src.redis_client import get_redis

        r = get_redis()
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if await r.get(f"ag:mktg:reddit_reminder:{today_str}"):
            logger.debug("Reddit reminder already sent today")
            return False
    except Exception:
        pass

    cands = await _candidate_threads()
    pool = [c for c in cands if not c["used"]] or cands  # fresh first, recycle if dry

    # Plan: 2 replies/day — one 1-2 sentence (short) + one 3-4 paragraph (long).
    styles = ["short", "long"]
    used_now: set[str] = set()
    sent = 0
    for style in styles:
        thread_info = next((c for c in pool if c["url"] not in used_now), None)
        if not thread_info:
            break
        used_now.add(thread_info["url"])
        draft, _model, detail = await _generate_thread_reply(
            thread_info["url"], db, style=style,
        )
        if not draft:
            continue
        await _mark_thread_used(thread_info["url"])
        if await _email_reddit_draft(thread_info, draft, detail, style):
            sent += 1
            logger.info(
                "Reddit %s draft sent: r/%s — %s",
                style, thread_info.get("subreddit", ""),
                thread_info.get("title", "")[:50],
            )

    # No thread produced a draft → dry-feed alert (no news-post fallback; the
    # reply-guy feed is restored, so empty means a genuine feed problem to flag).
    if sent == 0:
        logger.info("No Reddit threads to draft — sending dry-feed alert")
        await _send_dry_feed_alert()

    # Mark the day done (one batch per day) regardless of outcome.
    try:
        from src.redis_client import get_redis

        r = get_redis()
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        await r.set(f"ag:mktg:reddit_reminder:{today_str}", "1", ex=86400)
    except Exception:
        pass

    return sent > 0
