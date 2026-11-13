"""Admin-only ad spend, and cost per action per campaign / utm_content.

Nothing else in the product knows what a campaign cost, so the admin enters it here:
one row per UTC day per ``utm_campaign`` / ``utm_content`` (one form row at a time, or
a pasted ads CSV export), tagged with its channel in ``utm_source`` (reddit, x, google,
...). The cost view divides that spend by the campaign funnel from
``/analytics/attribution/campaigns`` (sessions by first-touch UTM tags, bots left out)
to give cost per lp_view and cost per copy_plugin_cmd, per ad or per channel.

A row is keyed on (day, campaign, ad), not the channel: each channel runs its own
campaign names (2026-11-test-dev on reddit, 2026-11-test-x on x, ...). Entering spend
for a (day, campaign, ad) another channel already holds is refused (409), so one
channel can never silently overwrite another's row.

Endpoints (all under ``/admin``, admin only):
  * GET    /admin/ad-spend                  -> rows in the window + totals
  * PUT    /admin/ad-spend                  -> add or replace one day's spend
  * DELETE /admin/ad-spend/{id}             -> remove a row
  * POST   /admin/ad-spend/import           -> paste a CSV (Reddit, X or Google Ads
    export); ``dry_run=true`` returns the parsed rows without saving (the preview)
  * GET    /admin/ad-spend/cost-per-action  -> spend joined to the funnel per utm_content,
    or per channel (``group_by=source``); ``previous=true`` adds the period before

And one machine endpoint, NOT behind an admin login:
  * POST   /admin/ad-spend/ingest           -> the nightly Google Ads Script
    (docs/google-ads-script.js) sends the last 7 days per ad group. Authenticated by the
    shared secret AD_SPEND_INGEST_TOKEN in the ``X-Ad-Spend-Token`` header; answers 404
    while that is unset. Same upsert as the CSV import, so a re-send overwrites.
"""
from __future__ import annotations

import csv
import hmac
import io
import logging
import re
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, require_admin, require_admin_or_viewer
from src.api.rate_limit import (
    _get_client_ip,
    _limiter,
    _rate_limit_response,
    rate_limit_reads,
    rate_limit_writes,
)
from src.api.redaction import viewer_safe
from src.audit import log_action
from src.database import get_db
from src.models import AdSpend, Entity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])

_TAG_MAX = 200
# Channels the dashboard always lists, even with no spend or visits yet.
CHANNELS = ("reddit", "x", "google")
# utm_source spellings that mean the same channel.
_CHANNEL_ALIASES = {"twitter": "x", "x.com": "x", "t.co": "x", "googleads": "google",
                    "adwords": "google"}
NO_CHANNEL = "(no utm_source)"
# Our own marketing bot tags its links utm_source=agentgraph_bot_<platform>; some arrive
# cut short or garbled (agentgraph_, agentgraph_bot…). They are all one channel.
BOT_CHANNEL = "agentgraph_bot"
_BOT_PREFIX = "agentgraph_"
CHANNEL_LABELS = {"reddit": "Reddit", "x": "X", "google": "Google",
                  NO_CHANNEL: "No channel tag", BOT_CHANNEL: "Our bot posts (agentgraph_bot)"}


def channel_of(source: str | None) -> str:
    """The channel a utm_source belongs to: lowercased, aliases folded (twitter -> x),
    and every agentgraph_* source (trailing "…" / "..." stripped) folded into the bot."""
    s = (source or "").strip().lower()
    trimmed = s.removesuffix("…").removesuffix("...").strip()
    if trimmed.startswith(_BOT_PREFIX):
        return BOT_CHANNEL
    return _CHANNEL_ALIASES.get(s, s) or NO_CHANNEL


# --- Ad name / ad group -> utm_content ------------------------------------------
# The one place that says which ad tag (utm_content on the ad's link) an ad platform's
# own name stands for. An unknown name is stored under itself, never dropped.

# Google Ads ad group name (compared lowercased, spaces / underscores as "-").
GOOGLE_AD_GROUP_TAGS: dict[str, str] = {
    "scanner": "rsa-scanner",
    "claude-code": "d1-automatic",
}
# X ad names: the first rule whose pattern is found in the lowercased name wins. The
# x1 / x2 / x3 numbers are checked before the words.
X_AD_TAG_RULES: tuple[tuple[str, str], ...] = (
    (r"(?<![a-z0-9])x1(?![0-9])", "x1-archived"),
    (r"(?<![a-z0-9])x2(?![0-9])", "x2-automatic"),
    (r"(?<![a-z0-9])x3(?![0-9])", "x3-do-not-connect"),
    (r"do[\s_-]*not[\s_-]*connect", "x3-do-not-connect"),
    (r"archived", "x1-archived"),
    (r"automatic", "x2-automatic"),
)


def ad_tag_for(channel: str | None, name: str | None) -> str:
    """The utm_content an ad platform's ad (X) or ad group (Google) name maps to, or
    the cleaned name itself when no rule matches."""
    cleaned = _clean_tag(name)
    ch = channel_of(channel)
    if ch == "google":
        key = re.sub(r"[\s_]+", "-", cleaned.lower())
        return GOOGLE_AD_GROUP_TAGS.get(key, cleaned)
    if ch == "x":
        low = cleaned.lower()
        for pattern, tag in X_AD_TAG_RULES:
            if re.search(pattern, low):
                return tag
    return cleaned


_CSV_MAX_BYTES = 512 * 1024
_CSV_MAX_ROWS = 5000
_SPEND_MAX = Decimal("1000000")
# ad_spend.impressions / clicks are 32-bit integers.
_COUNT_MAX = 2_000_000_000


def _clean_tag(value: str | None) -> str:
    return (value or "").replace("\x00", "").strip()[:_TAG_MAX]


class SpendIn(BaseModel):
    day: date
    utm_campaign: str = Field(..., min_length=1, max_length=_TAG_MAX)
    utm_content: str | None = Field(None, max_length=_TAG_MAX)
    utm_source: str | None = Field(None, max_length=_TAG_MAX)
    spend_usd: Decimal = Field(..., ge=0, le=_SPEND_MAX, max_digits=12, decimal_places=2)
    impressions: int | None = Field(None, ge=0, le=10**10)
    clicks: int | None = Field(None, ge=0, le=10**10)

    @field_validator("utm_campaign")
    @classmethod
    def _campaign_not_blank(cls, v: str) -> str:
        v = _clean_tag(v)
        if not v:
            raise ValueError("utm_campaign is required")
        return v


class CsvImportIn(BaseModel):
    csv: str = Field(..., min_length=1, max_length=_CSV_MAX_BYTES)
    # Applied to every row when given: a Reddit campaign name need not match the
    # utm_campaign on its links. The ad name is read as utm_content.
    utm_campaign: str | None = Field(None, max_length=_TAG_MAX)
    utm_source: str | None = Field("reddit", max_length=_TAG_MAX)
    # True: parse and return the rows (the preview) without saving anything.
    dry_run: bool = False


def _row_out(r: AdSpend) -> dict:
    return {
        "id": str(r.id),
        "day": r.day.isoformat(),
        "utm_source": r.utm_source,
        "utm_campaign": r.utm_campaign,
        "utm_content": r.utm_content or None,
        "spend_usd": float(r.spend_usd),
        "impressions": r.impressions,
        "clicks": r.clicks,
        "source": r.source,
    }


async def _upsert(db: AsyncSession, row: dict) -> None:
    stmt = pg_insert(AdSpend).values(id=uuid.uuid4(), **row)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_ad_spend_day_campaign_content",
        set_={
            "utm_source": stmt.excluded.utm_source,
            "spend_usd": stmt.excluded.spend_usd,
            "impressions": stmt.excluded.impressions,
            "clicks": stmt.excluded.clicks,
            "source": stmt.excluded.source,
            "updated_at": datetime.now(timezone.utc),
        },
    )
    await db.execute(stmt)


def _window_start(days: int) -> date:
    return datetime.now(timezone.utc).date() - timedelta(days=days - 1)


async def _channel_clash(db: AsyncSession, row: dict) -> str | None:
    """The channel already holding this (day, campaign, ad) when it is a different one
    than ``row``'s, else None. A row with no channel on either side never clashes."""
    held = (await db.execute(
        select(AdSpend.utm_source).where(
            AdSpend.day == row["day"], AdSpend.utm_campaign == row["utm_campaign"],
            AdSpend.utm_content == row["utm_content"])
    )).scalar_one_or_none()
    if held and row.get("utm_source") and channel_of(held) != channel_of(row["utm_source"]):
        return held
    return None


@router.get("/ad-spend", dependencies=[Depends(rate_limit_reads)])
async def list_ad_spend(
    days: int = Query(28, ge=1, le=366),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Spend rows from the last ``days`` UTC days (newest first) and their total."""
    require_admin(current_entity)
    rows = (await db.execute(
        select(AdSpend).where(AdSpend.day >= _window_start(days))
        .order_by(AdSpend.day.desc(), AdSpend.utm_campaign, AdSpend.utm_content)
    )).scalars().all()
    return {
        "days": days,
        "rows": [_row_out(r) for r in rows],
        "total_usd": float(sum((r.spend_usd for r in rows), Decimal(0))),
    }


@router.put("/ad-spend", dependencies=[Depends(rate_limit_writes)])
async def put_ad_spend(
    body: SpendIn,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Add one day's spend for a campaign / utm_content, replacing any earlier entry
    for the same day, campaign and content."""
    require_admin(current_entity)
    row = {
        "day": body.day,
        "utm_campaign": body.utm_campaign,
        "utm_content": _clean_tag(body.utm_content),
        "utm_source": _clean_tag(body.utm_source) or None,
        "spend_usd": body.spend_usd,
        "impressions": body.impressions,
        "clicks": body.clicks,
        "source": "manual",
    }
    held = await _channel_clash(db, row)
    if held:
        raise HTTPException(
            status_code=409,
            detail=f"{body.day} {body.utm_campaign} {row['utm_content'] or '(no ad)'} already "
                   f"has spend from {held}. Use that channel's campaign name, or remove "
                   "that row first.")
    await _upsert(db, row)
    await db.flush()
    return {"status": "ok"}


@router.delete("/ad-spend/{row_id}", dependencies=[Depends(rate_limit_writes)])
async def delete_ad_spend(
    row_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    require_admin(current_entity)
    result = await db.execute(delete(AdSpend).where(AdSpend.id == row_id))
    if not result.rowcount:
        raise HTTPException(status_code=404, detail="No such spend row")
    return {"status": "ok"}


# --- CSV import -----------------------------------------------------------------

# Header names are compared lowercased with everything but letters removed, so
# "Amount Spent (USD)", "amount_spent_usd" and "AmountSpentUSD" are the same column.
# Covers the Reddit Ads export, X Ads Manager's export (its column names vary between
# report types: "Time period" / "Date", "Ad name", "Spend" / "Billed charge",
# "Link clicks" / "URL clicks") and a Google Ads ad group report ("Day", "Ad group",
# "Cost", "Impr.").
_HEADERS = {
    "day": ("date", "day", "timeperiod", "reportingstarts", "reportdate"),
    "campaign": ("utmcampaign", "campaignname", "campaign"),
    "content": ("utmcontent", "adname", "ad", "adgroupname", "adgroup"),
    "spend": ("amountspentusd", "amountspent", "spendusd", "spend", "cost", "costusd",
              "totalspend", "billedchargeusd", "billedcharge"),
    "impressions": ("impressions", "impr"),
    "clicks": ("clicks", "linkclicks", "urlclicks"),
}
# Per channel, where the generic order above is the wrong one: a Google ad group is
# the ad (its ads carry the ad group's tag), and X's "Clicks" counts every tap on the
# post, so its link clicks come first.
_CHANNEL_HEADERS = {
    "google": {"content": ("utmcontent", "adgroupname", "adgroup", "adname", "ad")},
    "x": {"clicks": ("linkclicks", "urlclicks", "clicks")},
}
# What the error for an unreadable header row names, per required column.
_EXPECTED = {
    "day": 'a date column ("Date", "Day" or "Time period")',
    "spend": 'a spend column ("Spend", "Amount spent", "Billed charge" or "Cost")',
}
_DATE_FORMATS = ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y", "%d.%m.%Y", "%Y/%m/%d",
                 "%b %d, %Y", "%B %d, %Y", "%a, %b %d, %Y", "%d %b %Y", "%d %B %Y")
# How many lines above the header row to look past (Google puts a report title and
# the date range there).
_HEADER_SEARCH_LINES = 10


def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z]", "", (h or "").lower())


def _headers_for(channel: str | None) -> dict[str, tuple[str, ...]]:
    return {**_HEADERS, **_CHANNEL_HEADERS.get(channel_of(channel), {})}


def _pick(norm_row: dict[str, str], field: str,
          headers: dict[str, tuple[str, ...]] | None = None) -> str:
    for name in (headers or _HEADERS)[field]:
        v = norm_row.get(name)
        if v not in (None, ""):
            return v.strip()
    return ""


def _parse_one_day(raw: str) -> date | None:
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(raw).date()  # "2026-11-17T00:00:00"
    except ValueError:
        return None


def _parse_day(raw: str) -> date | None:
    raw = raw.strip()[:64]
    day = _parse_one_day(raw)
    if day is not None:
        return day
    # X can write a day as a one-day range: "Nov 13, 2026 - Nov 13, 2026". A longer
    # range is not one day, so it is not read.
    parts = re.split(r"\s+[-–]\s+", raw)
    if len(parts) == 2:
        start, end = _parse_one_day(parts[0].strip()), _parse_one_day(parts[1].strip())
        if start is not None and start == end:
            return start
    return None


def _parse_money(raw: str) -> Decimal | None:
    cleaned = re.sub(r"[^0-9.\-]", "", raw or "")
    if not cleaned:
        return None
    try:
        value = Decimal(cleaned).quantize(Decimal("0.01"))
    except InvalidOperation:
        return None
    return value if Decimal(0) <= value <= _SPEND_MAX else None


def _parse_int(raw: str) -> int | None:
    cleaned = re.sub(r"[^0-9]", "", raw or "")
    return int(cleaned) if cleaned and len(cleaned) <= 11 else None


def _find_header(lines: list[list[str]], headers: dict[str, tuple[str, ...]]) -> int | None:
    """Index of the first line that has both a date and a spend column."""
    for i, cells in enumerate(lines[:_HEADER_SEARCH_LINES]):
        names = {_norm_header(c) for c in cells}
        if names & set(headers["day"]) and names & set(headers["spend"]):
            return i
    return None


def _header_error(first: list[str], headers: dict[str, tuple[str, ...]]) -> str:
    names = {_norm_header(c) for c in first}
    missing = [_EXPECTED[f] for f in ("day", "spend") if not names & set(headers[f])]
    found = ", ".join(f'"{c.strip()[:40]}"' for c in first[:20] if c.strip()) or "nothing"
    return (f"Unrecognised columns: expected {' and '.join(missing)}. Found: {found}. "
            'Also read when present: campaign ("Campaign name" or "Campaign"), ad '
            '("Ad name", "Ad" or "Ad group"), "Impressions", and clicks ("Link clicks", '
            '"URL clicks" or "Clicks").')


def parse_spend_csv(
    text: str, utm_campaign: str | None = None, utm_source: str | None = None,
) -> tuple[list[dict], list[str]]:
    """Parse a spend CSV into upsert rows, summed per (day, campaign, content).

    Reads a Reddit Ads export (Date, Campaign Name, Ad Group Name, Ad Name,
    Impressions, Clicks, Amount Spent (USD)), an X Ads Manager export (Time period,
    Campaign name, Ad name, Spend / Billed charge, Impressions, Link clicks), a Google
    Ads ad group report (Day, Campaign, Ad group, Cost, Impr., Clicks; the title lines
    above the header and the "Total" lines are skipped) or any CSV with similar headers.
    The ad name (Google: the ad group) is read as utm_content, mapped to our ad tag for
    X and Google by ``ad_tag_for``; ``utm_campaign`` overrides the campaign name on
    every row. Returns ``(rows, errors)``; a bad row is skipped and reported. A header
    row without a date or spend column is one error naming the columns it expected."""
    source = _clean_tag(utm_source) or None
    headers = _headers_for(source)
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    # (line number in the paste, cells), blank lines left out.
    numbered = [(reader.line_num, ln) for ln in reader if any(c.strip() for c in ln)]
    lines = [ln for _, ln in numbered]
    if not lines:
        return [], ["The CSV has no header row."]
    at = _find_header(lines, headers)
    if at is None:
        return [], [_header_error(lines[0], headers)]
    names = [_norm_header(c) for c in lines[at]]
    errors: list[str] = []
    totals: dict[tuple[date, str, str], dict] = {}
    campaign_override = _clean_tag(utm_campaign)
    for count, (n, cells) in enumerate(numbered[at + 1:], start=1):
        if count > _CSV_MAX_ROWS:
            errors.append(f"Stopped after {_CSV_MAX_ROWS} rows.")
            break
        first = next((c.strip().lower() for c in cells if c.strip()), "")
        if first.startswith("total"):
            continue  # Google's "Total: Campaigns" / "Total: Account" lines
        norm: dict[str, str] = {}
        for name, value in zip(names, cells):
            if name and name not in norm:
                norm[name] = value or ""
        line = f"Line {n}"
        day = _parse_day(_pick(norm, "day", headers))
        spend = _parse_money(_pick(norm, "spend", headers))
        campaign = campaign_override or _clean_tag(_pick(norm, "campaign", headers))
        if day is None:
            errors.append(f"{line}: no readable date (one row per day is needed).")
            continue
        if spend is None:
            errors.append(f"{line}: no readable spend.")
            continue
        if not campaign:
            errors.append(f"{line}: no campaign (set utm_campaign for the whole paste).")
            continue
        content = ad_tag_for(source, _pick(norm, "content", headers))
        key = (day, campaign, content)
        acc = totals.setdefault(key, {
            "day": day, "utm_campaign": campaign, "utm_content": content,
            "utm_source": source, "spend_usd": Decimal(0), "impressions": None,
            "clicks": None, "source": "csv",
        })
        acc["spend_usd"] += spend
        for field in ("impressions", "clicks"):
            v = _parse_int(_pick(norm, field, headers))
            if v is not None:
                acc[field] = min((acc[field] or 0) + v, _COUNT_MAX)
    return list(totals.values()), errors


def _preview_out(row: dict) -> dict:
    return {
        "day": row["day"].isoformat(),
        "utm_source": row["utm_source"],
        "utm_campaign": row["utm_campaign"],
        "utm_content": row["utm_content"] or None,
        "spend_usd": float(row["spend_usd"]),
        "impressions": row["impressions"],
        "clicks": row["clicks"],
    }


async def _save_rows(db: AsyncSession, rows: list[dict]) -> tuple[int, list[str]]:
    """Upsert each row (replacing the stored (day, campaign, ad)), skipping one another
    channel already holds. Returns ``(saved, problems)``."""
    saved = 0
    problems: list[str] = []
    for row in rows:
        label = f"{row['day']} {row['utm_content'] or '(no ad)'}"
        if row["spend_usd"] > _SPEND_MAX:
            problems.append(f"{label}: spend too large.")
            continue
        held = await _channel_clash(db, row)
        if held:
            problems.append(f"{label}: already has spend from {held}; skipped.")
            continue
        await _upsert(db, row)
        saved += 1
    await db.flush()
    return saved, problems


@router.post("/ad-spend/import", dependencies=[Depends(rate_limit_writes)])
async def import_ad_spend(
    body: CsvImportIn,
    request: Request,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Paste a spend CSV (Reddit, X or Google Ads export). Each (day, campaign, ad) row
    replaces the stored one, so pasting the same export twice changes nothing.
    ``dry_run=true`` returns the parsed ``rows`` and saves nothing."""
    require_admin(current_entity)
    rows, errors = parse_spend_csv(body.csv, body.utm_campaign, body.utm_source)
    if body.dry_run:
        return {"rows": [_preview_out(r) for r in rows[:500]], "row_count": len(rows),
                "errors": errors[:50]}
    imported, problems = await _save_rows(db, rows)
    errors += problems
    await log_action(
        db, action="admin.ad_spend.import", entity_id=current_entity.id,
        resource_type="ad_spend",
        details={"channel": _clean_tag(body.utm_source) or None, "rows": len(rows),
                 "imported": imported, "skipped": len(problems)},
        ip_address=_get_client_ip(request)[:45],
    )
    return {"imported": imported, "errors": errors[:50]}


# --- Machine ingest (Google Ads Script) -------------------------------------------

INGEST_TOKEN_HEADER = "X-Ad-Spend-Token"
_INGEST_TOKEN_MIN = 32
_INGEST_PER_MINUTE = 10
_INGEST_MAX_ROWS = 2000
_INGEST_MAX_AGE_DAYS = 400
_INGEST_SOURCE = {"google": "google_ads"}  # ad_spend.source per channel; else "ingest"
_warned_short_token = False


async def _require_ingest_token(request: Request) -> None:
    """404 while AD_SPEND_INGEST_TOKEN is unset (or too short to trust), 429 past
    ``_INGEST_PER_MINUTE`` calls per IP, 401 unless the header matches (constant time).
    Runs before the body is validated, so a caller without the token learns nothing."""
    global _warned_short_token
    from src.config import settings

    token = (settings.ad_spend_ingest_token or "").strip()
    if len(token) < _INGEST_TOKEN_MIN:
        if token and not _warned_short_token:
            logger.warning("AD_SPEND_INGEST_TOKEN is shorter than %d characters; the "
                           "ad spend ingest endpoint stays disabled.", _INGEST_TOKEN_MIN)
            _warned_short_token = True
        raise HTTPException(status_code=404, detail="Not Found")
    ip = _get_client_ip(request)
    if not await _limiter.check(f"ad-spend-ingest:{ip}", _INGEST_PER_MINUTE):
        raise HTTPException(status_code=429, detail="Rate limit exceeded",
                            headers=_rate_limit_response(0, _INGEST_PER_MINUTE))
    given = request.headers.get(INGEST_TOKEN_HEADER) or ""
    if not hmac.compare_digest(given.encode("utf-8"), token.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid or missing token")


class IngestRow(BaseModel):
    """One day of one ad group (or ad) as the ad platform reports it."""

    model_config = ConfigDict(extra="forbid")

    day: date
    campaign: str = Field(..., min_length=1, max_length=_TAG_MAX)
    # The platform's ad group name (mapped by ad_tag_for) or our ad tag outright. One
    # of them, or neither for campaign-level spend.
    ad_group: str | None = Field(None, max_length=_TAG_MAX)
    ad_tag: str | None = Field(None, max_length=_TAG_MAX)
    cost: Decimal = Field(..., ge=0, le=_SPEND_MAX, max_digits=12, decimal_places=2)
    impressions: int = Field(0, ge=0, le=_COUNT_MAX)
    clicks: int = Field(0, ge=0, le=_COUNT_MAX)

    @field_validator("day")
    @classmethod
    def _day_in_range(cls, v: date) -> date:
        today = datetime.now(timezone.utc).date()
        # +1: an account time zone ahead of UTC can already be on tomorrow.
        if not today - timedelta(days=_INGEST_MAX_AGE_DAYS) <= v <= today + timedelta(days=1):
            raise ValueError(f"day must be within the last {_INGEST_MAX_AGE_DAYS} days")
        return v

    @field_validator("campaign")
    @classmethod
    def _campaign_not_blank(cls, v: str) -> str:
        v = _clean_tag(v)
        if not v:
            raise ValueError("campaign is required")
        return v


class IngestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str = Field("google", pattern=r"^[a-z0-9][a-z0-9_.-]{0,31}$")
    rows: list[IngestRow] = Field(..., max_length=_INGEST_MAX_ROWS)


def ingest_rows(body: IngestIn) -> list[dict]:
    """IngestIn -> upsert rows, summed per (day, campaign, ad tag)."""
    channel = channel_of(body.channel)
    totals: dict[tuple[date, str, str], dict] = {}
    for r in body.rows:
        tag = _clean_tag(r.ad_tag) if r.ad_tag else ad_tag_for(channel, r.ad_group)
        acc = totals.setdefault((r.day, r.campaign, tag), {
            "day": r.day, "utm_campaign": r.campaign, "utm_content": tag,
            "utm_source": channel, "spend_usd": Decimal(0), "impressions": 0, "clicks": 0,
            "source": _INGEST_SOURCE.get(channel, "ingest"),
        })
        acc["spend_usd"] += r.cost
        acc["impressions"] = min(acc["impressions"] + r.impressions, _COUNT_MAX)
        acc["clicks"] = min(acc["clicks"] + r.clicks, _COUNT_MAX)
    return list(totals.values())


@router.post("/ad-spend/ingest", dependencies=[Depends(_require_ingest_token)])
async def ingest_ad_spend(
    body: IngestIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Machine ingest of daily spend per ad group (the nightly Google Ads Script).
    Header ``X-Ad-Spend-Token`` must match AD_SPEND_INGEST_TOKEN. Each (day, campaign,
    ad tag) replaces the stored row, so re-sending the last 7 days every night picks up
    the platform's late adjustments and never duplicates."""
    rows = ingest_rows(body)
    imported, problems = await _save_rows(db, rows)
    days = sorted({r["day"] for r in rows})
    await log_action(
        db, action="admin.ad_spend.ingest", entity_id=None, resource_type="ad_spend",
        details={"channel": channel_of(body.channel), "received": len(body.rows),
                 "rows": len(rows), "imported": imported, "skipped": len(problems),
                 "first_day": days[0].isoformat() if days else None,
                 "last_day": days[-1].isoformat() if days else None},
        ip_address=_get_client_ip(request)[:45],
    )
    return {"received": len(body.rows), "imported": imported, "skipped": problems[:50]}


# --- Cost per action ------------------------------------------------------------


def _cost(total: Decimal, n: int) -> float | None:
    return round(float(total) / n, 2) if n and total else None


async def _cost_view(
    db: AsyncSession, days: int, want: str | None, by_source: bool, offset_days: int = 0,
) -> tuple[list[dict], dict]:
    """``(rows, total)``: spend ÷ funnel per utm_content (or per channel) over ``days``
    UTC days ending ``offset_days`` days ago (0 = today included)."""
    from src.api.analytics_router import campaign_rows

    def key_of(source: str | None, content: str | None) -> str:
        return channel_of(source) if by_source else (content or "")

    funnel: dict[str, dict] = {}
    for r in await campaign_rows(db, days, offset_days):
        if want and r.campaign != want:
            continue
        acc = funnel.setdefault(key_of(r.source, r.content),
                                {"sessions": 0, "lp_view": 0, "copy_plugin_cmd": 0})
        acc["sessions"] += r.sessions
        acc["lp_view"] += r.lp_view
        acc["copy_plugin_cmd"] += r.copy_plugin_cmd

    start = _window_start(days + offset_days)
    q = select(AdSpend).where(
        AdSpend.day >= start, AdSpend.day < start + timedelta(days=days))
    if want:
        q = q.where(AdSpend.utm_campaign == want)
    spend: dict[str, dict] = {}
    for s in (await db.execute(q)).scalars().all():
        acc = spend.setdefault(key_of(s.utm_source, s.utm_content), {
            "spend": Decimal(0), "impressions": 0, "clicks": 0})
        acc["spend"] += s.spend_usd
        acc["impressions"] += s.impressions or 0
        acc["clicks"] += s.clicks or 0

    keys = set(funnel) | set(spend) | (set(CHANNELS) if by_source else set())
    rows = []
    for key in sorted(keys):
        f = funnel.get(key, {"sessions": 0, "lp_view": 0, "copy_plugin_cmd": 0})
        sp = spend.get(key, {"spend": Decimal(0), "impressions": 0, "clicks": 0})
        rows.append({
            **({"channel": key, "label": CHANNEL_LABELS.get(key, key)} if by_source
               else {"utm_content": key or None}),
            "spend_usd": float(sp["spend"]),
            "impressions": sp["impressions"],
            "clicks": sp["clicks"],
            **f,
            "cost_per_lp_view": _cost(sp["spend"], f["lp_view"]),
            "cost_per_copy_plugin_cmd": _cost(sp["spend"], f["copy_plugin_cmd"]),
        })
    rows.sort(key=lambda r: (-r["spend_usd"], -r["lp_view"]))
    tot_spend = sum((sp["spend"] for sp in spend.values()), Decimal(0))
    tot_lp = sum(f["lp_view"] for f in funnel.values())
    tot_copy = sum(f["copy_plugin_cmd"] for f in funnel.values())
    total = {
        "spend_usd": float(tot_spend),
        "sessions": sum(f["sessions"] for f in funnel.values()),
        "lp_view": tot_lp,
        "copy_plugin_cmd": tot_copy,
        "cost_per_lp_view": _cost(tot_spend, tot_lp),
        "cost_per_copy_plugin_cmd": _cost(tot_spend, tot_copy),
    }
    return rows, total


@router.get("/ad-spend/cost-per-action", dependencies=[Depends(rate_limit_reads)])
async def cost_per_action(
    days: int = Query(14, ge=1, le=90),
    campaign: str | None = Query(None, max_length=_TAG_MAX),
    group_by: str = Query("content", pattern="^(content|source)$"),
    previous: bool = Query(False),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Spend ÷ funnel per utm_content (``group_by=content``, the default) or per channel
    (``group_by=source``: utm_source, lowercased, twitter folded into x; reddit, x and
    google always listed) for one campaign (or all), over ``days``.

    Spend is summed over the last ``days`` UTC days; the funnel is the same window of
    ``/analytics/attribution/campaigns`` (distinct non-bot sessions by first touch).
    A cost is null when its action count is zero. Spend entered without a
    utm_content joins the "(no content)" row. ``previous=true`` adds ``previous``: the
    same totals for the ``days`` before, for a change-vs-last-period readout."""
    # Read-only metric: a viewer may read it (masked). The spend list and every write
    # above keep require_admin.
    viewer = require_admin_or_viewer(current_entity)
    want = _clean_tag(campaign) or None
    by_source = group_by == "source"
    rows, total = await _cost_view(db, days, want, by_source)
    out: dict = {"days": days, "campaign": want, "group_by": group_by,
                 "rows": rows, "total": total}
    if previous:
        _, out["previous"] = await _cost_view(db, days, want, by_source, offset_days=days)
    return viewer_safe(out, viewer)
