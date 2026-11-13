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
  * POST   /admin/ad-spend/import           -> paste a CSV (Reddit Ads export)
  * GET    /admin/ad-spend/cost-per-action  -> spend joined to the funnel per utm_content,
    or per channel (``group_by=source``); ``previous=true`` adds the period before
"""
from __future__ import annotations

import csv
import io
import re
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, require_admin, require_admin_or_viewer
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.api.redaction import viewer_safe
from src.database import get_db
from src.models import AdSpend, Entity

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
_CSV_MAX_BYTES = 512 * 1024
_CSV_MAX_ROWS = 5000
_SPEND_MAX = Decimal("1000000")


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
_HEADERS = {
    "day": ("date", "day", "reportingstarts", "reportdate"),
    "campaign": ("utmcampaign", "campaignname", "campaign"),
    "content": ("utmcontent", "adname", "ad", "adgroupname", "adgroup"),
    "spend": ("amountspentusd", "amountspent", "spendusd", "spend", "cost", "totalspend"),
    "impressions": ("impressions", "impr"),
    "clicks": ("clicks", "linkclicks"),
}
_DATE_FORMATS = ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y", "%d.%m.%Y", "%Y/%m/%d")


def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z]", "", (h or "").lower())


def _pick(norm_row: dict[str, str], field: str) -> str:
    for name in _HEADERS[field]:
        v = norm_row.get(name)
        if v not in (None, ""):
            return v.strip()
    return ""


def _parse_day(raw: str) -> date | None:
    raw = raw.strip()[:32]
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(raw).date()  # "2026-11-17T00:00:00"
    except ValueError:
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


def parse_spend_csv(
    text: str, utm_campaign: str | None = None, utm_source: str | None = None,
) -> tuple[list[dict], list[str]]:
    """Parse a spend CSV into upsert rows, summed per (day, campaign, content).

    Reads a Reddit Ads export (Date, Campaign Name, Ad Group Name, Ad Name,
    Impressions, Clicks, Amount Spent (USD)) or any CSV with similar headers.
    The ad name is read as utm_content; ``utm_campaign`` overrides the campaign name
    on every row. Returns ``(rows, errors)``; a bad row is skipped and reported."""
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    if not reader.fieldnames:
        return [], ["The CSV has no header row."]
    errors: list[str] = []
    totals: dict[tuple[date, str, str], dict] = {}
    campaign_override = _clean_tag(utm_campaign)
    source = _clean_tag(utm_source) or None
    for n, raw in enumerate(reader, start=2):
        if n - 1 > _CSV_MAX_ROWS:
            errors.append(f"Stopped after {_CSV_MAX_ROWS} rows.")
            break
        norm = {_norm_header(k): (v or "") for k, v in raw.items() if k}
        if not any(v.strip() for v in norm.values()):
            continue
        day = _parse_day(_pick(norm, "day"))
        spend = _parse_money(_pick(norm, "spend"))
        campaign = campaign_override or _clean_tag(_pick(norm, "campaign"))
        if day is None:
            errors.append(f"Line {n}: no readable date.")
            continue
        if spend is None:
            errors.append(f"Line {n}: no readable spend.")
            continue
        if not campaign:
            errors.append(f"Line {n}: no campaign (set utm_campaign for the whole paste).")
            continue
        content = _clean_tag(_pick(norm, "content"))
        key = (day, campaign, content)
        acc = totals.setdefault(key, {
            "day": day, "utm_campaign": campaign, "utm_content": content,
            "utm_source": source, "spend_usd": Decimal(0), "impressions": None,
            "clicks": None, "source": "csv",
        })
        acc["spend_usd"] += spend
        for field in ("impressions", "clicks"):
            v = _parse_int(_pick(norm, field))
            if v is not None:
                acc[field] = (acc[field] or 0) + v
    return list(totals.values()), errors


@router.post("/ad-spend/import", dependencies=[Depends(rate_limit_writes)])
async def import_ad_spend(
    body: CsvImportIn,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Paste a spend CSV (Reddit Ads export). Each (day, campaign, ad) row replaces
    the stored one, so pasting the same export twice changes nothing."""
    require_admin(current_entity)
    rows, errors = parse_spend_csv(body.csv, body.utm_campaign, body.utm_source)
    imported = 0
    for row in rows:
        if row["spend_usd"] > _SPEND_MAX:
            errors.append(f"{row['day']} {row['utm_content'] or '(no ad)'}: spend too large.")
            continue
        held = await _channel_clash(db, row)
        if held:
            errors.append(f"{row['day']} {row['utm_content'] or '(no ad)'}: already has spend "
                          f"from {held}; skipped.")
            continue
        await _upsert(db, row)
        imported += 1
    await db.flush()
    return {"imported": imported, "errors": errors[:50]}


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
