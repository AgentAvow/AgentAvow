"""POST /api/v1/public/send-setup: "Email me the setup" for phone visitors.

The Claude Code plugin installs on a computer, so someone who taps an ad on a phone
can't finish the install there. This endpoint sends them ONE fixed email with the two
install commands and a link back to /claude-code. The link carries the ad's UTM tags,
so an install made later on the computer is still credited to the ad.

Privacy: the address is used to send this one email and is never stored. No database
row, no list, and the logs say "<private recipient>" instead of the address (see
``src.email_queue.recipient_for_log``). Rate limiting keys on a keyed hash of the
address, which lives in Redis only as long as its window (a day).

Abuse: per-IP limits (hour and day) and a per-address limit, all on the shared rate
limiter. The email body is fixed: nothing the caller sends appears in it except the
UTM tags, which are allow-listed by name and by a strict character set and only ever
go into the link's query string.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from src.api.rate_limit import _get_client_ip, _limiter, _rate_limit_response
from src.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/public", tags=["public"])

PLUGIN_LINES = (
    "/plugin marketplace add AgentAvow/AgentAvow",
    "/plugin install agentavow-trust@agentavow",
)
SUBJECT = "Your AgentAvow setup for Claude Code"
UTM_FIELDS = ("utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term")
_UTM_VALUE = re.compile(r"^[A-Za-z0-9._~-]{1,64}$")
HOUR = 3600
DAY = 86400


class SendSetupRequest(BaseModel):
    email: EmailStr = Field(..., max_length=254)
    # The ad's tags, from the page's URL or the visitor's first touch. Anything that
    # isn't a known tag name with a plain value is dropped, never echoed.
    utm: dict[str, str] | None = Field(None, max_length=10)


def address_key(email: str) -> str:
    """A keyed hash of the normalized address, for the per-address limit. Keyed with a
    server secret so a copy of Redis can't be checked against a list of addresses."""
    norm = email.strip().lower().encode("utf-8")
    key = ("send-setup|" + settings.jwt_secret).encode("utf-8")
    return hmac.new(key, norm, hashlib.sha256).hexdigest()[:32]


def clean_utm(utm: dict[str, str] | None) -> dict[str, str]:
    """Only the five UTM names, each with a short plain value (letters, digits, . _ ~ -)."""
    out: dict[str, str] = {}
    for name in UTM_FIELDS:
        value = (utm or {}).get(name)
        if isinstance(value, str) and _UTM_VALUE.match(value):
            out[name] = value
    return out


def setup_link(utm: dict[str, str] | None) -> str:
    base = settings.base_url.rstrip("/")
    tags = clean_utm(utm)
    return f"{base}/claude-code" + (f"?{urlencode(tags)}" if tags else "")


def render_setup_email(utm: dict[str, str] | None) -> str:
    from src.email import _load_template

    return _load_template(
        "send_setup.html",
        line_1=PLUGIN_LINES[0],
        line_2=PLUGIN_LINES[1],
        setup_url=setup_link(utm),
        fallback=(
            "Paste these into Claude Code on your computer, one at a time: "
            f"{PLUGIN_LINES[0]} then {PLUGIN_LINES[1]}. Setup page: {setup_link(utm)}"
        ),
    )


async def _limit(key: str, limit: int, window: int) -> None:
    if not await _limiter.check(key, limit, window):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Try again later, or copy the link instead.",
            headers=_rate_limit_response(0, limit, window),
        )


@router.post("/send-setup", status_code=status.HTTP_202_ACCEPTED)
async def send_setup(body: SendSetupRequest, request: Request) -> dict:
    """Email the Claude Code plugin setup to the given address, once. No auth.

    Answers 202 whether or not the provider accepted it right away (the shared email
    queue retries), 422 for a bad address, 429 past a limit, 404 when turned off."""
    if not settings.send_setup_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    ip = _get_client_ip(request)
    await _limit(f"send_setup:ip:h:{ip}", settings.send_setup_per_ip_per_hour, HOUR)
    await _limit(f"send_setup:ip:d:{ip}", settings.send_setup_per_ip_per_day, DAY)
    await _limit(
        f"send_setup:addr:{address_key(str(body.email))}",
        settings.send_setup_per_address_per_day, DAY,
    )

    from src.email import send_email

    ok = await send_email(str(body.email), SUBJECT, render_setup_email(body.utm), private=True)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="We couldn't send the email just now. Copy the link instead.",
        )
    return {"status": "sent"}
