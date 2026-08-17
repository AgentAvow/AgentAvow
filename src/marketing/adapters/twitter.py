"""Twitter/X v2 API adapter using httpx.

Supports Free tier (write-only, 1500 tweets/mo) and Basic tier ($100/mo).
Uses OAuth 1.0a for tweet creation (user context).
Image uploads use the v1.1 media/upload endpoint (multipart/form-data).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import mimetypes
import time
import urllib.parse
import uuid
from base64 import b64encode
from datetime import datetime
from pathlib import Path

import httpx

from src.marketing.adapters.base import (
    AbstractPlatformAdapter,
    EngagementMetrics,
    ExternalPostResult,
    Mention,
)
from src.marketing.config import marketing_settings

logger = logging.getLogger(__name__)

_API_BASE = "https://api.twitter.com/2"
_MEDIA_UPLOAD_URL = "https://upload.twitter.com/1.1/media/upload.json"
_TIMEOUT = 15.0
_MEDIA_UPLOAD_TIMEOUT = 30.0

# Default logo image — resolve relative to project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DEFAULT_LOGO_PATH = _PROJECT_ROOT / "agentavow-logo-512.png"
# Fallback to marketing assets card if logo not found
_FALLBACK_CARD_PATH = (
    Path(__file__).resolve().parent.parent / "assets" / "card-features.png"
)

# X surfaces write budgets via response headers. The 24h app/user caps are the
# ones that bite regular posting; the MONTHLY tier cap (Free ~1,500/mo) is not in
# a header, so a 403 whose 24h budget still has room usually means that monthly
# cap or an app-permission problem — which is why the plain 403 is ambiguous.
_X_LOW_REMAINING = 10  # warn when this few 24h posts remain


def _extract_x_limits(headers) -> tuple[str, int | None]:
    """Summarize X rate-limit headers and return the tightest 24h remaining
    (or None if X didn't report it). Purely diagnostic — never raises."""
    def _g(k: str) -> int | None:
        v = headers.get(k)
        return int(v) if v not in (None, "") and str(v).lstrip("-").isdigit() else None

    win_rem, win_lim = _g("x-rate-limit-remaining"), _g("x-rate-limit-limit")
    u24_rem, u24_lim = _g("x-user-limit-24hour-remaining"), _g("x-user-limit-24hour-limit")
    a24_rem, a24_lim = _g("x-app-limit-24hour-remaining"), _g("x-app-limit-24hour-limit")
    parts: list[str] = []
    if win_rem is not None:
        parts.append(f"window {win_rem}/{win_lim}")
    if u24_rem is not None:
        parts.append(f"user-24h {u24_rem}/{u24_lim}")
    if a24_rem is not None:
        parts.append(f"app-24h {a24_rem}/{a24_lim}")
    rem_24h = min([r for r in (u24_rem, a24_rem) if r is not None], default=None)
    summary = "limits: " + (", ".join(parts) if parts else "(none reported)")
    return summary, rem_24h


def _classify_x_403(body_text: str, remaining_24h: int | None) -> str:
    """Turn X's generic 403 into a specific, actionable reason."""
    b = (body_text or "").lower()
    if "duplicate" in b:
        return "duplicate content (X rejects identical posts) — vary the text"
    if remaining_24h == 0:
        return "24h post cap reached — resets within a day"
    if "not permitted" in b or "forbidden" in b:
        return ("monthly write cap or app permission — check developer.x.com "
                "usage/limits (Free tier ~1,500 posts/mo) and that the app is Read+Write")
    return "forbidden — check developer.x.com app permissions and usage"


def _reset_human(reset_epoch: str | None) -> str:
    """Format an X rate-limit reset epoch as a readable UTC time."""
    if not reset_epoch or not str(reset_epoch).isdigit():
        return "soon"
    try:
        from datetime import timezone
        return datetime.fromtimestamp(int(reset_epoch), tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC")
    except Exception:
        return "soon"


class TwitterAdapter(AbstractPlatformAdapter):
    platform_name = "twitter"
    max_content_length = 280
    supports_replies = True
    supports_monitoring = True  # Requires Basic tier ($100/mo)
    rate_limit_posts_per_hour = 100
    rate_limit_replies_per_hour = 100

    async def is_configured(self) -> bool:
        return bool(
            marketing_settings.twitter_consumer_key
            and marketing_settings.twitter_consumer_key_secret
            and marketing_settings.twitter_access_token
            and marketing_settings.twitter_access_token_secret
        )

    def _oauth1_header(
        self,
        method: str,
        url: str,
        body: dict | None = None,
        extra_params: dict | None = None,
    ) -> str:
        """Generate OAuth 1.0a Authorization header.

        For JSON body requests (Twitter v2), body params are NOT included
        in the signature base string.  For form-encoded/multipart requests
        (v1.1 media upload), pass relevant params via ``extra_params`` so
        they are included in the signature.
        """
        oauth_params = {
            "oauth_consumer_key": marketing_settings.twitter_consumer_key or "",
            "oauth_nonce": uuid.uuid4().hex,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_token": marketing_settings.twitter_access_token or "",
            "oauth_version": "1.0",
        }

        # Combine params for signature base
        all_params = {**oauth_params}
        if extra_params:
            all_params.update(extra_params)

        param_string = "&".join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(str(v), safe='')}"
            for k, v in sorted(all_params.items())
        )
        base_string = (
            f"{method.upper()}&"
            f"{urllib.parse.quote(url, safe='')}&"
            f"{urllib.parse.quote(param_string, safe='')}"
        )

        signing_key = (
            f"{urllib.parse.quote(marketing_settings.twitter_consumer_key_secret or '', safe='')}&"
            f"{urllib.parse.quote(marketing_settings.twitter_access_token_secret or '', safe='')}"
        )

        signature = b64encode(
            hmac.new(
                signing_key.encode(), base_string.encode(), hashlib.sha1,
            ).digest()
        ).decode()

        oauth_params["oauth_signature"] = signature

        header = "OAuth " + ", ".join(
            f'{urllib.parse.quote(k, safe="")}="{urllib.parse.quote(str(v), safe="")}"'
            for k, v in sorted(oauth_params.items())
        )
        return header

    async def upload_media(
        self,
        image_bytes: bytes,
        mime_type: str = "image/png",
    ) -> str | None:
        """Upload media via Twitter v1.1 media/upload endpoint.

        Returns the ``media_id_string`` on success, or None on failure.
        The v1.1 endpoint uses multipart/form-data with OAuth 1.0a.
        """
        # OAuth 1.0a signature for multipart — binary data is NOT
        # included in the signature base string per the OAuth spec.
        auth_header = self._oauth1_header("POST", _MEDIA_UPLOAD_URL)

        try:
            async with httpx.AsyncClient(
                timeout=_MEDIA_UPLOAD_TIMEOUT,
            ) as client:
                resp = await client.post(
                    _MEDIA_UPLOAD_URL,
                    files={
                        "media_data": (
                            "image.png",
                            b64encode(image_bytes),
                            mime_type,
                        ),
                    },
                    headers={"Authorization": auth_header},
                )

            if resp.status_code == 429:
                logger.warning("Twitter media upload rate limited")
                return None

            resp.raise_for_status()
            media_id = resp.json().get("media_id_string")
            if media_id:
                logger.info("Twitter media uploaded: %s", media_id)
            return media_id
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "Twitter media upload failed: %s %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
            return None
        except Exception:
            logger.exception("Twitter media upload failed")
            return None

    def _resolve_default_image(self) -> str | None:
        """Return the path to the default logo image, or None."""
        if _DEFAULT_LOGO_PATH.exists():
            return str(_DEFAULT_LOGO_PATH)
        if _FALLBACK_CARD_PATH.exists():
            return str(_FALLBACK_CARD_PATH)
        return None

    async def post(self, content: str, metadata: dict | None = None) -> ExternalPostResult:
        """Post a tweet, optionally with an image attachment.

        Image resolution order:
        1. ``metadata["image_bytes"]`` — raw bytes + optional ``metadata["image_mime"]``
        2. ``metadata["image_path"]`` — path to an image file on disk
        3. Default logo image (``agentgraph-logo-512.png`` or fallback card)

        If image upload fails, the tweet is still posted without media.
        """
        url = f"{_API_BASE}/tweets"
        body: dict = {"text": self.truncate(content)}

        # If replying in a thread
        if metadata and metadata.get("reply_to"):
            body["reply"] = {"in_reply_to_tweet_id": metadata["reply_to"]}

        # --- Resolve and upload image ---
        media_id = await self._resolve_and_upload_image(metadata)
        if media_id:
            body["media"] = {"media_ids": [media_id]}

        auth_header = self._oauth1_header("POST", url)

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    url, json=body,
                    headers={
                        "Authorization": auth_header,
                        "Content-Type": "application/json",
                    },
                )

            limits_str, remaining_24h = _extract_x_limits(resp.headers)

            if resp.status_code == 429:
                when = _reset_human(resp.headers.get("x-rate-limit-reset"))
                logger.warning("Twitter 429 rate limited; resets %s (%s)", when, limits_str)
                return ExternalPostResult(
                    success=False,
                    error=f"Rate limited by X — resets {when} ({limits_str})",
                    rate_limited=True,
                )

            if resp.status_code == 403:
                reason = _classify_x_403(resp.text, remaining_24h)
                logger.warning("Twitter 403: %s | %s | body=%s",
                               reason, limits_str, resp.text[:200])
                return ExternalPostResult(
                    success=False,
                    error=f"X 403 — {reason} ({limits_str})",
                    rate_limited=(remaining_24h == 0),
                )

            resp.raise_for_status()
            data = resp.json().get("data", {})
            tweet_id = data.get("id")

            # Proactively warn as the 24h write budget runs down (early alert
            # before posts start failing outright).
            if remaining_24h is not None and remaining_24h <= _X_LOW_REMAINING:
                logger.warning("Twitter 24h post budget low: %s remaining (%s)",
                               remaining_24h, limits_str)

            return ExternalPostResult(
                success=True,
                external_id=tweet_id,
                url=f"https://x.com/i/status/{tweet_id}" if tweet_id else None,
            )
        except httpx.HTTPStatusError as exc:
            limits_str, _ = _extract_x_limits(exc.response.headers)
            logger.warning(
                "Twitter post failed: %s %s | %s",
                exc.response.status_code, exc.response.text, limits_str,
            )
            return ExternalPostResult(
                success=False,
                error=f"HTTP {exc.response.status_code}: "
                      f"{exc.response.text[:200]}",
            )
        except Exception as exc:
            logger.exception("Twitter post failed")
            return ExternalPostResult(success=False, error=str(exc))

    async def _resolve_and_upload_image(
        self, metadata: dict | None,
    ) -> str | None:
        """Resolve image from metadata or default, upload, return media_id."""
        image_bytes: bytes | None = None
        mime_type = "image/png"

        # 1. Explicit bytes in metadata
        if metadata and metadata.get("image_bytes"):
            image_bytes = metadata["image_bytes"]
            mime_type = metadata.get("image_mime", "image/png")

        # 2. File path in metadata
        elif metadata and metadata.get("image_path"):
            image_bytes, mime_type = self._read_image_file(
                metadata["image_path"],
            )

        # 3. Default logo / fallback card
        else:
            default_path = self._resolve_default_image()
            if default_path:
                image_bytes, mime_type = self._read_image_file(default_path)

        if not image_bytes:
            return None

        return await self.upload_media(image_bytes, mime_type)

    @staticmethod
    def _read_image_file(path: str) -> tuple[bytes | None, str]:
        """Read an image file and guess its MIME type."""
        try:
            with open(path, "rb") as f:
                data = f.read()
            mime, _ = mimetypes.guess_type(path)
            return data, mime or "image/png"
        except Exception:
            logger.warning("Could not read image file: %s", path)
            return None, "image/png"

    async def reply(
        self, parent_id: str, content: str, metadata: dict | None = None,
    ) -> ExternalPostResult:
        return await self.post(content, metadata={"reply_to": parent_id, **(metadata or {})})

    async def fetch_mentions(self, since: datetime | None = None) -> list[Mention]:
        """Fetch mentions — requires Bearer token (Basic tier)."""
        if not marketing_settings.twitter_bearer_token:
            return []

        # Would use search/recent endpoint with query "@agentavow"
        # Skipping for free tier — implement when upgrading
        return []

    async def fetch_metrics(self, post_external_id: str) -> EngagementMetrics:
        """Fetch tweet metrics — requires Basic tier."""
        if not marketing_settings.twitter_bearer_token:
            return EngagementMetrics()

        url = f"{_API_BASE}/tweets/{post_external_id}"
        params = {"tweet.fields": "public_metrics"}

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    url, params=params,
                    headers={"Authorization": f"Bearer {marketing_settings.twitter_bearer_token}"},
                )
                resp.raise_for_status()
                metrics = resp.json().get("data", {}).get("public_metrics", {})

            return EngagementMetrics(
                likes=metrics.get("like_count", 0),
                comments=metrics.get("reply_count", 0),
                shares=metrics.get("retweet_count", 0),
                impressions=metrics.get("impression_count", 0),
            )
        except Exception:
            logger.debug("Failed to fetch Twitter metrics for %s", post_external_id)
            return EngagementMetrics()

    async def health_check(self) -> bool:
        if not await self.is_configured():
            return False
        # Lightweight check — just verify credentials parse
        return True
