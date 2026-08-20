"""Bluesky adapter using the AT Protocol via httpx.

Free, growing dev audience. No API cost.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from src.marketing.adapters.base import (
    AbstractPlatformAdapter,
    EngagementMetrics,
    ExternalPostResult,
    Mention,
)
from src.marketing.config import marketing_settings

logger = logging.getLogger(__name__)

_PDS_URL = "https://bsky.social/xrpc"
_TIMEOUT = 15.0


class BlueskyAdapter(AbstractPlatformAdapter):
    platform_name = "bluesky"
    max_content_length = 300
    supports_replies = True
    supports_monitoring = True
    rate_limit_posts_per_hour = 30
    rate_limit_replies_per_hour = 50

    _access_jwt: str | None = None
    _did: str | None = None

    async def is_configured(self) -> bool:
        return bool(
            marketing_settings.bluesky_handle
            and marketing_settings.bluesky_app_password
        )

    async def _ensure_session(self) -> bool:
        """Create or refresh ATP session."""
        if self._access_jwt:
            return True

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{_PDS_URL}/com.atproto.server.createSession",
                    json={
                        "identifier": marketing_settings.bluesky_handle,
                        "password": marketing_settings.bluesky_app_password,
                    },
                )
                resp.raise_for_status()
                data = resp.json()

            self._access_jwt = data["accessJwt"]
            self._did = data["did"]
            return True
        except Exception as exc:
            logger.warning(
                "Bluesky session creation failed: %s", exc,
            )
            return False

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self._access_jwt}"}

    async def _upload_image(
        self, image_path: str,
    ) -> dict | None:
        """Upload an image blob to Bluesky, return the blob ref."""
        try:
            with open(image_path, "rb") as f:
                image_data = f.read()

            async with httpx.AsyncClient(
                timeout=30.0,
            ) as client:
                resp = await client.post(
                    f"{_PDS_URL}/com.atproto.repo.uploadBlob",
                    content=image_data,
                    headers={
                        **self._auth_headers(),
                        "Content-Type": "image/png",
                    },
                )
                resp.raise_for_status()
                return resp.json().get("blob")
        except Exception as exc:
            logger.warning(
                "Bluesky image upload failed: %s", exc,
            )
            return None

    async def post(self, content: str, metadata: dict | None = None) -> ExternalPostResult:
        if not await self._ensure_session():
            return ExternalPostResult(success=False, error="Bluesky auth failed")

        now = datetime.now(timezone.utc).isoformat()
        record: dict = {
            "$type": "app.bsky.feed.post",
            "text": self.truncate(content),
            "createdAt": now,
        }

        # Add reply reference if provided
        if metadata and metadata.get("reply_to"):
            record["reply"] = metadata["reply_to"]

        # Detect and add link facets
        facets = _extract_link_facets(content)
        if facets:
            record["facets"] = facets

        # Attach image if provided
        image_path = (
            metadata.get("image_path") if metadata else None
        )
        if image_path:
            blob = await self._upload_image(image_path)
            if blob:
                record["embed"] = {
                    "$type": "app.bsky.embed.images",
                    "images": [{
                        "alt": "AgentAvow — trust infrastructure "
                               "for AI agents",
                        "image": blob,
                        "aspectRatio": {
                            "width": 1200,
                            "height": 630,
                        },
                    }],
                }

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{_PDS_URL}/com.atproto.repo.createRecord",
                    json={
                        "repo": self._did,
                        "collection": "app.bsky.feed.post",
                        "record": record,
                    },
                    headers=self._auth_headers(),
                )

            if resp.status_code == 429:
                return ExternalPostResult(
                    success=False, error="Rate limited", rate_limited=True,
                )

            resp.raise_for_status()
            data = resp.json()
            uri = data.get("uri", "")
            # Convert AT URI to web URL
            rkey = uri.split("/")[-1] if uri else ""
            handle = marketing_settings.bluesky_handle or ""
            web_url = f"https://bsky.app/profile/{handle}/post/{rkey}" if rkey else None

            return ExternalPostResult(
                success=True, external_id=uri, url=web_url,
            )
        except httpx.HTTPStatusError as exc:
            logger.warning("Bluesky post failed: %s", exc.response.text[:200])
            return ExternalPostResult(
                success=False, error=f"HTTP {exc.response.status_code}",
            )
        except Exception as exc:
            logger.exception("Bluesky post failed")
            return ExternalPostResult(success=False, error=str(exc))

    async def reply(
        self, parent_id: str, content: str, metadata: dict | None = None,
    ) -> ExternalPostResult:
        # parent_id is an AT URI — need to resolve the CID
        if not await self._ensure_session():
            return ExternalPostResult(success=False, error="Bluesky auth failed")

        # Build reply reference
        reply_ref = metadata.get("reply_ref") if metadata else None
        if not reply_ref:
            # Try to resolve from URI
            reply_ref = await self._resolve_reply_ref(parent_id)
            if not reply_ref:
                return ExternalPostResult(
                    success=False, error="Could not resolve parent post for reply",
                )

        return await self.post(content, metadata={"reply_to": reply_ref})

    async def _resolve_reply_ref(self, uri: str) -> dict | None:
        """Resolve an AT URI to a reply reference structure."""
        try:
            parts = uri.replace("at://", "").split("/")
            if len(parts) < 3:
                return None
            repo, collection, rkey = parts[0], parts[1], parts[2]

            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_PDS_URL}/com.atproto.repo.getRecord",
                    params={"repo": repo, "collection": collection, "rkey": rkey},
                    headers=self._auth_headers(),
                )
                resp.raise_for_status()
                data = resp.json()

            return {
                "root": {"uri": uri, "cid": data["cid"]},
                "parent": {"uri": uri, "cid": data["cid"]},
            }
        except Exception:
            return None

    async def fetch_mentions(self, since: datetime | None = None) -> list[Mention]:
        if not await self._ensure_session():
            return []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_PDS_URL}/app.bsky.notification.listNotifications",
                    params={"limit": 50},
                    headers=self._auth_headers(),
                )
                resp.raise_for_status()
                notifications = resp.json().get("notifications", [])

            mentions: list[Mention] = []
            for notif in notifications:
                if notif.get("reason") in ("mention", "reply"):
                    record = notif.get("record", {})
                    mentions.append(Mention(
                        platform="bluesky",
                        external_id=notif.get("uri", ""),
                        author=notif.get("author", {}).get("handle", ""),
                        content=record.get("text", ""),
                    ))
            return mentions
        except Exception:
            logger.debug("Bluesky mention fetch failed")
            return []

    async def fetch_metrics(self, post_external_id: str) -> EngagementMetrics:
        """Engagement for one post via the public app.bsky.feed.getPosts endpoint.

        ``post_external_id`` is an at:// URI (what post()/reply() return as external_id).
        Returns like/reply/repost counts; empty on any error (never raises)."""
        uri = post_external_id or ""
        if not uri.startswith("at://"):
            return EngagementMetrics()
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://public.api.bsky.app/xrpc/app.bsky.feed.getPosts",
                    params={"uris": uri},
                    timeout=15,
                )
            if resp.status_code != 200:
                return EngagementMetrics()
            posts = resp.json().get("posts", [])
            if not posts:
                return EngagementMetrics()
            p = posts[0]
            return EngagementMetrics(
                likes=p.get("likeCount", 0) or 0,
                comments=p.get("replyCount", 0) or 0,
                shares=p.get("repostCount", 0) or 0,
            )
        except Exception:
            logger.debug("Bluesky fetch_metrics failed for %s", uri, exc_info=True)
            return EngagementMetrics()

    async def health_check(self) -> bool:
        return await self._ensure_session()


def _extract_link_facets(text: str) -> list[dict]:
    """Extract URLs from text and create Bluesky facets.

    Handles both full URLs (https://...) and bare domains
    (agentavow.com/...) since LLMs sometimes strip the protocol.
    """
    import re

    # Match full URLs and bare domain patterns
    url_pattern = re.compile(
        r"https?://\S+"
        r"|(?:agentavow\.com\S*)",
    )
    facets = []
    for match in url_pattern.finditer(text):
        start = match.start()
        end = match.end()
        url = match.group()

        # Ensure the URI has a protocol for the facet
        uri = url if url.startswith("http") else f"https://{url}"

        # Bluesky uses byte offsets
        byte_start = len(text[:start].encode("utf-8"))
        byte_end = len(text[:end].encode("utf-8"))
        facets.append({
            "index": {
                "byteStart": byte_start,
                "byteEnd": byte_end,
            },
            "features": [{
                "$type": "app.bsky.richtext.facet#link",
                "uri": uri,
            }],
        })
    return facets
