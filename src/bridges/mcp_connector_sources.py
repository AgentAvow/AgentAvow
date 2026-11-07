"""Reviewed maps for sign-in (OAuth) MCP connectors.

A hosted MCP server that needs sign-in hides its ``tools/list`` from an anonymous
scanner, so ``scan_mcp_server`` cannot read it. Two small, hand-reviewed maps let the
tool still give a useful, honest answer:

* ``OFFICIAL_SOURCES`` maps a hosted endpoint to the vendor's OWN published source
  repository. Every entry was checked on GitHub (2026-11-07): the owner is the vendor's
  organization, the repo is not a fork and not archived, and the vendor's README names
  the hosted endpoint. ``relation`` says how the two relate:

  - ``"hosted"``: the vendor publishes this repo as the code of the hosted server.
  - ``"separate"``: the vendor publishes it as a separate, self-hosted MCP server; the
    hosted server's own code is not public, so its tools can differ.

  ``None`` marks a host checked and found to have NO public source for its server, so
  the answer can say so instead of pointing at a stranger's clone.

* ``KNOWN_CONNECTORS`` maps a connector NAME (what claude.ai shows; it never shows the
  URL) to the vendor's documented endpoint, only where that endpoint is certain.
  ``None`` marks a common connector with no endpoint we can name with certainty.

Never add a fork, a community port, or an "unofficial" server here. A change to these
maps changes tool RESULTS only, never the tool contract.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class OfficialSource:
    vendor: str
    repo: str  # GitHub "owner/name"
    relation: str  # "hosted" | "separate"

    @property
    def owner(self) -> str:
        return self.repo.split("/", 1)[0]


# host -> source (or None: checked, no public source). Matched on the exact host; a
# ``path`` prefix narrows a shared host (huggingface.co serves far more than MCP).
_HostKey = tuple[str, str]  # (host, path prefix)

OFFICIAL_SOURCES: dict[_HostKey, OfficialSource | None] = {
    # github/github-mcp-server README: "The remote GitHub MCP Server is hosted by GitHub",
    # url https://api.githubcopilot.com/mcp/
    ("api.githubcopilot.com", "/mcp"): OfficialSource(
        "GitHub", "github/github-mcp-server", "hosted"),
    # getsentry/sentry-mcp README: "This remote MCP server ...", deployed at mcp.sentry.dev
    ("mcp.sentry.dev", ""): OfficialSource("Sentry", "getsentry/sentry-mcp", "hosted"),
    # neondatabase/mcp-server-neon README: "This repository provides a remote MCP Server"
    ("mcp.neon.tech", ""): OfficialSource("Neon", "neondatabase/mcp-server-neon", "hosted"),
    # supabase/mcp (moved from supabase-community/supabase-mcp): README documents
    # https://mcp.supabase.com/mcp and "Self-hosting the MCP endpoint"
    ("mcp.supabase.com", ""): OfficialSource("Supabase", "supabase/mcp", "hosted"),
    # huggingface/hf-mcp-server README: "the official Hugging Face MCP Server",
    # url https://huggingface.co/mcp
    ("huggingface.co", "/mcp"): OfficialSource(
        "Hugging Face", "huggingface/hf-mcp-server", "hosted"),
    # cloudflare/mcp README: "MCP URL: https://mcp.cloudflare.com/mcp"
    ("mcp.cloudflare.com", ""): OfficialSource("Cloudflare", "cloudflare/mcp", "hosted"),
    # makenotion/notion-mcp-server README: "This repository is a separate, self-hosted MCP
    # server"; the hosted Remote Notion MCP is not open source.
    ("mcp.notion.com", ""): OfficialSource(
        "Notion", "makenotion/notion-mcp-server", "separate"),
    # square/square-mcp-server README: Square runs the remote server at
    # mcp.squareup.com; "This repository is the local, self-hosted server".
    ("mcp.squareup.com", ""): OfficialSource(
        "Square", "square/square-mcp-server", "separate"),
    # Checked, no public source for the hosted server:
    # Linear publishes no MCP server repo or package (github.com/linear has none; its
    # MCP-registry entry app.linear/linear lists no repository).
    ("mcp.linear.app", ""): None,
    # atlassian/atlassian-mcp-server holds client config, docs and skills, not the
    # server's code.
    ("mcp.atlassian.com", ""): None,
    # stripe/ai's @stripe/mcp is a client that connects to the hosted server, not its code.
    ("mcp.stripe.com", ""): None,
}

# cloudflare/mcp-server-cloudflare README lists each product server it hosts at
# <product>.mcp.cloudflare.com (docs, containers, browser, ...), one app per directory.
_CLOUDFLARE_PRODUCTS = OfficialSource("Cloudflare", "cloudflare/mcp-server-cloudflare", "hosted")

# Vendor display names for hosts with no public source (for the answer text).
_NO_SOURCE_VENDOR: dict[str, str] = {
    "mcp.linear.app": "Linear",
    "mcp.atlassian.com": "Atlassian",
    "mcp.stripe.com": "Stripe",
}


def _split(url: str) -> tuple[str, str]:
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return "", ""
    host = (parts.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host, parts.path or "/"


def _path_matches(path: str, prefix: str) -> bool:
    if not prefix:
        return True
    return path == prefix or path.startswith(prefix + "/")


_UNMAPPED = object()


def _lookup(url: str):
    host, path = _split(url)
    if not host:
        return _UNMAPPED, host
    for (h, prefix), src in OFFICIAL_SOURCES.items():
        if h == host and _path_matches(path, prefix):
            return src, host
    if host.endswith(".mcp.cloudflare.com"):
        return _CLOUDFLARE_PRODUCTS, host
    return _UNMAPPED, host


def official_source_for(url: str) -> OfficialSource | None:
    """The vendor's own published source for a hosted MCP endpoint, or None."""
    src, _ = _lookup(url)
    return src if isinstance(src, OfficialSource) else None


def no_public_source_vendor(url: str) -> str | None:
    """The vendor's name when this host was checked and has NO public server source."""
    src, host = _lookup(url)
    if src is None:
        return _NO_SOURCE_VENDOR.get(host)
    return None


# --- connector names ---------------------------------------------------------------
@dataclass(frozen=True)
class KnownConnector:
    vendor: str  # the connector's name as people say it
    endpoint: str | None  # None: no endpoint we can name with certainty
    publisher: str = ""  # the company behind it, when not the same word as ``vendor``

    @property
    def company(self) -> str:
        return self.publisher or self.vendor


_KC = KnownConnector
KNOWN_CONNECTORS: dict[str, KnownConnector] = {
    # Endpoints the vendor documents (README / docs checked 2026-11-07).
    "notion": _KC("Notion", "https://mcp.notion.com/mcp"),
    "linear": _KC("Linear", "https://mcp.linear.app/mcp"),
    "github": _KC("GitHub", "https://api.githubcopilot.com/mcp/"),
    "sentry": _KC("Sentry", "https://mcp.sentry.dev/mcp"),
    "atlassian": _KC("Atlassian", "https://mcp.atlassian.com/v2/mcp"),
    "atlassianrovo": _KC("Atlassian", "https://mcp.atlassian.com/v2/mcp"),
    "jira": _KC("Atlassian", "https://mcp.atlassian.com/v2/mcp"),
    "confluence": _KC("Atlassian", "https://mcp.atlassian.com/v2/mcp"),
    "neon": _KC("Neon", "https://mcp.neon.tech/mcp"),
    "supabase": _KC("Supabase", "https://mcp.supabase.com/mcp"),
    "huggingface": _KC("Hugging Face", "https://huggingface.co/mcp"),
    "stripe": _KC("Stripe", "https://mcp.stripe.com"),
    "square": _KC("Square", "https://mcp.squareup.com/mcp"),
    # Common sign-in connectors with no endpoint or published server source we can name
    # with certainty: answer with the next step, never a guess.
    "googledrive": _KC("Google Drive", None, "Google"),
    "gdrive": _KC("Google Drive", None, "Google"),
    "gmail": _KC("Gmail", None, "Google"),
    "googlecalendar": _KC("Google Calendar", None, "Google"),
    "gcal": _KC("Google Calendar", None, "Google"),
    "slack": _KC("Slack", None),
    "asana": _KC("Asana", None),
}

# Words people add to a connector's name that do not change which connector it is.
_NAME_SUFFIXES = ("mcpserver", "connector", "server", "mcp", "app")


def _norm(s: str) -> str:
    return "".join(ch for ch in (s or "").lower() if ch.isalnum())


def known_connector(name: str) -> KnownConnector | None:
    """A connector name ('Notion', 'GitHub MCP', 'Google Drive connector') → the reviewed
    entry, or None. Exact normalized match only (after dropping filler suffixes), so a
    third-party server whose name merely contains a vendor's name never matches."""
    key = _norm(name)
    for _ in range(3):  # "github mcp server app" → "github"
        if key in KNOWN_CONNECTORS:
            return KNOWN_CONNECTORS[key]
        for suffix in _NAME_SUFFIXES:
            if key.endswith(suffix) and len(key) > len(suffix):
                key = key[: -len(suffix)]
                break
        else:
            break
    return KNOWN_CONNECTORS.get(key)
