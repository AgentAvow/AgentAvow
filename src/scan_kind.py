"""What a public scan-API request was: a check of some kind, a render, or a read.

``scan_request`` counts every answered request under ``/api/v1/public/scan`` (and,
by prefix, ``/api/v1/public/scan-catalog``), so README badge renders and catalog
browsing used to sit in the same number as real checks. This buckets a request by
its path so the dashboard can show checks by kind with renders split out.

Kinds:
  checks   repo, package, mcp, skill, a2a, erc8004, wallet, submit, x402
  renders  badge, card, og, verdict_json
  other    preflight, drift_feed, registry_snippet, catalog, read (history, checks,
           collection, adoption, categories), beacon

x402 has no on-demand scan endpoint: an x402 listing is looked up through the
catalog with ``surface=x402``, so that is what the x402 kind counts.
"""
from __future__ import annotations

SCAN_KIND_PREFIXES = (
    "/api/v1/public/scan",          # also matches /api/v1/public/scan-catalog
    "/api/v1/public/preflight/",
    "/api/v1/public/drift/",
    "/api/v1/public/registry-snippet/",
)

CHECK_KINDS = ("repo", "package", "mcp", "skill", "a2a", "erc8004", "wallet", "submit", "x402")
RENDER_KINDS = ("badge", "card", "og", "verdict_json")
OTHER_KINDS = ("preflight", "drift_feed", "registry_snippet", "catalog", "read", "beacon")
SCAN_KINDS = CHECK_KINDS + RENDER_KINDS + OTHER_KINDS

_READ_SUFFIXES = ("/history", "/checks", "/collection", "/adoption")


def scan_kind(path: str | None, query: str | None = None) -> str | None:
    """The kind for a request path (and query string), or None when the path is not
    a public scan / preflight request."""
    p = (path or "").rstrip("/")
    if not p.startswith(SCAN_KIND_PREFIXES):
        return None
    if p.startswith("/api/v1/public/preflight/"):
        return "preflight"
    if p.startswith("/api/v1/public/drift/"):
        return "drift_feed"
    if p.startswith("/api/v1/public/registry-snippet/"):
        return "registry_snippet"
    if p.startswith("/api/v1/public/scan-catalog"):
        params = {kv.split("=", 1)[0]: kv.split("=", 1)[-1] for kv in (query or "").split("&")}
        return "x402" if params.get("surface", "").lower() == "x402" else "catalog"
    if not p.startswith("/api/v1/public/scan"):
        return None
    rest = p[len("/api/v1/public/scan"):]
    if rest == "" or rest == "/categories" or rest == "/adoption":
        return "read"
    if rest.startswith("/beacon/"):
        return "beacon"
    if rest in ("/og.png",) or rest.endswith("/og-image"):
        return "og"
    if rest.endswith("/badge"):
        return "badge"
    if rest.endswith("/card.svg"):
        return "card"
    if rest.endswith("/verdict.json"):
        return "verdict_json"
    if rest.endswith(_READ_SUFFIXES):
        return "read"
    if rest.startswith("/erc8004/"):
        return "erc8004"
    if rest.startswith("/wallet/"):
        return "wallet"
    if rest == "/submit":
        return "submit"
    if rest == "/a2a":
        return "a2a"
    if rest == "/mcp":
        return "mcp"
    if rest.startswith("/skill/"):
        return "skill"
    if rest.startswith("/package/"):
        return "package"
    if rest.count("/") == 2:  # /{owner}/{repo}
        return "repo"
    return "read"
