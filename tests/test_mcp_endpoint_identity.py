"""An MCP endpoint's identity is scheme, host and path: credentials in the URL are never
fetched, cached, signed into a subject or published (src/ssrf.mcp_endpoint_identity)."""
from __future__ import annotations

import pytest

from src.ssrf import CredentialedURLError, mcp_endpoint_identity


@pytest.mark.parametrize("url, want", [
    ("https://mcp.deepwiki.com/mcp", "https://mcp.deepwiki.com/mcp"),
    ("https://alice:s3cret@mcp.example.com/mcp", "https://mcp.example.com/mcp"),
    ("https://mcp.example.com/mcp?token=sk_live_abc123&tenant=acme", "https://mcp.example.com/mcp"),
    ("https://mcp.example.com/mcp#frag", "https://mcp.example.com/mcp"),
    ("https://MCP.Example.com:8443/v1/mcp", "https://mcp.example.com:8443/v1/mcp"),
    ("https://docs.mcp.cloudflare.com/mcp", "https://docs.mcp.cloudflare.com/mcp"),
    ("https://api.example.com/2026-07-28/mcp", "https://api.example.com/2026-07-28/mcp"),
])
def test_credentials_are_dropped_and_the_server_identity_kept(url, want):
    assert mcp_endpoint_identity(url) == want


@pytest.mark.parametrize("url", [
    "https://mcp.example.com/mcp/0f8fad5b-d9cb-469f-a165-70867728950e",
    "https://mcp.example.com/v1/sk9Xq2LmT7vB4nR8wZ3yK6pD1hF5jC0aE",
    "https://mcp.example.com/u/abc123def456ghi7/mcp",
])
def test_a_key_in_the_path_is_refused_not_stripped(url):
    with pytest.raises(CredentialedURLError):
        mcp_endpoint_identity(url)
