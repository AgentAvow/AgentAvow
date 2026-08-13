"""Centralized SSRF validation for all URL-accepting endpoints.

Uses Python's ipaddress module for proper IP range checking instead
of fragile startswith() string matching.  Includes DNS rebinding
protection: hostnames are resolved and their IPs checked against
blocked ranges before any HTTP request is made.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Hostnames that always resolve to loopback/internal
_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
})


def _is_blocked_ip(hostname: str) -> bool:
    """Check if a hostname is an IP address pointing to a blocked range."""
    # Strip IPv6 brackets
    clean = hostname.strip("[]")
    try:
        addr = ipaddress.ip_address(clean)
    except ValueError:
        return False

    return (
        addr.is_private        # RFC1918 (10/8, 172.16/12, 192.168/16) + IPv6 fc00::/7
        or addr.is_loopback    # 127.0.0.0/8, ::1
        or addr.is_link_local  # 169.254.0.0/16, fe80::/10
        or addr.is_multicast   # 224.0.0.0/4, ff00::/8
        or addr.is_reserved    # other IANA reserved
        or addr.is_unspecified  # 0.0.0.0, ::
        or _in_cgnat(addr)     # 100.64.0.0/10 (carrier-grade NAT)
    )


def _in_cgnat(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if address falls in CGNAT range (100.64.0.0/10)."""
    if isinstance(addr, ipaddress.IPv4Address):
        return addr in ipaddress.IPv4Network("100.64.0.0/10")
    return False


def validate_url(url: str, *, field_name: str = "url") -> str:
    """Validate a URL is not pointing to internal/private addresses.

    Args:
        url: The URL to validate.
        field_name: Name of the field for error messages.

    Returns:
        The validated URL string.

    Raises:
        ValueError: If the URL points to an internal address or has
            an invalid scheme.
    """
    if not url.startswith(("https://", "http://")):
        raise ValueError(f"{field_name} must use http:// or https:// scheme")

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise ValueError(f"{field_name} must contain a valid hostname")

    # Check blocked hostnames
    if hostname in _BLOCKED_HOSTNAMES:
        raise ValueError(f"{field_name} cannot point to internal addresses")

    # Check if hostname is an IP in a blocked range
    if _is_blocked_ip(hostname):
        raise ValueError(f"{field_name} cannot point to internal addresses")

    # DNS rebinding protection: resolve the hostname and verify the resolved
    # IPs are not in blocked ranges.  This prevents an attacker from pointing
    # a DNS name at 127.0.0.1 or an internal service.
    if not _is_blocked_ip(hostname):  # skip if already checked as IP literal
        _check_resolved_ips(hostname, field_name)

    return url


def _check_resolved_ips(hostname: str, field_name: str) -> None:
    """Resolve a hostname via DNS and reject if any address is blocked."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        # DNS resolution failed — let the downstream HTTP client handle it
        logger.debug("DNS resolution failed for %s, skipping rebind check", hostname)
        return

    for family, _type, _proto, _canonname, sockaddr in results:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
            or _in_cgnat(addr)
        ):
            raise ValueError(
                f"{field_name} resolves to a blocked internal address"
            )


def validate_url_https(url: str, *, field_name: str = "url") -> str:
    """Like validate_url but requires https:// scheme."""
    if not url.startswith("https://"):
        raise ValueError(f"{field_name} must use https:// scheme")

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise ValueError(f"{field_name} must contain a valid hostname")

    if hostname in _BLOCKED_HOSTNAMES:
        raise ValueError(f"{field_name} cannot point to internal addresses")

    if _is_blocked_ip(hostname):
        raise ValueError(f"{field_name} cannot point to internal addresses")

    # DNS rebinding protection
    if not _is_blocked_ip(hostname):
        _check_resolved_ips(hostname, field_name)

    return url


def _ip_is_blocked(ip_str: str) -> bool:
    """True if a resolved IP string is in a blocked range (or unparseable)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # can't parse → refuse
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
        or _in_cgnat(addr)
    )


def resolve_and_validate(hostname: str, *, field_name: str = "url") -> list[str]:
    """Resolve a hostname and return its SAFE public IPs (raising if ANY is blocked).
    Returns ``[]`` if resolution fails, so the caller can let the HTTP client surface
    the DNS error naturally. Powers the pinned transport below."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    ips: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in results:
        ip_str = sockaddr[0]
        if _ip_is_blocked(ip_str):
            raise ValueError(f"{field_name} resolves to a blocked internal address")
        if ip_str not in ips:
            ips.append(ip_str)
    return ips


def build_ssrf_safe_transport(**transport_kwargs):
    """An httpx AsyncHTTPTransport that closes the DNS-rebind TOCTOU: it resolves +
    validates the host ONCE and connects to that exact validated IP, preserving the
    Host header and TLS SNI (cert still verified against the original hostname). Without
    this, the guard's pre-flight IP check and httpx's own connect-time resolution are
    two separate lookups — an attacker's DNS can pass the check then rebind to
    127.0.0.1/169.254.169.254 for the real connection."""
    import httpx

    class _SsrfSafeTransport(httpx.AsyncHTTPTransport):
        async def handle_async_request(self, request):
            host = request.url.host or ""
            # IP-literal host: validate directly, no resolution/rebind possible.
            try:
                ipaddress.ip_address(host.strip("[]"))
                if _ip_is_blocked(host.strip("[]")):
                    raise ValueError(f"blocked internal address: {host}")
                return await super().handle_async_request(request)
            except ValueError as exc:
                if "blocked" in str(exc):
                    raise
                # not an IP literal → resolve, validate, and PIN to the safe IP.
            ips = resolve_and_validate(host, field_name="url")
            if not ips:
                return await super().handle_async_request(request)  # DNS failed; let httpx error
            # Connect to the validated IP; keep the original Host header (set at Request
            # creation) and force TLS SNI + cert verification against the real hostname.
            request.url = request.url.copy_with(host=ips[0])
            request.extensions = {**request.extensions, "sni_hostname": host}
            return await super().handle_async_request(request)

    return _SsrfSafeTransport(**transport_kwargs)


def ssrf_safe_async_client(**client_kwargs):
    """``httpx.AsyncClient`` wired with the rebind-safe transport (see above). Use for
    any fetch to a USER-SUPPLIED URL (e.g. a live MCP endpoint)."""
    import httpx

    return httpx.AsyncClient(transport=build_ssrf_safe_transport(), **client_kwargs)


def validate_url_optional(
    url: str | None, *, field_name: str = "url",
) -> str | None:
    """Validate URL if present, pass through None."""
    if url is None:
        return None
    return validate_url(url, field_name=field_name)


def validate_url_https_optional(
    url: str | None, *, field_name: str = "url",
) -> str | None:
    """Validate HTTPS URL if present, pass through None."""
    if url is None:
        return None
    return validate_url_https(url, field_name=field_name)
