"""MCP icon checks: findings for the ``icons`` a server attaches to its tools,
resources, prompts and implementation info, and an unsigned icon fingerprint for
the watch loop.

MCP 2025-11-25 lets a tool (and a resource, prompt or the server's ``serverInfo``)
carry ``icons``: ``[{src, mimeType?, sizes?, theme?}]`` where ``src`` is an https
URL or a ``data:`` URI. The signed per-tool digest (``agentavow.mcp-tool-definition.v1``)
does not hash icons, and it stays that way (Kenne, 2026-10-19): an icon can change
after a tool was approved without changing the digest. So icons are graded here as
findings, and their change is watched through a separate, unsigned fingerprint
(``compute_icon_fingerprint``) that never enters ``tool_manifest_digest``, the per-tool
digests or the attestation.

Nothing here fetches anything. A ``data:`` URI is decoded and read inline; a remote
URL is classified by its scheme and host only.

Severities (none is critical, so icons alone never read Do not connect; a plain
PNG/SVG on the server's own domain gets no finding):

* high   ``icon carries active content`` — an SVG/HTML icon with ``<script>``, an
         ``on*=`` event handler, a ``javascript:``/``vbscript:`` link, or an embedded
         frame (``<iframe>``/``<embed>``/``<object>``); also a ``javascript:`` src.
         No icon needs any of these; a client that renders the icon inline runs it.
         High (Review), not critical: most clients draw icons through ``<img>``, which
         does not run scripts, so the harm depends on the client.
* medium ``icon pulls in outside content`` — an SVG icon with ``<foreignObject>`` or
         an external ``href``/``xlink:href``/CSS ``url()``/``@import``: it loads more
         content each time it is drawn and can change after approval.
* medium ``icon is not an image`` — a ``data:`` URI whose type is not ``image/*``.
* medium ``icon loads over plain http`` (or another non-https scheme such as
         ``file:``): anyone on the network path can swap it.
* medium ``icon points at a private network address`` — loopback, RFC 1918,
         link-local or a ``localhost``/``.local``/``.internal`` name: drawing the icon
         makes the viewer's client send a request into its own network.
* low    ``icon loads from a third-party host`` — an https icon on a host other than
         the server's own site (registrable domain), or on a bare public IP: each view
         can be counted by that host and the image can change after approval. Only
         raised when the server's own host is known (``server_url`` or
         ``serverInfo.websiteUrl``).
* low    ``very large icon`` — a ``data:`` URI over 100 KB.

Findings are grouped: one per (rule, host or icon), listing where it appears, so a
server that gives all 40 tools the same CDN icon gets one finding, not 40.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import re
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit

import rfc8785

# Version label of the icon fingerprint preimage. Unsigned; never part of an
# attestation. A change to what is hashed means a new label.
MCP_ICON_FINGERPRINT_PROFILE = "agentavow.mcp-icons.v1"

ICON_DATA_URI_MAX = 100 * 1024     # bytes of the src string; over this: low finding
_DECODE_CAP = 2 * 1024 * 1024      # decode at most this much of a data: URI to inspect
_MAX_ICONS_PER_ENTRY = 16
_MAX_ICONS_TOTAL = 2000
_MAX_LOCATIONS_SHOWN = 5

# Active content in an SVG/HTML icon.
_SCRIPT_TAG = re.compile(r"<\s*script\b", re.I)
_FRAME_TAG = re.compile(r"<\s*(?:iframe|embed|object|frame|frameset)\b", re.I)
_TAG = re.compile(r"<[^<>]{1,8000}>")
_EVENT_ATTR = re.compile(r"[\s\"'/]on[a-z]{3,}\s*=", re.I)
_SCRIPT_URL = re.compile(r"(?:java|vb)script\s*:", re.I)
# Outside content an SVG pulls in.
_FOREIGN_OBJECT = re.compile(r"<\s*(?:svg:)?foreignObject\b", re.I)
_EXTERNAL_HREF = re.compile(
    r"\b(?:xlink:)?href\s*=\s*[\"']?\s*(?:https?:|//|ftp:|file:)", re.I)
_EXTERNAL_CSS = re.compile(
    r"@import\b|\burl\(\s*[\"']?\s*(?:https?:|//|ftp:|file:)", re.I)
# Whitespace/control characters a browser drops inside a URL scheme ("java\tscript:").
_URL_JUNK = re.compile(r"[\x00-\x20\x7f]+")

_LOCAL_NAMES = ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback")
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


# ── reading icons ─────────────────────────────────────────────────────────────

def _icon_list(entry: Any) -> list:
    icons = entry.get("icons") if isinstance(entry, dict) else None
    return icons if isinstance(icons, list) else []


def iter_icons(
    tools: list | None,
    resources: list | None = None,
    prompts: list | None = None,
    server_info: dict | None = None,
):
    """Yield ``(where, src, icon)`` for every icon with a string ``src``.

    ``where`` names the owner the way the other MCP findings do (``tool:<name>``,
    ``resource:<name>``, ``prompt:<name>``) plus ``server:serverInfo``. Bounded:
    16 icons per entry, 2,000 in all."""
    owners: list[tuple[str, Any]] = []
    if isinstance(server_info, dict):
        owners.append(("server:serverInfo", server_info))
    for prefix, items in (("tool", tools), ("resource", resources), ("prompt", prompts)):
        for it in items or []:
            if isinstance(it, dict):
                owners.append((f"{prefix}:{it.get('name') or it.get('uri') or '?'}", it))
    seen = 0
    for where, owner in owners:
        for icon in _icon_list(owner)[:_MAX_ICONS_PER_ENTRY]:
            if seen >= _MAX_ICONS_TOTAL:
                return
            src = icon.get("src") if isinstance(icon, dict) else None
            if not isinstance(src, str) or not src.strip():
                continue
            seen += 1
            yield where, src.strip(), icon


def _parse_data_uri(src: str) -> tuple[str, bytes | None]:
    """(mime type, decoded bytes or None if undecodable) of a ``data:`` URI. Decodes at
    most ``_DECODE_CAP`` bytes of payload."""
    head, sep, payload = src[5:].partition(",")
    if not sep:
        return "", None
    params = [p.strip() for p in head.split(";")]
    mime = (params[0] if params else "").lower() or "text/plain"
    is_b64 = any(p.lower() == "base64" for p in params[1:])
    try:
        if is_b64:
            chunk = re.sub(r"\s+", "", unquote_to_bytes(payload[: _DECODE_CAP * 2]).decode(
                "ascii", "ignore"))
            chunk = chunk[: (_DECODE_CAP // 3) * 4]
            chunk += "=" * (-len(chunk) % 4)
            return mime, base64.b64decode(chunk, validate=False)
        return mime, unquote_to_bytes(payload[:_DECODE_CAP])
    except (binascii.Error, ValueError):
        return mime, None


def _markup_text(data: bytes) -> str:
    """Decode markup bytes for inspection, entity-decoded so ``&#106;avascript:`` reads
    as ``javascript:``."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16", "ignore")
    else:
        text = data.decode("utf-8", "ignore")
    return html.unescape(text)


def active_content(text: str) -> tuple[list[str], list[str]]:
    """(active, outside) reasons found in SVG/HTML markup. ``active`` makes the
    finding high; ``outside`` alone makes it medium."""
    active: list[str] = []
    outside: list[str] = []
    if _SCRIPT_TAG.search(text):
        active.append("<script>")
    if any(_EVENT_ATTR.search(m.group()) for m in _TAG.finditer(text)):
        active.append("an on* event handler")
    if _SCRIPT_URL.search(_URL_JUNK.sub("", text)):
        active.append("a javascript: link")
    if _FRAME_TAG.search(text):
        active.append("an embedded frame")
    if _FOREIGN_OBJECT.search(text):
        outside.append("<foreignObject>")
    if _EXTERNAL_HREF.search(text):
        outside.append("an external href")
    if _EXTERNAL_CSS.search(text):
        outside.append("an external stylesheet reference")
    return active, outside


def _host_of(url: str | None) -> str:
    if not isinstance(url, str) or not url.strip():
        return ""
    try:
        return (urlsplit(url.strip()).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_private_host(host: str) -> bool:
    from src.ssrf import _is_blocked_ip
    h = host.strip("[]")
    return (_is_blocked_ip(h) or h in _LOCAL_NAMES or h.endswith(_LOCAL_SUFFIXES)
            or ("." not in h and not _is_ip(h)))


def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _same_site(host: str, own_hosts: set[str]) -> bool:
    """``host`` belongs to the server's own site: the same host, a subdomain of it, or
    the same registrable domain (``mcp.acme.com`` and ``static.acme.com``). Shared
    hosting suffixes (``*.vercel.app``) match by host only."""
    from src.scanner.skill_key_flow import registrable_domain
    reg = registrable_domain(host)
    for own in own_hosts:
        if host == own or host.endswith("." + own) or own.endswith("." + host):
            return True
        if reg and reg == registrable_domain(own):
            return True
    return False


# ── findings ─────────────────────────────────────────────────────────────────

_RULES: dict[str, tuple[str, str, str]] = {
    # rule: (category, severity, remediation)
    "active": (
        "obfuscation", "high",
        "Serve a plain image as the icon. An icon never needs scripts, event handlers,"
        " javascript: links or embedded frames; a client that draws it inline runs them."),
    "outside": (
        "dynamic_remote_load", "medium",
        "Inline everything the SVG icon draws. <foreignObject> and external href / url()"
        " references load more content each time it is drawn, and that content can"
        " change after the tool was approved."),
    "not_image": (
        "obfuscation", "medium",
        "An icon data: URI should carry an image/* type (image/png, image/svg+xml, …);"
        " other content under an icon is not what a reviewer expects to see there."),
    "insecure": (
        "dynamic_remote_load", "medium",
        "Serve the icon over https (or inline it as a data: URI). Over plain http anyone"
        " on the network path can replace it."),
    "private": (
        "dynamic_remote_load", "medium",
        "Do not point an icon at a private or local address: drawing it makes the"
        " viewer's own client send a request into its local network."),
    "third_party": (
        "dynamic_remote_load", "low",
        "Host the icon on the server's own domain or inline it as a data: URI. A"
        " third-party host is contacted each time the icon is shown (it can count views)"
        " and can change the image after the tool was approved."),
    "large": (
        "robustness", "low",
        "Keep icon data: URIs small (well under 100 KB); a large one bloats every"
        " tools/list response a client reads."),
}


def _rule_name(rule: str, detail: str, count: int) -> str:
    n = f" ({count} icons)" if count > 1 else ""
    return {
        "active": f"Icon carries active content: {detail}{n}",
        "outside": f"Icon pulls in outside content each time it is shown: {detail}{n}",
        "not_image": f"Icon data: URI is not an image ({detail}){n}",
        "insecure": f"Icon loads over {detail}, not https{n}",
        "private": f"Icon points at a private network address ({detail}){n}",
        "third_party": (f"Icon loads from a third-party host ({detail}) each time it is"
                        f" shown; it can track views and change after approval{n}"),
        "large": f"Very large icon data: URI ({detail}){n}",
    }[rule]


def _classify(src: str, own_hosts: set[str]) -> list[tuple[str, str]]:
    """``[(rule, detail)]`` for one icon src. ``detail`` also groups findings."""
    out: list[tuple[str, str]] = []
    low = src.lower()
    if low.startswith("data:"):
        if len(src) > ICON_DATA_URI_MAX:
            out.append(("large", f"{len(src) // 1024} KB"))
        mime, data = _parse_data_uri(src)
        if not mime.startswith("image/"):
            out.append(("not_image", mime or "no type"))
        if data is not None and (
                "svg" in mime or "html" in mime or "xml" in mime
                or not mime.startswith("image/") or data.lstrip()[:1] == b"<"):
            active, outside = active_content(_markup_text(data))
            if active:
                out.append(("active", ", ".join(active)))
            elif outside:
                out.append(("outside", ", ".join(outside)))
        return out
    try:
        parts = urlsplit(src)
    except ValueError:
        return out
    scheme = (parts.scheme or "").lower()
    if _SCRIPT_URL.match(_URL_JUNK.sub("", src)):
        return [("active", "a javascript: src")]
    if scheme and scheme not in ("http", "https"):
        return [("insecure", f"{scheme}:")]
    host = (parts.hostname or "").lower().rstrip(".") if scheme or src.startswith("//") else ""
    if not host:
        return out  # a relative reference: nothing is loaded from anywhere new
    if _is_private_host(host):
        out.append(("private", host))
    elif scheme == "http":
        out.append(("insecure", "plain http"))
    if not out and own_hosts and (_is_ip(host) or not _same_site(host, own_hosts)):
        out.append(("third_party", host))
    return out


def icon_findings(
    tools: list | None,
    *,
    resources: list | None = None,
    prompts: list | None = None,
    server_info: dict | None = None,
    server_url: str | None = None,
) -> list:
    """Scanner ``Finding``s for the icons on an MCP server's advertised surface.

    Pure and offline. ``server_url`` (the endpoint that was scanned) and
    ``serverInfo.websiteUrl`` say which host is the server's own; without either, the
    third-party-host rule is skipped (there is nothing to compare against)."""
    from src.scanner.scan import Finding

    own_hosts = {h for h in (
        _host_of(server_url),
        _host_of((server_info or {}).get("websiteUrl") if isinstance(server_info, dict)
                 else None),
    ) if h}
    groups: dict[tuple[str, str], list[str]] = {}
    for where, src, _icon in iter_icons(tools, resources, prompts, server_info):
        for rule, detail in _classify(src, own_hosts):
            locs = groups.setdefault((rule, detail), [])
            locs.append(where)
    out = []
    order = list(_RULES)
    for (rule, detail), locs in sorted(groups.items(), key=lambda kv: (
            order.index(kv[0][0]), kv[0][1])):
        category, severity, remediation = _RULES[rule]
        uniq = list(dict.fromkeys(locs))
        shown = ", ".join(uniq[:_MAX_LOCATIONS_SHOWN])
        more = len(uniq) - _MAX_LOCATIONS_SHOWN
        out.append(Finding(
            category=category,
            name=_rule_name(rule, detail, len(locs))[:200],
            severity=severity,
            file_path=f"{uniq[0]}:icons",
            line_number=0,
            snippet=(shown + (f" (+{more} more)" if more > 0 else ""))[:300],
            remediation=remediation,
        ))
    return out


# ── icon fingerprint (watch signal; unsigned) ────────────────────────────────

def _canon_bytes(obj: Any) -> bytes:
    from src.scanner.mcp_scan import _as_ijson
    try:
        return rfc8785.dumps(_as_ijson(obj))
    except Exception:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          default=str).encode("utf-8")


def _canon_icons(icons: Any) -> Any:
    """An icons array as a set: entries sorted by their canonical bytes, so a server
    that reorders the same icons is not a change."""
    if not isinstance(icons, list):
        return icons
    return sorted(icons, key=_canon_bytes)


def compute_icon_fingerprint(tools: list | None, server_info: dict | None = None) -> str | None:
    """``sha256:…`` over the icons a server serves, for the watch loop. Unsigned.

    Preimage (RFC 8785 JCS): ``{"profile": MCP_ICON_FINGERPRINT_PROFILE,
    "tools": {"tool:<name>": [icons, …]}, "server": icons}`` — every tool that carries a
    non-empty ``icons`` array, keyed like the per-tool digests (``tool_digest_key``);
    each array's entries sorted by their canonical bytes; tools that share a name list
    their arrays sorted the same way; ``server`` (``serverInfo.icons``) omitted when
    absent. Only icons are hashed: a description or schema change leaves it alone (that
    is the tool-definition digest's job), and nothing here enters an attestation.

    None when no tool was read (a failed ``tools/list`` must not look like "the icons
    went away"). A server with tools but no icons gets the fingerprint of the empty
    map, so icons appearing later is a change.
    """
    from src.scanner.mcp_scan import tool_digest_key

    dict_tools = [t for t in tools or [] if isinstance(t, dict)]
    if not dict_tools:
        return None
    tmap: dict[str, list] = {}
    for t in dict_tools:
        icons = t.get("icons")
        if icons is None or icons == []:
            continue
        key = tool_digest_key(str(t.get("name", "") or "unnamed"))
        tmap.setdefault(key, []).append(_canon_icons(icons))
    body: dict[str, Any] = {
        "profile": MCP_ICON_FINGERPRINT_PROFILE,
        "tools": {k: sorted(v, key=_canon_bytes) for k, v in tmap.items()},
    }
    server_icons = server_info.get("icons") if isinstance(server_info, dict) else None
    if server_icons is not None and server_icons != []:
        body["server"] = _canon_icons(server_icons)
    return "sha256:" + hashlib.sha256(_canon_bytes(body)).hexdigest()
