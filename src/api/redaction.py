"""Server-side masking of personal data for read-only admin viewers.

A read-only admin viewer (the viewer flag without ``is_admin``) may read the admin metrics
endpoints, but must never see a user's email address, IP address or a name tied to an
account. Every endpoint guarded by ``require_admin_or_viewer`` passes its response
through ``redact_for_viewer`` when the caller is a viewer. Full admins get the response
unchanged.

Two layers, so a field added to a metrics response later is still covered:

* by key: a value under a personal-data key (``email``, ``ip_address``,
  ``display_name``, ...) is masked whatever it looks like;
* by shape: any string anywhere that contains an email address or an IPv4 / IPv6
  address has that part masked.

Masks: ``p•••@gmail.com`` for an email, ``203.0.•••.•••`` for an IPv4 address, the
first group then ``:•••`` for IPv6, the first letter then ``•••`` for a name.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel

DOTS = "•••"

EMAIL_RE = re.compile(r"([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# Not part of a longer dotted number (1.2.3.4.5), but a sentence's full stop is fine.
IPV4_RE = re.compile(
    rf"(?<!\d)(?<!\d\.)({_OCTET})\.({_OCTET})\.{_OCTET}\.{_OCTET}(?!\d)(?!\.\d)"
)
# Full or compressed IPv6 with at least three groups, so a time such as 12:30 is left
# alone.
IPV6_RE = re.compile(
    r"(?<![0-9A-Za-z:])([0-9A-Fa-f]{1,4})(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])"
)

EMAIL_KEYS = frozenset({"email", "contact_email", "owner_email", "notify_email", "to_email"})
IP_KEYS = frozenset({"ip", "ip_address", "client_ip", "remote_addr", "source_ip"})
NAME_KEYS = frozenset({"display_name", "full_name", "first_name", "last_name", "username"})


def mask_email(value: str) -> str:
    """Mask every email address in ``value``: ``someone@gmail.com`` -> ``s•••@gmail.com``."""
    return EMAIL_RE.sub(lambda m: f"{m.group(1)[:1]}{DOTS}@{m.group(2)}", value)


def mask_ips(value: str) -> str:
    """Mask every IPv4 / IPv6 address in ``value``."""
    value = IPV4_RE.sub(lambda m: f"{m.group(1)}.{m.group(2)}.{DOTS}.{DOTS}", value)
    return IPV6_RE.sub(lambda m: f"{m.group(1)}:{DOTS}", value)


def mask_name(value: str) -> str:
    value = value.strip()
    return f"{value[:1]}{DOTS}" if value else value


def mask_string(value: str) -> str:
    """Mask every email and IP address inside a free-text string."""
    return mask_ips(mask_email(value))


def _redact(obj: Any, key: str | None = None) -> Any:
    k = (key or "").lower()
    if isinstance(obj, dict):
        return {kk: _redact(v, str(kk)) for kk, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_redact(v, key) for v in obj]
    if isinstance(obj, str):
        if not obj:
            return obj
        if k in EMAIL_KEYS:
            return mask_email(obj) if "@" in obj else f"{obj[:1]}{DOTS}"
        if k in IP_KEYS:
            masked = mask_ips(obj)
            return masked if masked != obj else DOTS
        if k in NAME_KEYS:
            return mask_name(obj)
        return mask_string(obj)
    return obj


def redact_for_viewer(data: Any) -> Any:
    """A copy of ``data`` with personal data masked (see the module docstring).

    Accepts JSON-shaped data or a Pydantic model (dumped in JSON mode first) and returns
    JSON-shaped data. Never mutates the input, so a cached admin response stays intact.
    """
    if isinstance(data, BaseModel):
        data = data.model_dump(mode="json")
    return _redact(data)


def viewer_safe(data: Any, viewer: bool) -> Any:
    """``data`` unchanged for a full admin, masked for a viewer."""
    return redact_for_viewer(data) if viewer else data
