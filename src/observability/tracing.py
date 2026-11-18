"""W3C Trace Context (``traceparent``), parsed and emitted here without OpenTelemetry.

Prod has no collector, so there is nothing to export spans to. What we need is the
ids: continue a caller's trace when it sends a valid ``traceparent``, start a new one
when it doesn't, and put the trace id on every log line. See
https://www.w3.org/TR/trace-context/ (version 00).
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX16 = re.compile(r"[0-9a-f]{16}")
_HEX2 = re.compile(r"[0-9a-f]{2}")

_ZERO_TRACE = "0" * 32
_ZERO_SPAN = "0" * 16

# A traceparent is short; anything much longer is not one.
_MAX_HEADER_LEN = 512


@dataclass(frozen=True)
class TraceContext:
    trace_id: str        # 32 lowercase hex
    span_id: str         # 16 lowercase hex: this server's span
    parent_id: str | None  # the caller's span id, when the trace was continued
    flags: str = "01"    # 2 lowercase hex

    @property
    def traceparent(self) -> str:
        """The header value naming this server's span (for responses and outbound calls)."""
        return f"00-{self.trace_id}-{self.span_id}-{self.flags}"


def new_trace_id() -> str:
    while True:
        tid = secrets.token_hex(16)
        if tid != _ZERO_TRACE:
            return tid


def new_span_id() -> str:
    while True:
        sid = secrets.token_hex(8)
        if sid != _ZERO_SPAN:
            return sid


def parse_traceparent(value: str | None) -> tuple[str, str, str] | None:
    """Return ``(trace_id, parent_id, flags)`` for a valid header, else None.

    Follows the spec's rules: lowercase hex only, version ``ff`` is invalid, all-zero
    trace or parent ids are invalid, version 00 has exactly four fields, and a higher
    version may append fields after the flags (we read the first four).
    """
    if not value or len(value) > _MAX_HEADER_LEN:
        return None
    parts = value.strip().split("-")
    if len(parts) < 4:
        return None
    version, trace_id, parent_id, flags = parts[0], parts[1], parts[2], parts[3]
    if not _HEX2.fullmatch(version) or version == "ff":
        return None
    if version == "00" and len(parts) != 4:
        return None
    if not _HEX32.fullmatch(trace_id) or trace_id == _ZERO_TRACE:
        return None
    if not _HEX16.fullmatch(parent_id) or parent_id == _ZERO_SPAN:
        return None
    if not _HEX2.fullmatch(flags):
        return None
    return trace_id, parent_id, flags


def start_server_span(traceparent: str | None) -> TraceContext:
    """Continue the caller's trace when its header is valid, otherwise start a new one.

    Either way this server gets a fresh span id. Only the ``sampled`` bit of the
    caller's flags is kept (the others are reserved in version 00).
    """
    parsed = parse_traceparent(traceparent)
    if parsed is None:
        return TraceContext(new_trace_id(), new_span_id(), None, "01")
    trace_id, parent_id, flags = parsed
    sampled = "01" if int(flags, 16) & 0x01 else "00"
    return TraceContext(trace_id, new_span_id(), parent_id, sampled)
