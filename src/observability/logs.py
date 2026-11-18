"""Log formatting: one JSON object per line in production, readable text for local dev.

Every line carries ``request_id`` and ``trace_id`` while a request is being served
(from src/observability/context.py), and every line is passed through
src/observability/redaction.py first, in both formats.

``LOG_FORMAT`` picks the format: ``json`` or ``text``. Left empty, it is ``text`` when
``DEBUG=true`` (dev, staging, tests) and ``json`` otherwise (production).
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from src.observability.context import current_request_id, current_span_id, current_trace_id
from src.observability.redaction import redact_field, redact_text

# Attributes every LogRecord has; anything else on a record came from ``extra=``.
_RECORD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message", "asctime", "taskName",
}
_ID_FIELDS = ("request_id", "trace_id", "span_id")


def _ids(record: logging.LogRecord) -> dict[str, str]:
    """The record's own ids when it was given them, else the current request's."""
    out: dict[str, str] = {}
    for name, current in (
        ("request_id", current_request_id),
        ("trace_id", current_trace_id),
        ("span_id", current_span_id),
    ):
        value = getattr(record, name, None) or current()
        if value:
            out[name] = str(value)
    return out


def _message(record: logging.LogRecord) -> str:
    try:
        return record.getMessage()
    except Exception:  # noqa: BLE001 — a bad format string must not lose the line
        return f"{record.msg!r} (args could not be formatted)"


class JSONFormatter(logging.Formatter):
    """One redacted JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(_message(record)),
        }
        entry.update(_ids(record))
        for key, value in record.__dict__.items():
            if key in _RECORD_ATTRS or key in _ID_FIELDS or key in entry or key.startswith("_"):
                continue
            entry[key] = redact_field(key, value)
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = redact_text(self.formatException(record.exc_info))
        elif record.exc_text:
            entry["exception"] = redact_text(record.exc_text)
        if record.stack_info:
            entry["stack"] = redact_text(self.formatStack(record.stack_info))
        return json.dumps(entry, default=lambda o: redact_text(str(o)), ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """Human-readable lines for local dev, redacted the same way."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-8s %(name)s: %(message)s", datefmt="%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        rid = getattr(record, "request_id", None) or current_request_id()
        if rid:
            line = f"{line} [request_id={rid}]"
        return redact_text(line)


def resolve_format(log_format: str, debug: bool) -> str:
    log_format = (log_format or "").strip().lower()
    if log_format in ("json", "text"):
        return log_format
    return "text" if debug else "json"


def build_formatter(log_format: str, debug: bool) -> logging.Formatter:
    return TextFormatter() if resolve_format(log_format, debug) == "text" else JSONFormatter()


def setup_logging(log_format: str | None = None, debug: bool | None = None) -> None:
    """Send all logging to stdout through one formatter (JSON or text).

    uvicorn's own loggers are pointed at the root handler too, so its startup and
    error lines come out in the same format.
    """
    if log_format is None or debug is None:
        from src.config import settings

        log_format = settings.log_format if log_format is None else log_format
        debug = settings.debug if debug is None else debug

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(build_formatter(log_format, debug))
    root.addHandler(handler)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        for h in lg.handlers[:]:
            lg.removeHandler(h)
        lg.propagate = True

    # Requests are logged once by the observability middleware, not by uvicorn.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
