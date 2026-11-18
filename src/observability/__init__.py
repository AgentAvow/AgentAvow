"""Logging, request correlation and trace context for the backend (#405).

Everything about how logs are formatted, which ids they carry and what gets redacted
lives in this package. Other code logs with ``logging.getLogger(__name__)`` as usual
and must not configure logging or import tracing libraries itself
(tests/test_observability_imports.py checks it).
"""
from __future__ import annotations

from src.observability.context import current_request_id, current_span_id, current_trace_id
from src.observability.logs import JSONFormatter, TextFormatter, setup_logging
from src.observability.middleware import ObservabilityMiddleware
from src.observability.redaction import redact_text, redact_value

__all__ = [
    "JSONFormatter",
    "ObservabilityMiddleware",
    "TextFormatter",
    "current_request_id",
    "current_span_id",
    "current_trace_id",
    "redact_text",
    "redact_value",
    "setup_logging",
]
