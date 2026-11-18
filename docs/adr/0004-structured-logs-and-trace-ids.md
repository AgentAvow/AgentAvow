# 0004: Structured logs and trace ids, without an OpenTelemetry SDK

- **Status:** Accepted
- **Date:** 2026-11-16
- **Decided by:** the owner (issue #405, triage of #402's wishlist)

## Context

Log lines for one scan or webhook were hard to tie together, and a token or email
could reach a log line. A GitHub token passed to a private scan is "never persisted",
and a log line would persist it. The backend already set and echoed `X-Request-ID`
(an 8-character uuid prefix) and wrote JSON lines when `DEBUG=false`, but only the
access log line carried the request id, and nothing was redacted.

Prod is one 2-vCPU host with no trace collector. The only reader of the backend's
logs is a person running `docker-compose logs backend`. The ops scripts that read
container logs (`scripts/ops/anthropic_traffic_snapshot.py`) read **nginx's** access
log; the deploy script's login and health checks read their own printed markers, not
backend log text.

## Decision

1. **One module.** `src/observability/` owns log formatting, redaction, request ids
   and trace context. Other code logs with `logging.getLogger(__name__)` and must not
   call `logging.basicConfig` / `logging.config` or import a tracing or
   structured-logging library (`tests/test_observability_imports.py`). CLI entry
   points call `src.observability.setup_logging()`.
2. **Keep `X-Request-ID`.** It is already in the CORS allow list and in error bodies.
   Generated ids are now 32 hex characters. A caller's value is kept when it is
   1-128 characters of `A-Z a-z 0-9 . _ : -`, and replaced otherwise (never rejected,
   so a client with an odd id still gets its answer).
3. **W3C `traceparent`, parsed by us.** A valid header continues the caller's trace
   with a new server span id; otherwise a new trace starts. The response carries this
   server's `traceparent`. No OpenTelemetry SDK, no exporter, no collector: on this
   box that would be cost with no reader. Revisit when there is somewhere to send
   spans.
4. **Ids on every line.** A pure ASGI middleware, installed outermost, binds
   `request_id`, `trace_id` and `span_id` in contextvars for the request; the
   formatter adds them to every line logged under it, including from inner
   middleware, routes and tasks started during the request.
5. **Redaction in the formatter**, in both formats: fields whose name says secret or
   email (Authorization, X-API-Key, X-Provider-Key, cookies, passwords, tokens,
   secrets, emails, ...) are replaced whole, and every string written is searched for
   credential shapes (GitHub `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`/`github_pat_`, `sk-`,
   AWS `AKIA`/`ASIA`, JWTs, `ag_live_`/`ag_org_`/`whsec_`, Bearer/Basic credentials,
   `user:password@` in URLs, secret-named `key=value` pairs, PEM private keys) and
   email addresses.
6. **Format:** `LOG_FORMAT=json|text`. Empty means text when `DEBUG=true` (dev,
   staging, tests) and JSON otherwise, which is what prod already got.

## Consequences

- A log line from any request can be found by the `X-Request-ID` a user reports, and
  a caller that sends `traceparent` can join our lines to its own trace.
- Redaction is pattern-based. It errs toward replacing: a field named `email_sent` or
  a word after `secret=` is redacted too. It cannot catch a secret with no known shape
  logged under a harmless name, so don't log raw request bodies or headers anyway.
- Lines logged outside a request (startup, scheduled jobs) carry no request id.
- Adding OpenTelemetry later means swapping `src/observability/tracing.py`, not
  touching call sites.

## Evidence

- Issue #405; `src/observability/`; `src/main.py` (`ObservabilityMiddleware`).
- Tests: `tests/test_observability_redaction.py`, `tests/test_observability_tracing.py`,
  `tests/test_observability_imports.py`.
