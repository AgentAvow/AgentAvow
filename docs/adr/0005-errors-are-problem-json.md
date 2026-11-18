# 0005: API errors are RFC 9457 problem+json from one code catalog, old fields kept

- **Status:** Accepted
- **Date:** 2026-11-16
- **Decided by:** the owner (issue #409, triage of #402's wishlist)

## Context

Error bodies were `{"detail": ..., "request_id": ...}` with `application/json`, built
by three handlers in `src/main.py`. Clients could only branch on the HTTP status and
on free text in `detail`. Those clients read `detail` today and must keep working:
`sdk/js/src/client.js` (`JSON.parse(text).detail`), `sdk/js/src/gate.ts`
(`body?.detail ?? body?.error`), the Python SDK (`resp.json().get("detail")`), the
plugin hooks (`body.get("detail")`), and third parties we cannot see.

None of our clients checks the error response's content type: each parses the body as
JSON whatever the header says (`res.json()`, `JSON.parse`, `json.loads`, httpx
`.json()`, `jq`). The only content-type checks (`sdk/js/src/flue.ts`,
`sdk/js/src/gate.ts` `readRpc`/`captureRpc`, the plugin's `_read_rpc`) apply to
third-party MCP server replies, not to our API errors.

## Decision

1. **One module.** `src/errors/` holds the code catalog (`catalog.py`) and the
   handlers (`handlers.py`). `src/main.py` only calls `install_problem_handlers(app)`.
   `HTTPException`, `RequestValidationError`, the rate-limit 429 (an
   `HTTPException`) and any unhandled exception all go through it.
2. **Additive.** Every error body keeps `detail` and `request_id` with exactly their
   old values and adds `type`, `title`, `status`, `code`, `instance` and `trace_id`.
   `type` is `https://agentavow.com/problems/<code>`, an identifier that need not
   resolve yet (RFC 9457 section 3.1.1). `instance` is the request path without the
   query string, which can carry tokens or emails. `trace_id` is the W3C trace id
   from ADR 0004.
3. **Content type `application/problem+json`** on every route except the exclusions,
   with no `Accept` negotiation, because no client depends on `application/json` for
   errors (see Context). `HTTPException.headers` are now sent (the old handler
   dropped them), so a 429 carries its `X-RateLimit-*` headers.
4. **Stable codes.** Each HTTP status has a default code (`DEFAULT_CODE_BY_STATUS`),
   with `client_error` / `server_error` for a status that has none. A route can name a
   specific code with `src.errors.ApiError(status, detail, code=...)`, which refuses an
   unknown code or one for another status. `tests/test_errors_catalog.py` pins the
   table: renaming or removing a code fails CI. Codes are only ever added.
5. **422 deviation from RFC 9457.** The RFC makes `detail` a human-readable string.
   For a request validation error our `detail` stays the pydantic error list it has
   always been, because clients read it. The per-field errors the RFC's extension
   model expects are in an `errors` extension member: `location` (body, query, path,
   header, cookie), `field` (dotted path inside it), `message`, `type`. The code is
   `validation_failed`. A route that raises `HTTPException(422, "text")` keeps its
   string `detail` and gets `unprocessable_content`.
6. **Generic 500.** An unhandled exception answers `"detail": "Internal server error"`
   with code `internal_error`: no message, exception type or stack. It is logged with
   the request and trace ids. The response carries `X-Request-ID` (it is answered
   outside the observability middleware, which would otherwise add it).
7. **Exclusions keep the old answer exactly** (`application/json`,
   `{"detail", "request_id"}`, headers dropped as before), by path in
   `src/errors/handlers.py` `is_legacy_path`:
   - `/mcp` and `/mcp/*`: the hosted MCP endpoint; its clients speak JSON-RPC, whose
     own errors come from the MCP SDK and never reach these handlers.
   - badge and image routes: `/api/v1/badges/*`, paths ending `/badge`, `.svg`,
     `/og-image` or `.png`. They are embedded in READMEs and social cards.
   - `/.well-known/*`: fixed discovery documents (JWKS, `did:web`) read by verifiers.

## Consequences

- Clients can branch on `code`, and a reported `request_id` / `trace_id` finds the log
  lines (ADR 0004).
- Part 1 only: routers still raise plain `HTTPException`, so codes are the per-status
  defaults. Moving routers onto specific codes is a later change; it adds codes to the
  catalog and never renames one.
- Responses a route builds itself (`return JSONResponse(status_code=4xx, ...)`, e.g. in
  `auth_router`, `agent_router`, `sandbox_router`) bypass the handlers and keep their
  own shape until that later change.
- A client that strictly required `application/json` on errors would now see
  `application/problem+json`. We found none; if one turns up, the fallback is to serve
  problem+json only when `Accept` allows it.
- Don't add a new exclusion without a reason in `is_legacy_path` and here.

## Evidence

- Issue #409; `src/errors/`; `src/main.py` (`install_problem_handlers`).
- Tests: `tests/test_errors_catalog.py`, `tests/test_errors_problem_json.py` (shapes,
  old-field equality, exclusions, Python SDK and plugin hook parsing),
  `sdk/js/test/problem-json.test.js` (the JS client and gate).
