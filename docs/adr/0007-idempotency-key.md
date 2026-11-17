# 0007: An optional Idempotency-Key makes retried POST and PATCH writes safe

- **Status:** Accepted
- **Date:** 2026-11-16
- **Decided by:** the owner (issue #407, triage of #402's wishlist)

## Context

Clients and agents retry after a timeout, and a retried POST (a watch, a claim, an
alert webhook) could run twice. Issue #407 asked to *require* an `Idempotency-Key` on
every POST and PATCH and to refuse every write while Redis is down. The triage
rejected both: anonymous clients call write routes without a key and cannot be
changed in step (the public scan POSTs used by the MCP server, the GitHub Action, the
GitLab component, the plugin hooks and the ChatGPT app; `/beacon/{event}`; login and
register), and refusing writes on a Redis blip would turn it into an outage of the
whole API, the public scan included.

## Decision

1. **Optional everywhere.** A request without the header runs exactly as before. No
   route requires the key. Requiring it on authenticated account writes can be
   considered once the web client and the SDKs send it; that is a separate decision.
2. **When the header is sent** on a covered POST or PATCH, `src/idempotency.py`
   (a pure ASGI middleware, innermost in `src/main.py`) stores the first answer in
   Redis: status, the headers that describe the body (`content-type`, `location`,
   `etag`, `last-modified`, `link`, `cache-control`, `content-language`,
   `content-disposition`; never `set-cookie`, rate-limit counters or ids) and the
   body. The record is keyed by a SHA-256 of (caller, method, path, key), so neither
   the raw key nor a credential appears in a Redis key name.
3. **Caller scope.** The caller is the hashed `X-API-Key` (it wins, as in
   `get_current_entity`), else the `sub` of a valid access JWT, else `anon`. Two
   accounts that use the same key never see each other's answers. A request whose
   `Authorization` is not a valid access token runs as if it sent no key (the route
   answers it, a 401 where auth is required), and nothing is stored for it.
   **Credentials are checked before anything stored goes out.** Before a replay, a
   409 or a 422 for a caller with a credential, the middleware runs
   `get_current_entity`, the check a protected route runs: the API key must still be
   active, the JWT must not be blacklisted by logout or invalidated by a password
   change, and the account must be active. When it fails, the caller gets that 401
   (problem+json) and nothing from the store. A logged-out token or a revoked key
   cannot replay.
4. **Answers.** Same key and same request (method, path, query, content type and a
   SHA-256 of the body): the stored answer, with `Idempotent-Replayed: true`. Same key,
   different request: 422 `idempotency_key_reused`. Same key while the first request
   still runs: 409 `idempotency_key_in_use` with `Retry-After: 1`. A key that is not
   1 to 255 printable ASCII characters, or two key headers: 400
   `idempotency_key_invalid`. All are problem+json from the `src/errors` catalog
   (ADR 0005).
5. **One runner across instances.** The first request takes the key with Redis
   `SET NX` (in-flight marker, 5-minute TTL) and swaps in the stored answer with a
   compare-and-set script, so with several API processes only one runs the write.
6. **Not stored, so a retry runs again:** 5xx, 401, 408, 425 and 429 answers, an
   unhandled exception, a `text/event-stream` answer and a body over 256 KiB. The key
   is freed at once in those cases.
7. **TTL.** A stored answer lives 24 hours (`RECORD_TTL_SECONDS`). After that the key
   is new again.
8. **Redis down.** Only a request that sent a key fails closed: 503
   `idempotency_unavailable` with `Retry-After: 5`, and the write does not run. A
   request without a key never touches Redis here. Each Redis call has a 2-second
   timeout. If storing the answer fails after the write ran, the answer is still
   sent; the in-flight marker then expires after 5 minutes.
9. **Exclusions** (`EXCLUDED_PREFIXES`; the header is ignored, not even validated):
   - `/mcp`: the hosted connector is outside `/api/v1` and never covered (the ChatGPT
     app's additive-only rule); `/api/v1/mcp/*`, the MCP bridge, has JSON-RPC retry
     semantics too.
   - `/api/v1/public/scan*` (scans, `/submit`, `/beacon/{event}`) and
     `/api/v1/public/plugin/*`: anonymous clients; scans already cache for an hour.
   - `/api/v1/auth/*`: anonymous, and the answers carry tokens and cookies.
   - Webhooks we receive: `/api/v1/marketplace/stripe/webhook`,
     `/api/v1/gateway/webhook/rescan`, and `/api/v1/sso/*` (posted by the IdP).
   - **Routes that mint or rotate a secret** (`SECRET_ROUTES`, each with its reason):
     a plaintext secret shown once must never sit in Redis. Personal, agent, bot,
     attestation-provider and organization API keys (create, register, rotate,
     recover, A2A import); the alert-webhook `rotate-secret`; `POST /api/v1/webhooks`
     (its signing secret); the Moltbook migration's claim token; the sandbox bearer
     token; and the marketplace purchase routes that return a Stripe `client_secret`.
   - **Backstop:** an answer whose JSON has a secret-named member (`SECRET_FIELD_RE`:
     `*secret`, `*api_key`, `*token`, `*password`, `*private_key`, `*credentials` and
     the like) with a string value is never stored, even on a covered route; the key
     is freed and a retry runs again.
     `tests/test_idempotency_key.py` walks every covered operation's response schema,
     and the source of every covered endpoint for secret-named dict keys, and fails
     on a hit: such a route goes into `SECRET_ROUTES`.
   Every other POST and PATCH under `/api/v1` is covered, first of all the account
   writes: watches, claims, the alert-webhook test, webhook updates and the GitHub App
   claim.
10. **OpenAPI.** The header is documented as an optional parameter on every covered
    operation (`add_openapi_parameter`). Adding an optional parameter is additive for
    the ADR 0006 gate.

## Consequences

- A client can make any covered write safe to retry by sending a fresh key per
  logical write and reusing it on retries.
- A replay skips the route, so its other dependencies (rate limits, scope or role
  checks) do not run again; the credential check does (3). The scope limits a replay
  to the same API key or JWT subject, with the same request body.
- Retrying a route that mints a secret still mints a second one: the client has to
  clean up the extra key. That is the price of never storing plaintext secrets.
- Keyed requests buffer the request body and, up to 256 KiB, the answer.
- Don't add an exclusion without a reason in `EXCLUDED_PREFIXES` and here. Don't make
  the header required on a route anonymous clients call.

## Evidence

- Issue #407; triage in the #402 wishlist; `src/idempotency.py`; `src/main.py`;
  catalog codes in `src/errors/catalog.py`; `docs/api/openapi.json`.
- Tests: `tests/test_idempotency_key.py` (replay, 422, 409, unkeyed writes, Redis down
  with and without a key, exclusions, secret routes and the secret walk, TTL, caller
  separation, logged-out and revoked credentials through the real app),
  `tests/test_errors_catalog.py`.
