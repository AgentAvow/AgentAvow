# agentavow-trust

> **Formerly `agentgraph-trust`.** This package is now published as **`agentavow-trust`**.

JavaScript/TypeScript SDK for **AgentAvow Trust Score v2** — signed,
self-verifiable trust-score envelopes. This is the JS peer of the Python
`agentavow-sdk` verify module; both reproduce the server's
JCS-canonical, Ed25519-over-SHA-256 verification **byte-for-byte**.

- Zero crypto deps: uses Node's built-in `node:crypto` for Ed25519.
- One runtime dep: [`canonicalize`](https://www.npmjs.com/package/canonicalize)
  (RFC 8785 JCS — byte-matches Python's `rfc8785`).
- Node >= 18 (uses the global `fetch`).

## Install

```bash
npm install agentavow-trust
```

## CLI — a signed score from the terminal, no install

The package ships an `agentavow-trust` bin, so `npx` runs it without installing:

```bash
npx agentavow-trust scan modelcontextprotocol/servers   # GitHub repo
npx agentavow-trust scan npm:chalk                      # npm / pypi / crates / docker / hf
npx agentavow-trust badge you/your-repo                 # prints the README badge line
```

`scan` prints the 0–100 trust score, trust tier, finding counts, the report
link, and whether the result carries a signed attestation. `badge` prints the
markdown for a live badge that links to the full report. Both hit the free
public API (`AGENTAVOW_API` overrides the base, default
`https://agentavow.com/api/v1`).

## Trust Score v2 — signed, self-verifiable envelopes

Every v2 trust score is a signed envelope you can verify **without trusting our
server** — fetch it, then check the Ed25519 signature against our published JWKS
yourself.

```js
import { TrustClient } from 'agentavow-trust';

const client = new TrustClient('https://agentavow.com');
const did = 'did:web:agentgraph.co:agents:<id>';

// Signed envelope: score + per-source methodology breakdown + proof
const env = await client.getAggregate(did);
console.log(env.trust_score, env.contributions.map((c) => c.source));

// Verify it client-side (fetches JWKS, checks signature + freshness)
const result = await client.verify(did);
if (result.valid) {            // true iff signature valid AND fresh
  console.log('verified:', result.kid);
} else {
  console.log('NOT verified:', result.reason);
}

// Scan any GitHub repo -> trust score + findings + a verifiable envelope
const scan = await client.checkRepo('owner', 'repo');
if (scan.trust_envelope) {
  console.log(await client.verifyEnvelope(scan.trust_envelope));
}
```

> The signer identity (`did:web:agentgraph.co`) and the JWKS host intentionally
> keep the `agentgraph.co` name so existing attestations stay verifiable; the
> service and site are **AgentAvow** at `agentavow.com`.

### Standalone verification (no client)

`verifyEnvelope(envelope, jwks, { now })` only needs `canonicalize` plus
`node:crypto`, reproducing the server's JCS-canonical, Ed25519-over-SHA-256
check byte-for-byte.

```js
import { verifyEnvelope } from 'agentavow-trust';

const result = verifyEnvelope(envelope, jwks);
// => { valid, signatureValid, fresh, kid, reason }
```

It (1) strips the top-level `proof` key, (2) JCS-canonicalizes the rest,
(3) SHA-256s it, (4) reads `kid` from the detached JWS header, (5) finds the
matching `{ kty: 'OKP', crv: 'Ed25519', x }` key in the JWKS, (6) verifies the
Ed25519 signature over the digest, then (7) checks
`computed_at + freshness_ttl_seconds >= now`. `valid` is
`signatureValid && fresh`.

## Vercel AI SDK tool gate — `agentavow-trust/vercel-ai`

> Available from source (the `./vercel-ai` subpath export in `package.json`,
> built to `dist/` by `npm run build`). It is **not in the `0.2.1` release on
> npm**; it ships with the next publish.

`wrapTools(tools, options)` returns the same AI SDK `ToolSet` with each tool's
`execute` wrapped. Before a tool runs, the gate fetches the serving MCP server's
signed score from AgentAvow's free API and allows the call only when the score
clears `minScore` (default 81, the `trusted` tier), no critical / high finding
is on the result, and the tool definition the agent was served recomputes to
the per-tool digest signed into the attestation (`tool_digests["tool:<name>"]`,
profile `agentavow.mcp-tool-definition.v1`) — so a server that quietly changes
a tool's definition after it was scanned is blocked.

```ts
import { experimental_createMCPClient as createMCPClient, generateText } from 'ai';
import { wrapTools } from 'agentavow-trust/vercel-ai';

const mcp = await createMCPClient({ transport: { type: 'http', url: 'https://mcp.deepwiki.com/mcp' } });
const tools = wrapTools(await mcp.tools(), {
  server: 'https://mcp.deepwiki.com/mcp',  // one server for the whole set
  minScore: 81,                            // default
  onFail: 'block',                         // block | confirm | warn | throw
});

await generateText({ model, tools, prompt: '...' });
```

| Option | Default | Meaning |
|--------|---------|---------|
| `server` / `toolToServer` / `resolveServer` | — | Map a tool to its server coordinate (`https://…` MCP URL, `owner/repo`, `npm:name`, …). An unmapped tool is not gated (`unmapped: 'block'` to refuse it). |
| `minScore` | `81` | Lowest trust score (0–100) that is allowed to run. |
| `blockOn` | `['critical','high']` | Finding severities that block regardless of score. |
| `onFail` | `'block'` | `block` returns `{ error, agentavow }` as the tool result; `confirm` uses the AI SDK's `needsApproval` pause; `warn` runs and calls `onWarn`; `throw` throws `ToolGateError`. |
| `failClosed` | `true` | What to do when AgentAvow cannot be reached. |
| `servedTools` / `fetchServed` | fetch | The `tools/list` each server served (for the drift check); fetched from the https server by default. |
| `baseUrl` / `cacheTtlMs` / `timeoutMs` | `https://agentavow.com/api/v1`, 1h, 10s | API base and caching. |

Also exported: `TrustGate`, `TrustGateClient`, `evaluate` (the pure policy,
no I/O), `toolDigest` / `toolKey` (the per-tool digest exactly as the
attestation signs it), `parseCoordinate`, `ToolGateError`.

## API

### `new TrustClient(baseUrl, { apiKey?, token?, timeout? })`

| Method | Description |
|--------|-------------|
| `getAggregate(did)` | Signed v2 envelope for a subject DID |
| `getContributions(did)` | Just the methodology breakdown |
| `checkRepo(owner, repo)` | Scan a GitHub repo -> trust score + findings + envelope |
| `getJwks()` | Issuer JWKS from `<baseUrl>/.well-known/jwks.json` |
| `verifyEnvelope(env, { now? })` | Fetch JWKS + verify an envelope client-side |
| `verify(did, { now? })` | `getAggregate` + `verifyEnvelope` in one call |

API base is `<baseUrl>/api/v1`; the JWKS is served outside that prefix.

### `verifyEnvelope(envelope, jwks, { now? })`

Returns `{ valid, signatureValid, fresh, kid, reason }`. `reason` is one of:
`ok`, `missing or unsupported proof`, `malformed jws`,
`no matching key in JWKS`, `signature invalid`, `envelope expired (stale)`.

Also exported: `envelopeDigest(envelope)` (raw 32-byte SHA-256 of the
JCS-canonical, proof-stripped envelope), `isFresh(envelope, { now? })`,
`PROOF_TYPE`.

## Verification / tests

```bash
npm install
npm test          # node --test
```

The test suite validates against **production**: it fetches the real JWKS and a
real signed aggregate from the `agentgraph.co` signing host and asserts the JS
verifier accepts it (`valid === true`, `kid === 'trust-v2-2026'`). A passing
live check proves byte-compatible JCS canonicalization + Ed25519 with the
Python/server side. If prod is unreachable it falls back to a pinned fixture
captured from prod.

## Spec

[`docs/standards/trust-score-envelope-v2.0.md`](../../docs/standards/trust-score-envelope-v2.0.md)
(§6 verification). MIT licensed.
