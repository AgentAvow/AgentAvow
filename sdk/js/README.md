# agentavow-trust

> **Formerly `agentgraph-trust`.** This package is now published as **`agentavow-trust`**.

JavaScript/TypeScript SDK for **AgentAvow**: a signed, recomputable trust
score (0 to 100) and an adoption score for any tool, MCP server, package or
repo an AI agent connects to.

What is in the box:

- **`agentavow-trust/gate`**: the framework-agnostic gate. One policy object in,
  a `safe` / `review` / `do_not_connect` decision out, from AgentAvow's signed
  scan result (the EdDSA JWS is verified against the public JWKS, on WebCrypto,
  so it runs on Node 18+, Bun, Deno and Cloudflare Workers). Catches a tool whose
  definition changed after it was graded.
- **`agentavow-trust/flue`**: the gate wired into the Flue agent framework
  (`@flue/runtime` 2.x): refuse a server at connect time, deny a drifted tool
  call at run time.
- **`agentavow-trust/vercel-ai`**: the same gate for the Vercel AI SDK (`wrapTools`).
- **`agentavow-trust`** (root) and **`/verify`**: Trust Score v2 signed envelope
  verification, the JS peer of the Python `agentavow-sdk` verify module;
  both reproduce the server's JCS-canonical, Ed25519-over-SHA-256 check
  byte-for-byte (this part uses `node:crypto`).

One runtime dependency, [`canonicalize`](https://www.npmjs.com/package/canonicalize)
(RFC 8785 JCS, byte-matches Python's `rfc8785`). Node >= 18.

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

## The gate: `agentavow-trust/gate`

> New in 0.3.0 (not yet on npm; ships with the next publish).

```ts
import { createGate } from 'agentavow-trust/gate'

const gate = createGate({
  allowFloor: 51,          // trust score that is safe without review (81 = strict)
  onReview: 'block',       // what a review decision does: block | warn | confirm
  onDrift: 'block',        // a tool definition that changed since it was graded
  onApiError: 'block',     // AgentAvow unreachable or the attestation did not verify
})

const d = await gate.check('https://mcp.deepwiki.com/mcp')   // or 'npm:chalk', 'owner/repo'
d.decision     // 'safe' | 'review' | 'do_not_connect'
d.allowed      // the bottom line after the policy switches
d.score        // 74 (the signed trust score)
d.certified    // the Certified mark, its own field (a reader can show "Safe to connect · Certified")
d.reason       // one sentence with the report link
d.attestation  // { jws, kid, verified: true, payload }

// Per tool call: an in-memory compare of the definition the agent was served
// against the per-tool digest signed into the attestation.
const c = await gate.checkToolCall({ server, toolName: 'ask_wiki_question', servedDefinition })
if (!c.allowed) throw new Error(c.reason)
```

How it decides, in order:

1. AgentAvow could not answer, or the attestation did not verify: `onApiError`
   (default `block`, fail closed).
2. No grade for the target: `onUnscanned` (default `block`).
3. A `blockOn` trigger fired: `do_not_connect`. Defaults: a critical finding, a
   sandbox canary credential exfiltrated, a known-malicious dependency, the
   blocked tier (score 0 to 10). Add `'high'` to block on high findings too.
4. The score is under `allowFloor`, a high finding is on the result, or the
   analysis is older than `maxStaleMs` (default 30 days): `review`. `onReview`
   says what that means: `block`, `warn` (runs, `onWarn` is called), or `confirm`
   (your `confirm(decision)` hook decides, once per server and reason per cache
   period, per tool for drift; without a hook, `confirm` blocks).
5. Otherwise `safe`.

The Certified mark is never one of the three values and never changes them: it
rides along as `decision.certified` (from the API's `certified` field) so a
reader can show it next to the decision.

Then, for a tool call, the drift step: the served definition's digest
(`sha256` over JCS of `{profile, tool}`, profile `agentavow.mcp-tool-definition.v1`)
must equal the digest in the signed `tool_digests` map, or in your `pins` for
that server if you set any. A mismatch, or a tool the grade never saw, follows
`onDrift` (`block` | `review` | `allow`).

The policy is one JSON-able object:

| Field | Default | Meaning |
|-------|---------|---------|
| `allowFloor` | `51` | Lowest score that is `safe` without review. `81` is strict. |
| `blockOn` | `['critical', 'sandbox_canary', 'malicious_dependency', 'blocked_tier']` | Hard stops, regardless of score. `'high'` is available. |
| `onReview` | `'block'` | `block` / `warn` / `confirm`. |
| `onDrift` | `'block'` | `block` / `review` / `allow` for a changed or unknown tool definition. |
| `onUnscanned` | `'block'` | `block` / `review` / `allow` when there is no grade. |
| `onApiError` | `'block'` | `block` (fail closed) / `allow` (run with a warning). Headless agents should keep the default. |
| `maxStaleMs` | 30 days | Older analysis is `review`. |
| `cacheTtlMs` | 1 hour | In-memory grade cache; a stale entry is served while one refresh runs. |
| `pins` | `{}` | `{ server: { toolName: 'sha256:…' } }`: expected digests you reviewed; they replace the signed map for that server. |
| `verifySignature` | `true` | Verify the JWS and decide on signed fields only. See below. |
| `unmapped` | `'allow'` | A tool that maps to no server (your own function). |
| `baseUrl`, `jwksUrl`, `timeoutMs`, `headers` | AgentAvow's public API and JWKS | Endpoints and transport. |

Hooks (not JSON): `fetch` (injected for tests and proxies), `confirm`,
`onWarn`, `jwks` (an inline JWKS for air-gapped verification).

**Signatures.** Every scan response carries `jws`, `key_id` and `jwks_url`. With
`verifySignature: true` the gate verifies the EdDSA (Ed25519) JWS against the
JWKS at `https://agentgraph.co/.well-known/jwks.json` (the key is pinned by
`kid`; the JWKS is cached for an hour and refetched once on an unknown `kid`),
checks the subject is the coordinate you asked about and the attestation has not
expired, and then reads the score, tier, findings, tool digests and supply-chain
block from the signed payload. Fields that are not signed (the sandbox block,
a `decision` label) can only make the decision stricter, never looser. A
response whose signature does not verify is an API error (`onApiError`).
With `verifySignature: false` the unsigned JSON is trusted as served over https,
the same trust you place in the API itself; use it only where WebCrypto Ed25519
is unavailable.

The hot path never scans. `check` reads the cache (the API's own result is
cached an hour server-side too), and `checkToolCall` is an in-memory digest
compare. `gate.observeTools(server, tools)` records a `tools/list` so later
`checkToolCall`s can omit `servedDefinition`; `gate.pin(server, tools)` records
the digests you reviewed.

Also exported: `deriveDecision` (the three-phrase rule, pure), `applyDrift`,
`resolvePolicy`, `GradeClient`, `verifyGrade`, `toolDigest` / `toolKey` /
`digestMap`, `parseCoordinate` / `subjectId`, `captureRpc` / `readRpc` (JSON-RPC
replies, plain or SSE-framed), `GateError`. `agentavow-trust/jws` exports the
bare `verifyJws(jws, jwks, { expectKid })` and `JwksCache`.

## Flue: `agentavow-trust/flue`

For agents built on [Flue](https://flueframework.com) (`@flue/runtime` 2.x,
remote MCP servers). Two seams, both verified against the runtime source at
2.2.2:

```ts
// src/gate.ts
import { createFlueGate } from 'agentavow-trust/flue'

export const gate = createFlueGate({
  allowFloor: 51,
  onReview: 'block',
  onDrift: 'block',
  onApiError: 'block',
})
```

```ts
// src/app.ts (module scope, once)
import { instrument } from '@flue/runtime'
import { gate } from './gate.ts'

instrument(gate.instrumentation())     // every mcp__<server>__<tool> call is checked first
```

```ts
// src/agents/assistant.ts
'use agent'
import { useMcpConnection, useModel } from '@flue/runtime'
import { gate } from '../gate.ts'

export function Assistant() {
  useModel('anthropic/claude-sonnet-4-6')
  useMcpConnection(gate.connection({
    name: 'deepwiki',
    url: 'https://mcp.deepwiki.com/mcp',
    optional: true,       // do_not_connect mounts zero tools and tells the model why
  }))
  return 'Answer questions about public repositories.'
}
```

**Seam (a), `gate.connection(def)`:** returns the same definition with its
`fetch` wrapped (a field Flue's definition validator accepts, so it works with
`useMcpConnection` and `defineMcpConnection` unchanged). Flue hands that `fetch`
to the MCP transport, which POSTs every JSON-RPC message through it. On
`initialize` the wrapper fetches the server's grade and, on `do_not_connect`,
throws: the connect fails, and with `optional: true` Flue mounts no tools from
that server and announces the reason to the model as a `resources` signal.
Without `optional`, the submission fails with that reason. On `tools/list` the
wrapper reads the reply (plain JSON or SSE-framed), records each served
definition, checks it against the signed or pinned digest, and refuses the
connection when a tool drifted or is unknown under `onDrift: 'block'`. The
transport receives the same bytes. With `tools: [...]` on the definition, only
the mounted tools are judged.

**Seam (b), `gate.instrumentation()`:** a `FlueInstrumentation` for
`instrument(...)`. Its interceptor runs around every tool execution; for an
`mcp__<server>__<tool>` call it runs `checkToolCall` (an in-memory compare
against what `tools/list` served) and, when the call is not allowed, throws
instead of calling `next()`. Flue turns a tool's rejection into an error tool
outcome the model sees, and the conversation continues. This is the seam that
catches a server that redefines a tool after it connected: pin the digests you
reviewed with `gate.pin(server, tools)` or a `pins` policy entry and the next
call to a changed tool is denied.

Notes:

- Nothing runs at module scope; the grade is fetched inside the connect, which
  Flue performs in request context, so the Cloudflare Workers target works
  (the gate needs only `fetch` and WebCrypto).
- `onReview: 'confirm'` needs your `confirm` hook; Flue has no built-in approval
  pause, so without one `confirm` blocks.
- A server you proxy or grade under a package coordinate: `coordinates: { deepwiki: 'npm:@scope/server' }`.
- An `mcp__` tool from a connection you did not wrap with `gate.connection` is
  not gated (`unmapped: 'block'` to refuse it).
- Legacy `transport: 'sse'`: replies arrive on the GET stream, so the connect
  cannot be refused on drift; the listing is still recorded and the per-call
  check applies.
- `gate.lookup('mcp__deepwiki__ask_wiki_question')` gives the server and
  original tool name behind an adapted name.

## Vercel AI SDK tool gate — `agentavow-trust/vercel-ai`

> Shipped in 0.2.2. From 0.3.0 it is a thin adapter over `agentavow-trust/gate`,
> the same core as the Flue adapter: one policy object, the three-phrase
> decision, signature verification on by default, and drift blocked by default.

`wrapTools(tools, policy)` returns the same AI SDK `ToolSet` with each tool's
`execute` wrapped. Before a tool runs, the gate reads the serving MCP server's
signed result from AgentAvow's free API (cached), verifies the EdDSA
attestation against AgentAvow's JWKS, and runs `checkToolCall`: the decision
(`safe` / `review` / `do_not_connect`, see "How it decides" above) plus the
drift check of the definition this agent was handed against the per-tool digest
signed into the attestation. A server that quietly changes a tool's definition
after it was scanned is blocked.

```ts
import { createMCPClient } from '@ai-sdk/mcp';
import { generateText } from 'ai';
import { wrapTools } from 'agentavow-trust/vercel-ai';

const SERVER = 'https://mcp.deepwiki.com/mcp';
const mcp = await createMCPClient({ transport: { type: 'http', url: SERVER } });
const listing = await mcp.listTools();
const tools = wrapTools(mcp.toolsFromDefinitions(listing), {
  server: SERVER,          // one server for the whole set
  servedTools: listing,    // the exact tools/list, for the drift check (optional; see below)
  allowFloor: 51,          // trust score that is safe without review (81 is strict)
  onReview: 'confirm',     // block | warn | confirm (the AI SDK's needsApproval)
  onDrift: 'block',        // a definition that changed since it was graded
});

await generateText({ model, tools, prompt: '...' });
```

What a call does:

- **Safe to connect** (or `allowed` after the policy switches): the tool runs.
- **Do not connect**: the tool is not run. Its result is `{ error, agentavow }`:
  `error` is one line for the model that leads with the phrase
  (`"Do not connect — 'send_email' was not run. AgentAvow: the definition of …"`,
  with `· Certified` after the phrase when the tool carries the mark), and
  `agentavow` is the `Decision` (`decision`, `allowed`, `outcome`, `score`,
  `tier`, `certified`, `reportUrl`, `servedDigest`, `signedDigest`, `attestation`)
  without the raw grade and attestation payload. Nothing throws unless you set
  `onBlock: 'throw'` (a `GateError` whose `decision` is the same object).
- **Review before you connect**: per `onReview`. `block` (default) as above;
  `warn` runs and calls `onWarn`; `confirm` sets the tool's `needsApproval`, so
  `generateText`, `streamText` and `ToolLoopAgent` pause for the user and an
  approved call runs. `do_not_connect` is never put to the user. If you pass a
  `confirm(decision)` hook, the hook decides instead of `needsApproval`.

The served definition for the drift check comes from, in order: `servedTools`
(the `tools/list` you built the tools from; exact), then the wrapped tool itself
(its description and JSON input schema are what the model is shown;
`@ai-sdk/mcp` normalises a definition when it builds a tool, and the gate tries
the few definitions that normalise to what the tool carries), then the server's
own `tools/list` (`fetchServed`, default on), used only when it shows the model
the same thing the wrapped tool does. A server that serves the gate one
definition and the agent another is drift. If a tool declares an `outputSchema`
or other fields the AI SDK drops and the server cannot be fetched, pass
`servedTools`, or the call is reported as drift (fail closed).

| Option | Default | Meaning |
|--------|---------|---------|
| `server` / `toolToServer` / `resolveServer` | — | Map a tool to its server coordinate (`https://…` MCP URL, `owner/repo`, `npm:name`, …). An unmapped tool is not gated (`unmapped: 'block'` to refuse it). |
| every `createGate` policy field | see the gate table | `allowFloor` (51), `blockOn`, `onReview`, `onDrift`, `onUnscanned`, `onApiError`, `maxStaleMs`, `pins`, `verifySignature` (true), `cacheTtlMs`, `baseUrl`, `jwksUrl`, … |
| `servedTools` | — | A `tools/list` (array or `listTools()` result) for every server, a map keyed by coordinate, or `(server) => listing`. |
| `fetchServed` | `true` | Fetch the server's `tools/list` when the wrapped tool alone cannot decide the drift check. |
| `serverHeaders` | — | Per-server headers for that fetch. |
| `onBlock` | `'output'` | `output` returns `{ error, agentavow }`; `throw` throws `GateError`. |
| hooks | — | `onWarn`, `confirm`, `fetch`, `jwks`. |

`createVercelGate(policy)` gives the gate itself (`decide(toolName, tool?)`,
`wrap(tools)`, plus everything on `createGate`'s gate). Also exported:
`blockedOutput`, `gateMessage`, `headline`, `toolDigest` / `toolKey`,
`parseCoordinate`, `GateError`.

### Upgrading from 0.2.x

0.2.x options still work as deprecated aliases (a 0.3.0 name wins when both are given):

| 0.2.x | 0.3.0 |
|-------|-------|
| `minScore: n` | `allowFloor: n` |
| `onFail: 'block'` | `onReview: 'block'` |
| `onFail: 'warn'` | `onReview: 'warn'` |
| `onFail: 'confirm'` | `onReview: 'confirm'` (sets `needsApproval`) |
| `onFail: 'throw'` | `onReview: 'block'` + `onBlock: 'throw'` |
| `failClosed: true` / `false` | `onApiError: 'block'` / `'allow'` |
| `blockOn: ['critical', 'high', 'medium']` | same; `'medium'` / `'low'` still block, the rest are gate triggers |

What changes for a 0.2.x caller:

- **The default floor is 51, not 81.** A tool graded 51 to 80 now runs. Pass
  `allowFloor: 81` (or keep `minScore: 81`) for the old floor.
- **A high finding is review, not a block,** unless `blockOn` includes `'high'`
  (the 0.2.x default `blockOn` did; passing it explicitly keeps that).
- **`onFail` / `onReview` only soften review.** A do-not-connect result (a
  critical finding, a known-malicious dependency, the blocked tier, drift under
  `onDrift: 'block'`) is blocked whatever `onReview` says. Use `onDrift` to soften drift.
- **The signature is verified by default.** A response whose attestation does
  not verify is an API error (`onApiError`, default block).
  `verifySignature: false` restores the 0.2.x behaviour.
- **The blocked output's `agentavow` is the full `Decision`**: the 0.2.x keys
  (`outcome`, `server`, `score`, `tier`, `reportUrl`, `servedDigest`,
  `signedDigest`) are still there, plus `decision`, `allowed`, `certified`.
  Messages lead with the phrase instead of "AgentAvow blocked …".
- **`onFail: 'throw'` throws `GateError`** (`err.decision` is a `Decision`), not `ToolGateError`.
- **`TrustGate`** is deprecated (use `createVercelGate`); its `check` / `decide`
  return a `Decision` (`allowed`) instead of a `GateDecision` (`allow`).
  `evaluate`, `GateDecision` and `ToolGateError` are still exported, deprecated.

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
npm run build     # tsc -> dist/ (the gate, flue, jws and vercel-ai entry points)
npm test          # builds first (pretest), then node --test against dist/
```

The gate tests use no network: the API, the JWKS and the MCP server are a fake
`fetch`, and signatures come from an Ed25519 key generated per run. To also run
the Flue adapter against a real `@flue/runtime` install, point
`FLUE_RUNTIME_DIR` at a directory whose `node_modules` holds it
(`FLUE_RUNTIME_DIR=/tmp/flue-install npm test`).

The v2 envelope test validates against **production**: it fetches the real JWKS and a
real signed aggregate from the `agentgraph.co` signing host and asserts the JS
verifier accepts it (`valid === true`, `kid === 'trust-v2-2026'`). A passing
live check proves byte-compatible JCS canonicalization + Ed25519 with the
Python/server side. If prod is unreachable it falls back to a pinned fixture
captured from prod.

## Spec

[`docs/standards/trust-score-envelope-v2.0.md`](../../docs/standards/trust-score-envelope-v2.0.md)
(§6 verification). MIT licensed.
