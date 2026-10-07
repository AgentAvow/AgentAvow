# agentavow.com/mcp-tool-admission

A `tool_admission` component for the [federation-port/v0](https://github.com/aeoess/federation-port)
adapter contract. It performs, at the port's admission boundary, the check AgentAvow already performs
for a gate authorizing one MCP tool call: is there a signed static grade for this server, is the tool
definition the gateway holds the one that was graded, and is the attestation still inside its window.

Written against `src/contract/types.ts` only. Node built-ins only. Nothing under `src/runtime` is
imported or changed. Apache-2.0.

## What it checks

Given the frozen action (`action.tool`) and the native evidence bytes addressed to this component:

1. **Fetch** `GET https://agentavow.com/api/v1/public/scan/mcp?endpoint=<url>` through `ctx.fetch`.
   The only data that leaves is the MCP endpoint URL. Declared destination: `https://agentavow.com`.
2. **Verify** the compact JWS in the response offline: `alg` EdDSA, `kid` equal to the pinned key's,
   Ed25519 signature over `ASCII(BASE64URL(header) || "." || BASE64URL(payload))`, and the payload
   bytes equal to their own RFC 8785 (JCS) canonical form. The key `agentgraph-security-v1` is pinned in
   `adapter.ts` (the same key is published at `https://agentgraph.co/.well-known/jwks.json`); policy
   may supply its own copy via `config.jwk`.
3. **Bind the subject**: `payload.subject.id` must equal `"mcp:" + endpoint`.
4. **Recompute** the per-tool digest of the definition the caller submitted, with the
   `agentavow.mcp-tool-definition.v1` derivation (copied from
   `docs/standards/tool-manifest-digest-vectors-v1/verify.mjs`), and compare it with
   `payload.scan.toolDigests["tool:<name>"]`.
5. **Report** three claims and a `valid_until`.

## Claims

| claim | established means | not_established reasons |
|---|---|---|
| `agentavow.grade` | AgentAvow signed a static-analysis grade for this server with `trustScore >= min_score` (default 81) and `findings.critical == 0 && findings.high == 0` | `score_below_min:<n><<min>`, `blocking_findings:critical=<n>,high=<n>` |
| `agentavow.tool_definition_binds` | the served definition of `action.tool` (or `config.tool_name`) has the digest AgentAvow signed for that tool | `tool_definition_digest_differs`, `tool_not_in_signed_scan` |
| `agentavow.fresh` | `input.now` is inside `[issuedAt, expiresAt)` | `attestation_expired`, `attestation_not_yet_valid` |

Shared prerequisites, reported on all three claims as `not_established`: `signature_invalid`,
`payload_not_canonical`, `subject_mismatch`.

**Claim ceiling.** All three established means exactly: at the evaluation instant AgentAvow had signed a
static-analysis grade for this server, the grade covered a tool of this name, the definition the gate was
served for that tool is the one the scan graded, and the signature, subject and validity window check.
It establishes nothing about runtime behaviour, nothing about what the tool does when invoked, nothing
about other tools on the server, and nothing about definitions the scan did not observe. Whether a gate
proceeds is the customer policy's decision (which claims it requires).

### Status mapping (contract section 4)

- `established` / `not_established`: the check ran (attestation fetched and parsed) and the claim holds
  or does not.
- `failed`: the check could not complete. Malformed input (`evidence_missing`, `evidence_not_json`,
  `evidence_tool_invalid`, `evidence_tool_name_mismatch`, `endpoint_missing`, `endpoint_invalid`,
  `endpoint_mismatch`), AgentAvow answering other than 200 (`scan_http_<status>`), or a response that is
  not a parseable attestation (`scan_response_not_json`, `attestation_malformed`,
  `attestation_times_invalid`, `attestation_scan_fields_missing`).
- `unsupported`: evidence whose `profile` is not `agentavow.mcp-tool-definition.v1`.
- A transport error from `ctx.fetch` propagates; the runtime records the component `unavailable`.

A tool the scan never observed is `not_established` with reason `tool_not_in_signed_scan`, not
`unsupported`: the profile is implemented and the check ran; what is missing is a signed digest for that
name, so the claim "the served definition is the one graded" does not hold. (AgentAvow's own vectors call
this axis `not_evaluated`; the contract has no claim status for "not measured", so the reason string
carries the distinction.)

## Evidence

**In** (`schemas.check_evidence`, `application/json`):

```json
{
  "profile": "agentavow.mcp-tool-definition.v1",
  "endpoint": "https://mcp.deepwiki.com/mcp",
  "tool": { "name": "ask_wiki_question", "description": "...", "inputSchema": { ... } }
}
```

`tool` is the `tools/list` entry the gateway holds, as served. `endpoint` may be omitted when policy
pins `config.endpoint`; when both are present they must agree.

**Out** (`schemas.output_evidence`, `application/json`): the compact JWS exactly as fetched, the tool
key, the recomputed digest and the signed digest (or `null`). The runtime stores these bytes unparsed and
records only their digest in provenance. For a `failed` check before an attestation was obtained the
bytes are the raw HTTP body, or empty.

## `valid_until`

`expiresAt - 1 ms`, as exact UTC milliseconds. The port's deadline is inclusive (`now <= valid_until`);
the attestation's `expiresAt` is exclusive. Offered only once the signature verified.

## Policy configuration (`ctx.config`)

| key | default | meaning |
|---|---|---|
| `endpoint` | from evidence | MCP endpoint the workflow is bound to |
| `tool_name` | `action.tool` | MCP tool name when the executor's tool name differs |
| `min_score` | `81` | minimum trust score for `agentavow.grade` |
| `api_base` | `https://agentavow.com` | AgentAvow origin; must be inside the granted destinations |
| `jwk` | pinned key | OKP / Ed25519 JWK with `kid`, replacing the pin |

## Pin values

```
node scripts/seal.ts adapters/agentavow-mcp-admission
```

prints `artifact_digest` and `manifest_digest` for a customer policy. Both are recomputed by the
runtime at load (contract section 8).
