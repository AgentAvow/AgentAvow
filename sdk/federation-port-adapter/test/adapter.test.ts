// The adapter called directly through the published contract (src/contract/types.ts), with a
// ctx.fetch that serves the pinned DeepWiki attestation. Offline. Each case names the contract
// status it expects and why.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { AdapterContext, CheckInput, ClaimResult } from '../src/contract/types.ts'
import { CLAIM_BINDS, CLAIM_FRESH, CLAIM_GRADE, DEFAULT_MIN_SCORE, PINNED_JWK, createAdapter, toolDigest, toolKey } from '../adapters/agentavow-mcp-admission/adapter.ts'
import { ENDPOINT, T_EXPIRED, T_FRESH, TAMPERED_JWS, TOOL, driftedTool, evidenceBytes, evidenceFor, fakeAgentAvow, localSigner, scanResponse, servedTool, signedPayload, vectors } from './fixture.ts'

function make(config: Record<string, unknown> = {}) {
  const av = fakeAgentAvow()
  const ctx: AdapterContext = { config: { min_score: 70, ...config }, secrets: Object.freeze({}), fetch: av.fetch }
  return { av, adapter: createAdapter(ctx) }
}
const input = (evidence: Uint8Array | undefined, now = T_FRESH, tool = TOOL): CheckInput =>
  ({ operation_id: 'op-1', workflow: 'wiki', action: { tool, args: { repoName: 'aeoess/federation-port', question: 'what is it' } }, ...(evidence ? { evidence } : {}), now })
const byId = (claims: ClaimResult[]) => Object.fromEntries(claims.map(c => [c.claim, c]))
const decode = (b: Uint8Array) => JSON.parse(Buffer.from(b).toString('utf8'))

test('derivation: toolDigest and toolKey reproduce every signed digest in the pinned vectors', () => {
  for (const t of vectors.observed_tools) assert.equal(toolDigest(t), vectors.attestation.toolDigests[toolKey(t.name)])
  assert.equal(Object.keys(vectors.attestation.toolDigests).length, vectors.observed_tools.length)
  assert.equal(toolKey('a b%c=dé'), 'tool:a%20b%25c%3Dd%C3%A9')
})

test('match: served definition equals the signed one, score above policy minimum, inside the window: all three established', async () => {
  const { av, adapter } = make()
  const out = await adapter.check!(input(evidenceFor(servedTool())))
  const c = byId(out.claims)
  assert.equal(c[CLAIM_GRADE].status, 'established')
  assert.equal(c[CLAIM_BINDS].status, 'established')
  assert.equal(c[CLAIM_FRESH].status, 'established')
  assert.equal(out.claims.length, 3)
  // Evidence bytes: the attestation JWS as fetched plus the recomputed digest, as JSON.
  const ev = decode(out.evidence)
  assert.equal(ev.attestation, vectors.attestation.jws)
  assert.equal(ev.tool_key, 'tool:ask_wiki_question')
  assert.equal(ev.observed_tool_digest, vectors.attestation.toolDigests['tool:ask_wiki_question'])
  assert.equal(ev.signed_tool_digest, ev.observed_tool_digest)
  // valid_until: exact UTC milliseconds, one ms before expiresAt (exclusive there, inclusive at the port).
  assert.equal(out.valid_until, new Date(Date.parse(vectors.attestation.expiresAt) - 1).toISOString())
  assert.match(out.valid_until!, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
  // What left the process: one GET to agentavow.com naming the endpoint, nothing else.
  assert.equal(av.calls.length, 1)
  assert.equal(av.calls[0].searchParams.get('endpoint'), ENDPOINT)
})

test('default threshold: the fixture scores 74, below the default 81: grade not_established, the other two unaffected', async () => {
  const { adapter } = make({ min_score: undefined })
  const c = byId((await adapter.check!(input(evidenceFor(servedTool())))).claims)
  assert.equal(DEFAULT_MIN_SCORE, 81)
  assert.deepEqual(c[CLAIM_GRADE], { claim: CLAIM_GRADE, status: 'not_established', reason: 'score_below_min:74<81' })
  assert.equal(c[CLAIM_BINDS].status, 'established')
  assert.equal(c[CLAIM_FRESH].status, 'established')
})

test('drift: the served definition changed after the scan: tool_definition_binds not_established, grade and fresh still hold', async () => {
  const { adapter } = make()
  const out = await adapter.check!(input(evidenceFor(driftedTool())))
  const c = byId(out.claims)
  assert.deepEqual(c[CLAIM_BINDS], { claim: CLAIM_BINDS, status: 'not_established', reason: 'tool_definition_digest_differs' })
  assert.equal(c[CLAIM_GRADE].status, 'established')
  assert.equal(c[CLAIM_FRESH].status, 'established')
  const ev = decode(out.evidence)
  assert.notEqual(ev.observed_tool_digest, ev.signed_tool_digest)
  assert.equal(ev.observed_tool_digest, toolDigest(driftedTool()))
  assert.equal(ev.signed_tool_digest, vectors.attestation.toolDigests['tool:ask_wiki_question'])
})

test('unknown tool: the scan never observed a tool of this name: not_established (tool_not_in_signed_scan), signed digest null', async () => {
  const { adapter } = make()
  const t = servedTool()
  t.name = 'delete_wiki_page'
  const out = await adapter.check!(input(evidenceFor(t), T_FRESH, 'delete_wiki_page'))
  const c = byId(out.claims)
  assert.deepEqual(c[CLAIM_BINDS], { claim: CLAIM_BINDS, status: 'not_established', reason: 'tool_not_in_signed_scan' })
  assert.equal(c[CLAIM_GRADE].status, 'established')
  assert.equal(c[CLAIM_FRESH].status, 'established')
  assert.equal(decode(out.evidence).signed_tool_digest, null)
})

test('expired: evaluation instant past expiresAt: fresh not_established, grade and binding still hold', async () => {
  const { adapter } = make()
  const c = byId((await adapter.check!(input(evidenceFor(servedTool()), T_EXPIRED))).claims)
  assert.deepEqual(c[CLAIM_FRESH], { claim: CLAIM_FRESH, status: 'not_established', reason: 'attestation_expired' })
  assert.equal(c[CLAIM_GRADE].status, 'established')
  assert.equal(c[CLAIM_BINDS].status, 'established')
})

test('window boundaries: issuedAt is admissible, expiresAt is not, one ms before expiresAt is', async () => {
  const { adapter } = make()
  const at = async (now: string) => byId((await adapter.check!(input(evidenceFor(servedTool()), now))).claims)[CLAIM_FRESH].status
  const issued = Date.parse(vectors.attestation.issuedAt)
  const expires = Date.parse(vectors.attestation.expiresAt)
  assert.equal(await at(new Date(issued).toISOString()), 'established')
  assert.equal(await at(new Date(issued - 1).toISOString()), 'not_established')
  assert.equal(await at(new Date(expires - 1).toISOString()), 'established')
  assert.equal(await at(new Date(expires).toISOString()), 'not_established')
})

test('tampered: payload edited after signing (canonical, unsigned): every claim not_established with signature_invalid', async () => {
  const { av, adapter } = make()
  av.respond = () => scanResponse(TAMPERED_JWS)
  const out = await adapter.check!(input(evidenceFor(servedTool())))
  assert.deepEqual(out.claims.map(c => [c.status, c.reason]), [['not_established', 'signature_invalid'], ['not_established', 'signature_invalid'], ['not_established', 'signature_invalid']])
  assert.equal(out.valid_until, undefined, 'no deadline is offered for an attestation that did not verify')
  assert.equal(decode(out.evidence).attestation, TAMPERED_JWS, 'the bytes relied on are the ones that failed')
})

test('wrong key: a policy-supplied JWK that is not the signer: signature_invalid; the pinned key verifies', async () => {
  const { adapter } = make({ jwk: localSigner().jwk })
  const out = await adapter.check!(input(evidenceFor(servedTool())))
  assert.ok(out.claims.every(c => c.status === 'not_established' && c.reason === 'signature_invalid'))
  const pinned = make({ jwk: { ...PINNED_JWK } })
  assert.ok((await pinned.adapter.check!(input(evidenceFor(servedTool())))).claims.every(c => c.status === 'established'))
  assert.throws(() => make({ jwk: { kty: 'RSA' } }), /config_jwk_invalid/)
})

test('kid mismatch: a JWS whose header names another kid is not verified under the pin', async () => {
  const { av, adapter } = make()
  const [, p, s] = vectors.attestation.jws.split('.')
  const h = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'agentgraph-security-v2' })).toString('base64url')
  av.respond = () => scanResponse(`${h}.${p}.${s}`)
  assert.ok((await adapter.check!(input(evidenceFor(servedTool())))).claims.every(c => c.reason === 'signature_invalid'))
})

test('subject: the policy pins one endpoint and the attestation is for it; evidence naming another endpoint is refused as malformed', async () => {
  const pinned = make({ endpoint: ENDPOINT })
  assert.ok((await pinned.adapter.check!(input(evidenceFor(servedTool())))).claims.every(c => c.status === 'established'))
  const other = await pinned.adapter.check!(input(evidenceFor(servedTool(), 'https://mcp.example.com/mcp')))
  assert.ok(other.claims.every(c => c.status === 'failed' && c.reason === 'endpoint_mismatch'))
  assert.equal(pinned.av.calls.length, 1, 'nothing was fetched for the mismatched request')
  // No pin: the evidence names the server. A server the attestation is not about: subject_mismatch.
  const free = make()
  free.av.respond = () => scanResponse()
  const r = await free.adapter.check!(input(evidenceFor(servedTool(), 'https://mcp.example.com/mcp')))
  assert.ok(r.claims.every(c => c.status === 'not_established' && c.reason === 'subject_mismatch'))
})

test('malformed input is failed, not not_established: missing evidence, non-JSON, wrong tool name, no endpoint, non-https endpoint', async () => {
  const { av, adapter } = make()
  const reasons = async (ev: Uint8Array | undefined, tool = TOOL) => {
    const out = await adapter.check!(input(ev, T_FRESH, tool))
    assert.equal(new Set(out.claims.map(c => c.status)).size, 1)
    return [out.claims[0].status, out.claims[0].reason]
  }
  assert.deepEqual(await reasons(undefined), ['failed', 'evidence_missing'])
  assert.deepEqual(await reasons(new TextEncoder().encode('{nope')), ['failed', 'evidence_not_json'])
  assert.deepEqual(await reasons(evidenceFor(servedTool()), 'read_wiki_contents'), ['failed', 'evidence_tool_name_mismatch'])
  assert.deepEqual(await reasons(evidenceFor(servedTool(), null)), ['failed', 'endpoint_missing'])
  assert.deepEqual(await reasons(evidenceFor(servedTool(), 'http://mcp.deepwiki.com/mcp')), ['failed', 'endpoint_invalid'])
  assert.deepEqual(await reasons(evidenceBytes({ profile: 'agentavow.mcp-tool-definition.v1', endpoint: ENDPOINT, tool: 'ask_wiki_question' })), ['failed', 'evidence_tool_invalid'])
  assert.equal(av.calls.length, 0, 'no request leaves for malformed input')
})

test('unsupported: evidence under a profile this component does not implement', async () => {
  const { adapter } = make()
  const out = await adapter.check!(input(evidenceFor(servedTool(), ENDPOINT, 'agentavow.mcp-tool-definition.v0')))
  assert.ok(out.claims.every(c => c.status === 'unsupported' && c.reason === 'profile_not_implemented'))
})

test('tool_name config: the workflow tool is the executor name; the MCP tool it maps to is configured', async () => {
  const { adapter } = make({ tool_name: TOOL })
  const ok = await adapter.check!(input(evidenceFor(servedTool()), T_FRESH, 'wiki_query'))
  assert.ok(ok.claims.every(c => c.status === 'established'))
})

test('agentavow.com answers 503 or non-JSON or no jws: failed with the HTTP status or shape; raw body kept as evidence', async () => {
  const { av, adapter } = make()
  av.respond = () => new Response('{"error":"unavailable"}', { status: 503 })
  let out = await adapter.check!(input(evidenceFor(servedTool())))
  assert.ok(out.claims.every(c => c.status === 'failed' && c.reason === 'scan_http_503'))
  assert.equal(Buffer.from(out.evidence).toString(), '{"error":"unavailable"}')
  av.respond = () => new Response('<html>', { status: 200 })
  out = await adapter.check!(input(evidenceFor(servedTool())))
  assert.ok(out.claims.every(c => c.reason === 'scan_response_not_json'))
  av.respond = () => new Response('{"trust_score":74}', { status: 200 })
  out = await adapter.check!(input(evidenceFor(servedTool())))
  assert.ok(out.claims.every(c => c.status === 'failed' && c.reason === 'attestation_malformed'))
})

test('transport error propagates (the runtime records the component unavailable, never success)', async () => {
  const ctx: AdapterContext = { config: {}, secrets: Object.freeze({}), fetch: (() => Promise.reject(new Error('destination_not_granted:https://agentavow.com'))) as typeof fetch }
  await assert.rejects(createAdapter(ctx).check!(input(evidenceFor(servedTool()))), /destination_not_granted/)
})

// The pinned attestation cannot be re-signed here. The remaining branches are exercised with a local
// Ed25519 key supplied through config.jwk (the customer-policy override) signing altered payloads.
test('blocking findings: a signed scan with a shipped critical or high does not establish the grade whatever the score', async () => {
  const signer = localSigner()
  const { av, adapter } = make({ jwk: signer.jwk, min_score: 0 })
  const p = signedPayload() as { scan: { findings: Record<string, number>; trustScore: number } }
  p.scan.findings.critical = 1
  p.scan.trustScore = 100
  av.respond = () => scanResponse(signer.sign(p))
  let c = byId((await adapter.check!(input(evidenceFor(servedTool())))).claims)
  assert.deepEqual(c[CLAIM_GRADE], { claim: CLAIM_GRADE, status: 'not_established', reason: 'blocking_findings:critical=1,high=0' })
  assert.equal(c[CLAIM_BINDS].status, 'established')
  p.scan.findings.critical = 0
  p.scan.findings.high = 2
  av.respond = () => scanResponse(signer.sign(p))
  c = byId((await adapter.check!(input(evidenceFor(servedTool())))).claims)
  assert.equal(c[CLAIM_GRADE].reason, 'blocking_findings:critical=0,high=2')
})

test('non-canonical payload: correctly signed but not RFC 8785 bytes: not_established (payload_not_canonical) on every claim', async () => {
  const signer = localSigner()
  const { av, adapter } = make({ jwk: signer.jwk })
  const p = signedPayload()
  av.respond = () => scanResponse(signer.sign(p, JSON.stringify(p, null, 1)))
  const out = await adapter.check!(input(evidenceFor(servedTool())))
  assert.ok(out.claims.every(c => c.status === 'not_established' && c.reason === 'payload_not_canonical'))
})

test('scan fields missing from a verified payload: grade failed, binding and freshness still evaluated', async () => {
  const signer = localSigner()
  const { av, adapter } = make({ jwk: signer.jwk })
  const p = signedPayload() as { scan: Record<string, unknown> }
  delete p.scan.trustScore
  av.respond = () => scanResponse(signer.sign(p))
  const c = byId((await adapter.check!(input(evidenceFor(servedTool())))).claims)
  assert.deepEqual(c[CLAIM_GRADE], { claim: CLAIM_GRADE, status: 'failed', reason: 'attestation_scan_fields_missing' })
  assert.equal(c[CLAIM_BINDS].status, 'established')
  assert.equal(c[CLAIM_FRESH].status, 'established')
})

test('attestation times unparseable: failed (attestation_times_invalid) on every claim, no deadline offered', async () => {
  const signer = localSigner()
  const { av, adapter } = make({ jwk: signer.jwk })
  const p = signedPayload()
  p.expiresAt = 'never'
  av.respond = () => scanResponse(signer.sign(p))
  const out = await adapter.check!(input(evidenceFor(servedTool())))
  assert.ok(out.claims.every(c => c.status === 'failed' && c.reason === 'attestation_times_invalid'))
  assert.equal(out.valid_until, undefined)
})
