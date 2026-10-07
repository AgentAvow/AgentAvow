// The adapter run through federation-port's own runtime and test harness (test/helpers.ts: the APS
// authority component, the simulated refund executor and provider, SQLite store), as a third
// component the `refund` workflow requires. Nothing under federation-port's src/ is changed.
//
// Needs a federation-port checkout with `npm ci` done: FEDERATION_PORT_DIR=/path/to/federation-port.
// Skipped otherwise. The only network stub is agentavow.com, served from the pinned fixture through
// the global fetch the runtime's restricted fetch delegates to; the sim provider on 127.0.0.1 is real.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { CLAIM_BINDS, CLAIM_FRESH, CLAIM_GRADE } from '../adapters/agentavow-mcp-admission/adapter.ts'
import { ADAPTER_DIR, COMPONENT, ENDPOINT, T_EXPIRED, T_FRESH, TAMPERED_JWS, TOOL, driftedTool, evidenceFor, fakeAgentAvow, scanResponse, servedTool, vectors } from './fixture.ts'

const FP = process.env.FEDERATION_PORT_DIR
const ready = !!FP && existsSync(join(FP, 'test/helpers.ts')) && existsSync(join(FP, 'node_modules/agent-passport-system'))
const opts = { skip: ready ? false : 'set FEDERATION_PORT_DIR to a federation-port checkout with node_modules' }

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any
let H: Any
let APS_REQUIRED: { component: string; claim: string }[]
const OUR_CLAIMS = [CLAIM_GRADE, CLAIM_BINDS, CLAIM_FRESH]
const ourRefs = OUR_CLAIMS.map(claim => ({ component: COMPONENT, claim }))

const realFetch = globalThis.fetch
const av = fakeAgentAvow(realFetch)

test.before(async () => {
  if (!ready) return
  H = await import(pathToFileURL(join(FP!, 'test/helpers.ts')).href)
  APS_REQUIRED = H.APS_CLAIMS.map((claim: string) => ({ component: H.APS, claim }))
  globalThis.fetch = av.fetch
})
test.after(() => { globalThis.fetch = realFetch })

/** Policy: APS + sim executor from the harness, plus this component with `config`, all required unless `as` says optional. */
async function withAgentAvow(as: 'required' | 'optional', config: Record<string, unknown>, clockIso: string) {
  const pin = H.pinFromDisk(ADAPTER_DIR, { config: { endpoint: ENDPOINT, tool_name: TOOL, min_score: 70, ...config } })
  const env = await H.setup({ extraComponents: { [COMPONENT]: pin }, required: as === 'required' ? [...APS_REQUIRED, ...ourRefs] : APS_REQUIRED, optional: as === 'optional' ? ourRefs : [] })
  // The vectors pin an evaluation instant; the runtime clock and the APS approval are set to it.
  const now = new Date(clockIso)
  await H.restart(env, env.policy, () => now)
  const submit = async (tool: Record<string, unknown>) => {
    const { req } = H.request(env, undefined, undefined, { issuedAt: now, ttlMs: 60_000 })
    req.evidence[COMPONENT] = evidenceFor(tool)
    const r = await env.rt.submit(req)
    const adm = env.rt.provenance(req.operation_id).admissions.at(-1)
    const ours = Object.fromEntries(adm.claims.filter((c: Any) => c.component === COMPONENT).map((c: Any) => [c.claim, c]))
    return { r, req, adm, ours }
  }
  return { env, submit, close: () => env.close() }
}

test('H1 served definition matches the signed one: admitted, provider called once, three claims established, JWS stored as evidence', opts, async () => {
  av.respond = () => scanResponse()
  const t = await withAgentAvow('required', {}, T_FRESH)
  try {
    const { r, req, adm, ours } = await t.submit(servedTool())
    assert.equal(r.status, 'provider_confirmed', JSON.stringify(r))
    assert.equal(adm.decision, 'admitted')
    for (const c of OUR_CLAIMS) assert.equal(ours[c].status, 'established', c)
    assert.equal(t.env.provider.requests, 1)
    const ev = JSON.parse(Buffer.from(t.env.rt.store.evidence(req.operation_id, COMPONENT, 'check:0')!).toString())
    assert.equal(ev.attestation, vectors.attestation.jws)
    assert.equal(ev.observed_tool_digest, vectors.attestation.toolDigests['tool:ask_wiki_question'])
    assert.deepEqual(t.env.rt.store.usage(req.operation_id).map((u: Any) => u.component), [H.APS, COMPONENT, H.EXEC].sort())
    // Admission deadline: the earliest valid_until among required components. The APS approval (now+60s)
    // is earlier than the attestation's expiresAt-1ms, so the stored deadline is the approval's.
    assert.equal(t.env.rt.store.getOperation(req.operation_id).valid_until_ms, now60(T_FRESH))
  } finally { await t.close() }
})
const now60 = (iso: string) => Date.parse(iso) + 60_000

test('H2 served definition drifted from the signed one: refused on tool_definition_binds, nothing dispatched', opts, async () => {
  av.respond = () => scanResponse()
  const t = await withAgentAvow('required', {}, T_FRESH)
  try {
    const { r, ours } = await t.submit(driftedTool())
    assert.equal(r.status, 'refused')
    assert.deepEqual(r.reasons, [`required_claim_not_established:${COMPONENT}#${CLAIM_BINDS}:tool_definition_digest_differs`])
    assert.equal(ours[CLAIM_GRADE].status, 'established')
    assert.equal(ours[CLAIM_FRESH].status, 'established')
    assert.equal(t.env.provider.requests, 0)
    assert.equal(t.env.rt.store.countDispatches(), 0)
  } finally { await t.close() }
})

test('H3 tool the scan never observed: refused, tool_not_in_signed_scan', opts, async () => {
  av.respond = () => scanResponse()
  const t = await withAgentAvow('required', { tool_name: 'delete_wiki_page' }, T_FRESH)
  try {
    const def = servedTool()
    def.name = 'delete_wiki_page'
    const { r } = await t.submit(def)
    assert.equal(r.status, 'refused')
    assert.deepEqual(r.reasons, [`required_claim_not_established:${COMPONENT}#${CLAIM_BINDS}:tool_not_in_signed_scan`])
    assert.equal(t.env.provider.requests, 0)
  } finally { await t.close() }
})

test('H4 evaluation instant past expiresAt: refused on fresh; grade and binding still established', opts, async () => {
  av.respond = () => scanResponse()
  const t = await withAgentAvow('required', {}, T_EXPIRED)
  try {
    const { r, ours } = await t.submit(servedTool())
    assert.equal(r.status, 'refused')
    assert.deepEqual(r.reasons, [`required_claim_not_established:${COMPONENT}#${CLAIM_FRESH}:attestation_expired`])
    assert.equal(ours[CLAIM_GRADE].status, 'established')
    assert.equal(ours[CLAIM_BINDS].status, 'established')
    assert.equal(t.env.provider.requests, 0)
  } finally { await t.close() }
})

test('H5 tampered attestation (payload edited after signing): refused, every claim not_established:signature_invalid', opts, async () => {
  av.respond = () => scanResponse(TAMPERED_JWS)
  const t = await withAgentAvow('required', {}, T_FRESH)
  try {
    const { r } = await t.submit(servedTool())
    assert.equal(r.status, 'refused')
    assert.deepEqual(r.reasons, OUR_CLAIMS.map(c => `required_claim_not_established:${COMPONENT}#${c}:signature_invalid`))
    assert.equal(t.env.provider.requests, 0)
  } finally { await t.close() }
})

test('H6 default threshold (81) against a score of 74: refused on grade alone', opts, async () => {
  av.respond = () => scanResponse()
  const t = await withAgentAvow('required', { min_score: undefined }, T_FRESH)
  try {
    const { r } = await t.submit(servedTool())
    assert.equal(r.status, 'refused')
    assert.deepEqual(r.reasons, [`required_claim_not_established:${COMPONENT}#${CLAIM_GRADE}:score_below_min:74<81`])
  } finally { await t.close() }
})

test('H7 agentavow.com answers 503: required refuses with failed; optional proceeds and records failed', opts, async () => {
  av.respond = () => new Response('{"error":"unavailable"}', { status: 503 })
  let t = await withAgentAvow('required', {}, T_FRESH)
  try {
    const { r } = await t.submit(servedTool())
    assert.equal(r.status, 'refused')
    assert.deepEqual(r.reasons, OUR_CLAIMS.map(c => `required_claim_failed:${COMPONENT}#${c}:scan_http_503`))
    assert.equal(t.env.provider.requests, 0)
  } finally { await t.close() }
  t = await withAgentAvow('optional', {}, T_FRESH)
  try {
    const { r, ours } = await t.submit(servedTool())
    assert.equal(r.status, 'provider_confirmed')
    for (const c of OUR_CLAIMS) assert.deepEqual([ours[c].status, ours[c].reason, ours[c].requirement], ['failed', 'scan_http_503', 'optional'])
  } finally { await t.close() }
})

test('H8 agentavow.com unreachable (transport error): required claims unavailable, optional unevaluated', opts, async () => {
  av.respond = () => { throw new TypeError('fetch failed') }
  let t = await withAgentAvow('required', {}, T_FRESH)
  try {
    const { r } = await t.submit(servedTool())
    assert.equal(r.status, 'refused')
    assert.ok(r.reasons.every((x: string) => x.startsWith(`required_claim_unavailable:${COMPONENT}#`) && x.includes('component_unavailable')), JSON.stringify(r.reasons))
  } finally { await t.close() }
  t = await withAgentAvow('optional', {}, T_FRESH)
  try {
    const { r, ours } = await t.submit(servedTool())
    assert.equal(r.status, 'provider_confirmed')
    for (const c of OUR_CLAIMS) assert.equal(ours[c].status, 'unevaluated')
  } finally { await t.close() }
})

/** setup() with a provider we own, so a load refusal does not leave its HTTP server open. */
async function loadRefused(pin: Any, pattern: RegExp) {
  const { startProvider } = await import(pathToFileURL(join(FP!, 'sim/provider.ts')).href)
  const apiKey = 'k'.repeat(48)
  const provider = await startProvider({ apiKey })
  try {
    await assert.rejects(H.setup({ provider, apiKey, extraComponents: { [COMPONENT]: pin }, required: [...APS_REQUIRED, ...ourRefs] }), pattern)
  } finally { await provider.close() }
}

test('H9 destination not granted by the operator: the component does not load (destinations_exceed_grant)', opts, async () => {
  await loadRefused(H.pinFromDisk(ADAPTER_DIR, { config: {}, destinations_allowed: [] }), /destinations_exceed_grant:agentavow.com\/mcp-tool-admission/)
})

test('H10 adapter.ts changed after pinning: refused at load (artifact_digest_mismatch)', opts, async () => {
  const { writeFileSync, readFileSync, mkdtempSync, cpSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const copy = join(mkdtempSync(join(tmpdir(), 'fp-av-')), 'c')
  cpSync(ADAPTER_DIR, copy, { recursive: true })
  const pin = H.pinFromDisk(copy, { config: {} })
  writeFileSync(join(copy, 'adapter.ts'), readFileSync(join(copy, 'adapter.ts'), 'utf8') + '\n// changed after pinning\n')
  await loadRefused(pin, /artifact_digest_mismatch/)
})
