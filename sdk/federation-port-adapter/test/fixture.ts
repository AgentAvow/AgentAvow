// Shared test fixture: the pinned DeepWiki attestation from
// docs/standards/tool-manifest-digest-vectors-v1 (one real signed scan of https://mcp.deepwiki.com/mcp,
// trust score 74, three tools), plus a fetch that serves it the way agentavow.com does. Nothing is fetched.
import { generateKeyPairSync, sign as edSign } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { PROFILE, SCAN_PATH, jcs } from '../adapters/agentavow-mcp-admission/adapter.ts'

export const ROOT = join(import.meta.dirname, '..')
export const ADAPTER_DIR = join(ROOT, 'adapters/agentavow-mcp-admission')
export const COMPONENT = 'agentavow.com/mcp-tool-admission'
export const FIXTURE_PATH = join(import.meta.dirname, 'fixtures/tool-manifest-digest-v1-vectors.json')

export interface Vectors {
  issuer: { jwk: { kty: string; crv: string; x: string; kid: string } }
  attestation: { jws: string; subject: { id: string }; issuedAt: string; expiresAt: string; trustScore: number; toolDigests: Record<string, string> }
  observed_tools: (Record<string, unknown> & { name: string })[]
  vectors: { name: string; jws?: string; gate: { subject_id: string; tool_name: string; observed_tool_digest: string; evaluation_time: string } }[]
}
export const vectors: Vectors = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'))

export const ENDPOINT = 'https://mcp.deepwiki.com/mcp'
export const TOOL = 'ask_wiki_question'
/** The vectors' pinned evaluation instant: inside the window. */
export const T_FRESH = '2026-10-01T22:28:34.085Z'
/** One day later: past expiresAt. */
export const T_EXPIRED = '2026-10-02T22:28:34.085Z'
export const TAMPERED_JWS = vectors.vectors.find(v => v.name === 'tampered-payload')!.jws!

export const servedTool = (name = TOOL) => structuredClone(vectors.observed_tools.find(t => t.name === name)!)
export const driftedTool = (name = TOOL) => {
  const t = servedTool(name)
  t.description = String(t.description) + ' (changed after the scan)'
  return t
}

export const evidenceBytes = (o: Record<string, unknown>) => new TextEncoder().encode(JSON.stringify(o))
/** Evidence a gateway would submit: the definition it holds for the tool it is about to dispatch. `endpoint: null` omits the field. */
export const evidenceFor = (tool: Record<string, unknown>, endpoint: string | null = ENDPOINT, profile = PROFILE) =>
  evidenceBytes({ profile, ...(endpoint !== null ? { endpoint } : {}), tool })

/** The signed payload of the pinned attestation, decoded. */
export const signedPayload = (): Record<string, unknown> => JSON.parse(Buffer.from(vectors.attestation.jws.split('.')[1], 'base64url').toString('utf8'))

/** A local Ed25519 signer standing in for AgentAvow, so altered payloads can be signed in tests. */
export function localSigner(kid = vectors.issuer.jwk.kid) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const pub = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string }
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid })).toString('base64url')
  return {
    jwk: { kty: pub.kty, crv: pub.crv, x: pub.x, kid },
    /** Signs `payload`; canonical (JCS) bytes unless `raw` is given, which is signed as-is. */
    sign(payload: Record<string, unknown>, raw?: string): string {
      const p = Buffer.from(raw ?? jcs(payload), 'utf8').toString('base64url')
      const s = edSign(null, Buffer.from(`${header}.${p}`, 'ascii'), privateKey).toString('base64url')
      return `${header}.${p}.${s}`
    },
  }
}

export interface ScanServer {
  /** What agentavow.com answers with. Replaced per test. */
  respond: (url: URL) => Response
  /** URLs this fake received, for assertions on what the adapter sent out. */
  calls: URL[]
}

/** The agentavow.com scan response for the fixture, as the live endpoint shapes it (jws at top level). */
export const scanResponse = (jws = vectors.attestation.jws, status = 200) =>
  new Response(JSON.stringify({ repo: vectors.attestation.subject.id, trust_score: vectors.attestation.trustScore, jws, algorithm: 'EdDSA', key_id: vectors.issuer.jwk.kid, jwks_url: 'https://agentgraph.co/.well-known/jwks.json' }),
    { status, headers: { 'content-type': 'application/json' } })

/** A fake agentavow.com behind a `fetch`. Anything but the scan path is answered 404; `fallback` can forward it. */
export function fakeAgentAvow(fallback?: typeof fetch): ScanServer & { fetch: typeof fetch } {
  const s: ScanServer = { respond: () => scanResponse(), calls: [] }
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    if (url.origin === 'https://agentavow.com' && url.pathname === SCAN_PATH) { s.calls.push(url); return s.respond(url) }
    if (fallback) return fallback(input, init)
    return new Response('not found', { status: 404 })
  }) as typeof fetch
  return Object.assign(s, { fetch: f })
}
