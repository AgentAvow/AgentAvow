// AgentAvow tool-admission component for federation-port/v0.
//
// The check AgentAvow already performs, at the port's boundary: for the one MCP tool call about to be
// dispatched, fetch the signed scan attestation for its server from agentavow.com, verify the JWS
// offline against the pinned AgentAvow key, recompute the per-tool digest of the definition the caller
// holds (profile agentavow.mcp-tool-definition.v1) and compare it with the digest AgentAvow signed for
// that tool, and report whether the evaluation instant lies inside the attestation's validity window.
//
// Written against src/contract/types.ts only. Node built-ins only. Nothing from src/runtime.
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { readFileSync } from 'node:fs'
import type { Adapter, AdapterContext, CheckInput, CheckOutput, ClaimResult, ClaimStatus, Manifest } from '../../src/contract/types.ts'

const manifest: Manifest = JSON.parse(readFileSync(new URL('./manifest.json', import.meta.url), 'utf8'))

export const PROFILE = 'agentavow.mcp-tool-definition.v1'
export const CLAIM_GRADE = 'agentavow.grade'
export const CLAIM_BINDS = 'agentavow.tool_definition_binds'
export const CLAIM_FRESH = 'agentavow.fresh'
const CLAIM_IDS = [CLAIM_GRADE, CLAIM_BINDS, CLAIM_FRESH] as const
export const DEFAULT_MIN_SCORE = 81
export const DEFAULT_API_BASE = 'https://agentavow.com'
export const SCAN_PATH = '/api/v1/public/scan/mcp'

export interface Jwk { kty: string; crv: string; x: string; kid: string }

/**
 * AgentAvow attestation signing key, pinned. The same key is published at
 * https://agentgraph.co/.well-known/jwks.json under this kid. Policy may override it (config.jwk).
 */
export const PINNED_JWK: Readonly<Jwk> = Object.freeze({
  kty: 'OKP', crv: 'Ed25519', x: 'JwovTLVbpgk85zlMNruTiLzp85dAucsZWngs8NisBFg', kid: 'agentgraph-security-v1',
})

/** Policy configuration (ctx.config). Every field is optional. */
export interface Config {
  /** MCP endpoint the workflow is bound to. When set, evidence naming another endpoint is refused. */
  endpoint?: string
  /** MCP tool name, when the workflow's executor tool name differs from it. Defaults to action.tool. */
  tool_name?: string
  /** Minimum trust score for agentavow.grade. Default 81. */
  min_score?: number
  /** AgentAvow API origin. Default https://agentavow.com; must be inside the granted destinations. */
  api_base?: string
  /** Verification key overriding the pin. OKP / Ed25519 with kid. */
  jwk?: Jwk
}

/** Native evidence this component accepts: the served definition the caller holds, and its server. */
export interface Evidence {
  profile: string
  endpoint?: string
  tool: Record<string, unknown> & { name: string }
}

// ---- Derivation: agentavow.mcp-tool-definition.v1, copied from
// docs/standards/tool-manifest-digest-vectors-v1/verify.mjs (toolDigest, toolKey). ----

/** RFC 8785 canonical form for the JSON subset the attestation uses (JSON.stringify string escaping). */
export function jcs(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']'
  const o = v as Record<string, unknown>
  return '{' + Object.keys(o).sort().map(k => JSON.stringify(k) + ':' + jcs(o[k])).join(',') + '}'
}
const FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations'] as const

export function toolDigest(tool: Record<string, unknown>): string {
  const body: Record<string, unknown> = {}
  for (const f of FIELDS) if (tool[f] !== undefined && tool[f] !== null) body[f] = tool[f]
  return 'sha256:' + createHash('sha256').update(jcs({ profile: PROFILE, tool: body })).digest('hex')
}

export function toolKey(name: string): string {
  // Every character outside 0x21-0x7E (so space, controls and all non-ASCII), plus
  // % and =, is percent-encoded as its UTF-8 bytes. If the encoded key body is longer
  // than 128 characters it is cut to its first 96 and suffixed with "~" and the first
  // 16 lowercase hex characters of sha256 over the raw UTF-8 name. The cut is a plain
  // character count and may land inside a %XX triplet.
  const enc = Array.from(name).map(ch =>
    (/[\x21-\x7e]/.test(ch) && ch !== '%' && ch !== '=') ? ch
      : Array.from(Buffer.from(ch, 'utf8')).map(b => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('')
  ).join('')
  const body = enc.length > 128
    ? enc.slice(0, 96) + '~' + createHash('sha256').update(Buffer.from(name, 'utf8')).digest('hex').slice(0, 16)
    : enc
  return 'tool:' + body
}

// ---- Attestation ----

interface Parsed {
  jws: string
  header: { alg?: unknown; kid?: unknown }
  payloadBytes: Buffer
  payload: Record<string, unknown>
  signature: Buffer
  signingInput: Buffer
}

/** Splits a compact JWS. Returns undefined for anything that is not three base64url parts with JSON in the first two. */
function parseJws(jws: unknown): Parsed | undefined {
  if (typeof jws !== 'string') return undefined
  const parts = jws.split('.')
  if (parts.length !== 3) return undefined
  const [h, p, s] = parts as [string, string, string]
  try {
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'))
    const payloadBytes = Buffer.from(p, 'base64url')
    const payload = JSON.parse(payloadBytes.toString('utf8'))
    if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object' || Array.isArray(payload)) return undefined
    return { jws, header, payloadBytes, payload, signature: Buffer.from(s, 'base64url'), signingInput: Buffer.from(`${h}.${p}`, 'ascii') }
  } catch { return undefined }
}

function signatureValid(a: Parsed, key: KeyObject, kid: string): boolean {
  if (a.header.alg !== 'EdDSA' || a.header.kid !== kid) return false
  try { return edVerify(null, a.signingInput, key, a.signature) } catch { return false }
}

const get = (o: unknown, ...path: string[]): unknown => path.reduce<unknown>((v, k) => (v && typeof v === 'object' ? (v as Record<string, unknown>)[k] : undefined), o)
const isJwk = (v: unknown): v is Jwk => !!v && typeof v === 'object'
  && (v as Jwk).kty === 'OKP' && (v as Jwk).crv === 'Ed25519' && typeof (v as Jwk).x === 'string' && typeof (v as Jwk).kid === 'string'

const bytes = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o))
const claim = (id: string, status: ClaimStatus, reason?: string): ClaimResult => (reason ? { claim: id, status, reason } : { claim: id, status })
const every = (status: ClaimStatus, reason: string): ClaimResult[] => CLAIM_IDS.map(id => claim(id, status, reason))

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i
/** True when a path segment looks like a credential rather than a route (same rule as the plugin's
 *  `_has_secret_path`): a UUID, a 32+ character alphanumeric run, or a 16+ character run mixing
 *  letters with three or more digits. Words, versions and dates split on - _ . ~ pass. */
export function hasSecretPath(pathname: string): boolean {
  let path: string
  try { path = decodeURIComponent(pathname) } catch { return true }
  for (const segment of path.split('/')) {
    if (UUID_RE.test(segment)) return true
    for (const run of segment.split(/[-_.~]/)) {
      if (run.length >= 32 && /^[A-Za-z0-9]+$/.test(run)) return true
      if (run.length >= 16 && /[A-Za-z]/.test(run) && (run.match(/\d/g) ?? []).length >= 3) return true
    }
  }
  return false
}

export function createAdapter(ctx: AdapterContext): Adapter {
  const cfg = ctx.config as Config
  if (cfg.jwk !== undefined && !isJwk(cfg.jwk)) throw new Error('config_jwk_invalid')
  const jwk: Jwk = cfg.jwk ?? PINNED_JWK
  const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: 'jwk' })
  const minScore = typeof cfg.min_score === 'number' && Number.isFinite(cfg.min_score) ? cfg.min_score : DEFAULT_MIN_SCORE
  const apiBase = (cfg.api_base ?? DEFAULT_API_BASE).replace(/\/+$/, '')

  return {
    describe: () => manifest,
    async check(input: CheckInput): Promise<CheckOutput> {
      // 1. The caller's evidence: which server, and the definition it holds for the tool being dispatched.
      if (!input.evidence) return { evidence: new Uint8Array(), claims: every('failed', 'evidence_missing') }
      let ev: Evidence
      try { ev = JSON.parse(Buffer.from(input.evidence).toString('utf8')) } catch {
        return { evidence: new Uint8Array(), claims: every('failed', 'evidence_not_json') }
      }
      if (!ev || typeof ev !== 'object') return { evidence: new Uint8Array(), claims: every('failed', 'evidence_not_object') }
      if (ev.profile !== PROFILE) return { evidence: new Uint8Array(), claims: every('unsupported', 'profile_not_implemented') }
      if (!ev.tool || typeof ev.tool !== 'object' || typeof ev.tool.name !== 'string') {
        return { evidence: new Uint8Array(), claims: every('failed', 'evidence_tool_invalid') }
      }
      const toolName = cfg.tool_name ?? input.action.tool
      if (ev.tool.name !== toolName) return { evidence: new Uint8Array(), claims: every('failed', 'evidence_tool_name_mismatch') }
      if (cfg.endpoint !== undefined && ev.endpoint !== undefined && ev.endpoint !== cfg.endpoint) {
        return { evidence: new Uint8Array(), claims: every('failed', 'endpoint_mismatch') }
      }
      const endpoint = cfg.endpoint ?? ev.endpoint
      if (typeof endpoint !== 'string') return { evidence: new Uint8Array(), claims: every('failed', 'endpoint_missing') }
      let scanUrl: string
      try {
        const u = new URL(endpoint)
        if (u.protocol !== 'https:') throw new Error()
        // A server is identified by scheme, host and path. Credentials in the URL (user:pass@, a
        // ?token=, a #fragment) are not part of that identity and never leave the process: the
        // scan is requested, and the signed subject compared, for the URL without them. A path
        // segment that looks like a key is withheld rather than sent. Same rule as the plugin.
        scanUrl = `${u.protocol}//${u.host}${u.pathname}`
        if (hasSecretPath(u.pathname)) return { evidence: new Uint8Array(), claims: every('failed', 'endpoint_path_looks_like_a_credential') }
      } catch {
        return { evidence: new Uint8Array(), claims: every('failed', 'endpoint_invalid') }
      }

      // 2. Recompute what the gate would sign against: the digest of the definition it holds.
      const key_ = toolKey(toolName)
      const observed = toolDigest(ev.tool)

      // 3. The signed attestation for that server. A transport error propagates: the runtime records
      //    the component as unavailable, which is never success.
      const res = await ctx.fetch(`${apiBase}${SCAN_PATH}?endpoint=${encodeURIComponent(scanUrl)}`, { headers: { accept: 'application/json' } })
      const body = new Uint8Array(await res.arrayBuffer())
      if (res.status !== 200) return { evidence: body, claims: every('failed', `scan_http_${res.status}`) }
      let jws: unknown
      try { jws = (JSON.parse(Buffer.from(body).toString('utf8')) as { jws?: unknown }).jws } catch {
        return { evidence: body, claims: every('failed', 'scan_response_not_json') }
      }
      const a = parseJws(jws)
      if (!a) return { evidence: body, claims: every('failed', 'attestation_malformed') }
      const out = { profile: PROFILE, attestation: a.jws, tool_key: key_, observed_tool_digest: observed, signed_tool_digest: null as string | null }
      const signed = get(a.payload, 'scan', 'toolDigests', key_)
      if (typeof signed === 'string') out.signed_tool_digest = signed

      // 4. Prerequisites shared by every claim: the signature, the canonical bytes, the subject.
      //    None of the three claims holds for an attestation that is not AgentAvow's, not
      //    recomputable, or about another server.
      if (!signatureValid(a, key, jwk.kid)) return { evidence: bytes(out), claims: every('not_established', 'signature_invalid') }
      if (jcs(a.payload) !== a.payloadBytes.toString('utf8')) return { evidence: bytes(out), claims: every('not_established', 'payload_not_canonical') }
      if (get(a.payload, 'subject', 'id') !== `mcp:${scanUrl}`) return { evidence: bytes(out), claims: every('not_established', 'subject_mismatch') }
      const issuedMs = Date.parse(String(a.payload.issuedAt))
      const expiresMs = Date.parse(String(a.payload.expiresAt))
      if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs)) return { evidence: bytes(out), claims: every('failed', 'attestation_times_invalid') }

      // 5. agentavow.grade: a signed static grade at or above the policy minimum, with no shipped critical or high finding.
      const score = get(a.payload, 'scan', 'trustScore')
      const critical = get(a.payload, 'scan', 'findings', 'critical')
      const high = get(a.payload, 'scan', 'findings', 'high')
      let grade: ClaimResult
      if (typeof score !== 'number' || typeof critical !== 'number' || typeof high !== 'number') grade = claim(CLAIM_GRADE, 'failed', 'attestation_scan_fields_missing')
      else if (critical > 0 || high > 0) grade = claim(CLAIM_GRADE, 'not_established', `blocking_findings:critical=${critical},high=${high}`)
      else if (score < minScore) grade = claim(CLAIM_GRADE, 'not_established', `score_below_min:${score}<${minScore}`)
      else grade = claim(CLAIM_GRADE, 'established')

      // 6. agentavow.tool_definition_binds: the scan observed a tool of this name and signed this digest for it.
      //    A tool the scan never saw has no signed digest to compare; the claim does not hold
      //    (not_established), and the reason says which of the two it was.
      const binds = typeof signed !== 'string'
        ? claim(CLAIM_BINDS, 'not_established', 'tool_not_in_signed_scan')
        : signed === observed ? claim(CLAIM_BINDS, 'established') : claim(CLAIM_BINDS, 'not_established', 'tool_definition_digest_differs')

      // 7. agentavow.fresh: the evaluation instant inside [issuedAt, expiresAt).
      const nowMs = Date.parse(input.now)
      const fresh = !Number.isFinite(nowMs) ? claim(CLAIM_FRESH, 'failed', 'now_invalid')
        : nowMs < issuedMs ? claim(CLAIM_FRESH, 'not_established', 'attestation_not_yet_valid')
        : nowMs >= expiresMs ? claim(CLAIM_FRESH, 'not_established', 'attestation_expired')
        : claim(CLAIM_FRESH, 'established')

      // valid_until is inclusive at the port and expiresAt is exclusive here, so the last admissible
      // instant is one millisecond before expiresAt.
      return { evidence: bytes(out), claims: [grade, binds, fresh], valid_until: new Date(expiresMs - 1).toISOString() }
    },
  }
}
