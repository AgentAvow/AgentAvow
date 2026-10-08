// The AgentAvow gate core: framework-agnostic "may this agent use this tool?"
// decisions from AgentAvow's signed scan results.
//
//   const gate = createGate({ allowFloor: 51, onReview: 'block' })
//   const d = await gate.check('https://mcp.deepwiki.com/mcp')        // safe | review | do_not_connect
//   const c = await gate.checkToolCall({ server, toolName, servedDefinition })  // + drift check
//
// What it decides from: the public scan response for the server, package or
// repo the tool comes from (one auth-free GET, cached; never a re-scan). With
// `verifySignature: true` (the default) the EdDSA JWS attestation in the
// response is verified against AgentAvow's JWKS (pinned by `kid`, WebCrypto
// Ed25519) and the score, tier, findings, tool digests and supply-chain block
// are read from the *signed* payload. Unsigned fields of the response (the
// sandbox `behavioral` block, a `decision`/`verdict` label) can only make the
// decision stricter, never looser.
//
// Three-phrase decision, derived in ONE place (`deriveDecision`) so the rule can
// be swapped when the API grows a `decision` field:
//   do_not_connect  a `blockOn` trigger fired (critical finding, sandbox canary
//                   exfiltration, known-malicious dependency, blocked tier), or
//                   a tool definition drifted / was never graded under
//                   `onDrift: 'block'`, or AgentAvow could not answer under
//                   `onApiError: 'block'`.
//   review          the score is under `allowFloor`, a high finding is on the
//                   result, the result is older than `maxStaleMs`, or a softer
//                   policy routed drift / unscanned / API error here. What
//                   `review` does is `onReview`: block, warn, or confirm (ask
//                   the `confirm` hook; without one, `confirm` blocks).
//   safe            everything else. `allowed` is the bottom line.
//
// Hot path: `check` reads the in-memory cache (1h TTL, stale-while-revalidate)
// and `checkToolCall` compares the served definition's digest with the pinned
// or signed digest in memory. Nothing in the per-call path triggers a scan.
//
// Runtime: WebCrypto + global fetch only (no `node:crypto`, no `Buffer`), so the
// same code runs on Node 18+, Bun, Deno and Cloudflare Workers. One dependency,
// `canonicalize` (RFC 8785), for the per-tool digest.

import canonicalizeImport from 'canonicalize';
import { sha256Hex } from './sha256.js';
import {
  DEFAULT_JWKS_URL, JwksCache, decodeJws, verifyJws, type Jwks,
} from './jws.js';

// `canonicalize` is CommonJS (`module.exports = fn`), but its .d.ts says `export default`,
// so under NodeNext the default import is typed as the module namespace. At runtime
// (ESM importing CJS) it is the function itself.
const canonicalize = canonicalizeImport as unknown as (input: unknown) => string | undefined;

export const DEFAULT_BASE_URL = 'https://agentavow.com/api/v1';
/** @deprecated The 0.2.x `evaluate` / `minScore` floor (Trusted). Use `allowFloor`. */
export const DEFAULT_MIN_SCORE = 81;
export const DEFAULT_ALLOW_FLOOR = 51; // the gate's default floor (Standard); 81 is strict
/** @deprecated The 0.2.x `evaluate` severities. Use `DEFAULT_BLOCK_TRIGGERS`. */
export const DEFAULT_BLOCK_ON: readonly string[] = ['critical', 'high'];
export const DEFAULT_BLOCK_TRIGGERS: readonly BlockTrigger[] =
  ['critical', 'sandbox_canary', 'malicious_dependency', 'blocked_tier'];
export const DEFAULT_CACHE_TTL_MS = 3_600_000;
export const DEFAULT_MAX_STALE_MS = 30 * 24 * 3_600_000;
export const BLOCKED_TIER_CEILING = 10; // 0-10 is the `blocked` tier
export const ISSUER_DID = 'did:web:agentgraph.co';
export { DEFAULT_JWKS_URL };
const WEB = 'https://agentavow.com';
const MAX_REDIRECTS = 3;
export const VERSION = '0.3.0';

// ── the per-tool digest, exactly as the attestation signs it ────────────────

export const PROFILE = 'agentavow.mcp-tool-definition.v1';
export const DIGEST_FIELDS = [
  'name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations',
] as const;
const MAX_KEY_NAME = 128;
const MAX_TOOL_DIGESTS = 500;

export type ToolDefinition = Record<string, unknown> & { name: string };

function sha256(text: string): string {
  return 'sha256:' + sha256Hex(text);
}

/** `tool:<name>`: everything outside printable ASCII, plus % and =, is
 *  percent-encoded as UTF-8 bytes; an overlong key is cut and suffixed. */
export function toolKey(name: string): string {
  const encoder = new TextEncoder();
  let enc = '';
  for (const ch of name) {
    const cp = ch.codePointAt(0) as number;
    if (cp >= 0x21 && cp <= 0x7e && ch !== '%' && ch !== '=') {
      enc += ch;
    } else {
      for (const b of encoder.encode(ch)) {
        enc += '%' + b.toString(16).toUpperCase().padStart(2, '0');
      }
    }
  }
  if (enc.length > MAX_KEY_NAME) {
    enc = enc.slice(0, 96) + '~' + sha256Hex(name).slice(0, 16);
  }
  return 'tool:' + enc;
}

/** The JCS preimage of a tool's digest: `{ profile, tool: <restricted definition> }`;
 *  a missing or null field is omitted, `_meta` and unknown fields never enter. */
export function toolDigestInput(def: Record<string, unknown>): string | null {
  const body: Record<string, unknown> = {};
  for (const f of DIGEST_FIELDS) {
    if (def[f] !== undefined && def[f] !== null) body[f] = def[f];
  }
  try {
    return canonicalize({ profile: PROFILE, tool: body }) ?? null;
  } catch {
    return null;
  }
}

/** `sha256:<hex>` over the digest preimage; null when the definition cannot be
 *  canonicalized. */
export function toolDigest(def: Record<string, unknown>): string | null {
  const canon = toolDigestInput(def);
  return canon === null ? null : sha256(canon);
}

/** `{ "tool:<name>": "sha256:…" }` for a served tools/list. Tools that cannot be
 *  hashed are left out. */
export function digestMap(tools: readonly Record<string, unknown>[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of tools) {
    if (!t || typeof t !== 'object' || typeof t.name !== 'string') continue;
    const d = toolDigest(t);
    if (d) out[toolKey(t.name)] = d;
  }
  return out;
}

// ── coordinates ──────────────────────────────────────────────────────────────

const PACKAGE_SURFACES = ['npm', 'pypi', 'crates', 'docker', 'huggingface'];

export function parseCoordinate(server: string): { kind: string; target: string } {
  const s = (server ?? '').trim();
  if (!s) throw new Error('empty server coordinate');
  const low = s.toLowerCase();
  if (low.startsWith('https://') || low.startsWith('http://')) return { kind: 'mcp', target: s };
  if (low.startsWith('mcp:')) return { kind: 'mcp', target: s.slice(4).trim() };
  if (low.startsWith('github:')) {
    return { kind: 'github', target: s.slice(7).trim().replace(/^\/+|\/+$/g, '') };
  }
  for (const surface of PACKAGE_SURFACES) {
    if (low.startsWith(surface + ':')) return { kind: surface, target: s.slice(surface.length + 1).trim() };
  }
  if ((s.match(/\//g) ?? []).length === 1 && !s.includes(':')) {
    return { kind: 'github', target: s.replace(/^\/+|\/+$/g, '') };
  }
  throw new Error(`unrecognized server coordinate: ${server}`);
}

export function gradeUrl(baseUrl: string, server: string): string {
  const { kind, target } = parseCoordinate(server);
  const base = baseUrl.replace(/\/+$/, '');
  if (kind === 'mcp') return `${base}/public/scan/mcp?endpoint=${encodeURIComponent(target)}`;
  if (kind === 'github') return `${base}/public/scan/${target}`;
  return `${base}/public/scan/package/${kind}/${target}`;
}

export function reportUrl(server: string): string {
  try {
    const { kind, target } = parseCoordinate(server);
    if (kind === 'mcp') return `${WEB}/check/mcp?endpoint=${encodeURIComponent(target)}`;
    if (kind === 'github') return `${WEB}/check/${target}`;
    return `${WEB}/check/pkg/${kind}/${target}`;
  } catch {
    return `${WEB}/check`;
  }
}

/** The attestation `subject.id` AgentAvow signs for a coordinate
 *  (`github:owner/repo`, `npm:name`, `mcp:https://…`). */
export function subjectId(server: string): string {
  const { kind, target } = parseCoordinate(server);
  return `${kind}:${target}`;
}

function sameSubject(a: string, b: string): boolean {
  const norm = (s: string) => s.trim().replace(/\/+$/, '').toLowerCase();
  return norm(a) === norm(b);
}

// ── the grade: what the gate needs from one scan response ───────────────────

export type SignatureState = 'verified' | 'invalid' | 'unverified' | 'missing';

export interface Grade {
  server: string;
  score: number | null;
  tier: string;
  critical: number;
  high: number;
  findings: Array<Record<string, unknown>>;
  toolDigests: Record<string, string>;
  toolManifestDigest: string | null;
  reportUrl: string;
  jws: string | null;
  fetchedAt: number;
  error: string | null;
  /** ISO time the analysis ran (signed `scannedAt` when verified). */
  scannedAt: string | null;
  /** The API's own label when the response carries one (unsigned; tighten-only). */
  apiDecision: string | null;
  verdict: string | null;
  /** Adoption score when the response carries one (never a verdict input). */
  adoption: number | null;
  /** The Certified mark (`certified.eligible` / `certified_mark` / a boolean `certified`).
   *  Its own mark, carried next to the decision and never folded into it. */
  certified: boolean;
  /** OSV `MAL-` ids among the dependencies (signed supplyChain when verified). */
  maliciousDeps: string[];
  /** The behavioral sandbox leaked a canary credential (unsigned block). */
  canaryExfil: boolean;
  signature: SignatureState;
  signatureReason: string | null;
  kid: string | null;
  /** The decoded attestation payload (verified when `signature === 'verified'`). */
  attestation: Record<string, unknown> | null;
}

export function errorGrade(server: string, error: string): Grade {
  return {
    server, score: null, tier: '', critical: 0, high: 0, findings: [], toolDigests: {},
    toolManifestDigest: null, reportUrl: reportUrl(server), jws: null, fetchedAt: Date.now(), error,
    scannedAt: null, apiDecision: null, verdict: null, adoption: null, certified: false, maliciousDeps: [],
    canaryExfil: false, signature: 'missing', signatureReason: null, kid: null, attestation: null,
  };
}

type Dict = Record<string, any>;

function findingsOf(findings: unknown): {
  items: Array<Record<string, unknown>>; critical: number; high: number;
} {
  const f: Dict = findings && typeof findings === 'object' ? findings as Dict : {};
  const rawItems = Array.isArray(findings) ? findings : f.items ?? [];
  const items = (rawItems as unknown[]).filter(
    (x): x is Record<string, unknown> => !!x && typeof x === 'object');
  const sev = items.map((x) => String(x.severity ?? '').toLowerCase());
  const count = (k: string) => Number((!Array.isArray(findings) && f[k]) || 0);
  return {
    items,
    critical: Math.max(count('critical'), sev.filter((s) => s === 'critical').length),
    high: Math.max(count('high'), sev.filter((s) => s === 'high').length),
  };
}

function maliciousOf(supplyChain: unknown, items: Array<Record<string, unknown>>): string[] {
  const out = new Set<string>();
  const sc: Dict = supplyChain && typeof supplyChain === 'object' ? supplyChain as Dict : {};
  for (const id of Array.isArray(sc.malicious) ? sc.malicious : []) out.add(String(id));
  for (const f of items) {
    const name = String(f.name ?? f.title ?? '').toLowerCase();
    if (name.startsWith('known-malicious')) out.add(String(f.advisory ?? f.id ?? name));
  }
  return [...out];
}

function canaryOf(behavioral: unknown): boolean {
  const b: Dict = behavioral && typeof behavioral === 'object' ? behavioral as Dict : {};
  if (!b.ran || b.plan === 'live-probe' || b.advisory === true) return false;
  const c = b.canary_exfil;
  return Array.isArray(c) ? c.length > 0 : !!c;
}

function digestsOf(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (raw && typeof raw === 'object') {
    for (const [k, v] of Object.entries(raw as Dict)) out[String(k)] = String(v);
  }
  return out;
}

const DECISIONS = ['safe', 'review', 'do_not_connect'];

/** The Certified mark as the API carries it: `certified: { eligible }`, a bare
 *  boolean `certified`, or `certified_mark`. */
export function certifiedOf(data: Dict): boolean {
  const c = data.certified;
  if (typeof c === 'boolean') return c;
  if (c && typeof c === 'object' && typeof c.eligible === 'boolean') return c.eligible;
  const m = data.certified_mark;
  if (typeof m === 'boolean') return m;
  if (m && typeof m === 'object' && typeof m.eligible === 'boolean') return m.eligible;
  return false;
}

/** The unsigned view of a public scan response. */
export function gradeFromResponse(server: string, data: Dict): Grade {
  const { items, critical, high } = findingsOf(data.findings);
  const score = typeof data.trust_score === 'number' ? Math.trunc(data.trust_score) : null;
  const adoptionRaw = data.adoption?.score ?? data.adoption_score;
  const apiDecision = DECISIONS.includes(String(data.decision)) ? String(data.decision) : null;
  return {
    server, score, tier: String(data.trust_tier ?? ''), critical, high, findings: items,
    toolDigests: digestsOf(data.tool_digests),
    toolManifestDigest: typeof data.tool_manifest_digest === 'string' ? data.tool_manifest_digest : null,
    reportUrl: reportUrl(server),
    jws: typeof data.jws === 'string' ? data.jws : null, fetchedAt: Date.now(), error: null,
    scannedAt: typeof data.scanned_at === 'string' ? data.scanned_at : null,
    apiDecision, verdict: typeof data.verdict === 'string' ? data.verdict : null,
    adoption: typeof adoptionRaw === 'number' ? adoptionRaw : null,
    certified: certifiedOf(data),
    maliciousDeps: maliciousOf(data.supply_chain, items),
    canaryExfil: canaryOf(data.behavioral),
    signature: typeof data.jws === 'string' ? 'unverified' : 'missing', signatureReason: null,
    kid: typeof data.key_id === 'string' ? data.key_id : null, attestation: null,
  };
}

/**
 * Verify the grade's JWS and, when it verifies, replace the decision inputs with
 * the signed ones (`scan.trustScore`, `scan.trustTier`, `scan.findings`,
 * `scan.toolDigests`, `scan.toolManifestDigest`, `scan.supplyChain`, `scannedAt`).
 * The subject must be the coordinate that was asked for and the attestation must
 * not have expired, and an issuer it names must be `expectIssuer` (AgentAvow's DID
 * unless the policy's `issuer` says otherwise). On any failure the grade is marked `invalid` with the reason;
 * what that means for the decision is `deriveDecision`'s call.
 */
export async function verifyGrade(
  grade: Grade, jwks: Jwks, now: number = Date.now(), expectIssuer: string = ISSUER_DID,
): Promise<Grade> {
  if (!grade.jws) return { ...grade, signature: 'missing', signatureReason: 'response carries no jws' };
  const r = await verifyJws(grade.jws, jwks, { expectKid: grade.kid });
  if (!r.valid || !r.payload) return { ...grade, signature: 'invalid', signatureReason: r.reason, kid: r.kid };
  const p: Dict = r.payload;
  const subject = String(p.subject?.id ?? p.subject?.repo ?? '');
  let expected: string;
  try {
    expected = subjectId(grade.server);
  } catch {
    expected = grade.server;
  }
  if (!sameSubject(subject, expected)) {
    return { ...grade, signature: 'invalid', kid: r.kid,
      signatureReason: `attestation subject ${subject || '(none)'} is not ${expected}` };
  }
  const expires = Date.parse(String(p.expiresAt ?? ''));
  if (Number.isFinite(expires) && expires < now) {
    return { ...grade, signature: 'invalid', kid: r.kid, signatureReason: `attestation expired at ${p.expiresAt}` };
  }
  const issuer = String(p.issuer?.id ?? '');
  if (issuer && issuer !== expectIssuer) {
    return { ...grade, signature: 'invalid', kid: r.kid, signatureReason: `attestation issuer ${issuer} is not ${expectIssuer}` };
  }
  const scan: Dict = p.scan && typeof p.scan === 'object' ? p.scan : {};
  const { items, critical, high } = findingsOf(scan.findings);
  const score = typeof scan.trustScore === 'number' ? Math.trunc(scan.trustScore) : null;
  const signedDecision = DECISIONS.includes(String(scan.decision)) ? String(scan.decision) : null;
  return {
    ...grade,
    score, tier: String(scan.trustTier ?? grade.tier), critical, high, findings: items,
    toolDigests: digestsOf(scan.toolDigests),
    toolManifestDigest: typeof scan.toolManifestDigest === 'string' ? scan.toolManifestDigest : null,
    scannedAt: typeof p.scannedAt === 'string' ? p.scannedAt : grade.scannedAt,
    // An unsigned label may only tighten; a signed one (future) is authoritative.
    apiDecision: signedDecision ?? grade.apiDecision,
    maliciousDeps: [...new Set([...maliciousOf(scan.supplyChain, items), ...grade.maliciousDeps])],
    signature: 'verified', signatureReason: null, kid: r.kid, attestation: p,
  };
}

// ── policy ───────────────────────────────────────────────────────────────────

export type BlockTrigger =
  | 'critical' | 'high' | 'sandbox_canary' | 'malicious_dependency' | 'blocked_tier';
export type OnReview = 'confirm' | 'warn' | 'block';
export type OnDrift = 'block' | 'review' | 'allow';
export type OnApiError = 'allow' | 'block';

/** One JSON-able object. Every field has a default; `pins` is the only one you
 *  would normally generate rather than write. */
export interface GatePolicy {
  /** Lowest trust score (0-100) that is `safe` without review. Default 51 (Standard); 81 is strict (Trusted). */
  allowFloor?: number;
  /** What makes a target `do_not_connect` regardless of score. */
  blockOn?: readonly BlockTrigger[];
  /** What a `review` decision does: block the call, let it run with a warning, or ask `confirm`. Default block. */
  onReview?: OnReview;
  /** A served tool definition that does not match its pinned/signed digest, or a tool the grade never saw. Default block. */
  onDrift?: OnDrift;
  /** The target has no grade (AgentAvow returned none). Default block. */
  onUnscanned?: OnDrift;
  /** AgentAvow unreachable, bad response, or the attestation did not verify. Default block (fail closed). */
  onApiError?: OnApiError;
  /** A grade whose analysis is older than this is `review`. Default 30 days. */
  maxStaleMs?: number;
  /** In-memory cache of grades; stale entries are served while a refresh runs. Default 1 hour. */
  cacheTtlMs?: number;
  /** Expected tool digests per server coordinate (`{ server: { "tool:<name>" | "<name>": "sha256:…" } }`).
   *  A pinned server is compared against the pins instead of the signed digests. */
  pins?: Record<string, Record<string, string>>;
  /** Verify the attestation and decide on signed fields only. Default true. When false the
   *  unsigned JSON is trusted as served over https (same trust as the API itself). */
  verifySignature?: boolean;
  /** A tool that maps to no server (your own function): run it, or refuse. Default allow. */
  unmapped?: 'allow' | 'block';
  baseUrl?: string;
  jwksUrl?: string;
  /** The issuer DID the attestation must name. Default AgentAvow's (`did:web:agentgraph.co`).
   *  Change it only together with `jwksUrl`/`jwks`, for a grader you run yourself
   *  (the offline demo in `demos/rugpull` uses `did:web:demo.invalid`). */
  issuer?: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
}

export interface GateHooks {
  fetch?: FetchLike;
  /** `onReview: 'confirm'`: resolve true to let the call run. Without it, confirm blocks. */
  confirm?: (decision: Decision) => boolean | Promise<boolean>;
  onWarn?: (message: string, decision?: Decision) => void;
  /** An inline JWKS (tests, air-gapped use) instead of fetching `jwksUrl`. */
  jwks?: Jwks;
  now?: () => number;
}

export type ResolvedPolicy = Required<Omit<GatePolicy, 'pins' | 'headers' | 'timeoutMs'>> &
  { pins: Record<string, Record<string, string>>; headers: Record<string, string>; timeoutMs: number };

export function resolvePolicy(p: GatePolicy = {}): ResolvedPolicy {
  const pick = <T extends string>(v: unknown, allowed: readonly T[], name: string, dflt: T): T => {
    if (v === undefined) return dflt;
    if (!allowed.includes(v as T)) throw new Error(`${name} must be ${allowed.join(' | ')}, got ${String(v)}`);
    return v as T;
  };
  const allowFloor = p.allowFloor ?? DEFAULT_ALLOW_FLOOR;
  if (typeof allowFloor !== 'number' || allowFloor < 0 || allowFloor > 100) {
    throw new Error(`allowFloor must be 0..100, got ${String(allowFloor)}`);
  }
  return {
    allowFloor,
    blockOn: (p.blockOn ?? DEFAULT_BLOCK_TRIGGERS).map((t) => String(t).toLowerCase() as BlockTrigger),
    onReview: pick(p.onReview, ['confirm', 'warn', 'block'] as const, 'onReview', 'block'),
    onDrift: pick(p.onDrift, ['block', 'review', 'allow'] as const, 'onDrift', 'block'),
    onUnscanned: pick(p.onUnscanned, ['block', 'review', 'allow'] as const, 'onUnscanned', 'block'),
    onApiError: pick(p.onApiError, ['allow', 'block'] as const, 'onApiError', 'block'),
    maxStaleMs: p.maxStaleMs ?? DEFAULT_MAX_STALE_MS,
    cacheTtlMs: p.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS,
    pins: normalizePins(p.pins ?? {}),
    verifySignature: p.verifySignature ?? true,
    unmapped: pick(p.unmapped, ['allow', 'block'] as const, 'unmapped', 'allow'),
    baseUrl: (p.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, ''),
    jwksUrl: p.jwksUrl ?? DEFAULT_JWKS_URL,
    issuer: p.issuer ?? ISSUER_DID,
    timeoutMs: p.timeoutMs ?? 10_000,
    headers: p.headers ?? {},
  };
}

/** Pins keyed by bare tool name become `tool:<name>` keys. */
function normalizePins(pins: Record<string, Record<string, string>>): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  for (const [server, map] of Object.entries(pins)) {
    const m: Record<string, string> = {};
    for (const [k, v] of Object.entries(map ?? {})) m[k.startsWith('tool:') ? k : toolKey(k)] = String(v);
    out[server] = m;
  }
  return out;
}

// ── the decision ─────────────────────────────────────────────────────────────

export type DecisionLabel = 'safe' | 'review' | 'do_not_connect';
export type DecisionOutcome =
  | 'allow' | 'low_score' | 'finding' | 'blocked' | 'stale' | 'drift' | 'unknown_tool'
  | 'unscanned' | 'api_error' | 'unverified' | 'unmapped';

export interface Decision {
  decision: DecisionLabel;
  /** The bottom line after `onReview` / `onDrift` / `onApiError` are applied. */
  allowed: boolean;
  outcome: DecisionOutcome;
  reason: string;
  score: number | null;
  tier: string | null;
  adoption?: number;
  /** The Certified mark, next to the decision and never folded into it: a reader
   *  can show "Safe to connect · Certified". Pass-through from the API (unsigned). */
  certified: boolean;
  reportUrl: string;
  attestation: {
    jws: string; kid: string | null; verified: boolean; payload: Record<string, unknown> | null;
  } | null;
  server: string | null;
  toolName: string | null;
  servedDigest: string | null;
  signedDigest: string | null;
  warnings: string[];
  grade: Grade | null;
}

export class GateError extends Error {
  decision: Decision;
  constructor(decision: Decision) {
    super(decision.reason);
    this.name = 'AgentAvowGateError';
    this.decision = decision;
  }
}

function scoreText(grade: Grade): string {
  if (grade.score === null) return 'no score';
  return `${grade.score}/100${grade.tier ? `, tier ${grade.tier}` : ''}`;
}

function base(grade: Grade, server: string, toolName: string | null): Decision {
  const d: Decision = {
    decision: 'review', allowed: false, outcome: 'low_score', reason: '',
    score: grade.score, tier: grade.tier || null, certified: grade.certified,
    reportUrl: grade.reportUrl || reportUrl(server),
    attestation: grade.jws ? {
      jws: grade.jws, kid: grade.kid, verified: grade.signature === 'verified', payload: grade.attestation,
    } : null,
    server, toolName, servedDigest: null, signedDigest: null, warnings: [], grade,
  };
  if (grade.adoption !== null) d.adoption = grade.adoption;
  return d;
}

/** Apply `onReview` to a `review` decision; `confirm` is the caller's (async) job. */
function applyReview(d: Decision, policy: ResolvedPolicy): Decision {
  if (d.decision !== 'review') return d;
  if (policy.onReview === 'warn') {
    d.allowed = true;
    d.warnings.push(d.reason);
  } else {
    d.allowed = false; // 'block', and 'confirm' until the hook says otherwise
  }
  return d;
}

function softened(d: Decision, mode: OnDrift, policy: ResolvedPolicy): Decision {
  if (mode === 'block') {
    d.decision = 'do_not_connect';
    d.allowed = false;
    return d;
  }
  if (mode === 'review') {
    d.decision = 'review';
    return applyReview(d, policy);
  }
  d.decision = 'safe';
  d.allowed = true;
  d.warnings.push(d.reason);
  return d;
}

/**
 * THE three-phrase rule, grade -> decision, no I/O. Kept in one function so it can
 * be swapped when the API's own `decision` field lands (today an unsigned label can
 * only tighten the derived decision; a signed one is taken as authoritative).
 */
export function deriveDecision(grade: Grade, policy: ResolvedPolicy, toolName: string | null = null): Decision {
  const server = grade.server;
  const d = base(grade, server, toolName);
  const what = toolName ? `'${toolName}' on ${server}` : server;
  const report = `Report: ${d.reportUrl}`;

  if (grade.error) {
    d.outcome = 'api_error';
    d.reason = `AgentAvow could not grade ${server} (${grade.error}). ${report}`;
    return softened(d, policy.onApiError === 'block' ? 'block' : 'allow', policy);
  }
  if (policy.verifySignature && grade.signature !== 'verified') {
    d.outcome = 'unverified';
    d.reason = `AgentAvow's attestation for ${server} did not verify (${grade.signatureReason ?? grade.signature}). ${report}`;
    return softened(d, policy.onApiError === 'block' ? 'block' : 'allow', policy);
  }
  if (grade.score === null) {
    d.outcome = 'unscanned';
    d.reason = `AgentAvow has no grade for ${server}. ${report}`;
    return softened(d, policy.onUnscanned, policy);
  }

  // Hard stops: policy triggers, then an API/signed label that says so.
  const hits: string[] = [];
  for (const t of policy.blockOn) {
    if (t === 'critical' && grade.critical > 0) hits.push(`${grade.critical} critical finding${grade.critical > 1 ? 's' : ''}`);
    if (t === 'high' && grade.high > 0) hits.push(`${grade.high} high finding${grade.high > 1 ? 's' : ''}`);
    if (t === 'sandbox_canary' && grade.canaryExfil) hits.push('a sandbox canary credential was exfiltrated');
    if (t === 'malicious_dependency' && grade.maliciousDeps.length) {
      hits.push(`a known-malicious dependency (${grade.maliciousDeps.join(', ')})`);
    }
    if (t === 'blocked_tier' && grade.score <= BLOCKED_TIER_CEILING) hits.push(`the blocked tier (${scoreText(grade)})`);
  }
  const tierOnly = hits.length === 1 && hits[0]?.startsWith('the blocked tier');
  if (grade.apiDecision === 'do_not_connect') hits.push('AgentAvow says do not connect');
  if (hits.length) {
    d.decision = 'do_not_connect';
    d.allowed = false;
    d.outcome = tierOnly ? 'blocked' : 'finding';
    d.reason = `AgentAvow: do not connect ${what}: ${hits.join('; ')} (graded ${scoreText(grade)}). ${report}`;
    return d;
  }

  // Review: a floor miss, a high finding, a stale analysis, or the API's label.
  const scanned = grade.scannedAt ? Date.parse(grade.scannedAt) : NaN;
  const stale = Number.isFinite(scanned) && (Date.now() - scanned) > policy.maxStaleMs;
  if (grade.score < policy.allowFloor) {
    d.outcome = 'low_score';
    d.reason = `AgentAvow: review ${what}: graded ${scoreText(grade)}, below the floor of ${policy.allowFloor}. ${report}`;
  } else if (grade.high > 0 && !policy.blockOn.includes('high')) {
    d.outcome = 'finding';
    d.reason = `AgentAvow: review ${what}: the grade (${scoreText(grade)}) carries ${grade.high} high finding${grade.high > 1 ? 's' : ''}. ${report}`;
  } else if (stale) {
    d.outcome = 'stale';
    d.reason = `AgentAvow: review ${what}: the grade (${scoreText(grade)}) is from ${grade.scannedAt}, older than ${Math.round(policy.maxStaleMs / 86_400_000)} days. ${report}`;
  } else if (grade.apiDecision === 'review') {
    d.outcome = 'finding';
    d.reason = `AgentAvow: review ${what}: AgentAvow labels it review (graded ${scoreText(grade)}). ${report}`;
  } else {
    d.decision = 'safe';
    d.allowed = true;
    d.outcome = 'allow';
    d.reason = `AgentAvow: ${server} graded ${scoreText(grade)}${grade.certified ? ', Certified' : ''}` +
      `${grade.signature === 'verified' ? ', attestation verified' : ''}; ${toolName ? `'${toolName}' allowed` : 'safe to connect'}.`;
    return d;
  }
  d.decision = 'review';
  return applyReview(d, policy);
}

/**
 * The drift step: compare a served definition with the expected digest (the
 * server's pins, else the signed `toolDigests`). Only runs on a decision that is
 * not already `do_not_connect`; a mismatch or unknown tool is routed by `onDrift`.
 */
export function applyDrift(
  d: Decision, grade: Grade, served: Record<string, unknown> | null, policy: ResolvedPolicy,
  runtimePins: Record<string, string> | undefined,
): Decision {
  if (d.decision === 'do_not_connect' || !served) {
    if (!served && Object.keys(grade.toolDigests).length) {
      d.warnings.push(`no served definition for '${d.toolName ?? '?'}' was available; drift not checked`);
    }
    return d;
  }
  const server = grade.server;
  const pins = runtimePins ?? policy.pins[server];
  const expectedMap = pins && Object.keys(pins).length ? pins : grade.toolDigests;
  const source = expectedMap === grade.toolDigests ? 'signed' : 'pinned';
  if (!Object.keys(expectedMap).length) {
    d.warnings.push(`the grade for ${server} carries no signed tool digests; drift not checked`);
    return d;
  }
  if (Object.keys(expectedMap).length > MAX_TOOL_DIGESTS) {
    d.warnings.push('the signed digest map is folded (too many tools); drift not checked');
    return d;
  }
  const servedDigest = toolDigest(served);
  d.servedDigest = servedDigest;
  if (servedDigest === null) {
    d.warnings.push(`the definition of '${d.toolName}' cannot be canonicalized; drift not checked`);
    return d;
  }
  const key = toolKey(String(served.name ?? d.toolName));
  const expected = expectedMap[key];
  d.signedDigest = expected ?? null;
  const report = `Report: ${d.reportUrl}`;
  if (expected === undefined) {
    d.outcome = 'unknown_tool';
    d.reason = `AgentAvow: '${d.toolName}' on ${server} is not among the tools ${source === 'signed' ? 'AgentAvow graded' : 'you pinned'} (${scoreText(grade)}); the server added it since. ${report}`;
    return softened(d, policy.onDrift, policy);
  }
  if (expected !== servedDigest) {
    d.outcome = 'drift';
    d.reason = `AgentAvow: the definition of '${d.toolName}' on ${server} changed since it was ${source === 'signed' ? 'graded' : 'pinned'} (${scoreText(grade)}): ${source} ${expected.slice(0, 19)}…, served ${servedDigest.slice(0, 19)}…. ${report}`;
    return softened(d, policy.onDrift, policy);
  }
  if (d.decision === 'safe') d.reason += ` Definition matches the ${source} digest.`;
  return d;
}

// ── legacy evaluator (0.2.x; deprecated) ─────────────────────────────────────
//
// The 0.2.x Vercel AI adapter's allow/fail policy. Nothing in this package uses
// it any more (`wrapTools` runs `createGate` since 0.3.0); it stays exported for
// callers that import it and will be removed in a future major version.

/** @deprecated 0.2.x. Use `DecisionOutcome`. */
export type Outcome =
  | 'allow' | 'low_score' | 'finding' | 'drift' | 'unknown_tool' | 'api_error' | 'unmapped';

/** @deprecated 0.2.x. Use `Decision` (`allowed`, `decision`). */
export interface GateDecision {
  allow: boolean;
  outcome: Outcome;
  reason: string;
  toolName: string;
  server: string | null;
  grade: Grade | null;
  servedDigest: string | null;
  signedDigest: string | null;
  warnings: string[];
}

/** @deprecated 0.2.x. `wrapTools` throws `GateError` (`onBlock: 'throw'`). */
export class ToolGateError extends Error {
  decision: GateDecision;
  constructor(decision: GateDecision) {
    super(decision.reason);
    this.name = 'ToolGateError';
    this.decision = decision;
  }
}

function blockingFindings(grade: Grade, blockOn: readonly string[]): string[] {
  const counts: Record<string, number> = { critical: grade.critical, high: grade.high };
  for (const f of grade.findings) {
    const s = String(f.severity ?? '').toLowerCase();
    if (!(s in counts)) counts[s] = (counts[s] ?? 0) + 1;
  }
  return blockOn.filter((s) => (counts[s.toLowerCase()] ?? 0) > 0);
}

/** @deprecated 0.2.x. */
export interface EvaluateOptions {
  minScore?: number;
  blockOn?: readonly string[];
  failClosed?: boolean;
  servedDefinition?: Record<string, unknown> | null;
}

/** Pure policy (the Python `src/bridges/tool_gate.py` twin): grade + optional
 *  served definition -> allow/fail decision. No I/O.
 *  @deprecated 0.2.x. Use `deriveDecision` + `applyDrift`, or `createGate().checkToolCall`. */
export function evaluate(
  toolName: string, server: string, grade: Grade, opts: EvaluateOptions = {},
): GateDecision {
  const minScore = opts.minScore ?? DEFAULT_MIN_SCORE;
  const blockOn = opts.blockOn ?? DEFAULT_BLOCK_ON;
  const failClosed = opts.failClosed ?? true;
  const report = grade.reportUrl || reportUrl(server);
  const b = {
    toolName, server, grade, servedDigest: null, signedDigest: null, warnings: [] as string[],
  };
  if (grade.error) {
    const reason = `AgentAvow could not grade ${server} (${grade.error}); '${toolName}' was ` +
      `${failClosed ? 'not run' : 'run unchecked'}. Report: ${report}`;
    const d: GateDecision = { ...b, allow: !failClosed, outcome: 'api_error', reason };
    if (!failClosed) d.warnings.push(reason);
    return d;
  }
  if (grade.score === null || grade.score < minScore) {
    return {
      ...b, allow: false, outcome: 'low_score',
      reason: `AgentAvow blocked '${toolName}' on ${server}: graded ${scoreText(grade)}, ` +
        `below the floor of ${minScore}. Not run. Report: ${report}`,
    };
  }
  const hits = blockingFindings(grade, blockOn);
  if (hits.length) {
    return {
      ...b, allow: false, outcome: 'finding',
      reason: `AgentAvow blocked '${toolName}' on ${server}: the grade (${scoreText(grade)}) ` +
        `carries ${hits.join(' and ')} findings. Not run. Report: ${report}`,
    };
  }
  const decision: GateDecision = {
    ...b, allow: true, outcome: 'allow',
    reason: `AgentAvow: ${server} graded ${scoreText(grade)}; '${toolName}' allowed.`,
  };
  const signedMap = grade.toolDigests;
  const served = opts.servedDefinition ?? null;
  const signedCount = Object.keys(signedMap).length;
  if (!served) {
    if (signedCount) decision.warnings.push(
      `no served definition for '${toolName}' was available; drift not checked`);
    return decision;
  }
  if (!signedCount) {
    decision.warnings.push(`the grade for ${server} carries no signed tool digests; drift not checked`);
    return decision;
  }
  if (signedCount > MAX_TOOL_DIGESTS) {
    decision.warnings.push('the signed digest map is folded (too many tools); drift not checked');
    return decision;
  }
  const servedDigest = toolDigest(served);
  decision.servedDigest = servedDigest;
  if (servedDigest === null) {
    decision.warnings.push(
      `the definition of '${toolName}' cannot be canonicalized; drift not checked`);
    return decision;
  }
  const key = toolKey(String(served.name ?? toolName));
  const signed = signedMap[key];
  decision.signedDigest = signed ?? null;
  if (signed === undefined) {
    return {
      ...decision, allow: false, outcome: 'unknown_tool',
      reason: `AgentAvow blocked '${toolName}' on ${server}: it was not among the tools AgentAvow ` +
        `graded (${scoreText(grade)}); the server added it since. Not run. Report: ${report}`,
    };
  }
  if (signed !== servedDigest) {
    return {
      ...decision, allow: false, outcome: 'drift',
      reason: `AgentAvow blocked '${toolName}' on ${server}: its definition changed since AgentAvow ` +
        `graded this server (${scoreText(grade)}) — signed ${signed.slice(0, 19)}…, served ` +
        `${servedDigest.slice(0, 19)}…. Not run. Report: ${report}`,
    };
  }
  decision.reason += ' Definition matches the signed digest.';
  return decision;
}

// ── JSON-RPC replies: plain JSON or SSE-framed ───────────────────────────────

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

const MCP_HEADERS = {
  'Content-Type': 'application/json',
  Accept: 'application/json, text/event-stream',
};
const INIT_BODY = {
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: {
    protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'agentavow-tool-gate', version: VERSION },
  },
};
const LIST_BODY = { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} };

function isReplyTo(doc: unknown, wantId: number | string): doc is Record<string, any> {
  if (!doc || typeof doc !== 'object') return false;
  const d = doc as Record<string, any>;
  return ('result' in d || 'error' in d) && (d.id === wantId || d.id === undefined || d.id === null);
}

/** The JSON-RPC reply to `wantId` in one SSE `data:` line, if that is what it is. */
export function rpcFromLine(line: string, wantId: number | string): Record<string, any> | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith('data:')) return null;
  const payload = trimmed.slice(5).trim();
  if (!payload.startsWith('{') && !payload.startsWith('[')) return null;
  try {
    const doc = JSON.parse(payload);
    const docs: unknown[] = Array.isArray(doc) ? doc : [doc];
    for (const d of docs) if (isReplyTo(d, wantId)) return d;
  } catch { /* not JSON */ }
  return null;
}

/** The JSON-RPC reply to `wantId` from a response body: JSON (a single reply or a
 *  batch) or an SSE stream, which is left as soon as the reply arrives so an open
 *  stream cannot hold the gate. Consumes the body. */
export async function readRpc(res: Response, wantId: number | string): Promise<Record<string, any> | null> {
  const ctype = (res.headers.get('content-type') ?? '').toLowerCase();
  if (!ctype.includes('text/event-stream')) {
    try {
      const doc = await res.json();
      const docs: unknown[] = Array.isArray(doc) ? doc : [doc];
      for (const d of docs) if (isReplyTo(d, wantId)) return d;
      return null;
    } catch {
      return null;
    }
  }
  if (!res.body) return null;
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        const doc = rpcFromLine(line, wantId);
        if (doc) return doc;
      }
    }
    return rpcFromLine(buf, wantId);
  } finally {
    try { await reader.cancel(); } catch { /* already closed */ }
  }
}

/**
 * Read a response up to and including the JSON-RPC reply to `wantId`, and hand
 * back both the reply and an equivalent `Response` to pass on: for JSON the whole
 * body; for SSE the frames up to the reply, after which the stream closes (what a
 * well-behaved server does anyway: the reply ends the request's stream). The
 * original body is consumed and cancelled.
 */
export async function captureRpc(
  res: Response, wantId: number | string,
): Promise<{ reply: Record<string, any> | null; response: Response }> {
  const rewrap = (bytes: Uint8Array<ArrayBuffer>) => new Response(bytes, {
    status: res.status, statusText: res.statusText, headers: res.headers,
  });
  const ctype = (res.headers.get('content-type') ?? '').toLowerCase();
  if (!ctype.includes('text/event-stream')) {
    const bytes = new Uint8Array(await res.arrayBuffer()) as Uint8Array<ArrayBuffer>;
    let reply: Record<string, any> | null = null;
    try {
      const doc = JSON.parse(new TextDecoder().decode(bytes));
      const docs: unknown[] = Array.isArray(doc) ? doc : [doc];
      for (const d of docs) if (isReplyTo(d, wantId)) reply = d;
    } catch { /* not JSON; pass through untouched */ }
    return { reply, response: rewrap(bytes) };
  }
  if (!res.body) return { reply: null, response: res };
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const chunks: Uint8Array[] = [];
  let text = '';
  let reply: Record<string, any> | null = null;
  let scanned = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
      text += decoder.decode(value, { stream: true });
      let nl: number;
      while ((nl = text.indexOf('\n', scanned)) >= 0) {
        const line = text.slice(scanned, nl);
        scanned = nl + 1;
        const doc = rpcFromLine(line, wantId);
        if (doc) { reply = doc; break; }
      }
      if (reply) break;
    }
    if (!reply) reply = rpcFromLine(text.slice(scanned), wantId);
  } finally {
    try { await reader.cancel(); } catch { /* already closed */ }
  }
  let size = 0;
  for (const c of chunks) size += c.length;
  const bytes = new Uint8Array(new ArrayBuffer(size));
  let off = 0;
  for (const c of chunks) { bytes.set(c, off); off += c.length; }
  // Close the event cleanly so the transport's SSE parser dispatches the last frame.
  const tail = text.endsWith('\n\n') ? '' : text.endsWith('\n') ? '\n' : '\n\n';
  const closed = tail ? concat(bytes, new TextEncoder().encode(tail)) : bytes;
  return { reply, response: rewrap(closed) };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(a.length + b.length));
  out.set(a);
  out.set(b, a.length);
  return out;
}

// ── HTTP: the grade, and a server's own tools/list ───────────────────────────

export interface ClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
  cacheTtlMs?: number;
  fetch?: FetchLike;
  headers?: Record<string, string>;
  /** Verify each grade's JWS and decide on the signed payload (default false here;
   *  `createGate` turns it on). */
  verifySignature?: boolean;
  jwksUrl?: string;
  jwks?: Jwks;
  /** The issuer DID a verified attestation must name (default AgentAvow's). */
  issuer?: string;
}

/** Fetches grades (and, for drift, a server's own tools/list) with a TTL cache:
 *  a hit past its TTL is served at once while one refresh runs in the background.
 *  Redirects are followed only to https://. `fetch` is injectable for tests. */
export class GradeClient {
  baseUrl: string;
  timeoutMs: number;
  cacheTtlMs: number;
  verifySignature: boolean;
  issuer: string;
  jwks: JwksCache;
  private _fetch: FetchLike;
  private _headers: Record<string, string>;
  private _grades = new Map<string, { expires: number; grade: Grade }>();
  private _inflight = new Map<string, Promise<Grade>>();
  private _served = new Map<string, { expires: number; tools: ToolDefinition[] | null }>();

  constructor(opts: ClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.cacheTtlMs = opts.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.verifySignature = opts.verifySignature ?? false;
    this.issuer = opts.issuer ?? ISSUER_DID;
    this._fetch = opts.fetch ?? ((input, init) => fetch(input, init));
    this._headers = {
      'User-Agent': `agentavow-tool-gate/${VERSION} (js)`, Accept: 'application/json',
      ...(opts.headers ?? {}),
    };
    this.jwks = new JwksCache({
      url: opts.jwksUrl, fetch: this._fetch, timeoutMs: this.timeoutMs, jwks: opts.jwks,
    });
  }

  clearCache(): void {
    this._grades.clear();
    this._served.clear();
  }

  /** The cached grade, fresh or stale, without any I/O. */
  cached(server: string): Grade | null {
    return this._grades.get(server)?.grade ?? null;
  }

  private async _get(url: string, headers: Record<string, string>): Promise<Response> {
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      const res = await this._fetch(url, {
        method: 'GET', headers, redirect: 'manual', signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (![301, 302, 303, 307, 308].includes(res.status)) return res;
      const loc = res.headers.get('location');
      if (!loc) throw new Error('redirect without Location');
      const target = new URL(loc, url).toString();
      if (!target.toLowerCase().startsWith('https://')) {
        throw new Error(`refusing redirect to non-https URL ${target}`);
      }
      url = target;
    }
    throw new Error('too many redirects');
  }

  private _store(server: string, grade: Grade): Grade {
    const ttl = grade.error === null ? this.cacheTtlMs : Math.min(this.cacheTtlMs, 30_000);
    this._grades.set(server, { expires: Date.now() + ttl, grade });
    return grade;
  }

  private async _fetchGrade(server: string): Promise<Grade> {
    let url: string;
    try {
      url = gradeUrl(this.baseUrl, server);
    } catch (e) {
      return this._store(server, errorGrade(server, (e as Error).message));
    }
    try {
      const res = await this._get(url, this._headers);
      if (res.status !== 200) {
        let detail = '';
        try {
          const body = await res.json();
          detail = String(body?.detail ?? body?.error ?? '').slice(0, 160);
        } catch { /* no body */ }
        return this._store(server, errorGrade(server, `HTTP ${res.status}${detail ? `: ${detail}` : ''}`));
      }
      const data = await res.json();
      if (!data || typeof data !== 'object') {
        return this._store(server, errorGrade(server, 'unexpected response shape'));
      }
      let grade = gradeFromResponse(server, data);
      if (this.verifySignature) {
        if (!grade.jws) {
          grade = { ...grade, signature: 'missing', signatureReason: 'response carries no jws' };
        } else {
          try {
            const { header } = decodeJws(grade.jws);
            const kid = typeof header?.kid === 'string' ? header.kid : null;
            grade = await verifyGrade(grade, await this.jwks.get(kid), Date.now(), this.issuer);
          } catch (e) {
            grade = { ...grade, signature: 'invalid', signatureReason: `JWKS: ${(e as Error).message}` };
          }
        }
      }
      return this._store(server, grade);
    } catch (e) {
      const err = e as Error;
      return this._store(server, errorGrade(server, `${err.name}: ${String(err.message).slice(0, 160)}`));
    }
  }

  /** The grade for a coordinate: cached when fresh; stale-while-revalidate when
   *  past TTL; fetched when absent. `force` bypasses the cache (never a re-scan:
   *  the API's own 1h cache still applies). */
  async grade(server: string, force = false): Promise<Grade> {
    const hit = this._grades.get(server);
    if (!force && hit) {
      if (hit.expires > Date.now()) return hit.grade;
      if (hit.grade.error === null) {
        this._refresh(server);
        return hit.grade;
      }
    }
    return this._refresh(server);
  }

  private _refresh(server: string): Promise<Grade> {
    const running = this._inflight.get(server);
    if (running) return running;
    const p = this._fetchGrade(server).finally(() => {
      if (this._inflight.get(server) === p) this._inflight.delete(server);
    });
    this._inflight.set(server, p);
    return p;
  }

  /** `tools/list` as the server serves it now (Streamable HTTP). null on failure. */
  async servedTools(
    endpoint: string, extraHeaders?: Record<string, string>, force = false,
  ): Promise<ToolDefinition[] | null> {
    const hit = this._served.get(endpoint);
    if (!force && hit && hit.expires > Date.now()) return hit.tools;
    const store = (tools: ToolDefinition[] | null) => {
      const ttl = tools ? this.cacheTtlMs : Math.min(this.cacheTtlMs, 30_000);
      this._served.set(endpoint, { expires: Date.now() + ttl, tools });
      return tools;
    };
    if (!endpoint.toLowerCase().startsWith('https://')) return store(null);
    const headers: Record<string, string> = {
      ...MCP_HEADERS, 'User-Agent': `agentavow-tool-gate/${VERSION} (js)`, ...(extraHeaders ?? {}),
    };
    const post = (body: unknown) => this._fetch(endpoint, {
      method: 'POST', headers, body: JSON.stringify(body), redirect: 'manual',
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    try {
      const initRes = await post(INIT_BODY);
      const init = await readRpc(initRes, 1);
      if (!init || !('result' in init)) return store(null);
      const session = initRes.headers.get('mcp-session-id');
      if (session) headers['Mcp-Session-Id'] = session;
      headers['MCP-Protocol-Version'] = '2025-06-18';
      try {
        const n = await post({ jsonrpc: '2.0', method: 'notifications/initialized' });
        try { await n.body?.cancel(); } catch { /* ignore */ }
      } catch { /* a notification; any answer is fine */ }
      const listing = await readRpc(await post(LIST_BODY), 2);
      const tools = listing?.result?.tools;
      return store(Array.isArray(tools) ? tools : null);
    } catch {
      return store(null);
    }
  }
}

// ── the gate ─────────────────────────────────────────────────────────────────

export interface ToolCall {
  /** The coordinate of the server the tool came from (`https://…`, `npm:name`, `owner/repo`). */
  server: string;
  toolName: string;
  /** The `tools/list` entry the agent was served, for the drift check. Omitted: the
   *  definition recorded by `observeTools` for this server, if any. */
  servedDefinition?: Record<string, unknown> | null;
}

export interface Gate {
  policy: ResolvedPolicy;
  client: GradeClient;
  /** The decision for a target (server, package or repo) from its cached grade. */
  check(target: string): Promise<Decision>;
  /** The decision for one tool call: the target's decision plus the drift check. */
  checkToolCall(call: ToolCall): Promise<Decision>;
  /** Pin the expected digests of a server's tools (from a `tools/list` you reviewed,
   *  or a digest map). Pinned servers are compared against the pins, not the grade. */
  pin(server: string, tools: readonly Record<string, unknown>[] | Record<string, string>): Record<string, string>;
  /** The pins for a server (policy pins merged with runtime pins), or null. */
  pins(server: string): Record<string, string> | null;
  /** Record the `tools/list` a server served (merged per tool name, so a paged
   *  listing accumulates; later `checkToolCall`s can omit `servedDefinition`) and
   *  return the decision for each tool. */
  observeTools(server: string, tools: readonly Record<string, unknown>[]): Promise<Decision[]>;
  /** The recorded served definition of a tool, if `observeTools` saw one. */
  servedDefinition(server: string, toolName: string): Record<string, unknown> | null;
  /** The decision for a tool that maps to no server. */
  unmapped(toolName: string): Decision;
  clearCache(): void;
}

export function createGate(options: GatePolicy & GateHooks = {}): Gate {
  const policy = resolvePolicy(options);
  const client = new GradeClient({
    baseUrl: policy.baseUrl, timeoutMs: policy.timeoutMs, cacheTtlMs: policy.cacheTtlMs,
    fetch: options.fetch, headers: policy.headers, verifySignature: policy.verifySignature,
    jwksUrl: policy.jwksUrl, jwks: options.jwks, issuer: policy.issuer,
  });
  const onWarn = options.onWarn ?? ((m: string) => console.warn(m));
  const runtimePins = new Map<string, Record<string, string>>();
  const served = new Map<string, Map<string, Record<string, unknown>>>();

  // One answer per server and reason for a cache period (per tool for drift), so
  // a connect followed by N tool calls asks once, not N+1 times.
  const confirmations = new Map<string, { allowed: boolean; expires: number }>();
  const finish = async (d: Decision): Promise<Decision> => {
    if (d.decision === 'review' && policy.onReview === 'confirm' && !d.allowed) {
      if (options.confirm) {
        const perTool = d.outcome === 'drift' || d.outcome === 'unknown_tool';
        const key = `${d.server}|${perTool ? d.toolName : ''}|${d.outcome}`;
        const prior = confirmations.get(key);
        if (prior && prior.expires > Date.now()) {
          d.allowed = prior.allowed;
        } else {
          try {
            d.allowed = !!(await options.confirm(d));
          } catch {
            d.allowed = false;
          }
          confirmations.set(key, { allowed: d.allowed, expires: Date.now() + policy.cacheTtlMs });
        }
        if (d.allowed) d.reason += ' Confirmed.';
        else d.reason += ' Not confirmed.';
      } else {
        d.reason += " (onReview: 'confirm' with no confirm hook blocks.)";
      }
    }
    for (const w of d.warnings) onWarn(w, d);
    return d;
  };

  const gate: Gate = {
    policy, client,
    async check(target) {
      const grade = await client.grade(target);
      return finish(deriveDecision(grade, policy));
    },
    async checkToolCall({ server, toolName, servedDefinition }) {
      const grade = await client.grade(server); // in memory after the first call
      const def = servedDefinition === undefined ? gate.servedDefinition(server, toolName) : servedDefinition;
      const d = deriveDecision(grade, policy, toolName);
      return finish(applyDrift(d, grade, def, policy, gate.pins(server) ?? undefined));
    },
    pin(server, tools) {
      const map = Array.isArray(tools)
        ? digestMap(tools as readonly Record<string, unknown>[])
        : normalizePins({ s: tools as Record<string, string> }).s as Record<string, string>;
      runtimePins.set(server, { ...(runtimePins.get(server) ?? {}), ...map });
      return { ...runtimePins.get(server) };
    },
    pins(server) {
      const merged = { ...(policy.pins[server] ?? {}), ...(runtimePins.get(server) ?? {}) };
      return Object.keys(merged).length ? merged : null;
    },
    async observeTools(server, tools) {
      let byName = served.get(server);
      if (!byName) served.set(server, byName = new Map());
      const out: Decision[] = [];
      for (const t of tools) {
        if (!t || typeof t !== 'object' || typeof t.name !== 'string') continue;
        byName.set(t.name, t);
        out.push(await gate.checkToolCall({ server, toolName: t.name, servedDefinition: t }));
      }
      return out;
    },
    servedDefinition(server, toolName) {
      return served.get(server)?.get(toolName) ?? null;
    },
    unmapped(toolName) {
      const block = policy.unmapped === 'block';
      return {
        decision: block ? 'do_not_connect' : 'safe', allowed: !block, outcome: 'unmapped',
        reason: block
          ? `AgentAvow: '${toolName}' maps to no graded server (unmapped: 'block'). Not run.`
          : `'${toolName}' maps to no server; not gated.`,
        score: null, tier: null, certified: false, reportUrl: `${WEB}/check`, attestation: null, server: null, toolName,
        servedDigest: null, signedDigest: null, warnings: [], grade: null,
      };
    },
    clearCache() {
      client.clearCache();
      served.clear();
      confirmations.clear();
    },
  };
  return gate;
}
