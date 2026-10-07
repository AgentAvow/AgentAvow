// Compact JWS (RFC 7515) verification for AgentAvow scan attestations, on
// WebCrypto only (no `node:crypto`, no `Buffer`), so it runs on Node 18+, Bun,
// Deno, Cloudflare Workers and in a browser.
//
// The public scan response carries `jws`, `key_id` and `jwks_url`. The JWS is
// `header.payload.signature` with header `{"alg":"EdDSA","kid":"<key id>"}`; the
// signing input is the ASCII bytes of `header_b64 + "." + payload_b64`
// (src/signing.py `create_jws`), and the key is the `{kty:"OKP",crv:"Ed25519"}`
// entry in the JWKS whose `kid` matches. The payload is the attestation: the
// signed `scan` block (`trustScore`, `trustTier`, `findings`, `toolDigests`,
// `toolManifestDigest`, `supplyChain`, …), `subject`, `scannedAt`, `expiresAt`.
//
// This is a different envelope from `src/verify.js` (Trust Score v2 envelopes:
// detached JWS over a SHA-256 of the JCS-canonical body); the two are not
// interchangeable.

export const DEFAULT_JWKS_URL = 'https://agentgraph.co/.well-known/jwks.json';
export const DEFAULT_JWKS_TTL_MS = 3_600_000;

export interface Jwk {
  kty?: string;
  crv?: string;
  x?: string;
  kid?: string;
  alg?: string;
  use?: string;
  [k: string]: unknown;
}
export type Jwks = { keys: Jwk[] } | Jwk[];

export interface JwsResult {
  valid: boolean;
  kid: string | null;
  alg: string | null;
  payload: Record<string, unknown> | null;
  reason: string;
}

const textDecoder = new TextDecoder();

export function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeJsonPart(part: string): Record<string, unknown> | null {
  try {
    const doc = JSON.parse(textDecoder.decode(b64urlDecode(part)));
    return doc && typeof doc === 'object' && !Array.isArray(doc) ? doc : null;
  } catch {
    return null;
  }
}

/** The decoded header and payload of a compact JWS, without verifying anything. */
export function decodeJws(jws: string): {
  header: Record<string, unknown> | null; payload: Record<string, unknown> | null;
} {
  const parts = typeof jws === 'string' ? jws.split('.') : [];
  if (parts.length !== 3) return { header: null, payload: null };
  return { header: decodeJsonPart(parts[0] as string), payload: decodeJsonPart(parts[1] as string) };
}

export function findJwk(jwks: Jwks | null | undefined, kid: string | null): Jwk | null {
  const keys = Array.isArray(jwks) ? jwks : jwks?.keys ?? [];
  const candidates = keys.filter(
    (k) => k && k.kty === 'OKP' && k.crv === 'Ed25519' && typeof k.x === 'string');
  if (kid !== null) return candidates.find((k) => k.kid === kid) ?? null;
  return candidates[0] ?? null;
}

async function importEd25519(jwk: Jwk): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x as string }, { name: 'Ed25519' }, false, ['verify']);
}

/**
 * Verify a compact EdDSA JWS against a JWKS. `expectKid` pins the key id the
 * response announced (`key_id`): a JWS whose header names another kid fails.
 */
export async function verifyJws(
  jws: string, jwks: Jwks, opts: { expectKid?: string | null } = {},
): Promise<JwsResult> {
  const fail = (reason: string, kid: string | null = null, alg: string | null = null): JwsResult =>
    ({ valid: false, kid, alg, payload: null, reason });
  if (typeof jws !== 'string') return fail('no jws');
  const parts = jws.split('.');
  if (parts.length !== 3) return fail('malformed jws');
  const header = decodeJsonPart(parts[0] as string);
  if (!header) return fail('malformed jws header');
  const alg = typeof header.alg === 'string' ? header.alg : null;
  const kid = typeof header.kid === 'string' ? header.kid : null;
  if (alg !== 'EdDSA') return fail(`unsupported alg ${alg ?? '(none)'}`, kid, alg);
  if (opts.expectKid && kid !== opts.expectKid) {
    return fail(`kid ${kid ?? '(none)'} does not match the announced key id ${opts.expectKid}`, kid, alg);
  }
  const jwk = findJwk(jwks, kid);
  if (!jwk) return fail(`no Ed25519 key ${kid ?? '(none)'} in the JWKS`, kid, alg);
  const payload = decodeJsonPart(parts[1] as string);
  if (!payload) return fail('malformed jws payload', kid, alg);
  let ok = false;
  try {
    const key = await importEd25519(jwk);
    const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, b64urlDecode(parts[2] as string), signingInput);
  } catch (e) {
    return fail(`verification error: ${(e as Error).message}`, kid, alg);
  }
  if (!ok) return fail('signature invalid', kid, alg);
  return { valid: true, kid, alg, payload, reason: 'ok' };
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** Fetches and caches a JWKS. A miss on `kid` refetches once (key rotation). */
export class JwksCache {
  url: string;
  ttlMs: number;
  private _fetch: FetchLike;
  private _timeoutMs: number;
  private _doc: { expires: number; jwks: Jwks } | null = null;
  private _inflight: Promise<Jwks> | null = null;

  constructor(opts: { url?: string; ttlMs?: number; fetch?: FetchLike; timeoutMs?: number; jwks?: Jwks } = {}) {
    this.url = opts.url ?? DEFAULT_JWKS_URL;
    this.ttlMs = opts.ttlMs ?? DEFAULT_JWKS_TTL_MS;
    this._fetch = opts.fetch ?? ((input, init) => fetch(input, init));
    this._timeoutMs = opts.timeoutMs ?? 10_000;
    if (opts.jwks) this._doc = { expires: Number.POSITIVE_INFINITY, jwks: opts.jwks };
  }

  private async _load(): Promise<Jwks> {
    if (this._inflight) return this._inflight;
    this._inflight = (async () => {
      try {
        const res = await this._fetch(this.url, {
          method: 'GET', headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(this._timeoutMs),
        });
        if (res.status !== 200) throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
        const doc = await res.json();
        if (!doc || typeof doc !== 'object') throw new Error('JWKS fetch failed: not JSON');
        this._doc = { expires: Date.now() + this.ttlMs, jwks: doc as Jwks };
        return this._doc.jwks;
      } finally {
        this._inflight = null;
      }
    })();
    return this._inflight;
  }

  /** The JWKS, fetched if absent or expired. With `kid`, a stale-key miss refetches once. */
  async get(kid: string | null = null): Promise<Jwks> {
    if (this._doc && this._doc.expires > Date.now()) {
      if (kid === null || findJwk(this._doc.jwks, kid)) return this._doc.jwks;
      if (this._doc.expires === Number.POSITIVE_INFINITY) return this._doc.jwks; // pinned inline
    }
    return this._load();
  }
}
