// Vercel AI SDK tool-call gate on the AgentAvow grade.
//
// `wrapTools(tools, options)` returns the same ToolSet with each tool's `execute`
// wrapped: before the tool runs, the gate fetches the serving MCP server's signed
// grade from AgentAvow's free API and allows the call only when the score clears
// `minScore` (default 81, Trusted), no critical / high finding is on the grade, and
// the definition the agent was served recomputes to the per-tool digest signed into
// the attestation (`scan.toolDigests["tool:<name>"]`, profile
// agentavow.mcp-tool-definition.v1). Anything else is a fail, handled per `onFail`:
//
//   block   (default) the tool is not run; its result is `{ error, agentavow }` so the
//           model is told why. Nothing throws.
//   confirm the SDK's own approval flow: the wrapped tool gets a `needsApproval`
//           function that returns true when the gate fails, so `generateText` /
//           `streamText` / `ToolLoopAgent` pause for the user; an approved call runs.
//   warn    the tool runs; the verdict goes to `onWarn` (default: console.warn).
//   throw   throw a ToolGateError.
//
// Why `execute` and not a lifecycle callback: the AI SDK's `onToolExecutionStart`
// (and the deprecated `experimental_onToolCallStart`) observes a call but cannot
// stop it — errors thrown inside it are swallowed. Wrapping `execute` is the hook
// that decides. `needsApproval` is the SDK's documented pause point, so `confirm`
// uses it.
//
// Mapping a tool to its server: tools from `createMCPClient().tools()` carry no
// server URL, so give it once per set (`server`), per tool (`toolToServer`), or via
// `resolveServer(toolName)`. A tool that maps to no server (your own function) is
// not gated. The served definition for the drift check comes from `servedTools`
// (the `tools/list` you loaded the tools from) or, by default, is fetched from the
// https server itself and cached.
//
// Node 18+ (global fetch, node:crypto). Depends on `canonicalize` (RFC 8785).

import { createHash } from 'node:crypto';
import canonicalizeImport from 'canonicalize';

// `canonicalize` is CommonJS (`module.exports = fn`), but its .d.ts says `export default`,
// so under NodeNext the default import is typed as the module namespace. At runtime
// (Node ESM importing CJS) it is the function itself, as src/verify.js relies on.
const canonicalize = canonicalizeImport as unknown as (input: unknown) => string | undefined;

export const DEFAULT_BASE_URL = 'https://agentavow.com/api/v1';
export const DEFAULT_MIN_SCORE = 81;
export const DEFAULT_BLOCK_ON: readonly string[] = ['critical', 'high'];
export const DEFAULT_CACHE_TTL_MS = 3_600_000;
const WEB = 'https://agentavow.com';
const MAX_REDIRECTS = 3;
const VERSION = '0.1.0';

// ── the per-tool digest, exactly as the attestation signs it ────────────────

export const PROFILE = 'agentavow.mcp-tool-definition.v1';
export const DIGEST_FIELDS = [
  'name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations',
] as const;
const MAX_KEY_NAME = 128;
const MAX_TOOL_DIGESTS = 500;

export type ToolDefinition = Record<string, unknown> & { name: string };

function sha256(text: string): string {
  return 'sha256:' + createHash('sha256').update(text, 'utf8').digest('hex');
}

/** `tool:<name>`: everything outside printable ASCII, plus % and =, is
 *  percent-encoded as UTF-8 bytes; an overlong key is cut and suffixed. */
export function toolKey(name: string): string {
  let enc = '';
  for (const ch of name) {
    const cp = ch.codePointAt(0) as number;
    if (cp >= 0x21 && cp <= 0x7e && ch !== '%' && ch !== '=') {
      enc += ch;
    } else {
      for (const b of Buffer.from(ch, 'utf8')) {
        enc += '%' + b.toString(16).toUpperCase().padStart(2, '0');
      }
    }
  }
  if (enc.length > MAX_KEY_NAME) {
    const suffix = createHash('sha256').update(name, 'utf8').digest('hex').slice(0, 16);
    enc = enc.slice(0, 96) + '~' + suffix;
  }
  return 'tool:' + enc;
}

/** `sha256:<hex>` over JCS({ profile, tool: <restricted definition> }); a missing or
 *  null field is omitted, `_meta` and unknown fields are never hashed. Returns null
 *  when the definition cannot be canonicalized. */
export function toolDigest(def: Record<string, unknown>): string | null {
  const body: Record<string, unknown> = {};
  for (const f of DIGEST_FIELDS) {
    if (def[f] !== undefined && def[f] !== null) body[f] = def[f];
  }
  try {
    const canon = canonicalize({ profile: PROFILE, tool: body });
    return canon === undefined ? null : sha256(canon);
  } catch {
    return null;
  }
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

// ── grade and decision ───────────────────────────────────────────────────────

export interface Grade {
  server: string;
  score: number | null;
  tier: string;
  critical: number;
  high: number;
  findings: Array<Record<string, unknown>>;
  toolDigests: Record<string, string>;
  reportUrl: string;
  jws: string | null;
  fetchedAt: number;
  error: string | null;
}

export type Outcome =
  | 'allow' | 'low_score' | 'finding' | 'drift' | 'unknown_tool' | 'api_error' | 'unmapped';

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

export class ToolGateError extends Error {
  decision: GateDecision;
  constructor(decision: GateDecision) {
    super(decision.reason);
    this.name = 'ToolGateError';
    this.decision = decision;
  }
}

function errorGrade(server: string, error: string): Grade {
  return {
    server, score: null, tier: '', critical: 0, high: 0, findings: [], toolDigests: {},
    reportUrl: reportUrl(server), jws: null, fetchedAt: Date.now(), error,
  };
}

export function gradeFromResponse(server: string, data: Record<string, any>): Grade {
  const findings = data.findings ?? {};
  const rawItems = Array.isArray(findings) ? findings : findings.items ?? [];
  const items = (rawItems as unknown[]).filter(
    (f): f is Record<string, unknown> => !!f && typeof f === 'object');
  const sev = items.map((f) => String(f.severity ?? '').toLowerCase());
  const count = (k: string) => Number((!Array.isArray(findings) && findings[k]) || 0);
  const score = typeof data.trust_score === 'number' ? Math.trunc(data.trust_score) : null;
  const digests: Record<string, string> = {};
  for (const [k, v] of Object.entries(data.tool_digests ?? {})) digests[String(k)] = String(v);
  return {
    server, score, tier: String(data.trust_tier ?? ''),
    critical: Math.max(count('critical'), sev.filter((s) => s === 'critical').length),
    high: Math.max(count('high'), sev.filter((s) => s === 'high').length),
    findings: items, toolDigests: digests, reportUrl: reportUrl(server),
    jws: typeof data.jws === 'string' ? data.jws : null, fetchedAt: Date.now(), error: null,
  };
}

function blockingFindings(grade: Grade, blockOn: readonly string[]): string[] {
  const counts: Record<string, number> = { critical: grade.critical, high: grade.high };
  for (const f of grade.findings) {
    const s = String(f.severity ?? '').toLowerCase();
    if (!(s in counts)) counts[s] = (counts[s] ?? 0) + 1;
  }
  return blockOn.filter((s) => (counts[s.toLowerCase()] ?? 0) > 0);
}

function scoreText(grade: Grade): string {
  if (grade.score === null) return 'no score';
  return `${grade.score}/100${grade.tier ? `, tier ${grade.tier}` : ''}`;
}

export interface EvaluateOptions {
  minScore?: number;
  blockOn?: readonly string[];
  failClosed?: boolean;
  servedDefinition?: Record<string, unknown> | null;
}

/** Pure policy: grade + optional served definition -> decision. No I/O. */
export function evaluate(
  toolName: string, server: string, grade: Grade, opts: EvaluateOptions = {},
): GateDecision {
  const minScore = opts.minScore ?? DEFAULT_MIN_SCORE;
  const blockOn = opts.blockOn ?? DEFAULT_BLOCK_ON;
  const failClosed = opts.failClosed ?? true;
  const report = grade.reportUrl || reportUrl(server);
  const base = {
    toolName, server, grade, servedDigest: null, signedDigest: null, warnings: [] as string[],
  };
  if (grade.error) {
    const reason = `AgentAvow could not grade ${server} (${grade.error}); '${toolName}' was ` +
      `${failClosed ? 'not run' : 'run unchecked'}. Report: ${report}`;
    const d: GateDecision = { ...base, allow: !failClosed, outcome: 'api_error', reason };
    if (!failClosed) d.warnings.push(reason);
    return d;
  }
  if (grade.score === null || grade.score < minScore) {
    return {
      ...base, allow: false, outcome: 'low_score',
      reason: `AgentAvow blocked '${toolName}' on ${server}: graded ${scoreText(grade)}, ` +
        `below the floor of ${minScore}. Not run. Report: ${report}`,
    };
  }
  const hits = blockingFindings(grade, blockOn);
  if (hits.length) {
    return {
      ...base, allow: false, outcome: 'finding',
      reason: `AgentAvow blocked '${toolName}' on ${server}: the grade (${scoreText(grade)}) ` +
        `carries ${hits.join(' and ')} findings. Not run. Report: ${report}`,
    };
  }
  const decision: GateDecision = {
    ...base, allow: true, outcome: 'allow',
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

// ── HTTP: the grade, and a server's own tools/list ───────────────────────────

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

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

function rpcFromLine(line: string, wantId: number): Record<string, any> | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith('data:')) return null;
  const payload = trimmed.slice(5).trim();
  if (!payload.startsWith('{')) return null;
  try {
    const doc = JSON.parse(payload);
    if (doc && typeof doc === 'object' && ('result' in doc || 'error' in doc) &&
        (doc.id === wantId || doc.id === undefined || doc.id === null)) return doc;
  } catch { /* not JSON */ }
  return null;
}

/** The JSON-RPC reply to `wantId` from a JSON body or an SSE stream; the stream is
 *  left as soon as the reply arrives, so an open stream cannot hold the gate. */
async function readRpc(res: Response, wantId: number): Promise<Record<string, any> | null> {
  const ctype = (res.headers.get('content-type') ?? '').toLowerCase();
  if (!ctype.includes('text/event-stream')) {
    try {
      const doc = await res.json();
      return doc && typeof doc === 'object' ? doc : null;
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

export interface ClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
  cacheTtlMs?: number;
  fetch?: FetchLike;
  headers?: Record<string, string>;
}

/** Fetches grades (and, for drift, a server's own tools/list) with a TTL cache.
 *  Redirects are followed only to https://. `fetch` is injectable for tests. */
export class TrustGateClient {
  baseUrl: string;
  timeoutMs: number;
  cacheTtlMs: number;
  private _fetch: FetchLike;
  private _headers: Record<string, string>;
  private _grades = new Map<string, { expires: number; grade: Grade }>();
  private _served = new Map<string, { expires: number; tools: ToolDefinition[] | null }>();

  constructor(opts: ClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.cacheTtlMs = opts.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this._fetch = opts.fetch ?? ((input, init) => fetch(input, init));
    this._headers = {
      'User-Agent': `agentavow-tool-gate/${VERSION} (js)`, Accept: 'application/json',
      ...(opts.headers ?? {}),
    };
  }

  clearCache(): void {
    this._grades.clear();
    this._served.clear();
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

  async grade(server: string, force = false): Promise<Grade> {
    const hit = this._grades.get(server);
    if (!force && hit && hit.expires > Date.now()) return hit.grade;
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
      return this._store(server, gradeFromResponse(server, data));
    } catch (e) {
      const err = e as Error;
      return this._store(server, errorGrade(server, `${err.name}: ${String(err.message).slice(0, 160)}`));
    }
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

export type OnFail = 'block' | 'confirm' | 'warn' | 'throw';

export interface GateOptions extends ClientOptions {
  minScore?: number;
  blockOn?: readonly string[];
  onFail?: OnFail;
  failClosed?: boolean;
  /** One server for every tool in the set (what `createMCPClient().tools()` gives you). */
  server?: string;
  toolToServer?: Record<string, string>;
  resolveServer?: (toolName: string) => string | null | undefined;
  /** The tools/list each server served, keyed by coordinate — or a function returning it. */
  servedTools?: Record<string, ToolDefinition[]> |
    ((server: string) => Promise<ToolDefinition[] | null> | ToolDefinition[] | null);
  /** Fetch tools/list from the https server when no served definition is given (default true). */
  fetchServed?: boolean;
  /** 'allow' (default) or 'block' a tool that maps to no server. */
  unmapped?: 'allow' | 'block';
  /** Per-server headers for the tools/list fetch (an Authorization the server needs). */
  serverHeaders?: Record<string, Record<string, string>>;
  onWarn?: (message: string) => void;
}

export class TrustGate {
  client: TrustGateClient;
  minScore: number;
  blockOn: readonly string[];
  onFail: OnFail;
  failClosed: boolean;
  unmapped: 'allow' | 'block';
  private _opts: GateOptions;
  onWarn: (m: string) => void;

  constructor(opts: GateOptions = {}) {
    this._opts = opts;
    this.client = new TrustGateClient(opts);
    this.minScore = opts.minScore ?? DEFAULT_MIN_SCORE;
    this.blockOn = (opts.blockOn ?? DEFAULT_BLOCK_ON).map((s) => s.toLowerCase());
    this.onFail = opts.onFail ?? 'block';
    if (!['block', 'confirm', 'warn', 'throw'].includes(this.onFail)) {
      throw new Error(`onFail must be block | confirm | warn | throw, got ${String(this.onFail)}`);
    }
    this.failClosed = opts.failClosed ?? true;
    this.unmapped = opts.unmapped ?? 'allow';
    this.onWarn = opts.onWarn ?? ((m) => console.warn(m));
  }

  resolve(toolName: string): string | null {
    const o = this._opts;
    if (o.toolToServer && toolName in o.toolToServer) return o.toolToServer[toolName];
    if (o.server) return o.server;
    return o.resolveServer?.(toolName) ?? null;
  }

  unmappedDecision(toolName: string): GateDecision {
    const block = this.unmapped === 'block';
    return {
      allow: !block, outcome: 'unmapped', toolName, server: null, grade: null,
      servedDigest: null, signedDigest: null, warnings: [],
      reason: block
        ? `AgentAvow blocked '${toolName}': it maps to no graded server (unmapped: 'block'). Not run.`
        : `'${toolName}' maps to no server; not gated.`,
    };
  }

  private async _servedDefinition(server: string, toolName: string): Promise<Record<string, unknown> | null> {
    const src = this._opts.servedTools;
    let tools: ToolDefinition[] | null | undefined;
    if (typeof src === 'function') tools = await src(server);
    else if (src) tools = src[server] ?? null;
    else if (this._opts.fetchServed ?? true) {
      const { kind, target } = parseCoordinate(server);
      if (kind !== 'mcp') return null;
      tools = await this.client.servedTools(target, this._opts.serverHeaders?.[server]);
    }
    return tools?.find((t) => t && typeof t === 'object' && t.name === toolName) ?? null;
  }

  async check(toolName: string, server: string): Promise<GateDecision> {
    const grade = await this.client.grade(server);
    let served: Record<string, unknown> | null = null;
    if (grade.error === null && Object.keys(grade.toolDigests).length) {
      served = await this._servedDefinition(server, toolName);
    }
    const d = evaluate(toolName, server, grade, {
      minScore: this.minScore, blockOn: this.blockOn, failClosed: this.failClosed,
      servedDefinition: served,
    });
    for (const w of d.warnings) this.onWarn(w);
    return d;
  }

  /** The decision for a tool call, mapping first. */
  async decide(toolName: string): Promise<GateDecision> {
    const server = this.resolve(toolName);
    return server ? this.check(toolName, server) : this.unmappedDecision(toolName);
  }
}

// ── wrapTools: the AI SDK hook ───────────────────────────────────────────────

/** The parts of an AI SDK `Tool` the gate touches (structural, so no `ai` import). */
export interface GateableTool {
  execute?: (input: any, options: any) => any;
  needsApproval?: boolean | ((input: any, options: any) => boolean | Promise<boolean>);
  [key: string]: unknown;
}
export type GateableToolSet = Record<string, GateableTool>;

export interface BlockedOutput {
  error: string;
  agentavow: {
    outcome: Outcome; server: string | null; score: number | null; tier: string | null;
    reportUrl: string | null; servedDigest: string | null; signedDigest: string | null;
  };
}

export function blockedOutput(d: GateDecision): BlockedOutput {
  return {
    error: d.reason,
    agentavow: {
      outcome: d.outcome, server: d.server, score: d.grade?.score ?? null,
      tier: d.grade?.tier ?? null, reportUrl: d.grade?.reportUrl ?? null,
      servedDigest: d.servedDigest, signedDigest: d.signedDigest,
    },
  };
}

/**
 * Gate every tool in an AI SDK ToolSet on the AgentAvow grade. Returns a new set
 * with the same keys; pass it as `tools` to generateText / streamText / an Agent.
 *
 * @example
 * const tools = wrapTools(await mcpClient.tools(), { server: 'https://mcp.deepwiki.com/mcp' })
 */
export function wrapTools<T extends GateableToolSet>(tools: T, options: GateOptions = {}): T {
  const gate = new TrustGate(options);
  const out: GateableToolSet = {};
  for (const [name, tool] of Object.entries(tools)) {
    out[name] = wrapTool(name, tool, gate);
  }
  return out as T;
}

export function wrapTool<T extends GateableTool>(name: string, tool: T, gate: TrustGate): T {
  const wrapped: GateableTool = { ...tool };
  if (gate.onFail === 'confirm') {
    const orig = tool.needsApproval;
    wrapped.needsApproval = async (input: any, options: any) => {
      const d = await gate.decide(name);
      if (!d.allow) return true;
      return typeof orig === 'function' ? await orig(input, options) : !!orig;
    };
  }
  if (typeof tool.execute === 'function') {
    const execute = tool.execute;
    wrapped.execute = async (input: any, options: any) => {
      const d = await gate.decide(name);
      if (!d.allow) {
        switch (gate.onFail) {
          case 'throw':
            throw new ToolGateError(d);
          case 'warn':
          case 'confirm': // reached only after the SDK's approval step let it through
            gate.onWarn(d.reason);
            break;
          default:
            return blockedOutput(d);
        }
      }
      return execute.call(tool, input, options);
    };
  }
  return wrapped as T;
}
