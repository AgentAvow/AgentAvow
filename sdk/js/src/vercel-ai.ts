// Vercel AI SDK adapter for the AgentAvow gate: a thin layer over the core in
// `./gate.ts` (`createGate`), the same core the Flue adapter uses.
//
//   import { wrapTools } from 'agentavow-trust/vercel-ai'
//
//   const tools = wrapTools(await mcp.tools(), {
//     server: 'https://mcp.deepwiki.com/mcp',   // the coordinate AgentAvow grades
//     allowFloor: 51, onReview: 'confirm', onDrift: 'block',
//   })
//
// `wrapTools(tools, policy)` returns the same ToolSet with each tool's `execute`
// wrapped. Before a tool runs, the gate reads the serving MCP server's signed
// grade (one auth-free GET, cached; the EdDSA JWS is verified against
// AgentAvow's JWKS by default) and runs `checkToolCall`: the three-phrase
// decision (safe / review / do_not_connect) plus the drift check of the
// definition this agent was served against the per-tool digest signed into the
// attestation. Then:
//
//   allowed         the tool runs.
//   do_not_connect  the tool is not run; its result is `{ error, agentavow }`
//                   (`onBlock: 'throw'` throws a GateError instead). A drifted or
//                   ungraded tool lands here under `onDrift: 'block'` (default).
//   review          per `onReview`: `block` (default) as above; `warn` runs and
//                   calls `onWarn`; `confirm` sets the AI SDK's `needsApproval`,
//                   so `generateText` / `streamText` / `ToolLoopAgent` pause for
//                   the user and an approved call runs. With a `confirm` hook of
//                   your own, the hook decides instead.
//
// Why `execute` and not a lifecycle callback: the AI SDK's `onToolExecutionStart`
// (and the deprecated `experimental_onToolCallStart`) observes a call but cannot
// stop it; errors thrown inside it are swallowed. Wrapping `execute` is the hook
// that decides. `needsApproval` is the SDK's documented pause point.
//
// The served definition for the drift check comes from, in order:
//   1. `servedTools`: the `tools/list` you built the tools from (exact; best).
//   2. The wrapped tool itself: its description and JSON input schema are what
//      the model is shown. `@ai-sdk/mcp` normalises a definition when it builds
//      a tool (adds `additionalProperties: false`, an empty `properties`, folds
//      `annotations.title` into `title`, drops `outputSchema`), so the few
//      definitions that normalise to what the tool carries are tried against
//      the expected digest. All of them show the model the same thing.
//   3. `fetchServed` (default true): the server's own `tools/list`, fetched once
//      and cached, used only when it is consistent with what the wrapped tool
//      shows the model (or the tool's schema cannot be read, e.g. zod). A server
//      that serves the gate one definition and the agent another is drift.
// With none of these, the call is decided without a drift check (a warning says so).
//
// Mapping a tool to its server: tools from `createMCPClient().tools()` carry no
// server URL, so give it once per set (`server`), per tool (`toolToServer`), or
// via `resolveServer(toolName)`. A tool that maps to no server (your own
// function) is not gated unless `unmapped: 'block'`.
//
// 0.2.x options still work as deprecated aliases: `minScore` -> `allowFloor`,
// `onFail` -> `onReview` (+ `onBlock: 'throw'` for `onFail: 'throw'`),
// `failClosed` -> `onApiError`. `blockOn` severities beyond critical/high
// (e.g. 'medium') still block.
//
// Runtime: WebCrypto + fetch only (Node 18+, Bun, Deno, edge runtimes).

import {
  GateError, createGate, parseCoordinate, toolDigest, toolKey,
  type BlockTrigger, type Decision, type Gate, type GateHooks, type GatePolicy, type OnReview,
  type ToolDefinition,
} from './gate.js';

export {
  DEFAULT_BASE_URL, DEFAULT_ALLOW_FLOOR, DEFAULT_BLOCK_TRIGGERS, DEFAULT_CACHE_TTL_MS,
  PROFILE, DIGEST_FIELDS, toolKey, toolDigest, parseCoordinate, gradeUrl, reportUrl,
  gradeFromResponse, createGate, deriveDecision, GateError, GradeClient as TrustGateClient,
  // Deprecated: the 0.2.x allow/fail evaluator, kept for callers that import it.
  DEFAULT_MIN_SCORE, DEFAULT_BLOCK_ON, evaluate, ToolGateError,
} from './gate.js';
export type {
  ToolDefinition, Grade, Decision, DecisionLabel, DecisionOutcome, GatePolicy, GateHooks,
  BlockTrigger, OnReview, OnDrift, OnApiError,
  // Deprecated (0.2.x).
  Outcome, GateDecision, EvaluateOptions, ClientOptions,
} from './gate.js';

// ── options ──────────────────────────────────────────────────────────────────

/** @deprecated 0.2.x `onFail`. Use `onReview` (and `onBlock: 'throw'`). */
export type OnFail = 'block' | 'confirm' | 'warn' | 'throw';

/** A `tools/list` (or the `{ tools }` result of `mcpClient.listTools()`). */
export type ServedListing = readonly ToolDefinition[] | { tools: readonly ToolDefinition[] };

export interface VercelGateOptions extends Omit<GatePolicy, 'blockOn'>, GateHooks {
  /** Hard stops, regardless of score (see `GatePolicy.blockOn`). For 0.2.x
   *  compatibility, other finding severities ('medium', 'low') also block. */
  blockOn?: readonly (BlockTrigger | (string & {}))[];
  /** One server for every tool in the set (what `createMCPClient().tools()` gives you). */
  server?: string;
  toolToServer?: Record<string, string>;
  resolveServer?: (toolName: string) => string | null | undefined;
  /** The tools/list each server served: one listing for every server, a map keyed by
   *  coordinate, or a function returning it. Exact, so it wins over everything else. */
  servedTools?: ServedListing | Record<string, ServedListing> |
    ((server: string) => Promise<ServedListing | null> | ServedListing | null);
  /** Fetch tools/list from the https server when the wrapped tool's own definition
   *  cannot decide the drift check (default true). */
  fetchServed?: boolean;
  /** Per-server headers for the tools/list fetch (an Authorization the server needs). */
  serverHeaders?: Record<string, Record<string, string>>;
  /** What a blocked call does: return `{ error, agentavow }` as the tool result
   *  (default), or throw a GateError. */
  onBlock?: 'output' | 'throw';
  /** @deprecated 0.2.x. Use `allowFloor` (note the new default is 51, not 81). */
  minScore?: number;
  /** @deprecated 0.2.x. Use `onReview` ('throw' maps to `onReview: 'block'` + `onBlock: 'throw'`). */
  onFail?: OnFail;
  /** @deprecated 0.2.x. Use `onApiError` (true -> 'block', false -> 'allow'). */
  failClosed?: boolean;
}

/** @deprecated The 0.2.x name of `VercelGateOptions`. */
export type GateOptions = VercelGateOptions;

const TRIGGERS: readonly string[] = ['critical', 'high', 'sandbox_canary', 'malicious_dependency', 'blocked_tier'];
const ON_FAIL: Record<OnFail, OnReview> = { block: 'block', confirm: 'confirm', warn: 'warn', throw: 'block' };

/** The core policy for a set of adapter options: the 0.2.x aliases mapped onto
 *  their 0.3.0 names (a 0.3.0 name wins when both are given). */
export function corePolicy(o: VercelGateOptions = {}): GatePolicy & {
  onBlock: 'output' | 'throw'; extraSeverities: string[];
} {
  if (o.onFail !== undefined && !(o.onFail in ON_FAIL)) {
    throw new Error(`onFail must be block | confirm | warn | throw, got ${String(o.onFail)}`);
  }
  if (o.onBlock !== undefined && o.onBlock !== 'output' && o.onBlock !== 'throw') {
    throw new Error(`onBlock must be output | throw, got ${String(o.onBlock)}`);
  }
  const blockOn = o.blockOn?.map((t) => String(t).toLowerCase());
  return {
    ...pickPolicy(o),
    allowFloor: o.allowFloor ?? o.minScore,
    onReview: o.onReview ?? (o.onFail ? ON_FAIL[o.onFail] : undefined),
    onApiError: o.onApiError ?? (o.failClosed === undefined ? undefined : o.failClosed ? 'block' : 'allow'),
    blockOn: blockOn?.filter((t) => TRIGGERS.includes(t)) as BlockTrigger[] | undefined,
    onBlock: o.onBlock ?? (o.onFail === 'throw' ? 'throw' : 'output'),
    extraSeverities: blockOn?.filter((t) => !TRIGGERS.includes(t)) ?? [],
  };
}

function pickPolicy(o: VercelGateOptions): GatePolicy {
  const keys = [
    'onDrift', 'onUnscanned', 'maxStaleMs', 'cacheTtlMs', 'pins', 'verifySignature', 'unmapped',
    'baseUrl', 'jwksUrl', 'timeoutMs', 'headers',
  ] as const;
  const out: Record<string, unknown> = {};
  for (const k of keys) if (o[k] !== undefined) out[k] = o[k];
  return out as GatePolicy;
}

// ── messages: the phrase first ───────────────────────────────────────────────

export const PHRASES = {
  safe: 'Safe to connect', review: 'Review before you connect', do_not_connect: 'Do not connect',
} as const;

/** "Do not connect", "Safe to connect · Certified", … (the mark only beside Safe). */
export function headline(d: Decision): string {
  return PHRASES[d.decision] + (d.certified && d.decision === 'safe' ? ' · Certified' : '');
}

const SWITCH: Partial<Record<Decision['outcome'], string>> = {
  api_error: 'onApiError', unverified: 'onApiError', unscanned: 'onUnscanned',
  drift: 'onDrift', unknown_tool: 'onDrift',
};

function detail(d: Decision): string {
  return d.reason
    .replace(/^AgentAvow: (do not connect|review) /, 'AgentAvow: ')
    .replace(/ Not run\.$/, '');
}

/** The one-line message for a decision, leading with the phrase. `ran`: whether
 *  the tool was run ('blocked' | 'ran' | 'approved'). */
export function gateMessage(d: Decision, ran: 'blocked' | 'ran' | 'approved' = 'blocked'): string {
  const who = d.toolName ? `'${d.toolName}'` : (d.server ?? 'the target');
  let what: string;
  if (ran === 'blocked') what = `${who} was not run.`;
  else if (ran === 'approved') what = `${who} ran after approval.`;
  else if (d.decision === 'review') what = `${who} ran (onReview: 'warn').`;
  else if (d.outcome !== 'allow' && SWITCH[d.outcome]) what = `${who} ran (${SWITCH[d.outcome]}: 'allow').`;
  else what = `${who} ran.`;
  return `${headline(d)} — ${what} ${detail(d)}`;
}

// ── the served definition, from the wrapped tool ─────────────────────────────

/** The parts of an AI SDK `Tool` the gate touches (structural, so no `ai` import). */
export interface GateableTool {
  execute?: (input: any, options: any) => any;
  needsApproval?: boolean | ((input: any, options: any) => boolean | PromiseLike<boolean>);
  [key: string]: unknown;
}
export type GateableToolSet = Record<string, GateableTool>;

type Dict = Record<string, any>;
const isObj = (v: unknown): v is Dict => !!v && typeof v === 'object' && !Array.isArray(v);

/** The JSON Schema behind an AI SDK schema (`jsonSchema(...)`, or plain JSON).
 *  null for a zod / Standard Schema value or anything unreadable. */
async function jsonOf(schema: unknown): Promise<Dict | null> {
  if (!isObj(schema)) return null;
  if ('~standard' in schema || '_def' in schema || '_zod' in schema) return null;
  if ('jsonSchema' in schema) {
    try {
      const v = await schema.jsonSchema;
      return isObj(v) ? v : null;
    } catch {
      return null;
    }
  }
  if ('type' in schema || 'properties' in schema || '$schema' in schema) return schema;
  return null;
}

interface ToolView { description?: string; title?: string; inputSchema: Dict; annotations?: Dict; outputSchema?: Dict }

/** What the wrapped tool shows the model, or null when its schema cannot be read. */
async function viewOf(tool: GateableTool): Promise<ToolView | null> {
  const inputSchema = await jsonOf(tool.inputSchema ?? tool.parameters);
  if (!inputSchema) return null;
  const v: ToolView = { inputSchema };
  if (typeof tool.description === 'string') v.description = tool.description;
  if (typeof tool.title === 'string') v.title = tool.title;
  const ann = isObj(tool.metadata) ? tool.metadata.annotations : undefined;
  if (isObj(ann)) v.annotations = ann;
  const out = await jsonOf(tool.outputSchema);
  if (out) v.outputSchema = out;
  return v;
}

/** The definitions that `@ai-sdk/mcp` would turn into this view, most literal first. */
function candidatesOf(name: string, v: ToolView): ToolDefinition[] {
  const schemas: Dict[] = [v.inputSchema];
  if (v.inputSchema.additionalProperties === false) {
    const { additionalProperties: _drop, ...rest } = v.inputSchema;
    schemas.push(rest);
  }
  for (const s of [...schemas]) {
    if (isObj(s.properties) && Object.keys(s.properties).length === 0) {
      const { properties: _drop, ...rest } = s;
      schemas.push(rest);
    }
  }
  const titles: (string | undefined)[] = [v.title];
  if (v.title !== undefined && v.annotations?.title === v.title) titles.push(undefined);
  const out: ToolDefinition[] = [];
  for (const title of titles) {
    for (const inputSchema of schemas) {
      const def: ToolDefinition = { name, inputSchema };
      if (v.description !== undefined) def.description = v.description;
      if (title !== undefined) def.title = title;
      if (v.annotations) def.annotations = v.annotations;
      if (v.outputSchema) def.outputSchema = v.outputSchema;
      out.push(def);
    }
  }
  return out;
}

/** Does a served definition show the model what the wrapped tool shows it? */
function consistent(v: ToolView, served: Dict): boolean {
  if ((v.description ?? null) !== (typeof served.description === 'string' ? served.description : null)) return false;
  if (v.title !== undefined && v.title !== (served.title ?? served.annotations?.title)) return false;
  const raw = isObj(served.inputSchema) ? served.inputSchema : {};
  const normalised = { ...raw, properties: raw.properties ?? {}, additionalProperties: false };
  const shape = (s: Dict) => toolDigest({ name: '_', inputSchema: s });
  const mine = shape(v.inputSchema);
  return mine !== null && (mine === shape(raw) || mine === shape(normalised));
}

function listingOf(l: unknown): ToolDefinition[] | null {
  const arr = Array.isArray(l) ? l : isObj(l) && Array.isArray(l.tools) ? l.tools : null;
  return arr ? arr.filter((t): t is ToolDefinition => isObj(t) && typeof t.name === 'string') : null;
}

// ── the gate ─────────────────────────────────────────────────────────────────

export interface VercelGate extends Gate {
  /** The server coordinate a tool maps to, or null. */
  resolve(toolName: string): string | null;
  /** The decision for one call of a tool (the wrapped tool, for the drift check). */
  decide(toolName: string, tool?: GateableTool): Promise<Decision>;
  /** The same, for a server you name instead of the mapping. */
  decideOn(server: string, toolName: string, tool?: GateableTool): Promise<Decision>;
  /** Gate every tool in a ToolSet; same keys. */
  wrap<T extends GateableToolSet>(tools: T): T;
  /** Gate one tool. */
  wrapTool<T extends GateableTool>(name: string, tool: T): T;
  /** True when `review` goes through the AI SDK's `needsApproval`. */
  readonly usesApproval: boolean;
  readonly onBlock: 'output' | 'throw';
}

export interface BlockedOutput {
  /** The message for the model, leading with the phrase ("Do not connect — …"). */
  error: string;
  /** The decision, without the raw grade and attestation payload (kept out of the
   *  model's context; `attestation.jws` still carries the signed result). */
  agentavow: Decision;
}

/** The tool result for a call the gate did not run. */
export function blockedOutput(d: Decision): BlockedOutput {
  return {
    error: gateMessage(d, 'blocked'),
    agentavow: {
      ...d, warnings: [...d.warnings], grade: null,
      attestation: d.attestation ? { ...d.attestation, payload: null } : null,
    },
  };
}

export function createVercelGate(options: VercelGateOptions = {}): VercelGate {
  const policy = corePolicy(options);
  const userWarn = options.onWarn ?? ((m: string) => console.warn(m));
  // `confirm` with no hook of yours: the AI SDK's needsApproval asks; the core blocks.
  const usesApproval = policy.onReview === 'confirm' && !options.confirm;
  const core = createGate({
    ...policy,
    onReview: usesApproval ? 'block' : policy.onReview,
    fetch: options.fetch, confirm: options.confirm, jwks: options.jwks, now: options.now,
    onWarn: (m, d) => userWarn(d && m === d.reason ? gateMessage(d, 'ran') : `AgentAvow: ${m}`, d),
  });
  const views = new WeakMap<GateableTool, Promise<{ view: ToolView | null; candidates: Array<[ToolDefinition, string | null]> }>>();

  const resolve = (toolName: string): string | null => {
    if (options.toolToServer && Object.hasOwn(options.toolToServer, toolName)) {
      return options.toolToServer[toolName] as string;
    }
    if (options.server) return options.server;
    return options.resolveServer?.(toolName) ?? null;
  };

  const explicit = async (server: string, toolName: string): Promise<ToolDefinition | null> => {
    const src = options.servedTools;
    if (!src) return null;
    let listing: unknown;
    if (typeof src === 'function') listing = await src(server);
    else if (Array.isArray(src) || (isObj(src) && Array.isArray((src as Dict).tools))) listing = src;
    else listing = (src as Record<string, ServedListing>)[server];
    return listingOf(listing)?.find((t) => t.name === toolName) ?? null;
  };

  const viewFor = (name: string, tool: GateableTool) => {
    let p = views.get(tool);
    if (!p) {
      p = viewOf(tool).then((view) => ({
        view, candidates: view ? candidatesOf(name, view).map((c) => [c, toolDigest(c)] as [ToolDefinition, string | null]) : [],
      }));
      views.set(tool, p);
    }
    return p;
  };

  /** The served definition for the drift check, and a note when the server served
   *  the gate's own fetch a different definition than the agent was given. */
  const servedFor = async (server: string, name: string, tool?: GateableTool): Promise<{
    def: Record<string, unknown> | null; cloaked: boolean;
  }> => {
    const given = await explicit(server, name);
    if (given) return { def: given, cloaked: false };
    const { view, candidates } = tool ? await viewFor(name, tool) : { view: null, candidates: [] };
    const grade = await core.client.grade(server); // cached; checkToolCall reads the same entry
    const expectedMap = core.pins(server) ?? grade.toolDigests;
    const expected = expectedMap[toolKey(name)];
    const literal = candidates[0]?.[0] ?? null;
    if (grade.error !== null || !Object.keys(expectedMap).length) return { def: literal, cloaked: false };
    const hit = candidates.find(([, digest]) => digest !== null && digest === expected);
    if (hit) return { def: hit[0], cloaked: false };
    if (options.fetchServed ?? true) {
      let fetched: ToolDefinition | null = null;
      try {
        const { kind, target } = parseCoordinate(server);
        if (kind === 'mcp') {
          fetched = (await core.client.servedTools(target, options.serverHeaders?.[server]))
            ?.find((t) => isObj(t) && t.name === name) ?? null;
        }
      } catch { /* not an MCP coordinate */ }
      if (fetched && (!view || consistent(view, fetched))) return { def: fetched, cloaked: false };
      if (fetched && literal) return { def: literal, cloaked: toolDigest(fetched) === expected };
    }
    return { def: literal, cloaked: false };
  };

  const tighten = (d: Decision): Decision => {
    if (!policy.extraSeverities.length || d.decision === 'do_not_connect' || !d.grade) return d;
    const hits = policy.extraSeverities.filter((s) =>
      d.grade?.findings.some((f) => String(f.severity ?? '').toLowerCase() === s));
    if (!hits.length) return d;
    return {
      ...d, decision: 'do_not_connect', allowed: false, outcome: 'finding',
      reason: `AgentAvow: do not connect '${d.toolName}' on ${d.server}: the grade carries ${hits.join(' and ')} ` +
        `findings (blockOn). Report: ${d.reportUrl}`,
    };
  };

  const decideOn = async (server: string, toolName: string, tool?: GateableTool): Promise<Decision> => {
    const { def, cloaked } = await servedFor(server, toolName, tool);
    const d = tighten(await core.checkToolCall({ server, toolName, servedDefinition: def }));
    if (cloaked && (d.outcome === 'drift' || d.outcome === 'unknown_tool')) {
      d.reason += ' The server served AgentAvow\'s check the graded definition and this agent a different one.';
    }
    return d;
  };

  const decide = async (toolName: string, tool?: GateableTool): Promise<Decision> => {
    const server = resolve(toolName);
    return server ? decideOn(server, toolName, tool) : core.unmapped(toolName);
  };

  const wrapTool = <T extends GateableTool>(name: string, tool: T): T => {
    const wrapped: GateableTool = { ...tool };
    if (usesApproval) {
      const orig = tool.needsApproval;
      wrapped.needsApproval = async (input: any, opts: any) => {
        const d = await decide(name, tool);
        if (!d.allowed && d.decision === 'review') return true;
        // do_not_connect is never put to the user: `execute` refuses it.
        return typeof orig === 'function' ? !!(await orig(input, opts)) : !!orig;
      };
    }
    if (typeof tool.execute === 'function') {
      const execute = tool.execute;
      wrapped.execute = async (input: any, opts: any) => {
        const d = await decide(name, tool);
        if (!d.allowed) {
          if (usesApproval && d.decision === 'review') {
            // Reached only after the SDK's approval step let the call through.
            userWarn(gateMessage(d, 'approved'), d);
          } else if (gate.onBlock === 'throw') {
            throw new GateError({ ...d, reason: gateMessage(d, 'blocked') });
          } else {
            return blockedOutput(d);
          }
        }
        return execute.call(tool, input, opts);
      };
    }
    return wrapped as T;
  };

  const gate: VercelGate = {
    ...core,
    usesApproval,
    onBlock: policy.onBlock,
    resolve,
    decide,
    decideOn,
    wrapTool,
    wrap<T extends GateableToolSet>(tools: T): T {
      const out: GateableToolSet = {};
      for (const [name, tool] of Object.entries(tools)) out[name] = wrapTool(name, tool);
      return out as T;
    },
  };
  return gate;
}

/**
 * Gate every tool in an AI SDK ToolSet on AgentAvow's signed result. Returns a new
 * set with the same keys; pass it as `tools` to generateText / streamText / an Agent.
 *
 * @example
 * const tools = wrapTools(await mcp.tools(), { server: 'https://mcp.deepwiki.com/mcp' })
 */
export function wrapTools<T extends GateableToolSet>(tools: T, options: VercelGateOptions = {}): T {
  return createVercelGate(options).wrap(tools);
}

/** Gate one tool with an existing gate (`createVercelGate`, or a deprecated `TrustGate`). */
export function wrapTool<T extends GateableTool>(name: string, tool: T, gate: VercelGate | TrustGate): T {
  return (gate instanceof TrustGate ? gate.gate : gate).wrapTool(name, tool);
}

/** @deprecated 0.2.x. Use `createVercelGate(options)`; `check` / `decide` now
 *  return the core `Decision` (`allowed`, `decision`), not the 0.2.x `GateDecision`. */
export class TrustGate {
  gate: VercelGate;
  constructor(opts: VercelGateOptions = {}) {
    this.gate = createVercelGate(opts);
  }
  get client() {
    return this.gate.client;
  }
  resolve(toolName: string): string | null {
    return this.gate.resolve(toolName);
  }
  /** The decision for a tool on a given server (served definition from `servedTools` / fetch). */
  check(toolName: string, server: string): Promise<Decision> {
    return this.gate.decideOn(server, toolName);
  }
  decide(toolName: string): Promise<Decision> {
    return this.gate.decide(toolName);
  }
}
