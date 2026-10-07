// Vercel AI SDK tool-call gate on the AgentAvow grade: a thin adapter over the
// core in `./gate.ts`.
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
// Node 18+ (global fetch, WebCrypto). Depends on `canonicalize` (RFC 8785).

import {
  DEFAULT_BLOCK_ON, DEFAULT_MIN_SCORE, GradeClient, ToolGateError, evaluate, parseCoordinate,
  type ClientOptions, type GateDecision, type Outcome, type ToolDefinition,
} from './gate.ts';

export {
  DEFAULT_BASE_URL, DEFAULT_MIN_SCORE, DEFAULT_BLOCK_ON, DEFAULT_CACHE_TTL_MS,
  PROFILE, DIGEST_FIELDS, toolKey, toolDigest, parseCoordinate, gradeUrl, reportUrl,
  gradeFromResponse, evaluate, ToolGateError, GradeClient as TrustGateClient,
} from './gate.ts';
export type {
  ToolDefinition, Grade, Outcome, GateDecision, EvaluateOptions, ClientOptions,
} from './gate.ts';

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
  client: GradeClient;
  minScore: number;
  blockOn: readonly string[];
  onFail: OnFail;
  failClosed: boolean;
  unmapped: 'allow' | 'block';
  private _opts: GateOptions;
  onWarn: (m: string) => void;

  constructor(opts: GateOptions = {}) {
    this._opts = opts;
    this.client = new GradeClient(opts);
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
    if (o.toolToServer && toolName in o.toolToServer) return o.toolToServer[toolName] as string;
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
