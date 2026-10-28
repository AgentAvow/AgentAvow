// Claude Agent SDK (@anthropic-ai/claude-agent-sdk) adapter for the AgentAvow gate:
// a thin layer over the core in `./gate.ts`, the same core the Flue and Vercel AI
// adapters use.
//
//   import { query } from '@anthropic-ai/claude-agent-sdk'
//   import { createClaudeAgentGate } from 'agentavow-trust/claude-agent-sdk'
//
//   const gate = createClaudeAgentGate({ onReview: 'confirm' })
//   const { servers, disallowedTools } = await gate.mcpServers({
//     deepwiki: { type: 'http', url: 'https://mcp.deepwiki.com/mcp' },
//   })
//   for await (const m of query({ prompt, options: {
//     mcpServers: servers, disallowedTools, hooks: gate.hooks(),
//   } })) { … }
//
// Two seams:
//
// (a) `gate.mcpServers(config)`, before the session starts. Each server is mapped to
//     the coordinate AgentAvow grades (its own https URL for `http` / `sse` servers;
//     `coordinates` for a stdio server, an in-process `sdk` server, or one graded as a
//     package or repo) and checked. A server whose answer fails the policy is left out
//     of the returned `servers`, so the session never connects to it. For an https
//     server the gate also reads the server's own `tools/list` (`fetchServed`, default
//     true) and checks every definition against the per-tool digest signed into the
//     attestation; a drifted or unknown tool goes into `disallowedTools`
//     (`mcp__<server>__<tool>`), which the SDK refuses before any hook runs.
//
// (b) `gate.hooks()`, a `PreToolUse` hook for every `mcp__…` call. It runs
//     `checkToolCall` (the cached grade plus the drift check against what the gate
//     recorded in (a)). A call that is not allowed returns
//     `permissionDecision: 'deny'` with the reason, which the SDK hands the model as
//     the tool result. A PreToolUse deny holds in every permission mode, including
//     `bypassPermissions`, which is why the gate uses a hook and not `canUseTool`
//     (auto-approved tools never reach `canUseTool`). `review` with
//     `onReview: 'confirm'` and no `confirm` hook of yours returns
//     `permissionDecision: 'ask'`, the SDK's own approval flow (your `canUseTool`, or
//     the permission prompt). `gate.canUseTool` is offered too, for code that already
//     routes approvals through it.
//
// Tools that are not `mcp__…` (Bash, Edit, your own SDK tools) are not gated. An
// `mcp__…` tool from a server the gate was not told about is decided by `unmapped`
// (default allow, with a warning once).
//
// Runtime: WebCrypto + fetch only. No `@anthropic-ai/claude-agent-sdk` import: the
// shapes below are structural, so the adapter works with any 0.x release that has
// `hooks` and `mcpServers`.

import {
  GateError, createGate, parseCoordinate,
  type Decision, type Gate, type GateHooks, type GatePolicy,
} from './gate.js';
import { gateMessage, headline } from './vercel-ai.js';

export { GateError } from './gate.js';
export type { Decision, GatePolicy, GateHooks } from './gate.js';
export { headline, gateMessage } from './vercel-ai.js';

/** The MCP server config shapes the SDK accepts (`McpServerConfig`), structurally. */
export type ClaudeMcpServerConfigLike =
  | { type?: 'stdio'; command: string; args?: string[]; env?: Record<string, string> }
  | { type: 'http' | 'sse'; url: string; headers?: Record<string, string> }
  | { type: 'sdk'; name: string; instance?: unknown }
  | { type?: string; [k: string]: unknown };

/** The fields of a `PreToolUse` hook input the gate reads. */
export interface PreToolUseInputLike {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: unknown;
  [k: string]: unknown;
}

export interface PreToolUseOutput {
  hookSpecificOutput?: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'allow' | 'deny' | 'ask';
    permissionDecisionReason?: string;
  };
  systemMessage?: string;
}

export type PreToolUseHook = (
  input: PreToolUseInputLike, toolUseId?: string, options?: { signal?: AbortSignal },
) => Promise<PreToolUseOutput>;

export type CanUseToolResult =
  | { behavior: 'allow'; updatedInput: Record<string, unknown> }
  | { behavior: 'deny'; message: string };

export interface ClaudeAgentGateOptions extends GatePolicy, GateHooks {
  /** Map a server name (the `mcpServers` key) to the coordinate AgentAvow grades, when
   *  it is not the server's own https URL: `npm:@scope/server`, `pypi:name`, `owner/repo`. */
  coordinates?: Record<string, string>;
  /** Read each https server's own `tools/list` in `mcpServers()` for the drift check. Default true. */
  fetchServed?: boolean;
}

export interface McpServersResult<T> {
  /** The servers to pass as `options.mcpServers`: the ones whose answer passed. */
  servers: Partial<T>;
  /** `mcp__<server>__<tool>` names whose served definition drifted or was never graded. */
  disallowedTools: string[];
  /** The decision per server name. */
  decisions: Record<string, Decision>;
  /** The decisions for the servers left out. */
  refused: Decision[];
}

export interface ClaudeAgentGate extends Gate {
  /** Seam (a): check the servers before the session starts. */
  mcpServers<T extends Record<string, ClaudeMcpServerConfigLike>>(config: T): Promise<McpServersResult<T>>;
  /** Seam (b): the `hooks` option, a PreToolUse hook on every `mcp__…` tool. */
  hooks(): { PreToolUse: Array<{ matcher: string; hooks: PreToolUseHook[] }> };
  /** The PreToolUse hook itself. */
  preToolUse: PreToolUseHook;
  /** The same decision as a `canUseTool` callback. */
  canUseTool(toolName: string, input: Record<string, unknown>): Promise<CanUseToolResult>;
  /** The decision for one `mcp__<server>__<tool>` call. */
  decide(toolName: string): Promise<Decision>;
  /** Tell the gate a server's coordinate without `mcpServers()`. */
  register(serverName: string, coordinate: string): void;
  /** `{ server, tool }` behind an `mcp__<server>__<tool>` name, or null. */
  parseToolName(toolName: string): { server: string; tool: string } | null;
}

/** Claude Code's name for an MCP tool: `mcp__<server>__<tool>`, the server name with
 *  anything outside [A-Za-z0-9_-] replaced by `_`. */
export function claudeToolName(serverName: string, toolName: string): string {
  return `mcp__${normalizeServerName(serverName)}__${toolName}`;
}

export function normalizeServerName(name: string): string {
  return name.replace(/[^A-Za-z0-9_-]/g, '_');
}

function configUrl(config: ClaudeMcpServerConfigLike): string | null {
  const c = config as Record<string, unknown>;
  if ((c.type === 'http' || c.type === 'sse') && typeof c.url === 'string') return c.url;
  return null;
}

export function createClaudeAgentGate(options: ClaudeAgentGateOptions = {}): ClaudeAgentGate {
  const userWarn = options.onWarn ?? ((m: string) => console.warn(m));
  // `confirm` with no hook of yours: the SDK's own approval flow asks; the core blocks.
  const sdkAsks = (options.onReview ?? 'block') === 'confirm' && !options.confirm;
  const core = createGate({
    ...options,
    onReview: sdkAsks ? 'block' : options.onReview,
    onWarn: (m, d) => userWarn(d && m === d.reason ? gateMessage(d, 'ran') : `AgentAvow: ${m}`, d),
  });
  // normalized server name -> coordinate
  const coords = new Map<string, string>();
  const headersFor = new Map<string, Record<string, string>>();
  const warnedUnmapped = new Set<string>();

  const register = (serverName: string, coordinate: string) => {
    parseCoordinate(coordinate); // throws on an unusable coordinate
    coords.set(normalizeServerName(serverName), coordinate);
  };
  for (const [name, coord] of Object.entries(options.coordinates ?? {})) register(name, coord);

  const parseToolName = (toolName: string): { server: string; tool: string } | null => {
    if (!toolName.startsWith('mcp__')) return null;
    const rest = toolName.slice(5);
    // Longest registered server name first: a server name may itself contain "__".
    const known = [...coords.keys()].sort((a, b) => b.length - a.length);
    for (const s of known) {
      if (rest.startsWith(s + '__') && rest.length > s.length + 2) return { server: s, tool: rest.slice(s.length + 2) };
    }
    const cut = rest.indexOf('__');
    if (cut <= 0 || cut + 2 >= rest.length) return null;
    return { server: rest.slice(0, cut), tool: rest.slice(cut + 2) };
  };

  const decide = async (toolName: string): Promise<Decision> => {
    const ref = parseToolName(toolName);
    const coordinate = ref ? coords.get(ref.server) : undefined;
    if (!ref || !coordinate) {
      const d = core.unmapped(toolName);
      if (d.allowed && !warnedUnmapped.has(toolName)) {
        warnedUnmapped.add(toolName);
        userWarn(`AgentAvow: '${toolName}' comes from a server the gate was not given (use gate.mcpServers or coordinates); not gated.`, d);
      }
      return d;
    }
    return core.checkToolCall({ server: coordinate, toolName: ref.tool });
  };

  const asks = (d: Decision) => sdkAsks && d.decision === 'review' && !d.allowed;

  const preToolUse: PreToolUseHook = async (input) => {
    const toolName = String(input?.tool_name ?? '');
    if (!toolName.startsWith('mcp__')) return {};
    const d = await decide(toolName);
    if (d.allowed) return {};
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: asks(d) ? 'ask' : 'deny',
        permissionDecisionReason: asks(d)
          ? `${headline(d)} — ${d.reason} Approve to run it anyway.`
          : gateMessage(d, 'blocked'),
      },
    };
  };

  const gate: ClaudeAgentGate = {
    ...core,
    register,
    parseToolName,
    decide,
    preToolUse,
    hooks() {
      return { PreToolUse: [{ matcher: 'mcp__.*', hooks: [preToolUse] }] };
    },
    async canUseTool(toolName, input) {
      if (!toolName.startsWith('mcp__')) return { behavior: 'allow', updatedInput: input };
      const d = await decide(toolName);
      if (d.allowed) return { behavior: 'allow', updatedInput: input };
      return { behavior: 'deny', message: gateMessage(d, 'blocked') };
    },
    async mcpServers(config) {
      const servers: Record<string, ClaudeMcpServerConfigLike> = {};
      const decisions: Record<string, Decision> = {};
      const refused: Decision[] = [];
      const disallowedTools: string[] = [];
      for (const [name, cfg] of Object.entries(config)) {
        const url = configUrl(cfg);
        const coordinate = options.coordinates?.[name] ?? url;
        if (!coordinate) {
          const d = core.unmapped(`server ${name}`);
          decisions[name] = d;
          if (d.allowed) {
            servers[name] = cfg;
            userWarn(`AgentAvow: MCP server "${name}" has no https URL and no coordinate (coordinates: { "${name}": "npm:…" }); not gated.`, d);
          } else {
            refused.push(d);
          }
          continue;
        }
        register(name, coordinate);
        const headers = (cfg as { headers?: Record<string, string> }).headers;
        if (headers) headersFor.set(coordinate, headers);
        const d = await core.check(coordinate);
        decisions[name] = d;
        // Review under onReview 'confirm' (SDK asks): keep the server; each call asks.
        if (!d.allowed && !asks(d)) {
          refused.push({ ...d, reason: `AgentAvow refused MCP server "${name}" (${coordinate}): ${d.reason}` });
          continue;
        }
        servers[name] = cfg;
        if ((options.fetchServed ?? true) && url && coordinate === url) {
          const served = await core.client.servedTools(url, headers).catch(() => null);
          if (served) {
            for (const td of await core.observeTools(coordinate, served)) {
              if (!td.allowed && (td.outcome === 'drift' || td.outcome === 'unknown_tool') && td.toolName) {
                disallowedTools.push(claudeToolName(name, td.toolName));
                userWarn(`AgentAvow: ${gateMessage(td, 'blocked')}`, td);
              }
            }
          }
        }
      }
      return { servers: servers as Partial<typeof config>, disallowedTools, decisions, refused };
    },
  };
  return gate;
}

/** Throws a GateError for a refused server: for code that wants the session to fail
 *  rather than start without it. */
export function assertAllowed(result: McpServersResult<unknown>): void {
  const first = result.refused[0];
  if (first) throw new GateError(first);
}
