// OpenAI Agents SDK (@openai/agents) adapter for the AgentAvow gate: a thin layer
// over the core in `./gate.ts`, the same core the Flue and Vercel AI adapters use.
//
//   import { Agent, run, MCPServerStreamableHttp } from '@openai/agents'
//   import { createOpenAIAgentsGate } from 'agentavow-trust/openai-agents'
//
//   const gate = createOpenAIAgentsGate({ onReview: 'block' })
//   const deepwiki = gate.wrap(new MCPServerStreamableHttp({
//     name: 'deepwiki', url: 'https://mcp.deepwiki.com/mcp',
//   }))
//   await deepwiki.connect()          // throws GateError on Do not connect
//   const agent = new Agent({ name: 'Assistant', mcpServers: [deepwiki] })
//
// `gate.wrap(server)` returns the same server object with three methods wrapped:
//
//   connect()    reads the server's signed grade first. When the answer fails the
//                policy it throws a GateError and never opens the connection.
//                `gate.connectAll(servers)` connects the ones that pass and returns
//                the rest as `refused`, for an agent that should start without them.
//   listTools()  checks every served definition against the per-tool digest signed
//                into the attestation and drops a drifted or unknown tool from the
//                list (`onDrift: 'block'`, default), so the model is never shown it.
//   callTool()   runs `checkToolCall` (the cached grade plus the drift check against
//                what listTools recorded) and throws a GateError when the call is not
//                allowed. The SDK turns a failed MCP call into model-visible text
//                (`errorFunction`), so the model sees why and the run continues.
//
// The coordinate AgentAvow grades is the server's own https URL (read from the
// server), or the one you pass: `gate.wrap(server, 'npm:@scope/server')` for a stdio
// server or one graded as a package or repo. A server with neither is decided by
// `unmapped` (default allow, with a warning).
//
// `review` with `onReview: 'confirm'` needs your `confirm` hook (the SDK's
// `needsApproval` belongs to function tools, not to MCP server tools); without one,
// `confirm` blocks.
//
// Runtime: WebCrypto + fetch only. No `@openai/agents` import: the server shape is
// structural, so the adapter works with MCPServerStreamableHttp, MCPServerSSE and
// MCPServerStdio.

import {
  GateError, createGate, parseCoordinate,
  type Decision, type Gate, type GateHooks, type GatePolicy,
} from './gate.js';
import { gateMessage } from './vercel-ai.js';

export { GateError } from './gate.js';
export type { Decision, GatePolicy, GateHooks } from './gate.js';
export { headline, gateMessage } from './vercel-ai.js';

/** The parts of an `MCPServer` the gate touches. */
export interface McpServerLike {
  name?: string;
  connect(): Promise<void>;
  listTools(...args: any[]): Promise<Array<Record<string, unknown>>>;
  callTool(toolName: string, args: any, ...rest: any[]): Promise<unknown>;
  [k: string]: unknown;
}

export interface OpenAIAgentsGateOptions extends GatePolicy, GateHooks {
  /** Map a server name to the coordinate AgentAvow grades, when it is not the
   *  server's own https URL. */
  coordinates?: Record<string, string>;
}

export interface ConnectAllResult<T> {
  /** The servers that passed and are now connected. */
  servers: T[];
  /** The decisions for the servers left unconnected. */
  refused: Decision[];
}

export interface OpenAIAgentsGate extends Gate {
  /** Wrap `connect`, `listTools` and `callTool` on this server (same object back). */
  wrap<T extends McpServerLike>(server: T, coordinate?: string): T;
  /** Wrap and connect each server; the ones that fail the policy stay unconnected. */
  connectAll<T extends McpServerLike>(servers: readonly T[]): Promise<ConnectAllResult<T>>;
  /** The coordinate the gate grades for a server, or null. */
  coordinateOf(server: McpServerLike): string | null;
}

const WRAPPED = Symbol.for('agentavow-trust/openai-agents');

/** The https URL an MCPServerStreamableHttp / MCPServerSSE was built with, if it keeps one. */
function serverUrl(server: McpServerLike): string | null {
  const s = server as Record<string, any>;
  for (const v of [s.url, s.options?.url, s.params?.url, s.serverUrl, s._url]) {
    if (typeof v === 'string' && /^https?:\/\//i.test(v)) return v;
    if (v instanceof URL) return v.toString();
  }
  return null;
}

export function createOpenAIAgentsGate(options: OpenAIAgentsGateOptions = {}): OpenAIAgentsGate {
  const core = createGate(options);
  const onWarn = options.onWarn ?? ((m: string) => console.warn(m));

  const coordinateOf = (server: McpServerLike): string | null => {
    const name = typeof server.name === 'string' ? server.name : '';
    const c = (name && options.coordinates?.[name]) || serverUrl(server);
    if (!c) return null;
    parseCoordinate(c); // throws on an unusable coordinate
    return c;
  };

  const wrap = <T extends McpServerLike>(server: T, coordinate?: string): T => {
    if ((server as Record<symbol, unknown>)[WRAPPED]) return server;
    const coord = coordinate ?? coordinateOf(server);
    const label = server.name || coord || 'MCP server';
    const connect = server.connect.bind(server);
    const listTools = server.listTools.bind(server);
    const callTool = server.callTool.bind(server);

    Object.defineProperty(server, WRAPPED, { value: true });
    if (!coord) {
      const d = core.unmapped(`server ${label}`);
      server.connect = async () => {
        if (!d.allowed) throw new GateError(d);
        onWarn(`AgentAvow: MCP server "${label}" has no https URL and no coordinate (gate.wrap(server, 'npm:…')); not gated.`, d);
        return connect();
      };
      return server;
    }

    server.connect = async () => {
      const d = await core.check(coord);
      if (!d.allowed) {
        throw new GateError({ ...d, reason: `AgentAvow refused MCP server "${label}" (${coord}): ${d.reason}` });
      }
      return connect();
    };
    server.listTools = async (...args: any[]) => {
      const tools = await listTools(...args);
      if (!Array.isArray(tools)) return tools;
      const decisions = await core.observeTools(coord, tools as Array<Record<string, unknown>>);
      const drop = new Set(decisions
        .filter((d) => !d.allowed && (d.outcome === 'drift' || d.outcome === 'unknown_tool'))
        .map((d) => d.toolName));
      for (const d of decisions) if (d.toolName && drop.has(d.toolName)) onWarn(`AgentAvow: ${gateMessage(d, 'blocked')}`, d);
      return drop.size ? tools.filter((t) => !drop.has(String(t?.name))) : tools;
    };
    server.callTool = async (toolName: string, args: any, ...rest: any[]) => {
      const d = await core.checkToolCall({ server: coord, toolName });
      if (!d.allowed) throw new GateError({ ...d, reason: gateMessage(d, 'blocked') });
      return callTool(toolName, args, ...rest);
    };
    return server;
  };

  return {
    ...core,
    wrap,
    coordinateOf,
    async connectAll(servers) {
      const ok: (typeof servers)[number][] = [];
      const refused: Decision[] = [];
      for (const s of servers) {
        wrap(s);
        try {
          await s.connect();
          ok.push(s);
        } catch (e) {
          if (e instanceof GateError) refused.push(e.decision);
          else throw e;
        }
      }
      return { servers: ok, refused };
    },
  };
}
