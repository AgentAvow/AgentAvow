// Flue (@flue/runtime 2.x) adapter for the AgentAvow gate.
//
//   import { instrument, useMcpConnection } from '@flue/runtime'
//   import { createFlueGate } from 'agentavow-trust/flue'
//
//   export const gate = createFlueGate({ allowFloor: 51, onReview: 'block' })
//   instrument(gate.instrumentation())                       // src/app.ts, module scope
//
//   export function Assistant() {                              // the agent
//     useMcpConnection(gate.connection({ name: 'deepwiki', url: 'https://mcp.deepwiki.com/mcp', optional: true }))
//     return 'Answer questions about public repositories.'
//   }
//
// Two seams, both verified against the Flue runtime source at 2.2.2:
//
// (a) `gate.connection(def)` returns the same connection definition with its
//     `fetch` wrapped. Flue hands that `fetch` to the MCP SDK's
//     StreamableHTTPClientTransport (packages/runtime/src/mcp.ts `createTransport`),
//     which POSTs every JSON-RPC message through it and rejects the pending request
//     when `fetch` throws (@modelcontextprotocol/client `_send`: `throw error`). So:
//       - on `initialize` the wrapper fetches the server's grade and, on
//         `do_not_connect`, throws: `createMcpConnection` rejects, and with
//         `optional: true` Flue mounts zero tools for that server and tells the
//         model why (packages/runtime/src/client.ts `resolveMcpTools`:
//         `{ name, reason: error.message }`). Without `optional`, the submission fails.
//       - on `tools/list` the wrapper reads the reply (plain JSON or SSE-framed),
//         records every served definition, checks each against the pinned or
//         signed digest, and refuses the connection (throws) when a tool drifted
//         or is unknown under `onDrift: 'block'`. The transport receives the same
//         reply bytes, so nothing else changes.
//     Flue validates definitions by key (hooks/use-mcp-connection.ts
//     `assertMcpConnectionDefinition`): `fetch` is a known field, so the wrapped
//     definition passes `useMcpConnection` and `defineMcpConnection` unchanged.
//
// (b) `gate.instrumentation()` is a `FlueInstrumentation` for `instrument(...)`
//     (packages/runtime/src/instrumentation.ts). Its interceptor runs around every
//     tool execution (session.ts: `interceptExecution({ type: 'tool', toolCallId,
//     toolName }, ctx, () => run())`). For an `mcp__<server>__<tool>` call it runs
//     `checkToolCall` first (an in-memory digest compare against what `tools/list`
//     served) and, when the call is not allowed, throws instead of calling
//     `next()`: the tool rejects, which Flue turns into an `isError` tool outcome
//     the model sees (session.ts, "a throw becomes an isError outcome the model
//     sees"); the submission continues. The interceptor API exists for tracing,
//     but not calling `next()` is a real contract: `dispatchExecution` only runs
//     the tool when the chain reaches `next`.
//
// `review` with `onReview: 'confirm'` needs your `confirm` hook (Flue has no
// built-in approval pause); without one, `confirm` blocks.
//
// Runtime: WebCrypto + fetch only, so this works on Flue's Node and Cloudflare
// Workers targets (`nodejs_compat` is what Flue itself needs). Nothing runs at
// module scope: the grade is fetched inside the connect, which Flue performs in
// request context.

import {
  GateError, captureRpc, createGate, parseCoordinate,
  type Decision, type Gate, type GateHooks, type GatePolicy,
} from './gate.ts';

export { GateError } from './gate.ts';
export type { Decision, GatePolicy, GateHooks } from './gate.ts';

/** The fields of Flue's `McpConnectionDefinition` the adapter reads; everything
 *  else passes through untouched. Structural, so there is no `@flue/runtime` import. */
export interface FlueMcpConnectionLike {
  name: string;
  url: string | URL;
  transport?: 'streamable-http' | 'sse';
  fetch?: typeof fetch;
  tools?: readonly string[];
  optional?: boolean;
}

/** Flue's execution interceptor contract (packages/runtime/src/execution-interceptor.ts). */
export type FlueExecutionOperationLike =
  | { type: 'tool'; toolCallId: string; toolName: string }
  | { type: string; [k: string]: unknown };
export type FlueExecutionInterceptorLike = <T>(
  operation: FlueExecutionOperationLike, ctx: unknown, next: () => Promise<T>,
) => Promise<T>;
export interface FlueInstrumentationLike {
  key?: symbol;
  observe: (observation: unknown, ctx: unknown) => void | Promise<void>;
  interceptor: FlueExecutionInterceptorLike;
  dispose(): void | Promise<void>;
}

export interface FlueGateOptions extends GatePolicy, GateHooks {
  /** Map a Flue server name to the coordinate AgentAvow grades, when it is not the
   *  connection's own https URL (a server you proxy, or one graded as a package). */
  coordinates?: Record<string, string>;
}

export interface FlueToolRef {
  server: string;
  toolName: string;
  flueName: string;
}

export interface FlueGate extends Gate {
  /** Seam (a): the same definition with `fetch` wrapped by the gate. */
  connection<T extends FlueMcpConnectionLike>(definition: T): T;
  /** Seam (b): the instrumentation for `instrument(...)`. */
  instrumentation(): FlueInstrumentationLike;
  /** The fetch wrapper itself, for a transport you build by hand. */
  gateFetch(serverName: string, coordinate: string, inner?: typeof fetch, tools?: readonly string[]): typeof fetch;
  /** The server and original tool name behind an adapted `mcp__<server>__<tool>` name. */
  lookup(flueToolName: string): FlueToolRef | null;
}

/** Flue's adapted tool name (packages/runtime/src/mcp.ts `createToolName`). */
export function flueToolName(serverName: string, toolName: string): string {
  return `mcp__${sanitizePart(serverName)}__${sanitizePart(toolName)}`;
}

function sanitizePart(value: string): string {
  const sanitized = value.replace(/[^A-Za-z0-9_-]/g, '_').replace(/^_+|_+$/g, '');
  return sanitized || 'unnamed';
}

type Rpc = Record<string, any>;

function rpcMessages(body: BodyInit | null | undefined): Rpc[] {
  if (typeof body !== 'string') return [];
  try {
    const doc = JSON.parse(body);
    const docs: unknown[] = Array.isArray(doc) ? doc : [doc];
    return docs.filter((d): d is Rpc => !!d && typeof d === 'object');
  } catch {
    return [];
  }
}

function refusal(serverName: string, coordinate: string, decisions: Decision[]): GateError {
  const lead = decisions[0] as Decision;
  const names = decisions.map((d) => d.toolName).filter(Boolean);
  const reason = names.length > 1
    ? `AgentAvow refused MCP server "${serverName}" (${coordinate}): ${names.length} tools did not pass ` +
      `(${names.join(', ')}). First: ${lead.reason}`
    : `AgentAvow refused MCP server "${serverName}" (${coordinate}): ${lead.reason}`;
  return new GateError({ ...lead, reason, allowed: false });
}

export function createFlueGate(options: FlueGateOptions = {}): FlueGate {
  const core = createGate(options);
  const onWarn = options.onWarn ?? ((m: string) => console.warn(m));
  const refs = new Map<string, FlueToolRef>();
  const warnedUnmapped = new Set<string>();

  const coordinateFor = (def: FlueMcpConnectionLike): string => {
    const mapped = options.coordinates?.[def.name];
    if (mapped) return mapped;
    const url = def.url instanceof URL ? def.url.toString() : String(def.url);
    parseCoordinate(url); // throws on an unusable coordinate
    return url;
  };

  const record = async (
    serverName: string, coordinate: string, tools: unknown, allow: readonly string[] | undefined,
  ): Promise<Decision[]> => {
    if (!Array.isArray(tools)) return [];
    const served = tools.filter((t): t is Record<string, unknown> & { name: string } =>
      !!t && typeof t === 'object' && typeof (t as Rpc).name === 'string');
    const wanted = allow ? served.filter((t) => allow.includes(t.name)) : served;
    for (const t of wanted) {
      const flueName = flueToolName(serverName, t.name);
      refs.set(flueName, { server: coordinate, toolName: t.name, flueName });
    }
    return core.observeTools(coordinate, wanted);
  };

  /** Legacy SSE transport: replies arrive on the GET stream, not the POST. Watch a
   *  copy of the stream for a tools/list reply and record it; nothing can be
   *  refused here, the per-call check covers it. */
  const watchStream = (res: Response, serverName: string, coordinate: string, allow?: readonly string[]): Response => {
    if (!res.body) return res;
    const [pass, watch] = res.body.tee();
    (async () => {
      const reader = watch.getReader();
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
            const trimmed = line.trim();
            if (!trimmed.startsWith('data:')) continue;
            let doc: Rpc | null = null;
            try { doc = JSON.parse(trimmed.slice(5)); } catch { continue; }
            if (doc && Array.isArray(doc.result?.tools)) {
              const decisions = await record(serverName, coordinate, doc.result.tools, allow);
              for (const d of decisions) if (!d.allowed) onWarn(
                `AgentAvow: ${d.reason} (legacy SSE transport: the connection cannot be refused; the call will be)`, d);
            }
          }
        }
      } catch { /* the stream closed; nothing to do */ }
    })();
    return new Response(pass, { status: res.status, statusText: res.statusText, headers: res.headers });
  };

  const gateFetch = (
    serverName: string, coordinate: string, inner?: typeof fetch, allow?: readonly string[],
  ): typeof fetch => {
    const base = inner ?? ((input: RequestInfo | URL, init?: RequestInit) => globalThis.fetch(input, init));
    return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
      const messages = method === 'POST' ? rpcMessages(init?.body) : [];
      if (messages.some((m) => m.method === 'initialize')) {
        const d = await core.check(coordinate);
        if (!d.allowed) {
          throw new GateError({ ...d, reason: `AgentAvow refused MCP server "${serverName}" (${coordinate}): ${d.reason}` });
        }
      }
      const list = messages.find((m) => m.method === 'tools/list' && m.id !== undefined && m.id !== null);
      const res = await base(input, init);
      if (!res.ok) return res;
      if (list) {
        const ctype = (res.headers.get('content-type') ?? '').toLowerCase();
        if (!ctype.includes('application/json') && !ctype.includes('text/event-stream')) return res;
        const { reply, response } = await captureRpc(res, list.id);
        if (reply && Array.isArray(reply.result?.tools)) {
          const decisions = await record(serverName, coordinate, reply.result.tools, allow);
          const denied = decisions.filter((d) => !d.allowed);
          if (denied.length) throw refusal(serverName, coordinate, denied);
        }
        return response;
      }
      const ctype = (res.headers.get('content-type') ?? '').toLowerCase();
      if (method === 'GET' && ctype.includes('text/event-stream')) {
        return watchStream(res, serverName, coordinate, allow);
      }
      return res;
    };
  };

  const flue: FlueGate = {
    ...core,
    gateFetch,
    connection(definition) {
      const coordinate = coordinateFor(definition);
      return {
        ...definition,
        fetch: gateFetch(definition.name, coordinate, definition.fetch, definition.tools),
      };
    },
    lookup(name) {
      return refs.get(name) ?? null;
    },
    instrumentation() {
      const interceptor: FlueExecutionInterceptorLike = async (operation, _ctx, next) => {
        if (operation.type !== 'tool') return next();
        const toolName = String((operation as { toolName?: unknown }).toolName ?? '');
        if (!toolName.startsWith('mcp__')) return next(); // your own tools are not gated
        const ref = refs.get(toolName);
        if (!ref) {
          const d = core.unmapped(toolName);
          if (!d.allowed) throw new GateError(d);
          if (!warnedUnmapped.has(toolName)) {
            warnedUnmapped.add(toolName);
            onWarn(`AgentAvow: '${toolName}' comes from a connection the gate did not wrap (use gate.connection); not gated.`, d);
          }
          return next();
        }
        const d = await core.checkToolCall({ server: ref.server, toolName: ref.toolName });
        if (!d.allowed) throw new GateError(d);
        return next();
      };
      return {
        key: Symbol.for('agentavow-trust/flue'),
        observe: () => {},
        interceptor,
        dispose: () => {},
      };
    },
  };
  return flue;
}
