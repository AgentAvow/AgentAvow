#!/usr/bin/env node
/**
 * In-sandbox MCP exerciser — Node 20 twin of mcp_exercise.py. Zero dependencies, one file.
 *
 * Same CLI, same transcript shape (the contract in src/scanner/behavioral/transcript.py),
 * and a line-for-line port of src/scanner/behavioral/synthetic_args.py so both exercisers
 * send byte-identical arguments for the same inputSchema (pinned by the golden files under
 * tests/fixtures/behavioral/schemas). Always prints one transcript and exits 0.
 *
 *   node mcp_exercise.js [--timeout S] [--per-call-timeout S] [--max-tools N]
 *       [--readme PATH] [--canary-env A,B] [--canary-value V] [--mounts /tmp,/work,/run]
 *       -- <server command and args...>
 *   node mcp_exercise.js --gen-args schema.json
 */
"use strict";
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

// ---- synthetic_args port ----------------------------------------------------------------
const FALLBACK = "agentavow";
const SAMPLE_PATH = "/work/agentavow-sample.txt";
const SAMPLE_URL = "https://example.com/agentavow";
const MAX_DEPTH = 6, MAX_OPTIONAL = 6, MAX_ARRAY_ITEMS = 4;
const FORMAT_VALUES = {
  uri: SAMPLE_URL, url: SAMPLE_URL, "uri-reference": SAMPLE_URL, iri: SAMPLE_URL,
  email: "agentavow@example.com", "idn-email": "agentavow@example.com",
  date: "2024-01-01", "date-time": "2024-01-01T00:00:00Z", time: "00:00:00Z",
  uuid: "00000000-0000-4000-8000-000000000000",
  hostname: "example.com", "idn-hostname": "example.com",
  ipv4: "192.0.2.1", ipv6: "2001:db8::1",
};
const HINT_PATH = new Set(["path", "file", "dir", "directory", "filename", "filepath", "folder"]);
const HINT_URL = new Set(["url", "uri", "link", "href", "endpoint", "website"]);
const HINT_EMAIL = new Set(["email", "mail"]);
const HINT_HOST = new Set(["host", "hostname", "domain"]);
const HINT_ID = new Set(["id", "uuid", "guid", "identifier"]);
const TYPE_ORDER = new Set(["object", "array", "string", "integer", "number", "boolean", "null"]);

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isInt = (v) => Number.isInteger(v);

function tokens(name) {
  const s = String(name || "").replace(/([a-z0-9])([A-Z])/g, "$1_$2");
  return s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function stringFor(schema, name) {
  const fmt = schema.format;
  let value = typeof fmt === "string" ? FORMAT_VALUES[fmt] : undefined;
  if (value === undefined) {
    const toks = tokens(name);
    if (toks.some((t) => HINT_PATH.has(t) || t.endsWith("path") || t.endsWith("file"))) value = SAMPLE_PATH;
    else if (toks.some((t) => HINT_URL.has(t) || t.endsWith("url") || t.endsWith("uri"))) value = SAMPLE_URL;
    else if (toks.some((t) => HINT_EMAIL.has(t))) value = "agentavow@example.com";
    else if (toks.some((t) => HINT_HOST.has(t))) value = "example.com";
    else if (toks.some((t) => HINT_ID.has(t))) value = "1";
    else value = FALLBACK;
  }
  const minLen = schema.minLength;
  if (isInt(minLen) && value.length < minLen) value = value + "x".repeat(Math.min(minLen, 256) - value.length);
  const maxLen = schema.maxLength;
  if (isInt(maxLen) && maxLen > 0 && maxLen < value.length) value = value.slice(0, maxLen);
  return value;
}

const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);

function numberFor(schema, integer) {
  const minimum = num(schema.minimum);
  const exclMin = schema.exclusiveMinimum;
  let value;
  if (num(exclMin) !== null) value = num(exclMin) + 1;
  else if (minimum !== null) value = exclMin === true ? minimum + 1 : minimum;
  else value = 1;
  let maximum = num(schema.maximum);
  const exclMax = schema.exclusiveMaximum;
  if (num(exclMax) !== null) maximum = num(exclMax) - 1;
  else if (maximum !== null && exclMax === true) maximum = maximum - 1;
  if (maximum !== null && value > maximum) value = maximum;
  if (integer) value = Math.trunc(value);
  return num(value) !== null ? value : 1;
}

function resolveRef(ref, root) {
  if (typeof ref !== "string" || !ref.startsWith("#/")) return null;
  let node = root;
  for (const raw of ref.slice(2).split("/")) {
    const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (isObj(node) && has(node, key)) node = node[key];
    else if (Array.isArray(node) && /^\d+$/.test(key) && Number(key) < node.length) node = node[Number(key)];
    else return null;
  }
  return isObj(node) ? node : null;
}

function pickType(schema) {
  let t = schema.type;
  if (Array.isArray(t)) t = t.find((x) => typeof x === "string" && x !== "null");
  if (typeof t === "string" && TYPE_ORDER.has(t)) return t;
  if (isObj(schema.properties)) return "object";
  if (has(schema, "items") || has(schema, "prefixItems")) return "array";
  if (["format", "minLength", "maxLength", "pattern"].some((k) => has(schema, k))) return "string";
  if (["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"].some((k) => has(schema, k))) return "number";
  return null;
}

function value(schema, root, depth, name) {
  if (depth > MAX_DEPTH || !isObj(schema)) return FALLBACK;
  if (typeof schema.$ref === "string") {
    const target = resolveRef(schema.$ref, root);
    return target ? value(target, root, depth + 1, name) : FALLBACK;
  }
  if (has(schema, "const")) return schema.const;
  if (Array.isArray(schema.examples) && schema.examples.length) return schema.examples[0];
  if (has(schema, "default")) return schema.default;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];
  for (const key of ["anyOf", "oneOf", "allOf"]) {
    const branches = schema[key];
    if (Array.isArray(branches) && branches.length) return value(branches[0], root, depth + 1, name);
  }
  const t = pickType(schema);
  if (t === "string") return stringFor(schema, name);
  if (t === "integer") return numberFor(schema, true);
  if (t === "number") return numberFor(schema, false);
  if (t === "boolean") return false;
  if (t === "null") return null;
  if (t === "array") {
    let items = has(schema, "items") ? schema.items : undefined;
    if (items === undefined) {
      const prefix = schema.prefixItems;
      items = Array.isArray(prefix) && prefix.length ? prefix[0] : undefined;
    }
    if (Array.isArray(items)) items = items.length ? items[0] : undefined;
    let count = 1;
    if (isInt(schema.minItems)) count = Math.max(1, Math.min(schema.minItems, MAX_ARRAY_ITEMS));
    const one = items !== undefined ? value(items, root, depth + 1, name) : FALLBACK;
    return Array.from({ length: count }, () => JSON.parse(JSON.stringify(one === undefined ? null : one)));
  }
  if (t === "object") return objectFor(schema, root, depth);
  return FALLBACK;
}

function objectFor(schema, root, depth) {
  const props = isObj(schema.properties) ? schema.properties : {};
  const required = Array.isArray(schema.required) ? schema.required.filter((r) => typeof r === "string") : [];
  const out = {};
  let optionalUsed = 0;
  for (const key of Object.keys(props)) {
    if (required.includes(key)) out[key] = value(props[key], root, depth + 1, key);
    else if (optionalUsed < MAX_OPTIONAL) { optionalUsed += 1; out[key] = value(props[key], root, depth + 1, key); }
  }
  for (const key of required) if (!has(out, key)) out[key] = stringFor({}, key);
  return out;
}

function generateArgs(schema) {
  try {
    if (!isObj(schema)) return {};
    const v = value(schema, schema, 0, "");
    return isObj(v) ? v : {};
  } catch (e) { return {}; }
}

const FENCE_RE = /```[^\n]*\n([\s\S]*?)```/g;
const ARG_KEYS = ["arguments", "args", "params", "input"];
const MAX_README_CHARS = 400000, MAX_LOOKAHEAD_LINES = 12;

function balancedEnd(text, start) {
  let depth = 0, inStr = false, esc = false;
  const stop = Math.min(text.length, start + 100000);
  for (let pos = start; pos < stop; pos++) {
    const ch = text[pos];
    if (inStr) { if (esc) esc = false; else if (ch === "\\") esc = true; else if (ch === '"') inStr = false; }
    else if (ch === '"') inStr = true;
    else if (ch === "{") depth += 1;
    else if (ch === "}") { depth -= 1; if (depth === 0) return pos; }
  }
  return -1;
}

function jsonObjects(text) {
  try {
    const whole = JSON.parse(text);
    if (isObj(whole)) return [whole];
    if (Array.isArray(whole)) return whole.filter(isObj).slice(0, 20);
  } catch (e) { /* fall through */ }
  const out = [];
  let i = 0, attempts = 0;
  while (i < text.length && attempts < 50 && out.length < 20) {
    const start = text.indexOf("{", i);
    if (start < 0) break;
    const end = balancedEnd(text, start);
    attempts += 1;
    if (end < 0) { i = start + 1; continue; }
    try {
      const obj = JSON.parse(text.slice(start, end + 1));
      if (isObj(obj)) { out.push(obj); i = end + 1; continue; }
    } catch (e) { /* not JSON */ }
    i = start + 1;
  }
  return out;
}

function namedCallArgs(obj, names, found, depth) {
  if (depth > 8) return;
  if (isObj(obj)) {
    const name = obj.name;
    if (typeof name === "string" && names.has(name) && !has(found, name)) {
      for (const key of ARG_KEYS) if (isObj(obj[key])) { found[name] = obj[key]; break; }
    }
    for (const v of Object.values(obj)) namedCallArgs(v, names, found, depth + 1);
  } else if (Array.isArray(obj)) {
    for (const v of obj.slice(0, 50)) namedCallArgs(v, names, found, depth + 1);
  }
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function mineExamples(readmeText, toolNames) {
  try { return mine(readmeText, toolNames); } catch (e) { return {}; }
}

function mine(readmeText, toolNames) {
  const names = new Set((toolNames || []).filter((n) => typeof n === "string" && n));
  if (!readmeText || typeof readmeText !== "string" || !names.size) return {};
  const text = readmeText.slice(0, MAX_README_CHARS);
  const found = {};
  const blocks = [];
  for (const m of text.matchAll(FENCE_RE)) blocks.push([m.index, m[1]]);
  for (const [, body] of blocks) for (const obj of jsonObjects(body)) namedCallArgs(obj, names, found, 0);
  const lines = text.split("\n");
  const offsets = [];
  let pos = 0;
  for (const line of lines) { offsets.push(pos); pos += line.length + 1; }
  const blockStarts = blocks.map((b) => b[0]);
  let inFence = false;
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    if (line.trimStart().startsWith("```")) { inFence = !inFence; continue; }
    if (inFence) continue;
    for (const name of [...names].filter((n) => !has(found, n)).sort()) {
      if (!new RegExp("(?<![A-Za-z0-9_])" + escapeRe(name) + "(?![A-Za-z0-9_])").test(line)) continue;
      const limit = offsets[Math.min(idx + MAX_LOOKAHEAD_LINES, lines.length - 1)];
      const nxt = blockStarts.findIndex((s) => offsets[idx] < s && s <= limit);
      if (nxt < 0) continue;
      for (const obj of jsonObjects(blocks[nxt][1])) {
        if (has(obj, "name") && names.has(obj.name)) continue;
        found[name] = obj;
        break;
      }
    }
  }
  const cleaned = {};
  for (const [k, v] of Object.entries(found)) cleaned[k] = isObj(v) ? v : {};
  return cleaned;
}

function argsForTool(name, schema, mined) {
  const out = generateArgs(schema);
  const example = isObj(mined) ? mined[name] : undefined;
  if (isObj(example)) for (const [k, v] of Object.entries(example)) out[k] = v;
  return out;
}

// A copy of args with every URL-shaped value we generated (=== SAMPLE_URL) replaced by the
// SSRF sentinel. Returns [variant, changed]; mirrors synthetic_args.ssrf_variant.
function ssrfVariant(args, sentinel) {
  let changed = false;
  const walk = (v) => {
    if (typeof v === "string") { if (v === SAMPLE_URL) { changed = true; return sentinel; } return v; }
    if (Array.isArray(v)) return v.map(walk);
    if (isObj(v)) { const o = {}; for (const [k, x] of Object.entries(v)) o[k] = walk(x); return o; }
    return v;
  };
  const variant = walk(args);
  return [variant, changed];
}

// ---- exerciser --------------------------------------------------------------------------
const BEGIN = "AGENTAVOW_TRANSCRIPT_BEGIN", END = "AGENTAVOW_TRANSCRIPT_END";
const INIT_WAIT_MAX = 15; // seconds to wait for `initialize` before giving up on a candidate
const PROTOCOLS = ["2025-06-18", "2024-11-05"];
const CLIENT_INFO = { name: "agentavow-exerciser", version: "1.0" };
const MAX_WALK_ENTRIES = 50000, MAX_WRITES_PER_CALL = 50, SAMPLE_CHARS = 300, STDERR_TAIL = 500;
const now = () => Date.now();

function parseCli(argv) {
  const o = { timeout: 60, perCallTimeout: 8, maxTools: 25, readme: null, canaryEnv: [],
    canaryValue: "", mounts: ["/tmp", "/work", "/run"], genArgs: null, ssrfUrl: "",
    maxSsrf: 6, command: [] };
  const split = argv.indexOf("--");
  if (split >= 0) { o.command = argv.slice(split + 1); argv = argv.slice(0, split); }
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i], val = i + 1 < argv.length ? argv[i + 1] : "";
    if (flag === "--timeout") o.timeout = parseFloat(val);
    else if (flag === "--per-call-timeout") o.perCallTimeout = parseFloat(val);
    else if (flag === "--max-tools") o.maxTools = parseInt(val, 10);
    else if (flag === "--readme") o.readme = val;
    else if (flag === "--canary-env") o.canaryEnv = val.split(",").map((s) => s.trim()).filter(Boolean);
    else if (flag === "--canary-value") o.canaryValue = val;
    else if (flag === "--mounts") o.mounts = val.split(",").map((s) => s.trim()).filter(Boolean);
    else if (flag === "--gen-args") o.genArgs = val;
    else if (flag === "--ssrf-url") o.ssrfUrl = val;
    else if (flag === "--max-ssrf") o.maxSsrf = parseInt(val, 10);
    else i -= 1;
  }
  return o;
}

function emptyTranscript(command, canaryEnv) {
  return { version: 1, launch: { command, ok: false, error: null, startup_ms: 0 },
    server_info: { name: "", version: "" }, protocol_version: "", tools: [], calls: [],
    canary: { env_names: [...canaryEnv], seen_in_result: [] }, timed_out: false, error: null };
}

function walkMounts(mounts, exclude) {
  const seen = new Set();
  for (const mount of mounts) {
    const stack = [mount];
    while (stack.length && seen.size < MAX_WALK_ENTRIES) {
      const d = stack.pop();
      let entries;
      try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { continue; }
      for (const e of entries) {
        const p = path.join(d, e.name);
        if (exclude.has(p) || [...exclude].some((x) => p.startsWith(x + path.sep))) continue;
        seen.add(p);
        if (e.isDirectory()) stack.push(p);
      }
    }
  }
  return seen;
}

function sortedStringify(v) {
  if (Array.isArray(v)) return "[" + v.map(sortedStringify).join(",") + "]";
  if (isObj(v)) return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + sortedStringify(v[k])).join(",") + "}";
  return JSON.stringify(v === undefined ? null : v);
}

class StdioClient {
  constructor(command, env) {
    this.exited = false; this.spawnError = null; this.stderrTail = ""; this.nextId = 1;
    this.pending = new Map(); this.buf = "";
    this.proc = spawn(command[0], command.slice(1), { env, detached: true, stdio: ["pipe", "pipe", "pipe"] });
    this.proc.on("error", (e) => { this.spawnError = `${e.code || "ERR"}: ${e.message}`; this.settleAll(); });
    this.proc.on("exit", () => { this.exited = true; this.settleAll(); });
    this.proc.stdin.on("error", () => {});
    this.proc.stdout.on("data", (chunk) => this.onStdout(chunk));
    this.proc.stderr.on("data", (chunk) => { this.stderrTail = (this.stderrTail + String(chunk)).slice(-STDERR_TAIL); });
  }
  settleAll() { for (const [id, p] of this.pending) { this.pending.delete(id); p([null, "server_exited"]); } }
  onStdout(chunk) {
    this.buf += String(chunk);
    let nl;
    while ((nl = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, nl).trim();
      this.buf = this.buf.slice(nl + 1);
      if (!line.startsWith("{")) continue;
      let msg;
      try { msg = JSON.parse(line); } catch (e) { continue; }
      if (!isObj(msg)) continue;
      if (has(msg, "method")) {
        if (msg.id !== undefined && msg.id !== null)
          this.send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "not supported" } });
        continue;
      }
      const settle = this.pending.get(msg.id);
      if (!settle) continue;
      this.pending.delete(msg.id);
      if (has(msg, "error")) {
        const text = isObj(msg.error) ? msg.error.message : String(msg.error);
        settle([null, `rpc_error: ${String(text).slice(0, 200)}`]);
      } else settle([isObj(msg.result) ? msg.result : {}, null]);
    }
  }
  alive() { return !this.exited && !this.spawnError && this.proc.pid !== undefined; }
  send(msg) {
    if (!this.alive()) return false;
    try { return this.proc.stdin.write(JSON.stringify(msg) + "\n") !== undefined; } catch (e) { return false; }
  }
  request(method, params, timeoutS) {
    const id = this.nextId++;
    return new Promise((resolve) => {
      if (!this.alive() || !this.send({ jsonrpc: "2.0", id, method, params })) return resolve([null, "server_exited"]);
      const timer = setTimeout(() => { this.pending.delete(id); resolve([null, "timeout"]); }, Math.max(1, timeoutS * 1000));
      this.pending.set(id, (r) => { clearTimeout(timer); resolve(r); });
    });
  }
  kill() {
    try { process.kill(-this.proc.pid, "SIGKILL"); } catch (e) { /* gone */ }
    try { this.proc.kill("SIGKILL"); } catch (e) { /* gone */ }
  }
}

function resultText(result) {
  const parts = (Array.isArray(result.content) ? result.content : [])
    .filter((c) => isObj(c) && typeof c.text === "string").map((c) => c.text);
  if (parts.length) return parts.join("\n");
  return result.structuredContent !== undefined ? sortedStringify(result.structuredContent) : "";
}

async function listTools(client, deadline, perCall) {
  const tools = [];
  let cursor = null;
  for (let page = 0; page < 20; page++) {
    const [result, err] = await client.request("tools/list", cursor ? { cursor } : {},
      Math.min(perCall, Math.max(0.05, (deadline - now()) / 1000)));
    if (err) return [tools, err];
    for (const t of Array.isArray(result.tools) ? result.tools : [])
      if (isObj(t) && typeof t.name === "string") tools.push(t);
    cursor = result.nextCursor;
    if (!cursor) break;
  }
  return [tools, null];
}

async function callTool(client, spec, o, mined, exclude, deadline, canarySeen, overrideArgs, ssrfTarget) {
  const args = overrideArgs !== undefined && overrideArgs !== null
    ? overrideArgs : argsForTool(spec.name, spec.input_schema, mined);
  const before = walkMounts(o.mounts, exclude);
  const budget = Math.min(o.perCallTimeout, Math.max(0.05, (deadline - now()) / 1000));
  const t0 = now();
  const [result, err] = await client.request("tools/call", { name: spec.name, arguments: args }, budget);
  const duration = now() - t0;
  const writes = [...walkMounts(o.mounts, exclude)].filter((p) => !before.has(p)).sort().slice(0, MAX_WRITES_PER_CALL);
  const call = { tool: spec.name, args, ok: err === null, error: null, is_error: false,
    duration_ms: duration, fs_writes: writes, result_sample: "" };
  if (ssrfTarget) { call.ssrf_probe = true; call.ssrf_target = ssrfTarget; }
  if (err) { call.error = err === "timeout" ? "call_timeout" : err; return call; }
  const text = resultText(result);
  call.is_error = Boolean(result.isError);
  call.result_sample = text.slice(0, SAMPLE_CHARS);
  if (o.canaryValue && text.includes(o.canaryValue))
    for (const name of o.canaryEnv) if (!canarySeen.includes(name)) canarySeen.push(name);
  return call;
}

async function exercise(o, out) {
  const env = { ...process.env };
  for (const name of o.canaryEnv) env[name] = o.canaryValue;
  const started = now(), deadline = started + o.timeout * 1000;
  const client = new StdioClient(o.command, env);
  out._client = client;
  try {
    const initWait = Math.min(Math.max(o.timeout - 0.5, 0.5), INIT_WAIT_MAX); // fail fast: launcher may try 3 candidates
    let result = null, err = null, proto = PROTOCOLS[0];
    for (proto of PROTOCOLS) {
      [result, err] = await client.request("initialize", { protocolVersion: proto, capabilities: {}, clientInfo: CLIENT_INFO }, initWait);
      if (err === null || !err.startsWith("rpc_error")) break;
    }
    if (err) {
      let code = err === "timeout" ? "initialize_timeout" : err === "server_exited" ? "server_exited" : `initialize_error: ${err}`;
      if (client.spawnError) code = `spawn_failed: ${client.spawnError.slice(0, 200)}`;
      const tail = client.stderrTail.trim();
      out.launch.error = tail ? `${code}: ${tail}` : code;
      out.timed_out = err === "timeout" && now() >= deadline;
      return;
    }
    out.launch.ok = true;
    out.launch.startup_ms = now() - started;
    const info = isObj(result.serverInfo) ? result.serverInfo : {};
    out.server_info = { name: String(info.name ?? "").slice(0, 120), version: String(info.version ?? "").slice(0, 40) };
    out.protocol_version = String(result.protocolVersion || proto).slice(0, 40);
    client.send({ jsonrpc: "2.0", method: "notifications/initialized" });

    const [tools, listErr] = await listTools(client, deadline, Math.max(o.perCallTimeout, 5));
    out.tools = tools.map((t) => ({ name: t.name, description: String(t.description || "").slice(0, 2000),
      annotations: isObj(t.annotations) ? t.annotations : null,
      input_schema: isObj(t.inputSchema) ? t.inputSchema : null }));
    if (listErr) { out.error = `tools_list_failed: ${listErr}`; return; }

    let mined = {};
    if (o.readme) {
      try { mined = mineExamples(fs.readFileSync(o.readme, "utf8").slice(0, 400000), tools.map((t) => t.name)); } catch (e) { mined = {}; }
    }
    const exclude = new Set([path.resolve(__filename)]);
    if (o.readme) exclude.add(path.resolve(o.readme));
    for (const spec of out.tools.slice(0, o.maxTools)) {
      if (now() >= deadline) { out.timed_out = true; break; }
      if (!client.alive()) { out.error = "server_exited"; break; }
      const call = await callTool(client, spec, o, mined, exclude, deadline, out.canary.seen_in_result);
      out.calls.push(call);
      if (call.error === "server_exited") { out.error = "server_exited"; break; }
    }

    // SSRF probe: each URL-taking tool once more with a sentinel link-local URL.
    if (o.ssrfUrl && client.alive()) {
      let probed = 0;
      for (const spec of out.tools) {
        if (probed >= o.maxSsrf || now() >= deadline || !client.alive()) break;
        const base = argsForTool(spec.name, spec.input_schema, mined);
        const [variant, changed] = ssrfVariant(base, o.ssrfUrl);
        if (!changed) continue;
        probed += 1;
        const call = await callTool(client, spec, o, mined, exclude, deadline,
          out.canary.seen_in_result, variant, o.ssrfUrl);
        out.calls.push(call);
        if (call.error === "server_exited") { out.error = "server_exited"; break; }
      }
    }
  } finally {
    delete out._client;
    client.kill();
  }
}

function emit(out) {
  const doc = {};
  for (const [k, v] of Object.entries(out)) if (!k.startsWith("_")) doc[k] = v;
  fs.writeSync(1, `\n${BEGIN}\n${JSON.stringify(doc)}\n${END}\n`);
}

async function main(argv) {
  const o = parseCli(argv);
  if (o.genArgs) {
    fs.writeSync(1, sortedStringify(generateArgs(JSON.parse(fs.readFileSync(o.genArgs, "utf8")))) + "\n");
    return 0;
  }
  const out = emptyTranscript(o.command, o.canaryEnv);
  let emitted = false;
  setTimeout(() => {
    if (emitted) return;
    out.timed_out = true; out.error = out.error || "exerciser_watchdog";
    emit(out);
    if (out._client) out._client.kill();
    process.exit(0);
  }, (o.timeout + 10) * 1000);
  try {
    if (!o.command.length) out.launch.error = "no_command";
    else await exercise(o, out);
  } catch (e) {
    out.error = `exerciser_crash: ${e && e.name}: ${String(e && e.message).slice(0, 200)}`;
  }
  emitted = true;
  emit(out);
  process.exit(0);
}

if (require.main === module) {
  process.on("uncaughtException", (e) => { fs.writeSync(2, `exerciser: ${e && e.stack}\n`); });
  main(process.argv.slice(2));
}
