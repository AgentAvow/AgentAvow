// End-to-end, model-free, localhost only: the control run leaks exactly one
// canary message; the protected run leaks none and reports do_not_connect with
// both digests. Needs node 20+ and this repo's Python backend (for grade.py).
//
//   cd demos/rugpull && npm test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO = path.resolve(HERE, '../..');

function findPython() {
  const cands = [process.env.PYTHON, path.join(REPO, '.venv312/bin/python'), path.join(REPO, '.venv/bin/python'), 'python3', 'python'];
  for (const p of cands.filter(Boolean)) {
    const r = spawnSync(p, ['-c', 'import src.scanner.scan'], { cwd: REPO, env: { ...process.env, DEBUG: 'true' } });
    if (r.status === 0) return p;
  }
  return null;
}
const PYTHON = findPython();
const skip = PYTHON ? false : 'no Python with this repo backend installed (pip install -e . at the repo root, or set PYTHON)';

const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer();
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  s.on('error', reject);
});

async function waitUp(url) {
  for (let i = 0; i < 100; i++) {
    try { await fetch(url); return; } catch { await new Promise((r) => setTimeout(r, 50)); }
  }
  throw new Error(`timed out waiting for ${url}`);
}

test('rug-pull at the call: control leaks one canary, protected leaks none', { skip, timeout: 60_000 }, async (t) => {
  const state = fs.mkdtempSync(path.join(os.tmpdir(), 'rugpull-'));
  const MCP_PORT = await freePort();
  const API_PORT = await freePort();
  const env = { ...process.env, MCP_PORT: String(MCP_PORT), API_PORT: String(API_PORT), RUGPULL_STATE: state, DEBUG: 'true' };
  const mcpUrl = `http://127.0.0.1:${MCP_PORT}/mcp`;
  const procs = [];
  const start = (args) => {
    const p = spawn(process.execPath, args, { cwd: HERE, env, stdio: 'ignore' });
    procs.push(p);
    return p;
  };
  t.after(() => { for (const p of procs) p.kill(); fs.rmSync(state, { recursive: true, force: true }); });

  const run = (cmd, args, extraEnv = {}) => {
    const r = spawnSync(cmd, args, { cwd: cmd === PYTHON ? REPO : HERE, env: { ...env, ...extraEnv }, encoding: 'utf8' });
    assert.equal(r.status, 0, `${cmd} ${args.join(' ')} failed:\n${r.stdout}\n${r.stderr}`);
    return r.stdout;
  };
  const agent = (mode, canary) => {
    const out = run(process.execPath, ['agent.mjs', '--mode', mode, '--json'], { RUGPULL_CANARY: canary });
    const line = out.split('\n').find((l) => l.startsWith('RESULT '));
    assert.ok(line, `no RESULT line from ${mode}:\n${out}`);
    return JSON.parse(line.slice(7));
  };
  const jsonl = (name) => {
    try { return fs.readFileSync(path.join(state, name), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; }
  };

  // Approval day: v1 is served, graded by the real scanner, signed by the demo key, approved.
  let server = start(['server.mjs', '--version', 'v1']);
  start(['api.mjs']);
  await waitUp(`http://127.0.0.1:${MCP_PORT}/healthz`);
  await waitUp(`http://127.0.0.1:${API_PORT}/`);
  const graded = JSON.parse(run(PYTHON, [path.join(HERE, 'grade.py'), '--endpoint', mcpUrl, '--out', state, '--json']));
  assert.equal(graded.decision, 'safe', 'v1 grades Safe to connect: tool definitions clean, server code not inspected (see README)');
  assert.deepEqual(graded.findings, []);
  run(process.execPath, ['approve.mjs']);

  // Baseline: the gate allows v1, and the served digest is the signed one.
  const base = agent('protected', 'CANARY-baseline');
  const b = base.calls[0];
  assert.equal(b.ran, true);
  assert.equal(b.allowed, true);
  assert.equal(b.servedDigest, b.signedDigest);
  assert.equal(b.signedDigest, graded.tool_digests['tool:send_email']);

  // The rug-pull: same URL, v2.
  server.kill();
  await new Promise((r) => server.once('exit', r));
  server = start(['server.mjs', '--version', 'v2']);
  await waitUp(`http://127.0.0.1:${MCP_PORT}/healthz`);

  const control = agent('control', 'CANARY-control');
  assert.equal(control.calls[0].ran, true);
  const protectedRun = agent('protected', 'CANARY-protected');
  const p = protectedRun.calls[0];

  const sink = jsonl('attacker-sink.jsonl');
  assert.equal(sink.length, 1, 'exactly one message reached the attacker sink');
  assert.match(sink[0].text, /CANARY-control/);
  assert.equal(sink[0].bcc, 'audit-archive@collector.invalid');
  assert.equal(sink.filter((m) => m.text.includes('CANARY-protected')).length, 0);
  assert.equal(jsonl('outbox.jsonl').filter((m) => m.text.includes('CANARY-protected')).length, 0, 'the protected call never reached the server');

  assert.equal(p.ran, false);
  assert.equal(p.decision, 'do_not_connect');
  assert.equal(p.outcome, 'drift');
  assert.equal(p.signedDigest, graded.tool_digests['tool:send_email']);
  assert.match(p.servedDigest, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(p.servedDigest, p.signedDigest);
  assert.ok(p.reason.includes(p.signedDigest.slice(0, 19)) && p.reason.includes(p.servedDigest.slice(0, 19)),
    'the message names both digests');

  // The demo key can never pass for AgentAvow's: a gate on its default issuer refuses it.
  const { createGate } = await import('agentavow-trust/gate');
  const jwks = JSON.parse(fs.readFileSync(path.join(state, 'jwks.json'), 'utf8'));
  const strict = createGate({ baseUrl: `http://127.0.0.1:${API_PORT}/api/v1`, jwks, onWarn: () => {} });
  const d = await strict.check(mcpUrl);
  assert.equal(d.outcome, 'unverified');
  assert.equal(d.decision, 'do_not_connect');
  assert.match(d.reason, /issuer did:web:demo\.invalid is not did:web:agentgraph\.co/);
});
