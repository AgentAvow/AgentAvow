// The API answers errors as RFC 9457 problem+json (#409): content type
// application/problem+json, the old `detail` and `request_id` kept, new fields added.
// The client and the gate must read `detail` from it exactly as before.

import { test } from 'node:test';
import assert from 'node:assert/strict';

const gate = await import('../dist/gate.js');
const { TrustClient, AgentGraphError } = await import('../src/client.js');

const API = 'https://agentavow.test/api/v1';
const SERVER = 'https://mcp.example.com/mcp';

const problem = (status, detail, code) => new Response(JSON.stringify({
  type: `https://agentavow.com/problems/${code}`,
  title: 'Title',
  status,
  code,
  detail,
  instance: '/api/v1/public/scan/mcp',
  request_id: 'abc123',
  trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
}), { status, headers: { 'content-type': 'application/problem+json' } });

test('the gate reads detail from a problem+json error', async () => {
  const fetch = async () => problem(404, 'Server not found', 'not_found');
  const client = new gate.GradeClient({ baseUrl: API, fetch });
  const g = await client.grade(SERVER);
  assert.match(g.error, /^HTTP 404: Server not found$/);
});

test('the gate reads a problem+json 429 like before', async () => {
  const fetch = async () => problem(429, 'Rate limit exceeded', 'rate_limited');
  const client = new gate.GradeClient({ baseUrl: API, fetch });
  assert.match((await client.grade(SERVER)).error, /^HTTP 429: Rate limit exceeded$/);
});

test('TrustClient raises with the problem detail and status', async () => {
  const c = new TrustClient('https://agentavow.test');
  await assert.rejects(
    c._parseResponse(problem(404, 'Entity not found', 'not_found')),
    (err) => err instanceof AgentGraphError && err.message === 'Entity not found' && err.statusCode === 404,
  );
});
