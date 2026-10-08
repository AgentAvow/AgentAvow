#!/usr/bin/env node
// A stand-in for AgentAvow's public API, serving the one grade grade.py signed:
//
//   GET /api/v1/public/scan/mcp?endpoint=<url>   the signed scan response (404 for any other endpoint)
//   GET /.well-known/jwks.json                  the throwaway demo public key
//
// It serves files and does nothing else: no scanning, no re-grading. The gate
// reads it exactly as it reads https://agentavow.com/api/v1, so the client code
// path is the production one. Binds 127.0.0.1 only.

import http from 'node:http';
import fs from 'node:fs';
import { API_PORT, statePath } from './config.mjs';

const send = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${API_PORT}`);
  try {
    if (url.pathname === '/.well-known/jwks.json') return send(res, 200, fs.readFileSync(statePath('jwks.json'), 'utf8'));
    if (url.pathname === '/api/v1/public/scan/mcp') {
      const grade = JSON.parse(fs.readFileSync(statePath('grade.json'), 'utf8'));
      const endpoint = url.searchParams.get('endpoint');
      if (grade.repo !== `mcp:${endpoint}`) return send(res, 404, { detail: `no grade for ${endpoint}` });
      return send(res, 200, grade);
    }
  } catch (e) {
    return send(res, 503, { detail: `no grade yet (${e.code ?? e.message}); run grade.py first` });
  }
  send(res, 404, { detail: 'no route' });
});

server.listen(API_PORT, '127.0.0.1', () => {
  console.log(`[api] demo grader API at http://127.0.0.1:${API_PORT} (NOT AgentAvow; issuer did:web:demo.invalid)`);
});
const stop = () => server.close(() => process.exit(0));
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
