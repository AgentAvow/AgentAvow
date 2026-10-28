// Shared settings for the demo processes. Everything is localhost.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGate } from 'agentavow-trust/gate';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const MCP_PORT = Number(process.env.MCP_PORT ?? 8787);
export const API_PORT = Number(process.env.API_PORT ?? 8788);
export const MCP_URL = `http://127.0.0.1:${MCP_PORT}/mcp`;
export const API_BASE = `http://127.0.0.1:${API_PORT}/api/v1`;
export const JWKS_URL = `http://127.0.0.1:${API_PORT}/.well-known/jwks.json`;
export const STATE = path.resolve(process.env.RUGPULL_STATE ?? path.join(HERE, '.state'));

// The demo scanner's identity. Deliberately not AgentAvow's: a gate on its
// defaults (issuer did:web:agentgraph.co, AgentAvow's JWKS) rejects these results.
export const DEMO_ISSUER = 'did:web:demo.invalid';
export const DEMO_KID = 'demo-not-agentavow';

export const statePath = (name) => path.join(STATE, name);

export function readJsonl(name) {
  try {
    return fs.readFileSync(statePath(name), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

export function readApprovals() {
  try {
    return JSON.parse(fs.readFileSync(statePath('approvals.json'), 'utf8'));
  } catch {
    return [];
  }
}

/**
 * The gate the protected agent runs with. Policy, in words:
 *   - read results from the local demo scanner and verify them against its JWKS
 *     (issuer did:web:demo.invalid), never trusting the unsigned JSON;
 *   - onDrift 'block': a tool whose served definition does not hash to the
 *     signed digest is do_not_connect, whatever the score;
 *   - onReview 'confirm': a "Review before you connect" answer runs only if the
 *     security team recorded an approval of that exact scanned manifest
 *     (`approvals.json`, written by approve.mjs). No approval, no call.
 * Everything else is the SDK default (allowFloor 51, fail closed on API errors).
 */
export function demoGate({ onWarn } = {}) {
  return createGate({
    baseUrl: API_BASE,
    jwksUrl: JWKS_URL,
    issuer: DEMO_ISSUER,
    onDrift: 'block',
    onReview: 'confirm',
    confirm: (d) => readApprovals().some((a) =>
      a.server === d.server && a.toolManifestDigest === d.grade?.toolManifestDigest),
    onWarn: onWarn ?? (() => {}),
  });
}

/** The gate's reason without the trailing hosted-report link, which cannot see a
 *  localhost server. */
export const shortReason = (reason) => String(reason ?? '').replace(/\s*Report: \S+/, '');
