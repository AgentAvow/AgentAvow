#!/usr/bin/env node
// The security team's approval step. Reads the signed result through the gate (so the
// signature is verified first), shows it, and records an approval bound to the
// signed tool manifest digest: the approval covers exactly the definitions that
// were scanned, and nothing the server serves later.

import fs from 'node:fs';
import { createGate } from 'agentavow-trust/gate';
import { API_BASE, DEMO_ISSUER, JWKS_URL, MCP_URL, STATE, shortReason, statePath } from './config.mjs';

const PHRASE = { safe: 'Safe to connect', review: 'Review before you connect', do_not_connect: 'Do not connect' };

const gate = createGate({ baseUrl: API_BASE, jwksUrl: JWKS_URL, issuer: DEMO_ISSUER, onReview: 'block', onWarn: () => {} });
const d = await gate.check(MCP_URL);
const g = d.grade;
console.log(`  signed result for ${MCP_URL}`);
console.log(`    ${PHRASE[d.decision]} · trust ${d.score}/100 (${d.tier}) · signature ${d.attestation?.verified ? 'verified' : 'NOT verified'} (kid ${g?.kid})`);
try {
  const raw = await (await fetch(`${API_BASE}/public/scan/mcp?endpoint=${encodeURIComponent(MCP_URL)}`)).json();
  if (raw.decision_reason) console.log(`    why: ${raw.decision_reason}`);
} catch { /* display only */ }
for (const [k, v] of Object.entries(g?.toolDigests ?? {})) console.log(`    signed ${k} = ${v}`);
if (d.decision === 'do_not_connect' || !d.attestation?.verified) {
  console.log(`  not approving: ${shortReason(d.reason)}`);
  process.exit(1);
}
fs.mkdirSync(STATE, { recursive: true });
const approval = {
  server: MCP_URL,
  toolManifestDigest: g.toolManifestDigest,
  toolDigests: g.toolDigests,
  approvedBy: 'security-team@acme.example (demo)',
  at: new Date().toISOString(),
  note: d.decision === 'review'
    ? `Reviewed: ${g.apiDecision === 'review' ? 'AgentAvow said review' : shortReason(d.reason)}; one send-only tool, approved.`
    : 'Safe to connect; approved.',
};
fs.writeFileSync(statePath('approvals.json'), JSON.stringify([approval], null, 2) + '\n');
console.log(`  approved by ${approval.approvedBy}, bound to the signed tool manifest:`);
console.log(`    ${approval.toolManifestDigest}`);
